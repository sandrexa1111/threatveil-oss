"""The Business Effect Observer Contract, its qualification harness, and the limits of
what an observer's facts may mean.

The read-only PostgreSQL observer is exercised against a real temporary schema, over
every scenario qualification requires. An observer that is not QUALIFIED can record
facts and can never produce evidence.
"""

import os
from datetime import timedelta
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from pydantic import ValidationError

from threatveil.config import settings
from threatveil.db import now
from threatveil.observer_platform import SCENARIO_NAMES, run_harness
from threatveil.observer_sql import ObserverUnavailable, SqlObserverConfig, observe, read_rows
from test_assurance_intelligence import other_tenant
from test_product import customer as customer  # noqa: F401

CONTRACT = {
    "name": "Refund ledger observer",
    "system_of_record": "Billing PostgreSQL",
    "resource": "customer refunds",
    "observed_effects": ["ATTEMPTED", "COMMITTED", "DENIED", "COMPENSATED", "UNKNOWN"],
    "actions": ["refund.issue"],
    "correlation": {"method": "IDEMPOTENCY_KEY", "field": "correlation",
                    "note": "The agent sends its idempotency key and the ledger stores it verbatim."},
    "read_method": {"kind": "READ_ONLY_SQL", "writes": False,
                    "detail": "One bounded read-only SELECT against the refunds ledger."},
    "commit_semantics": {"durability": "COMMITTED_TRANSACTION",
                         "note": "A ledger row exists only after its transaction commits."},
    "observation_window_seconds": 3600,
    "coverage_limits": ["Refunds issued outside this ledger are invisible.",
                        "Partial refunds are not distinguished from full refunds."],
    "failure_semantics": {"on_missing_record": "DENIED",
                          "note": "This observer covers every commit to the refunds ledger inside the window."},
    "requalify_days": 90,
}
STATES = {"received": "ATTEMPTED", "posted": "COMMITTED", "refused": "DENIED", "reversed": "COMPENSATED"}


def admin_dsn():
    url = settings().admin_database_url
    if not url:
        pytest.skip("The migration identity is required to exercise the SQL observer")
    return url.replace("postgresql+psycopg://", "postgresql://")


@pytest.fixture
def ledger():
    """A temporary ledger schema with one row per qualification scenario."""
    dsn, schema = admin_dsn(), f"tv_obs_{uuid4().hex[:12]}"
    os.environ["TV_OBSERVER_DSN_LEDGER"] = dsn
    stamp = now()
    rows = [("commit-1", "posted", stamp, "refund/1", "acme"),
            ("denied-1", "refused", stamp, "refund/2", "acme"),
            ("compensated-1", "posted", stamp - timedelta(minutes=5), "refund/3", "acme"),
            ("compensated-1", "reversed", stamp, "refund/3", "acme"),
            ("multi-1", "posted", stamp - timedelta(minutes=2), "refund/4", "acme"),
            ("multi-1", "posted", stamp, "refund/5", "acme"),
            ("stale-1", "posted", stamp - timedelta(days=2), "refund/6", "acme"),
            ("tenant-1", "posted", stamp, "refund/7", "other-tenant")]
    name = sql.Identifier(schema)
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(name))
        connection.execute(sql.SQL("CREATE TABLE {}.refunds (correlation text, state text, "
                                   "occurred_at timestamptz, resource text, tenant text)").format(name))
        connection.cursor().executemany(
            sql.SQL("INSERT INTO {}.refunds VALUES (%s, %s, %s, %s, %s)").format(name), rows)
    yield schema
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(name))
    os.environ.pop("TV_OBSERVER_DSN_LEDGER", None)


def config_for(schema, **overrides):
    values = {"connection": "LEDGER", "schema_name": schema, "table": "refunds",
              "correlation_column": "correlation", "state_column": "state",
              "occurred_at_column": "occurred_at", "resource_column": "resource",
              "tenant_column": "tenant", "tenant_value": "acme", "state_map": STATES, "row_limit": 5}
    return SqlObserverConfig(**{**values, **overrides})


def scenario_answer(config, scenario):
    window = {"window_start": now() - timedelta(hours=1), "window_end": now() + timedelta(minutes=1),
              "covers_commit": True, "absence_is_denial": True}
    correlations = {"POSITIVE_COMMIT": "commit-1", "DENIED": "denied-1", "NO_EFFECT": "absent-1",
                    "COMPENSATED": "compensated-1", "MISSING_CORRELATION": "", "STALE": "stale-1",
                    "MULTIPLE_MATCHES": "multi-1", "WRONG_TENANT": "tenant-1",
                    "INSUFFICIENT_COVERAGE": "commit-1", "OUTAGE": "commit-1"}
    if scenario == "OUTAGE":
        unreachable = config.model_copy(update={"connection": "NOT_PROVISIONED"})
        return observe(unreachable, correlation_value=correlations[scenario], **window)["effect"]
    covered = scenario != "INSUFFICIENT_COVERAGE"
    return observe(config, correlation_value=correlations[scenario], covered=covered, **window)["effect"]


def setup_system(client, name="Support agent with a ledger"):
    system = client.post("/v1/systems", json={"name": name})
    assert system.status_code == 201, system.text
    environment = client.post("/v1/change-assurance/environments", json={
        "system_id": system.json()["id"], "name": "Staging", "purpose": "STAGING",
        "boundary": "Staging refunds ledger only", "owner": "Support engineering"})
    assert environment.status_code == 201, environment.text
    return system.json()["id"], environment.json()["id"]


def define(client, system_id, environment_id, **overrides):
    response = client.post(f"/v1/systems/{system_id}/observer-definitions",
                           json={**CONTRACT, "environment_id": environment_id, **overrides})
    assert response.status_code == 201, response.text
    return response.json()


def qualify(client, definition, harness, **overrides):
    body = {"contract_digest": definition["contract_digest"], "harness_version": harness["harness_version"],
            "results": harness["results"], "evidence_reference": "local harness run: .local/observer-harness.json",
            "review_note": "Reviewed the harness output against the declared contract and coverage limits.",
            **overrides}
    return client.post(f"/v1/observer-definitions/{definition['id']}/qualification", json=body)


def record(client, definition_id, effect, correlation="commit-1", **overrides):
    body = {"correlation_value": correlation, "effect": effect, "action": "refund.issue",
            "resource_reference": "refund/1", "observed_at": now().isoformat(),
            "idempotency_key": str(uuid4()), **overrides}
    return client.post(f"/v1/observer-definitions/{definition_id}/observations", json=body)


def effects(client, definition_id, correlation="commit-1"):
    response = client.get(f"/v1/observer-definitions/{definition_id}/effects",
                          params={"correlation_value": correlation})
    assert response.status_code == 200, response.text
    return response.json()


def test_the_read_only_sql_observer_answers_every_qualification_scenario(customer, ledger):
    config = config_for(ledger)
    harness = run_harness(lambda scenario: scenario_answer(config, scenario))
    assert harness["outcome"] == "PASSED", harness["failures"]
    assert set(harness["results"]) == set(SCENARIO_NAMES)
    assert harness["results"]["POSITIVE_COMMIT"] == "COMMITTED"
    assert harness["results"]["COMPENSATED"] == "COMPENSATED"
    assert harness["results"]["NO_EFFECT"] == "DENIED"
    assert all(harness["results"][name] == "UNKNOWN" for name in
               ("MISSING_CORRELATION", "STALE", "MULTIPLE_MATCHES", "OUTAGE", "WRONG_TENANT",
                "INSUFFICIENT_COVERAGE"))
    # The observer reads only; the ledger is untouched and no statement is caller-supplied.
    rows = read_rows(config, correlation_value="commit-1", window_start=now() - timedelta(hours=1),
                     window_end=now() + timedelta(minutes=1))
    assert [row["state"] for row in rows] == ["posted"]
    system_id, environment_id = setup_system(customer)
    definition = define(customer, system_id, environment_id)
    assert definition["qualification"]["state"] == "UNQUALIFIED"
    assert definition["produces_evidence"] is False
    result = qualify(customer, definition, harness)
    assert result.status_code == 201, result.text
    assert result.json()["outcome"] == "PASSED" and result.json()["failed_scenarios"] == []
    assert result.json()["qualification"]["state"] == "QUALIFIED"
    listed = customer.get(f"/v1/systems/{system_id}/observer-definitions").json()
    assert listed["items"][0]["produces_evidence"] is True
    assert len(listed["scenarios"]) == len(SCENARIO_NAMES)


def test_an_unqualified_observer_can_never_produce_qualified_evidence(customer, ledger):
    system_id, environment_id = setup_system(customer, "Unqualified observer system")
    definition = define(customer, system_id, environment_id)
    early = record(customer, definition["id"], "COMMITTED")
    assert early.status_code == 201, early.text
    assert early.json()["qualified"] is False and early.json()["qualification_state"] == "UNQUALIFIED"
    summary = effects(customer, definition["id"])
    assert summary["effect"] == "UNKNOWN" and summary["committed"] is None
    assert summary["qualified_facts"] == 0 and summary["unqualified_facts"] == 1
    assert "not evidence" in summary["reason"] or "no qualified" in summary["reason"].lower()
    # A failed harness run cannot qualify it either.
    failed = run_harness(lambda scenario: "COMMITTED")
    assert failed["outcome"] == "FAILED"
    response = qualify(customer, definition, failed)
    assert response.status_code == 201 and response.json()["outcome"] == "FAILED"
    assert response.json()["qualification"]["state"] == "QUALIFICATION_PENDING"
    assert effects(customer, definition["id"])["effect"] == "UNKNOWN"
    # A qualification produced for a different contract is refused.
    config = config_for(ledger)
    harness = run_harness(lambda scenario: scenario_answer(config, scenario))
    assert qualify(customer, definition, harness,
                   contract_digest="0" * 64).status_code == 409
    assert qualify(customer, definition, harness).json()["qualification"]["state"] == "QUALIFIED"
    # Only facts recorded while qualified are evidence. Earlier facts stay unqualified.
    later = record(customer, definition["id"], "COMMITTED")
    assert later.json()["qualified"] is True
    summary = effects(customer, definition["id"])
    assert (summary["effect"], summary["committed"]) == ("COMMITTED", True)
    assert summary["unqualified_facts"] == 1 and summary["qualified_facts"] == 1
    # Revocation ends new evidence without rewriting history.
    revoked = customer.post(f"/v1/observer-definitions/{definition['id']}/revoke",
                            json={"reason": "The ledger replica this observer read was decommissioned"})
    assert revoked.status_code == 201 and revoked.json()["qualification"]["state"] == "REVOKED"
    assert record(customer, definition["id"], "COMMITTED").status_code == 409
    assert effects(customer, definition["id"])["qualification"]["state"] == "REVOKED"


def test_compensation_never_erases_a_commit_and_absence_is_never_no_effect(customer, ledger):
    system_id, environment_id = setup_system(customer, "Compensation semantics system")
    definition = define(customer, system_id, environment_id)
    config = config_for(ledger)
    assert qualify(customer, definition,
                   run_harness(lambda s: scenario_answer(config, s))).json()["outcome"] == "PASSED"
    assert record(customer, definition["id"], "COMMITTED", "refund-9").status_code == 201
    assert record(customer, definition["id"], "COMPENSATED", "refund-9", compensates="refund-9").status_code == 201
    summary = effects(customer, definition["id"], "refund-9")
    assert summary["effect"] == "COMMITTED_THEN_COMPENSATED"
    assert summary["committed"] is True and summary["compensated"] is True
    assert "still happened" in summary["reason"]
    # No fact at all is never "no effect".
    nothing = effects(customer, definition["id"], "refund-never-attempted")
    assert nothing["effect"] == "UNKNOWN" and nothing["committed"] is None
    assert "not evidence that no effect committed" in nothing["reason"]
    assert "Missing evidence is not evidence of no effect" in nothing["principle"]
    # Pre-commit facts alone establish nothing.
    assert record(customer, definition["id"], "ATTEMPTED", "refund-10").status_code == 201
    pending = effects(customer, definition["id"], "refund-10")
    assert pending["effect"] in {"UNKNOWN", "NO_EFFECT_OBSERVED"}
    assert pending["committed"] is not True
    # An effect outside the declared contract is refused outright.
    assert record(customer, definition["id"], "DISPATCHED", "refund-11").status_code == 422


def test_observer_contracts_are_bounded_honest_and_tenant_isolated(customer, ledger):
    system_id, environment_id = setup_system(customer, "Observer boundary system")
    definition = define(customer, system_id, environment_id)
    other = other_tenant()
    assert other.get(f"/v1/observer-definitions/{definition['id']}").status_code == 404
    assert other.post(f"/v1/observer-definitions/{definition['id']}/observations", json={
        "correlation_value": "commit-1", "effect": "COMMITTED", "action": "refund.issue",
        "resource_reference": "refund/1", "observed_at": now().isoformat(),
        "idempotency_key": str(uuid4())}).status_code == 404
    assert other.get(f"/v1/systems/{system_id}/observer-definitions").status_code == 404
    # An observer that cannot see commits may never read absence as a denial.
    blind = customer.post(f"/v1/systems/{system_id}/observer-definitions", json={
        **CONTRACT, "environment_id": environment_id, "name": "Blind observer",
        "observed_effects": ["ATTEMPTED", "UNKNOWN"]})
    assert blind.status_code == 422
    # Coverage limits and a correlation note are mandatory, and a time window must admit its weakness.
    assert customer.post(f"/v1/systems/{system_id}/observer-definitions", json={
        **CONTRACT, "environment_id": environment_id, "coverage_limits": []}).status_code == 422
    assert customer.post(f"/v1/systems/{system_id}/observer-definitions", json={
        **CONTRACT, "environment_id": environment_id,
        "correlation": {"method": "TIME_WINDOW", "field": "occurred_at",
                        "note": "Matches the nearest row in time."}}).status_code == 422
    # The SQL template accepts plain identifiers only; no statement is ever caller-supplied.
    for bad in ({"schema_name": "public; DROP TABLE refunds"}, {"table": "refunds WHERE 1=1"},
                {"correlation_column": "correlation::text"}, {"connection": "ledger"},
                {"state_map": {"posted": "SETTLED"}}, {"tenant_value": None}):
        with pytest.raises(ValidationError):
            config_for(ledger, **bad)
    with pytest.raises(ObserverUnavailable):
        read_rows(config_for(ledger).model_copy(update={"connection": "NOT_PROVISIONED"}),
                  correlation_value="commit-1", window_start=now() - timedelta(hours=1), window_end=now())
