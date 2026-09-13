"""Canary and selection-audit acceptance with real tenant records and signed sink evidence."""

from copy import deepcopy
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from threatveil import api, assurance
from threatveil.db import Account, Membership, Record, now, transaction

from test_observers import create_fix, execute, observer_customer as observer_customer, qualify


@pytest.fixture
def canary_customer(observer_customer):
    h = observer_customer
    observer = qualify(h)
    failed = execute(h, observer, "vulnerable", candidate="candidate-v0")
    fixed = execute(h, observer, candidate="candidate-v1")
    baseline = create_fix(h, failed, fixed)["baseline_id"]
    assert baseline
    return h, observer, baseline


def candidate_run(harness, fixture="fixed"):
    h, observer, _ = harness
    return execute(h, observer, fixture, candidate="candidate-v2")


def create_canary(harness, run=None, **overrides):
    h, _, baseline = harness
    payload = {
        "system_id": h[1]["system"]["id"],
        "candidate": run["candidate"]
        if run
        else {
            "type": "application_version",
            "id": h[1]["system"]["id"],
            "version": "candidate-v2",
            "digest": "a" * 64,
        },
        "pairs": [{"baseline_id": baseline, "candidate_run_id": run["id"] if run else None}],
    }
    payload.update(overrides)
    return h[0].post("/v1/canaries", json=payload)


def impact(harness, run, fingerprint=None):
    h = harness[0]
    fingerprint = fingerprint or run["fingerprint"]
    response = h[0].post(
        "/v1/impact",
        json={"system_id": h[1]["system"]["id"], "previous": fingerprint, "candidate": fingerprint},
    )
    assert response.status_code in (200, 201), response.text
    return response.json()


def selection_audit(harness, run, selection, run_ids=None):
    return harness[0][0].post(
        "/v1/selection-audits",
        json={
            "impact_id": selection["id"],
            "candidate": run["candidate"],
            "candidate_run_ids": [run["id"]] if run_ids is None else run_ids,
        },
    )


def test_canary_preserves_exact_candidate_without_executing_or_spending(canary_customer):
    h = canary_customer[0]
    run = candidate_run(canary_customer)
    org = UUID(h[1]["system"]["organization_id"])
    with transaction(org_id=org) as session:
        before = session.get(Account, org).consumed
        run_ids = set(session.scalars(select(Record.id).where(Record.kind == "run")))
    response = create_canary(canary_customer, run)
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["snapshot"]["complete"] and result["current"]["release_action"] == "ALLOW"
    assert (
        result["current"]["counts"]["PRESERVED"] == 1
        and result["current"]["max_evidence_age_hours"] == 24
    )
    listing = h[0].get("/v1/canaries", params={"system_id": h[1]["system"]["id"]}).json()
    assert listing["history_only"] and listing["items"][0]["id"] == result["id"]
    assert "current" not in listing["items"][0]
    with transaction(org_id=org) as session:
        assert session.get(Account, org).consumed == before
        assert set(session.scalars(select(Record.id).where(Record.kind == "run"))) == run_ids


def test_canary_confirmed_regression_blocks_without_statistical_significance(canary_customer):
    response = create_canary(canary_customer, candidate_run(canary_customer, "regressed"))
    assert response.status_code == 201, response.text
    current = response.json()["current"]
    assert current["counts"]["REGRESSED"] == 1 and current["release_action"] == "BLOCK"
    assert current["rows"][0]["comparison"]["comparisons"] == []


def test_missing_candidate_is_explicitly_unknown(canary_customer):
    response = create_canary(canary_customer)
    assert response.status_code == 201
    current = response.json()["current"]
    assert current["counts"]["UNKNOWN"] == 1 and not current["complete"]
    assert current["release_action"] == "BLOCK"


def test_wrong_candidate_digest_cannot_preserve_history(canary_customer):
    run = candidate_run(canary_customer)
    response = create_canary(
        canary_customer, run, candidate={**run["candidate"], "digest": "0" * 64}
    )
    assert response.status_code == 201
    assert response.json()["current"]["counts"]["INCOMPATIBLE"] == 1
    assert response.json()["current"]["release_action"] == "BLOCK"


def test_duplicate_property_pairs_are_rejected(canary_customer):
    run = candidate_run(canary_customer)
    pair = {"baseline_id": canary_customer[2], "candidate_run_id": run["id"]}
    assert create_canary(canary_customer, run, pairs=[pair, pair]).status_code == 422


def test_foreign_target_pair_is_rejected_instead_of_warning(canary_customer):
    h, _, _ = canary_customer
    response = h[0].post(
        "/v1/runs",
        json={
            "system_id": h[1]["system"]["id"],
            "property_id": h[1]["property"]["id"],
            "target_id": h[1]["target"]["id"],
            "version": "fixed",
            "trials": 1,
            "idempotency_key": str(uuid4()),
        },
    )
    assert response.status_code == 202
    run = h[0].get("/v1/runs/" + response.json()["id"]).json()
    assert create_canary(canary_customer, run).status_code == 422


def test_revocation_changes_current_assessment_not_snapshot(canary_customer):
    h, observer, _ = canary_customer
    result = create_canary(canary_customer, candidate_run(canary_customer)).json()
    assert h[0].post(f"/v1/observers/{observer['id']}/revoke").status_code == 200
    fetched = h[0].get("/v1/canaries/" + result["id"]).json()
    assert (
        fetched["snapshot"] == result["snapshot"]
        and fetched["snapshot_digest"] == result["snapshot_digest"]
    )
    assert (
        fetched["current"]["counts"]["STALE"] == 1
        and fetched["current"]["release_action"] == "BLOCK"
    )


def test_candidate_evidence_expires_after_explicit_24_hours(canary_customer, monkeypatch):
    h = canary_customer[0]
    result = create_canary(canary_customer, candidate_run(canary_customer)).json()
    future = now() + timedelta(hours=25)
    monkeypatch.setattr(assurance, "now", lambda: future)
    fetched = h[0].get("/v1/canaries/" + result["id"]).json()
    assert (
        fetched["snapshot"]["release_action"] == "ALLOW"
        and fetched["current"]["counts"]["STALE"] == 1
    )
    assert any("24-hour" in reason for reason in fetched["current"]["rows"][0]["reasons"])


def test_assurance_records_are_tenant_scoped_and_viewers_cannot_create(canary_customer):
    h = canary_customer[0]
    run = candidate_run(canary_customer)
    record = create_canary(canary_customer, run).json()
    with TestClient(api.app) as other:
        other.cookies.set("tv_session", str(uuid4()))
        login = other.post(
            "/v1/auth/local",
            json={"email": f"{uuid4()}@local.invalid"},
            headers={"origin": "http://127.0.0.1:3000"},
        )
        assert login.status_code == 200
        assert other.get("/v1/canaries/" + record["id"]).status_code == 404
        assert other.get("/v1/canaries").json()["items"] == []
    org = UUID(h[1]["system"]["organization_id"])
    user = UUID(h[0].get("/v1/auth/me").json()["user"]["id"])
    with transaction(org_id=org, user_id=user) as session:
        session.get(Membership, (org, user)).role = "viewer"
    assert create_canary(canary_customer, run).status_code == 403
    assert h[0].get("/v1/canaries/" + record["id"]).status_code == 200


def test_selection_audit_discovers_an_excluded_confirmed_failure(canary_customer):
    h = canary_customer[0]
    run = candidate_run(canary_customer, "regressed")
    selection = impact(canary_customer, run)
    assert selection["selected"] == [] and len(selection["excluded"]) == 1
    response = selection_audit(canary_customer, run, selection)
    assert response.status_code == 201, response.text
    result = response.json()["current"]
    assert result["complete"] and result["impact_scope_valid"]
    assert result["missed_failure_property_ids"] == [h[1]["property"]["id"]]
    assert result["rows"][0]["classification"] == "FAILED" and result["release_action"] == "BLOCK"


def test_missing_full_suite_evidence_cannot_claim_zero_selection_misses(canary_customer):
    h = canary_customer[0]
    run = candidate_run(canary_customer)
    response = selection_audit(canary_customer, run, impact(canary_customer, run), [])
    assert response.status_code == 201
    result = response.json()["current"]
    assert not result["complete"] and result["missing_property_ids"] == [h[1]["property"]["id"]]
    assert result["release_action"] == "BLOCK"


def test_selection_requires_entire_observed_impact_configuration(canary_customer):
    run = candidate_run(canary_customer)
    expected = deepcopy(run["fingerprint"])
    expected["components"].append(
        {
            "type": "tool",
            "id": "erp",
            "version": "unobserved-tool-v2",
            "digest": "b" * 64,
            "provenance": "DECLARED",
        }
    )
    response = selection_audit(canary_customer, run, impact(canary_customer, run, expected))
    assert response.status_code == 201
    current = response.json()["current"]
    assert current["counts"]["INCOMPATIBLE"] == 1 and not current["complete"]
    assert current["release_action"] == "BLOCK"


def test_new_property_invalidates_current_full_suite_audit_only(canary_customer):
    h = canary_customer[0]
    run = candidate_run(canary_customer)
    record = selection_audit(canary_customer, run, impact(canary_customer, run)).json()
    assert record["snapshot"]["complete"] and record["snapshot"]["release_action"] == "ALLOW"
    prop = (
        h[0]
        .post(
            "/v1/properties",
            json={
                "system_id": h[1]["system"]["id"],
                "title": "Additional security property",
                "definition": h[1]["property"]["definition"],
            },
        )
        .json()
    )
    approved = h[0].post(f"/v1/properties/{prop['id']}/approve").json()
    fetched = h[0].get("/v1/selection-audits/" + record["id"]).json()
    assert fetched["snapshot"] == record["snapshot"]
    assert not fetched["current"]["complete"] and fetched["current"]["release_action"] == "BLOCK"
    assert fetched["current"]["new_property_ids"] == [approved["id"]]
