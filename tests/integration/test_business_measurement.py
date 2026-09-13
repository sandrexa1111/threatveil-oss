"""Truthful business measurement, proposed-change assurance, declared change impact
and the operator store, over the real API and PostgreSQL row security.

Synthetic activity is recorded and shown, and never counts. Feedback never changes a
consequence. A proposed change never changes current clearance.
"""

from copy import deepcopy
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from threatveil import commercial
from threatveil.change_assurance_api import GATEWAY_BASELINE, gateway_payload
from threatveil.db import now, transaction
from test_assurance_intelligence import change, cleared, other_tenant
from test_connectors import mcp_payload
from test_product import customer as customer  # noqa: F401

LABEL = "PROPOSED · NON-ACTIVE · NOT CURRENT STATE"


def identity(client):
    value = client.get("/v1/auth/me").json()
    return UUID(value["user"]["id"]), UUID(value["organization"]["id"])


def views(client, system_id):
    response = client.get(f"/v1/systems/{system_id}/changes")
    assert response.status_code == 200, response.text
    return response.json()["items"]


def observed(client, system_id):
    """The newest recorded change that is not a source's first observation."""
    return next(v for v in views(client, system_id) if v["kind"] == "SOURCE_CHANGE" and not v["initial"])


def judge(client, system_id, consequence_id, verdict, key=None, comment=None):
    return client.post(f"/v1/systems/{system_id}/consequences/{consequence_id}/feedback", json={
        "verdict": verdict, "comment": comment, "idempotency_key": key or str(uuid4())})


def business(client):
    response = client.get("/v1/measurements/business")
    assert response.status_code == 200, response.text
    return response.json()


def activation(client):
    response = client.get("/v1/measurements/activation")
    assert response.status_code == 200, response.text
    return response.json()


def gate(client, system_id):
    body = client.get(f"/v1/systems/{system_id}/assurance/current").json()
    return body["status"], body["cleared"], body["decision"]["id"], body["state"]["digest"]


def counted_kinds(org):
    with transaction(org_id=org) as session:
        return dict(session.execute(text(
            "SELECT kind, count(*) FROM records WHERE organization_id = :o GROUP BY kind"), {"o": org}).all())


def real_source(client, monkeypatch, name="Support agent"):
    """A customer system with an imported agent source. Nothing synthetic, nothing live."""
    monkeypatch.setattr(commercial, "can_use_connector_role", lambda *args: True)
    system = client.post("/v1/systems", json={"name": name})
    assert system.status_code == 201, system.text
    environment = client.post("/v1/change-assurance/environments", json={
        "system_id": system.json()["id"], "name": "Staging", "purpose": "STAGING",
        "boundary": "Staging support records only", "owner": "Support engineering"})
    assert environment.status_code == 201, environment.text
    installation = client.post("/v1/connectors", json={
        "system_id": system.json()["id"], "environment_id": environment.json()["id"], "connector_id": "mcp",
        "mode": "IMPORT", "roles": ["DISCOVER", "CHANGE"], "name": "Support tool gateway", "configuration": {},
        "credential_id": None, "expires_at": (now() + timedelta(days=1)).isoformat()})
    assert installation.status_code == 201, installation.text
    return system.json(), environment.json(), installation.json()


def imported(client, installation, tools, sequence):
    response = client.post(f"/v1/connectors/{installation['id']}/import", json={
        "event_id": str(uuid4()), "payload": mcp_payload(tools), "valid_at": now().isoformat(),
        "sequence": sequence})
    assert response.status_code in {200, 201}, response.text
    return response.json()


def tool_subject(client, installation, tool):
    rows = client.get(f"/v1/connectors/{installation['id']}/history",
                      params={"kind": "source_batch"}).json()["items"]
    for row in rows:
        for key, name in ((row.get("facts") or {}).get("tool_components") or {}).items():
            if name == tool:
                return key
    raise AssertionError(f"{tool} was never reported by this source")


def declare(client, system_id, environment_id, claim, dependencies, action="refund.issue"):
    response = client.post(f"/v1/systems/{system_id}/claim-definitions", json={
        "environment_id": environment_id, "action": action, "claim": claim,
        "permitted_outcome": "A refund is issued only after a recorded human approval",
        "forbidden_outcome": "A refund is issued with no recorded approval",
        "legitimate_task": "The support agent resolves a refund request",
        "ground_truth_source": "Support system audit log", "declared_dependencies": dependencies,
        "template_id": "approval_required", "resource": "customer refunds",
        "expected_conditions": ["An approval record exists before the refund"]})
    assert response.status_code == 201, response.text
    return response.json()


def map_subject(client, system_id, environment_id, installation, subject, maps_to):
    response = client.post(f"/v1/systems/{system_id}/dependency-mappings", json={
        "environment_id": environment_id, "installation_id": installation["id"], "subject": subject,
        "maps_to": maps_to, "review_note": "Reviewed: this declared tool controls the declared refund dependency"})
    assert response.status_code == 201, response.text
    return response.json()


def test_synthetic_consequences_are_shown_and_never_counted(customer):
    setup, _ = cleared(customer)
    change(customer, setup, "beneficiary_approval_relaxed")
    consequence = observed(customer, setup["system_id"])
    response = judge(customer, setup["system_id"], consequence["id"], "CORRECT")
    assert response.status_code == 201, response.text
    value = response.json()
    assert (value["provenance"], value["counted"], value["effect_on_assurance"]) == ("SYNTHETIC", False, "NONE")
    summary = business(customer)
    assert summary["activation"]["reached"] is False and summary["activation"]["qualified"] is False
    assert summary["consequences"]["by_provenance"]["SYNTHETIC"] >= 1
    assert summary["consequences"]["counted"] == 0
    assert summary["precision"]["consequences_with_feedback"] == 0
    assert summary["precision"]["excluded_synthetic_or_replayed"] == 1
    assert summary["precision"]["confirmed_rate"] == {"numerator": 0, "denominator": 0, "value": None}
    assert summary["north_star"]["current"] == 0 and summary["north_star"]["systems"] == []
    tracks = activation(customer)
    assert tracks["activation_event"] == "FIRST_CONFIRMED_CONSEQUENCE"
    assert tracks["system_event"] == "FIRST_MEANINGFUL_ASSURANCE_EVENT"
    assert not tracks["customer"]["activated"] and not tracks["synthetic"]["activated"]
    assert tracks["synthetic"]["demonstration_complete"] is True
    assert not tracks["synthetic"]["milestones"]["FIRST_CONFIRMED_CONSEQUENCE"]["reached"]


def test_feedback_is_append_only_isolated_and_changes_no_conclusion(customer):
    setup, _ = cleared(customer)
    change(customer, setup, "invoice_tenant_binding_removed")
    system = setup["system_id"]
    consequence = observed(customer, system)
    before_gate = gate(customer, system)
    key = str(uuid4())
    first = judge(customer, system, consequence["id"], "INCORRECT", key, "Tenant binding is enforced in the database")
    assert first.status_code == 201, first.text
    assert first.json()["category"] == "INVALIDATION" and first.json()["claim_basis"] == "EVIDENCED"
    again = judge(customer, system, consequence["id"], "INCORRECT", key, "Tenant binding is enforced in the database")
    assert again.status_code == 201 and again.json()["duplicate"] is True
    assert judge(customer, system, consequence["id"], "CORRECT", key).status_code == 409
    assert judge(customer, system, consequence["id"], "PARTIALLY_CORRECT").status_code == 201
    detail = customer.get(f"/v1/systems/{system}/consequences/{consequence['id']}/feedback").json()
    assert [f["verdict"] for f in detail["history"]] == ["PARTIALLY_CORRECT", "INCORRECT"]
    assert detail["latest"]["verdict"] == "PARTIALLY_CORRECT"
    # The consequence and the clearance are exactly what they were.
    after = next(v for v in views(customer, system) if v["id"] == consequence["id"])
    assert after["consequence"] == consequence["consequence"] and after["authority"] == consequence["authority"]
    assert gate(customer, system) == before_gate
    # Append-only in the database itself, for the runtime role.
    user, org = identity(customer)
    with pytest.raises(DBAPIError), transaction(user, org) as session:
        session.execute(text("UPDATE records SET payload = payload || '{\"verdict\": \"CORRECT\"}'::jsonb "
                             "WHERE id = :id"), {"id": first.json()["id"]})
    # Another tenant can neither read nor write it.
    other = other_tenant()
    assert judge(other, system, consequence["id"], "CORRECT").status_code == 404
    assert other.get(f"/v1/systems/{system}/consequences/{consequence['id']}/feedback").status_code == 404
    assert other.get(f"/v1/systems/{system}/consequence-feedback").status_code == 404
    # Bounded, scoped input only.
    assert judge(customer, system, system, "CORRECT").status_code == 404
    assert judge(customer, system, consequence["id"], "CORRECT", comment="x" * 501).status_code == 422
    assert judge(customer, system, consequence["id"], "MAYBE").status_code == 422
    listing = customer.get(f"/v1/systems/{system}/consequence-feedback").json()
    assert listing["consequences"][consequence["id"]]["responses"] == 2


def test_declared_claim_consequence_confirmed_on_a_real_system_is_activation(customer, monkeypatch):
    system, environment, installation = real_source(customer, monkeypatch)
    imported(customer, installation, ("ticket.update",), 1)
    imported(customer, installation, ("ticket.update", "refund.issue"), 2)
    declared = declare(customer, system["id"], environment["id"],
                       "A refund is never issued without a recorded approval", ["tool:refunds"])
    ladder = customer.get(f"/v1/systems/{system['id']}/claims").json()
    assert ladder["counts"]["NOT_YET_VERIFIED"] == 1 and ladder["counts"]["CURRENT"] == 0
    entry = next(c for c in ladder["claims"] if c["id"] == declared["id"])
    assert entry["verification"] == "NOT_YET_VERIFIED" and "prove it" in entry["next_step"].lower()
    map_subject(customer, system["id"], environment["id"], installation,
                tool_subject(customer, installation, "refund.issue"), ["tool:refunds"])
    consequence = observed(customer, system["id"])
    assert consequence["consequence"]["declared_effect"] == "DECLARED_CLAIMS_AFFECTED"
    assert [c["claim"] for c in consequence["consequence"]["declared_claims_affected"]] == [declared["claim"]]
    assert any("not yet verified" in line for line in consequence["explanation"])
    assert not activation(customer)["customer"]["activated"]
    response = judge(customer, system["id"], consequence["id"], "CORRECT")
    assert response.status_code == 201, response.text
    value = response.json()
    assert (value["provenance"], value["counted"], value["category"], value["claim_basis"]) == (
        "IMPORTED", True, "INVALIDATION", "DECLARED")
    track = activation(customer)["customer"]
    assert track["activated"] and track["activation_basis"] == "CONFIRMED"
    assert track["milestones"]["FIRST_CONFIRMED_CONSEQUENCE"]["seconds_from_signup"] >= 0
    summary = business(customer)
    assert summary["activation"]["reached"] and summary["activation"]["provenance"] == "IMPORTED"
    assert summary["activation"]["claim_basis"] == "DECLARED"
    # An imported answer about a declared claim is real, but it is not the strict qualified reading.
    assert summary["activation"]["qualified"] is False
    assert summary["consequences"]["by_provenance"]["IMPORTED"] >= 1
    assert summary["precision"]["confirmed_rate"] == {"numerator": 1, "denominator": 1, "value": 1.0}
    assert summary["precision"]["value"]["confirmed_invalidations"] == 1
    assert summary["precision"]["mapped_change_ratio"]["denominator"] >= 1
    # An imported source is not a live source: the system is not watched for the North Star.
    assert summary["north_star"]["systems"][0]["level"] == "NONE"
    assert summary["north_star"]["current"] == 0


def test_proposed_change_answers_what_would_break_without_touching_clearance(customer):
    setup, _ = cleared(customer)
    system = setup["system_id"]
    _, org = identity(customer)
    before_gate, before_kinds = gate(customer, system), counted_kinds(org)
    relaxed = deepcopy(GATEWAY_BASELINE)
    relaxed["beneficiary.update"]["approval_required"] = False
    body = {"installation_id": setup["gateway_installation_id"], "payload": gateway_payload(relaxed),
            "reference": {"type": "PULL_REQUEST", "id": "#42",
                          "url": "https://github.com/example/agent/pull/42", "revision": "a" * 40},
            "idempotency_key": str(uuid4())}
    response = customer.post(f"/v1/systems/{system}/proposed-changes", json=body)
    assert response.status_code == 201, response.text
    value = response.json()
    assert (value["mode"], value["active"], value["current_state"], value["label"]) == (
        "PROPOSED", False, False, LABEL)
    assert value["summary"]["effect"] == "WOULD_REQUIRE_REPROOF"
    assert value["summary"]["classification"] == "AUTHORITY_EXPANDED" and value["summary"]["scoped"] is True
    affected = [c["title"] for c in value["summary"]["claims_affected"]]
    assert affected and all("approval" in title.lower() for title in affected)
    assert value["clearance"] == {"current": "CLEARED", "unchanged": True, "if_applied": "NEEDS_REASSESSMENT"}
    assert (value["check"]["name"], value["check"]["conclusion"], value["check"]["blocking"],
            value["check"]["mode"]) == ("ThreatVeil — Change Assurance", "neutral", False, "WARN")
    assert LABEL in value["check"]["summary"]
    # Nothing current moved: only the assessment, its audit entry and service metrics were appended.
    after_kinds = counted_kinds(org)
    grown = {kind for kind, count in after_kinds.items() if count != before_kinds.get(kind)}
    assert grown <= {"proposed_change_assessment", "audit", "service_metric"}
    assert gate(customer, system) == before_gate
    # Idempotent; a reused key cannot bind a different proposal.
    assert customer.post(f"/v1/systems/{system}/proposed-changes", json=body).json()["duplicate"] is True
    reused = {**body, "payload": gateway_payload(GATEWAY_BASELINE)}
    assert customer.post(f"/v1/systems/{system}/proposed-changes", json=reused).status_code == 409
    unchanged = customer.post(f"/v1/systems/{system}/proposed-changes", json={
        **reused, "idempotency_key": str(uuid4())}).json()
    assert unchanged["summary"]["effect"] == "NO_CHANGE" and unchanged["check"]["conclusion"] == "success"
    # Tenant isolation, bounded references, and errors that never echo configuration.
    other = other_tenant()
    assert other.post(f"/v1/systems/{system}/proposed-changes",
                      json={**body, "idempotency_key": str(uuid4())}).status_code == 404
    assert other.get(f"/v1/proposed-changes/{value['id']}").status_code == 404
    assert customer.post(f"/v1/systems/{system}/proposed-changes", json={
        **body, "idempotency_key": str(uuid4()),
        "reference": {"type": "PULL_REQUEST", "url": "javascript:alert(1)"}}).status_code == 422
    broken = customer.post(f"/v1/systems/{system}/proposed-changes", json={
        **body, "idempotency_key": str(uuid4()), "payload": {"secret-marker-7": "unparseable"}})
    assert broken.status_code == 422 and "secret-marker-7" not in broken.text
    listed = customer.get(f"/v1/systems/{system}/proposed-changes").json()["items"]
    assert {item["id"] for item in listed} >= {value["id"], unchanged["id"]}
    # A proposed consequence on a synthetic system stays a demonstration.
    verdict = judge(customer, system, value["id"], "CORRECT").json()
    assert verdict["provenance"] == "SYNTHETIC" and verdict["counted"] is False
    assert business(customer)["time_to_wow"]["seconds_to_first_proposed_consequence"] is None


def test_replayed_history_is_labelled_and_never_counts(customer, monkeypatch):
    system, _, installation = real_source(customer, monkeypatch, name="Replay agent")
    catalogs = [("ticket.read",), ("ticket.read", "ticket.update"), ("ticket.read", "ticket.update", "refund.issue")]
    revisions = [{"revision": f"{index:07x}abc", "committed_at": (now() - timedelta(days=9 - index)).isoformat(),
                  "payload": mcp_payload(tools)} for index, tools in enumerate(catalogs)]
    response = customer.post(f"/v1/systems/{system['id']}/history-replay", json={
        "installation_id": installation["id"], "revisions": revisions, "idempotency_key": str(uuid4())})
    assert response.status_code == 201, response.text
    items = response.json()["items"]
    assert len(items) == 2
    assert all((item["mode"], item["active"], item["current_state"]) == ("REPLAYED", False, False) for item in items)
    assert items[-1]["reference"]["previous_revision"] == revisions[1]["revision"]
    assert items[-1]["summary"]["effect"] == "NO_CLAIMS"
    verdict = judge(customer, system["id"], items[-1]["id"], "CORRECT").json()
    assert (verdict["provenance"], verdict["counted"]) == ("REPLAYED", False)
    summary = business(customer)
    assert not summary["activation"]["reached"]
    assert summary["consequences"]["by_provenance"]["REPLAYED"] == 2
    assert summary["time_to_wow"]["first_proposed_consequence_at"] is None


def guidance(client, system_id):
    response = client.get(f"/v1/systems/{system_id}/guidance")
    assert response.status_code == 200, response.text
    return response.json()


def test_guidance_names_each_limitation_and_what_is_not_claimed(customer, monkeypatch):
    system, _, installation = real_source(customer, monkeypatch, "Guidance agent")
    imported(customer, installation, ("ticket.update",), 1)
    found = guidance(customer, system["id"])
    codes = {item["code"] for item in found["items"]}
    assert {"NO_LIVE_SOURCE", "BASELINE_MISSING", "NO_QUALIFIED_OBSERVER"} <= codes
    assert found["clear"] is False and found["items"][0]["severity"] == "BLOCKING_VALUE"
    assert all(item["not_claimed"] and item["next_step"] and item["meaning"] for item in found["items"])
    live = next(item for item in found["items"] if item["code"] == "NO_LIVE_SOURCE")
    assert live["severity"] == "LIMITS_SCOPE" and "not claim it is watching" in live["not_claimed"]
    observer = next(item for item in found["items"] if item["code"] == "NO_QUALIFIED_OBSERVER")
    assert "never read as 'no effect'" in observer["not_claimed"]
    assert len(found["codes"]) == 9


def test_guidance_after_a_change_names_the_unmapped_and_stale_states(customer):
    setup, _ = cleared(customer)
    before = {item["code"] for item in guidance(customer, setup["system_id"])["items"]}
    assert "BASELINE_MISSING" not in before and "EVIDENCE_STALE" not in before
    change(customer, setup, "payment_tool_added")
    found = guidance(customer, setup["system_id"])
    codes = {item["code"] for item in found["items"]}
    assert {"UNMAPPED_CHANGE", "EVIDENCE_STALE"} <= codes
    unmapped = next(item for item in found["items"] if item["code"] == "UNMAPPED_CHANGE")
    assert unmapped["evidence"] and "never assumed harmless" in unmapped["not_claimed"]
    assert "payment" in unmapped["detail"]


def test_operator_store_is_unreachable_by_the_runtime_role(customer):
    _, org = identity(customer)
    with pytest.raises(DBAPIError), transaction() as session:
        session.execute(text("SELECT count(*) FROM operator_records"))
    # Even with the operator flag set, the runtime role sees no other tenant's rows.
    with transaction() as session:
        session.execute(text("SELECT set_config('tv.operator_read', 'on', true)"))
        assert session.execute(text("SELECT count(*) FROM records")).scalar() == 0
        assert session.execute(text("SELECT count(*) FROM organizations")).scalar() == 0
    assert org is not None


def test_founder_report_counts_only_classified_external_organizations(customer):
    from threatveil.operator_store import (
        Classification, ProofEvent, StaffTime, founder_report, investor_export, operator_session, record,
    )

    setup, _ = cleared(customer)
    _, org = identity(customer)
    record(Classification(organization_id=org, classification="CUSTOMER",
                          reason="Acceptance-test organization classified for the report"),
           "org_classification", operator="acceptance")
    record(StaffTime(organization_id=org, work_date=now().date().isoformat(), minutes=90,
                     category="CLAIM_AUTHORING", stage="MODELING", note="Claim workshop"),
           "staff_time", operator="acceptance")
    record(ProofEvent(prospect="acceptance-prospect", event="OFFER_REJECTED", occurred_on=now().date().isoformat(),
                      offer="ASSURANCE_LAUNCH", price_usd=15000, reason="Wants a live source first"),
           "commercial_proof", operator="acceptance")
    report = founder_report(operator="acceptance")
    detail = next(o for o in report["organizations_detail"] if o["organization_id"] == str(org))
    assert detail["classification"] == "CUSTOMER" and detail["staff_hours"] == 1.5
    assert detail["activated"] is False and detail["customer_systems"] == 0
    assert report["staff_time"]["hours_by_category"]["CLAIM_AUTHORING"] >= 1.5
    assert report["commercial"]["offers_decided"] >= 1 and report["commercial"]["offers_accepted"] == 0
    experiment = next(e for e in report["commercial"]["pricing_experiments"] if e["price_usd"] == 15000)
    assert experiment["rejected"] >= 1 and experiment["accepted"] == 0
    assert "signups" in report["vanity_metrics_excluded"] and report["internal_only"] is True
    assert report["excluded"]["synthetic_systems_in_external_organizations"] >= 1
    assert report["activation"]["activated_organizations"] == 0
    export = investor_export(report)
    assert export.startswith("metric,value,numerator,denominator,definition,as_of")
    assert "rps_current" in export and "contracted_value_usd" in export
    # Operator records are append-only, even for the operator identity.
    with pytest.raises(DBAPIError), operator_session() as session:
        session.execute(text("UPDATE operator_records SET kind = 'tampered'"))
    # Reading the report is itself recorded, and the synthetic demonstration never became revenue.
    with operator_session() as session:
        accesses = session.execute(text("SELECT count(*) FROM operator_records WHERE kind = 'operator_access'")).scalar()
    assert accesses >= 1 and report["revenue"]["contracted_value_usd"] == 0
    assert setup["system_id"]
    # Leave the acceptance organization excluded from later report runs.
    record(Classification(organization_id=org, classification="TEST", reason="Acceptance test organization"),
           "org_classification", operator="acceptance")
