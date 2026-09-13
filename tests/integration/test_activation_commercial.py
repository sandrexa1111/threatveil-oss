"""Commercial value boundaries and activation metrics never alter security truth."""

import json
from uuid import uuid4

from threatveil.commercial import catalog
from test_assurance_intelligence import assess, change, cleared, intel, other_tenant
from test_product import customer as customer  # noqa: F401


def activation(client):
    response = client.get("/v1/measurements/activation")
    assert response.status_code == 200, response.text
    return response.json()


def moments(client):
    return {m["id"]: m for m in activation(client)["upgrade_moments"]}


def upgrade(client, plan):
    response = client.post("/v1/commercial/subscription", json={
        "action": "upgrade", "plan": plan, "idempotency_key": str(uuid4())})
    assert response.status_code == 200, response.text


def test_free_experiences_the_whole_category(customer):
    assert customer.get("/v1/commercial").json()["plan"] == "free"
    setup, _ = cleared(customer)
    change(customer, setup, "beneficiary_approval_relaxed")
    for path in ("/intelligence", "/system-map", "/authority", "/authority/changes", "/changes",
                 "/evidence-currency", "/lifecycle", "/reestablishment", "/history", "/assurance/current"):
        assert customer.get(f"/v1/systems/{setup['system_id']}{path}").status_code == 200, path
    passport = customer.post(f"/v1/systems/{setup['system_id']}/passports", json={})
    assert passport.status_code == 201, passport.text
    shared = customer.post(f"/v1/passports/{passport.json()['id']}/share", json={"label": "Free plan buyer", "confirm_disclosure": True})
    assert shared.status_code == 201, shared.text


def test_upgrade_moments_follow_value_boundaries_and_come_from_catalog_data(customer):
    assert moments(customer) == {}
    setup, _ = cleared(customer)
    found = moments(customer)
    first = found["first_clearance"]
    plans = {p.id: p for p in catalog().plans}
    offered = plans[first["plan"]]
    assert "enforcement.ci" in offered.entitlements.capabilities
    assert all("enforcement.ci" not in p.entitlements.capabilities for p in plans.values()
               if p.monthly_usd is not None and 0 < p.monthly_usd < offered.monthly_usd and not p.sales_assisted)
    assert offered.name in first["message"] and "never changes a security conclusion" in first["note"]
    assert found["system_allowance"]["plan"] == first["plan"]
    assert "production_assurance" not in found and "shared_review" not in found
    assert set(intel(customer, setup)["upgrade_moments"][0]) >= {"id", "plan", "message"}
    upgrade(customer, first["plan"])
    assert "first_clearance" not in moments(customer)


def test_a_team_prompt_appears_only_when_collaboration_is_attempted(customer):
    cleared(customer)
    assert "shared_review" not in moments(customer)
    refused = customer.post("/v1/members/invite", json={"email": f"{uuid4()}@local.invalid", "role": "security"})
    assert refused.status_code == 402, refused.text
    prompt = moments(customer)["shared_review"]
    assert "approval.workflow" in next(p for p in catalog().plans if p.id == prompt["plan"]).entitlements.capabilities
    assert "Multiple reviewers" in prompt["message"]


def test_business_entitlement_fabricates_no_integration_and_billing_never_changes_truth(customer):
    setup, _ = cleared(customer)
    change(customer, setup, "beneficiary_approval_relaxed")
    before = intel(customer, setup)
    upgrade(customer, "business")
    after = intel(customer, setup)
    for key in ("status", "action", "cleared", "claims"):
        assert before["gate"][key] == after["gate"][key]
    assert before["evidence"]["counts"] == after["evidence"]["counts"]
    assert [c["classification"] for c in before["authority_changes"]] == [c["classification"] for c in after["authority_changes"]]
    change(customer, setup, "gateway_restored")
    restored = assess(customer, setup)
    decision = customer.get(f"/v1/change-assurance/decisions/{restored['authorization_id']}").json()
    requested = customer.post("/v1/change-assurance/enforcement", json={
        "authorization_id": decision["id"], **{k: decision[k] for k in (
            "environment_id", "state_digest", "audience", "expected_prior_epoch", "request_nonce")},
        "mechanism": "external_request"})
    assert requested.status_code == 201, requested.text
    assert requested.json()["delivery_status"] == "AWAITING_QUALIFIED_ENFORCER"
    detail = customer.get(f"/v1/change-assurance/decisions/{decision['id']}").json()
    assert detail["enforcement"] == "REQUESTED" and detail["acknowledgement"] is None
    assert "production_assurance" not in moments(customer)


def test_activation_counts_the_meaningful_event_and_keeps_synthetic_systems_separate(customer):
    setup, _ = cleared(customer)
    first = activation(customer)
    synthetic = first["synthetic"]["milestones"]
    assert synthetic["FIRST_SOURCE"]["reached"] and synthetic["FIRST_BASELINE"]["reached"]
    assert synthetic["FIRST_CURRENT_CLEARANCE"]["reached"]
    assert not synthetic["FIRST_MEANINGFUL_ASSURANCE_EVENT"]["reached"]
    assert first["customer"]["systems"] == 0 and not first["customer"]["activated"]
    assert first["activation_event"] == "FIRST_CONFIRMED_CONSEQUENCE"
    assert first["system_event"] == "FIRST_MEANINGFUL_ASSURANCE_EVENT"
    change(customer, setup, "beneficiary_approval_relaxed")
    moved = activation(customer)["synthetic"]
    assert moved["milestones"]["FIRST_OBSERVED_CHANGE"]["reached"]
    # The demonstration shows the whole journey, but a synthetic track is never activated.
    assert moved["milestones"]["FIRST_MEANINGFUL_ASSURANCE_EVENT"]["reached"] and moved["demonstration_complete"]
    assert not moved["activated"] and not moved["milestones"]["FIRST_CONFIRMED_CONSEQUENCE"]["reached"]
    assert not moved["milestones"]["FIRST_REESTABLISHMENT"]["reached"]
    change(customer, setup, "gateway_restored")
    assess(customer, setup)
    restored = activation(customer)["synthetic"]
    assert restored["milestones"]["FIRST_REESTABLISHMENT"]["reached"]
    assert all(step["seconds"] is None or step["seconds"] >= 0 for step in restored["funnel"])


def test_product_signals_and_interest_are_recorded_without_contacting_anyone(customer):
    setup, _ = cleared(customer)
    passport = customer.post(f"/v1/systems/{setup['system_id']}/passports", json={}).json()
    customer.post(f"/v1/passports/{passport['id']}/share", json={"label": "Buyer review", "confirm_disclosure": True})
    signals = {s["signal"]: s for s in activation(customer)["product_qualified_signals"]}
    assert signals["external_passport_shared"]["present"] and not signals["private_deployment_requested"]["present"]
    key = str(uuid4())
    first = customer.post("/v1/commercial/interest", json={"topic": "private_deployment", "idempotency_key": key})
    assert first.status_code == 201 and first.json()["contacted"] is False
    again = customer.post("/v1/commercial/interest", json={"topic": "private_deployment", "idempotency_key": key})
    assert again.json()["duplicate"] is True
    signals = {s["signal"]: s for s in activation(customer)["product_qualified_signals"]}
    assert signals["private_deployment_requested"]["count"] == 1
    assert customer.post("/v1/commercial/interest", json={"topic": "send_email", "idempotency_key": str(uuid4())}).status_code == 422


def test_activation_is_tenant_private_and_carries_no_evidence_or_names(customer):
    setup, _ = cleared(customer)
    change(customer, setup, "beneficiary_approval_relaxed")
    text = json.dumps(activation(customer))
    for sensitive in ("Beneficiary", "synthetic-tenant-a", "evidence_id", setup["system_id"], "Finance Agent",
                      "approval_required"):
        assert sensitive not in text
    theirs = activation(other_tenant())
    assert theirs["synthetic"]["systems"] == 0 and theirs["customer"]["systems"] == 0
    assert not theirs["synthetic"]["milestones"]["FIRST_CURRENT_CLEARANCE"]["reached"]
