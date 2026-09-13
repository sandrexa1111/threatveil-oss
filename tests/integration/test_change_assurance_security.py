"""Adversarial acceptance over real PostgreSQL and the committed finance fixture."""

import base64
from copy import deepcopy
from datetime import timedelta
import json
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from threatveil.api import app
from threatveil.db import add_record, get_record, now, transaction
from threatveil.release_signing import signing_key
from threatveil.sdk.change_records import verify_change_record
from threatveil.sdk.receipts import ReceiptVerificationError

from test_product import customer as customer, with_enforcement
from test_change_assurance import prepare, assess


def approved(customer):
    setup = prepare(customer)
    result = assess(customer, setup)
    decision = customer.get(f"/v1/change-assurance/decisions/{result['authorization_id']}").json()
    assert decision["action"] == "ALLOW", decision
    journey = customer.get(f"/v1/change-assurance/systems/{setup['system_id']}").json()
    return setup, result, decision, journey["environments"][0]["state"]


def enforcement(decision):
    return {"authorization_id": decision["id"], **{k: decision[k] for k in (
        "environment_id", "state_digest", "audience", "expected_prior_epoch", "request_nonce")},
        "mechanism": "synthetic_compare_and_set"}


def state_body(state):
    return {k: state[k] for k in ("system_id", "environment_id", "envelope_id", "candidate",
        "fingerprint", "evidence_id", "coverage", "unknowns")}


@pytest.mark.parametrize("field,value", [
    ("environment_id", str(uuid4())), ("state_digest", "f" * 64), ("audience", "wrong-enforcement-surface"),
    ("expected_prior_epoch", 999), ("request_nonce", "wrong-activation-nonce"),
    ("policy_epoch", 999), ("envelope_digest", "f" * 64),
])
def test_enforcement_rejects_wrong_signed_binding(customer, field, value):
    _, _, decision, _ = approved(customer)
    body = {**enforcement(decision), field: value}
    rejected = customer.post("/v1/change-assurance/enforcement", json=body)
    assert rejected.status_code in {409, 422}, rejected.text
    detail = customer.get(f"/v1/change-assurance/decisions/{decision['id']}").json()
    assert detail["enforcement"] == "NOT_REQUESTED" and detail["acknowledgement"] is None


def test_cross_tenant_state_decision_and_enforcement_are_inaccessible(customer):
    setup, _, decision, state = approved(customer)
    with TestClient(app) as other:
        login = other.post("/v1/auth/local", json={"email": f"{uuid4()}@local.invalid"},
            headers={"origin": "http://127.0.0.1:3000"})
        assert login.status_code == 200, login.text
        other.headers.update({"origin": "http://127.0.0.1:3000", "x-csrf-token": login.json()["csrf_token"]})
        assert other.get(f"/v1/change-assurance/systems/{setup['system_id']}").status_code == 404
        assert other.get(f"/v1/change-assurance/states/{state['id']}/current").status_code == 404
        assert other.get(f"/v1/change-assurance/decisions/{decision['id']}").status_code == 404
        assert other.post("/v1/change-assurance/enforcement", json=enforcement(decision)).status_code == 404
        assert other.post("/v1/change-assurance/states", json=state_body(state)).status_code == 404


def test_wrong_candidate_and_unbound_environment_cannot_claim_observed_state(customer):
    setup, _, decision, state = approved(customer)
    wrong = state_body(state)
    wrong["candidate"] = {**wrong["candidate"], "digest": "f" * 64}
    assert customer.post("/v1/change-assurance/states", json=wrong).status_code == 422
    wrong = {**state_body(state), "environment_id": str(uuid4())}
    assert customer.post("/v1/change-assurance/states", json=wrong).status_code == 404
    wrong = {**state_body(state), "envelope_id": str(uuid4())}
    assert customer.post("/v1/change-assurance/states", json=wrong).status_code == 404
    assert customer.get(f"/v1/change-assurance/decisions/{decision['id']}").json()["action"] == "ALLOW"


def test_revocation_and_expiry_never_activate_or_rewrite_signature(customer, monkeypatch):
    _, _, decision, _ = approved(customer)
    historical = deepcopy(decision["envelope"])
    revoke = customer.post(f"/v1/change-assurance/decisions/{decision['id']}/revoke",
        json={"reason": "Withdraw the synthetic operating authorization"})
    assert revoke.status_code == 201, revoke.text
    assert customer.post("/v1/change-assurance/enforcement", json=enforcement(decision)).status_code == 409
    detail = customer.get(f"/v1/change-assurance/decisions/{decision['id']}").json()
    assert detail["current_status"] == "REVOKED" and detail["envelope"] == historical
    monkeypatch.setattr("threatveil.change_assurance_api.now", lambda: now() + timedelta(hours=1))
    detail = customer.get(f"/v1/change-assurance/decisions/{decision['id']}").json()
    assert detail["current_status"] == "EXPIRED" and detail["envelope"] == historical


def test_authorization_nonce_and_operating_epoch_replay(customer):
    _, result, first, state = approved(customer)
    body = {"state_id": state["id"], "release_id": result["release_id"],
        "audience": "synthetic-finance-activation", "expected_prior_epoch": 0,
        "request_nonce": str(uuid4()), "unknown_action": "REQUIRE_APPROVAL"}
    created = customer.post("/v1/change-assurance/decisions", json=body)
    assert created.status_code == 201, created.text
    second = created.json()
    repeated = customer.post("/v1/change-assurance/decisions", json=body)
    assert repeated.json()["id"] == second["id"]
    changed = customer.post("/v1/change-assurance/decisions", json={**body, "expected_prior_epoch": 1})
    assert changed.status_code == 409
    applied = customer.post("/v1/change-assurance/enforcement", json=enforcement(first))
    assert applied.status_code == 201, applied.text
    replay = customer.post("/v1/change-assurance/enforcement", json=enforcement(first))
    assert replay.json()["id"] == applied.json()["id"]
    # Independently issued prior-epoch-0 decision cannot activate after epoch 1.
    assert customer.post("/v1/change-assurance/enforcement", json=enforcement(second)).status_code == 409


def test_expanded_envelope_cannot_reuse_pre_expansion_evidence(customer):
    setup, result, decision, state = approved(customer)
    with transaction(org_id=UUID(decision["organization_id"])) as session:
        prior = get_record(session, UUID(decision["organization_id"]), setup["envelope_id"], "permission_envelope").payload
    fields = ("system_id", "environment_id", "principals", "actions", "resources", "constraints", "expires_at")
    revised = customer.post("/v1/change-assurance/envelopes", json={
        **{k: prior[k] for k in fields}, "supersedes_id": setup["envelope_id"],
        "resources": prior["resources"] + ["synthetic-tenant-b/vendor-1"],
        "actions": prior["actions"] + ["beneficiary.update_without_approval"],
    })
    assert revised.status_code == 201, revised.text
    rebound = customer.post("/v1/change-assurance/states", json={
        **state_body(state), "envelope_id": revised.json()["id"]})
    if rebound.status_code in {409, 422}:
        return
    assert rebound.status_code == 201, rebound.text
    next_decision = customer.post("/v1/change-assurance/decisions", json={
        "state_id": rebound.json()["id"], "release_id": result["release_id"],
        "audience": decision["audience"], "request_nonce": str(uuid4())})
    assert next_decision.status_code in {201, 409, 422}, next_decision.text
    if next_decision.status_code == 201:
        assert next_decision.json()["action"] != "ALLOW", "Old evidence cannot authorize an expanded consequential envelope"


def test_acknowledgement_for_old_state_does_not_protect_new_state(customer):
    setup, _, decision, state = approved(customer)
    applied = customer.post("/v1/change-assurance/enforcement", json=enforcement(decision))
    assert applied.status_code == 201, applied.text
    next_state = customer.post("/v1/change-assurance/states", json={**state_body(state),
        "coverage": "A newly reviewed state coverage boundary requires its own exact decision"})
    assert next_state.status_code == 201, next_state.text
    assert next_state.json()["state_digest"] != state["state_digest"]
    journey = customer.get(f"/v1/change-assurance/systems/{setup['system_id']}").json()
    assert journey["environments"][0]["stage"] != "PROTECTED", "Old-state acknowledgement cannot protect a new state"


def test_source_outage_removes_positive_support_without_erasing_history(customer, monkeypatch):
    setup, _, decision, state = approved(customer)
    from threatveil import commercial
    from threatveil.connectors import configuration, record_failure
    monkeypatch.setattr(commercial, "can_use_connector_role", lambda *args: True)
    installed = customer.post("/v1/connectors", json={"system_id": setup["system_id"],
        "environment_id": setup["environment_id"], "connector_id": "otel", "mode": "PUSH",
        "roles": ["OBSERVE"], "name": "Qualified-source continuity test", "configuration": {},
        "expires_at": (now() + timedelta(days=1)).isoformat()})
    assert installed.status_code == 201, installed.text
    org = UUID(decision["organization_id"])
    with transaction(org_id=org) as session:
        source = get_record(session, org, installed.json()["id"], "connector_installation")
        record_failure(session, org, source, configuration(session, org, source), "UNAVAILABLE")
    current = customer.get(f"/v1/change-assurance/states/{state['id']}/current").json()
    assert not current["all_supported"] and current["policy_action"] != "ALLOW"
    assert current["source_health"][0]["freshness"] == "UNKNOWN"
    assert customer.post("/v1/change-assurance/enforcement", json=enforcement(decision)).status_code == 409
    detail = customer.get(f"/v1/change-assurance/decisions/{decision['id']}").json()
    assert detail["action"] == "ALLOW" and detail["current_status"] == "REASSESS"
    assert detail["envelope"] == decision["envelope"]


def test_changed_approved_scope_cannot_be_omitted(customer):
    setup, result, decision, state = approved(customer)
    org = UUID(decision["organization_id"])
    with transaction(org_id=org) as session:
        original = get_record(session, org, setup["property_ids"][0], "property")
        add_record(session, org, "property", {**original.payload, "title": "New approved obligation"})
    attempt = customer.post("/v1/change-assurance/decisions", json={
        "state_id": state["id"], "release_id": result["release_id"],
        "audience": decision["audience"], "request_nonce": str(uuid4())})
    assert attempt.status_code == 409, attempt.text


def test_observed_later_transition_supersedes_old_activation(customer):
    setup, _, decision, _ = approved(customer)
    regressed = assess(customer, setup, "regressed")
    assert regressed["action"] == "BLOCK"
    detail = customer.get(f"/v1/change-assurance/decisions/{decision['id']}").json()
    assert detail["action"] == "ALLOW" and detail["current_status"] in {"SUPERSEDED", "REASSESS"}
    assert customer.post("/v1/change-assurance/enforcement", json=enforcement(decision)).status_code == 409


def test_expired_state_observation_cannot_preserve_support(customer, monkeypatch):
    _, _, decision, state = approved(customer)
    monkeypatch.setattr("threatveil.change_assurance.now", lambda: now() + timedelta(days=2))
    current = customer.get(f"/v1/change-assurance/states/{state['id']}/current").json()
    assert not current["all_supported"] and current["policy_action"] != "ALLOW"
    assert all(p["applicability"] == "STALE" for p in current["properties"])
    assert customer.post("/v1/change-assurance/enforcement", json=enforcement(decision)).status_code == 409


def test_qualified_test_evidence_never_identifies_a_running_production_deployment(customer):
    setup, _, decision, state = approved(customer)
    org = UUID(decision["organization_id"])
    with transaction(org_id=org) as session:
        environment = add_record(session, org, "environment", {"schema_version": "change-assurance/v1",
            "system_id": setup["system_id"], "name": "Production boundary", "purpose": "PRODUCTION",
            "boundary": "Distinct unobserved production deployment boundary", "owner": "Security owner"})
        environment_id = str(environment.id)
        old = get_record(session, org, setup["envelope_id"], "permission_envelope").payload
    fields = ("system_id", "principals", "actions", "resources", "constraints", "expires_at")
    envelope = customer.post("/v1/change-assurance/envelopes", json={
        **{k: old[k] for k in fields}, "environment_id": environment_id})
    assert envelope.status_code == 201, envelope.text
    binding = customer.post("/v1/change-assurance/target-bindings", json={"system_id": setup["system_id"],
        "environment_id": environment_id, "target_id": setup["target_id"],
        "review_note": "Declared routing does not establish production deployment observation"})
    assert binding.status_code == 201, binding.text
    attempted = customer.post("/v1/change-assurance/states", json={**state_body(state),
        "environment_id": environment_id, "envelope_id": envelope.json()["id"]})
    assert attempted.status_code in {201, 409, 422}, attempted.text
    if attempted.status_code == 201:
        assert attempted.json()["provenance"] == "DECLARED"
        assert attempted.json()["running_deployment_identified"] is False
        current = customer.get(f"/v1/change-assurance/states/{attempted.json()['id']}/current").json()
        assert not current["all_supported"]


@pytest.mark.parametrize("expand_scope", [False, True])
def test_fresh_finance_assessment_adopts_reviewed_envelope_without_inventing_coverage(customer, expand_scope):
    setup, _, original, old_state = approved(customer)
    org = UUID(original["organization_id"])
    with transaction(org_id=org) as session:
        prior = get_record(session, org, setup["envelope_id"], "permission_envelope").payload
    fields = ("system_id", "environment_id", "principals", "actions", "resources", "constraints", "expires_at")
    request = {**{k: prior[k] for k in fields}, "supersedes_id": setup["envelope_id"]}
    if expand_scope:
        request["resources"] = prior["resources"] + ["unobserved-tenant-c/vendor-99"]
        request["actions"] = prior["actions"] + ["payment.settle"]
    revised = customer.post("/v1/change-assurance/envelopes", json=request)
    assert revised.status_code == 201, revised.text
    current = customer.get(f"/v1/change-assurance/states/{old_state['id']}/current").json()
    assert not current["all_supported"]
    refreshed = assess(customer, setup, "fixed")
    assert (refreshed["action"] != "ALLOW") if expand_scope else (refreshed["action"] == "ALLOW")
    journey = customer.get(f"/v1/change-assurance/systems/{setup['system_id']}").json()
    assert journey["environments"][0]["state"]["envelope_id"] == revised.json()["id"]
    old = customer.get(f"/v1/change-assurance/decisions/{original['id']}").json()
    assert old["envelope"] == original["envelope"]


def test_exception_status_is_visible_without_converting_failure_to_allow(customer):
    from threatveil.db import Membership
    setup = prepare(customer)
    failed = assess(customer, setup, "regressed")
    identity = customer.get("/v1/auth/me").json()
    org = UUID(identity["organization"]["id"])
    exception = customer.post("/v1/release-exceptions", json={"plan_id": failed["plan_id"],
        "property_ids": [setup["property_ids"][0]],
        "reason": "Bounded emergency review of the synthetic failed beneficiary boundary",
        "risk_acknowledgment": "The observed unauthorized beneficiary commit remains a security failure",
        "expires_at": (now() + timedelta(hours=1)).isoformat()})
    assert exception.status_code == 201, exception.text
    identifier = exception.json()["id"]
    with TestClient(app) as reviewer:
        login = reviewer.post("/v1/auth/local", json={"email": f"{uuid4()}@local.invalid"},
            headers={"origin": "http://127.0.0.1:3000"})
        assert login.status_code == 200, login.text
        reviewer.headers.update({"origin": "http://127.0.0.1:3000", "x-csrf-token": login.json()["csrf_token"]})
        reviewer_id = UUID(reviewer.get("/v1/auth/me").json()["user"]["id"])
        with transaction(org_id=org) as session:
            session.add(Membership(organization_id=org, user_id=reviewer_id, role="security"))
        assert reviewer.post("/v1/auth/switch", json={"organization_id": str(org)}).status_code == 200
        assert reviewer.post(f"/v1/release-exceptions/{identifier}/approve").status_code == 201
    with_enforcement(customer)
    release = customer.post("/v1/releases", json={"plan_id": failed["plan_id"],
        "policy": {"mode": "BLOCK"}, "exception_ids": [identifier]})
    assert release.status_code == 201, release.text
    assert release.json()["underlying_action"] == "BLOCK"
    decision = customer.post("/v1/change-assurance/decisions", json={"state_id": failed["state_id"],
        "release_id": release.json()["id"], "audience": "synthetic-exception-review", "request_nonce": str(uuid4())})
    assert decision.status_code == 201, decision.text
    decision = decision.json()
    assert decision["exception"] == "ACTIVE" and decision["security"] == "FAIL" and decision["action"] == "BLOCK"
    path = f"/v1/change-assurance/systems/{setup['system_id']}"
    journey = customer.get(path).json()["environments"][0]
    assert journey["current"]["exception"] == "ACTIVE" and journey["stage"] != "PROTECTED"
    assert customer.post(f"/v1/release-exceptions/{identifier}/revoke").status_code == 201
    current = customer.get(path).json()["environments"][0]
    assert current["current"]["exception"] == "REVOKED" and current["current"]["security"] == "FAIL"
    historic = customer.get(f"/v1/change-assurance/decisions/{decision['id']}").json()
    assert historic["exception"] == "ACTIVE" and historic["envelope"] == decision["envelope"]


def test_independent_signed_record_binding_integrity_and_expiry(customer):
    _, _, decision, _ = approved(customer)
    expected = {k: decision[k] for k in ("organization_id", "system_id", "environment_id", "state_digest", "audience")}
    public = signing_key().public_key()
    assert verify_change_record(decision["envelope"], public, **expected, at=now())["predicate"]["action"] == "ALLOW"
    for key in expected:
        with pytest.raises(ReceiptVerificationError):
            verify_change_record(decision["envelope"], public, **{**expected, key: "incorrect-binding"}, at=now())
    with pytest.raises(ReceiptVerificationError):
        verify_change_record(decision["envelope"], Ed25519PrivateKey.generate().public_key(), **expected)
    with pytest.raises(ReceiptVerificationError):
        verify_change_record(decision["envelope"], public, **expected, at=now()+timedelta(hours=1))
    forged = deepcopy(decision["envelope"])
    content = json.loads(base64.b64decode(forged["payload"]))
    content["predicate"]["policy_epoch"] += 1
    content["predicate"]["envelope_digest"] = "f" * 64
    forged["payload"] = base64.b64encode(json.dumps(content).encode()).decode()
    with pytest.raises(ReceiptVerificationError):
        verify_change_record(forged, public, **expected)
