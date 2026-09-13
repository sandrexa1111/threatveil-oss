"""Real tenant persistence with a simulated HTTPS transport and actual signed sink observations."""

import base64
import json
from datetime import timedelta
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from threatveil import api, targets
from threatveil.config import settings
from threatveil.core.contracts import Observation, SystemFingerprint, digest
from threatveil.core.procurement import _trial, SINK
from threatveil.core.variants import bounded_variants
from threatveil.db import now
from threatveil.sdk.signing import sign_observation


@pytest.fixture
def observer_customer(monkeypatch):
    monkeypatch.setenv("TV_ENV", "test")
    monkeypatch.setenv("TV_LOCAL_AUTH", "true")
    settings.cache_clear()
    keys = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
    challenge = {"value": ""}
    deployment = {"fixture_version": "fixed", "candidate": "candidate-v1"}
    initial = digest({"account": "SYNTHETIC-ORIGINAL-ACCOUNT"})
    def endpoint(origin, path, method="POST", body=None, *args, **kwargs):
        if path == "/.well-known/threatveil-authorization":
            return {"status_code": 200, "body": challenge["value"].encode()}
        request = json.loads(body)
        payload = request["input"]
        obs = _trial(deployment["fixture_version"], bounded_variants(1)[0], request["correlation_id"])
        obs = obs.model_copy(update={"initial_state_digest": initial, "fingerprint": SystemFingerprint.model_validate({
            "components": [{"type": "application", "id": "customer-agent", "version": deployment["candidate"],
                            "digest": digest(deployment["candidate"]), "provenance": "OBSERVED"}]})})
        obs = sign_observation(sign_observation(obs, keys[0]), keys[1], "ground_truth")
        if payload.get("tamper"):
            obs = obs.model_copy(update={"correlation_id": str(uuid4())})
        return {"status_code": 200, "body": obs.model_dump_json().encode(), "headers": {}, "peer": "8.8.8.8"}
    monkeypatch.setattr(api, "public_addresses", lambda *_: ["8.8.8.8"])
    monkeypatch.setattr(api, "bounded_request", endpoint)
    monkeypatch.setattr(targets, "bounded_request", endpoint)
    with TestClient(api.app) as client:
        client.observer_fixture_deployment = deployment
        client.cookies.set("tv_session", str(uuid4()))
        login = client.post("/v1/auth/local", json={"email": f"{uuid4()}@local.invalid"}, headers={"origin": "http://127.0.0.1:3000"})
        client.headers.update({"origin": "http://127.0.0.1:3000", "x-csrf-token": login.json()["csrf_token"]})
        demo = client.post("/v1/demo/setup", json={}).json()
        response = client.post("/v1/targets", json={"name": "Signed customer test adapter", "system_id": demo["system"]["id"],
            "adapter": "http", "origin": "https://customer-staging.invalid", "paths": ["/test"], "methods": ["POST"],
            "expires_at": (now()+timedelta(hours=1)).isoformat(), "authorization_note": "Simulated transport for customer collector acceptance tests."})
        assert response.status_code == 201, response.text
        target = response.json()
        challenge["value"] = target["challenge"]
        assert client.post(f"/v1/targets/{target['id']}/verify").status_code == 200
        response = client.post("/v1/observers", json={"system_id": demo["system"]["id"], "property_id": demo["property"]["id"],
            "target_id": target["id"], "source_id": SINK, "source_version": "sqlite-ledger-v1",
            "candidate_component_id": "customer-agent",
            "public_key": base64.b64encode(keys[0].public_key().public_bytes_raw()).decode(),
            "ground_truth_public_key": base64.b64encode(keys[1].public_key().public_bytes_raw()).decode(),
            "initial_state_digest": initial, "fixture_reference": "test:procurement/vendor-1",
            "independence_review": "Test-only separate collector keys sign an actual SQLite sink observation; no customer network claim."})
        assert response.status_code == 201, response.text
        yield client, demo, target, response.json(), keys
    settings.cache_clear()


def execute(h, observer, fixture="fixed", case=None, candidate=None, baseline=None,
            overrides=None):
    client, demo, target, _, _ = h
    # Distinct fixture code must have distinct signed build identities. Explicit
    # candidate labels remain available for intentional same-artifact tests.
    candidate = candidate or ("candidate-v1" if fixture == "fixed" else f"candidate-{fixture}-v1")
    # Deployment changes are independent of the frozen adversarial stimulus.
    client.observer_fixture_deployment.update(fixture_version=fixture, candidate=candidate)
    payload = {"system_id": demo["system"]["id"], "property_id": demo["property"]["id"], "target_id": target["id"],
        "version": candidate, "trials": 1, "variant_count": 1, "idempotency_key": str(uuid4()),
        "observer_id": observer["id"], "qualification_case": case, "baseline_id": baseline,
        "candidate": {"type": "application_version", "id": demo["system"]["id"],
                      "version": candidate, "digest": digest(candidate)},
        "stimulus": {"path": "/test", "payload": {"document": "synthetic malicious procurement document"}}}
    payload.update(overrides or {})
    response = client.post("/v1/runs", json=payload)
    assert response.status_code == 202, response.text
    return client.get("/v1/runs/" + response.json()["id"]).json()


def qualify(h):
    client, _, _, observer, _ = h
    permitted = execute(h, observer, case="KNOWN_PERMITTED")
    prohibited = execute(h, observer, "vulnerable", "KNOWN_PROHIBITED")
    missing = execute(h, observer, "missing_witness", "MISSING_OBSERVATION")
    assert permitted["security_verdict"] == "PASS", permitted
    assert permitted["fix_eligible"] is False
    assert prohibited["security_verdict"] == "FAIL"
    assert missing["security_verdict"] == "INCONCLUSIVE"
    response = client.post(f"/v1/observers/{observer['id']}/approve", json={"permitted_run_id": permitted["id"],
        "prohibited_run_id": prohibited["id"], "missing_run_id": missing["id"], "review_note": "Reviewed source separation and all three assigned control outcomes."})
    assert response.status_code == 200, response.text
    return response.json()


def test_active_qualification_installs_scoped_source_and_verifies_candidate(observer_customer):
    h = observer_customer
    approved = qualify(h)
    failed = execute(h, approved, "vulnerable")
    fixed = execute(h, approved)
    assert fixed["security_verdict"] == "PASS" and fixed["candidate_observed"]
    assert fixed["fix_eligible"] and fixed["release_action"] == "ALLOW"
    fix = h[0].post("/v1/fixes", json={"run_id": failed["id"], "verification_run_id": fixed["id"],
        "description": "The tested customer collector verifies the useful boundary fix."})
    assert fix.status_code == 201 and fix.json()["baseline_id"]
    assert h[0].post(f"/v1/observers/{approved['id']}/revoke").status_code == 200
    run = h[0].post("/v1/runs", json={"system_id": h[1]["system"]["id"], "property_id": h[1]["property"]["id"],
        "target_id": h[2]["id"], "observer_id": approved["id"], "version": "candidate-v1", "trials": 1,
        "idempotency_key": str(uuid4()), "stimulus": {"path": "/test", "payload": {}}})
    assert run.status_code == 403


def test_signed_self_report_cannot_skip_control_qualification(observer_customer):
    h = observer_customer
    response = h[0].post(f"/v1/observers/{h[3]['id']}/approve", json={"permitted_run_id": str(uuid4()),
        "prohibited_run_id": str(uuid4()), "missing_run_id": str(uuid4()), "review_note": "An arbitrary caller cannot assert that these controls passed."})
    assert response.status_code == 404
    from threatveil.observers import attestations_valid
    obs = _trial("fixed", bounded_variants(1)[0])
    obs = obs.model_copy(update={"initial_state_digest": h[3]["initial_state_digest"]})
    signed = sign_observation(sign_observation(obs, h[4][0]), h[4][1], "ground_truth")
    assert attestations_valid(signed, h[3])
    assert not attestations_valid(signed.model_copy(update={"initial_state_digest": "0"*64}), h[3])
    assert not attestations_valid(signed.model_copy(update={"attestations": {"observer": signed.attestations["observer"]}}), h[3])


def create_fix(h, failed, verified):
    response = h[0].post("/v1/fixes", json={"run_id": failed["id"],
        "verification_run_id": verified["id"],
        "description": "Verify the same scoped adversarial challenge against the observed deployment."})
    assert response.status_code == 201, response.text
    return response.json()


def test_wrong_expected_candidate_digest_cannot_verify_or_release(observer_customer):
    h = observer_customer
    approved = qualify(h)
    failed = execute(h, approved, "vulnerable")
    candidate = {"type": "application_version", "id": h[1]["system"]["id"],
                 "version": "candidate-v1", "digest": digest("different-build")}
    result = execute(h, approved, overrides={"candidate": candidate})
    assert result["security_verdict"] == "PASS" and result["witness_attested"]
    assert not result["candidate_observed"] and not result["fix_eligible"]
    assert result["release_action"] == "BLOCK"
    fix = create_fix(h, failed, result)
    assert not fix["verified"] and fix["baseline_id"] is None


def test_signed_captures_cannot_be_replayed_into_another_assigned_run(observer_customer, monkeypatch):
    h = observer_customer
    approved = qualify(h)
    endpoint, captured = targets.bounded_request, []
    def replaying_endpoint(*args, **kwargs):
        if not captured:
            captured.append(endpoint(*args, **kwargs))
        return captured[0]
    monkeypatch.setattr(targets, "bounded_request", replaying_endpoint)
    original = execute(h, approved)
    assert original["fix_eligible"]
    replayed = execute(h, approved)
    assert replayed["security_verdict"] == "INCONCLUSIVE"
    assert replayed["execution_status"] == "ERROR"
    assert not replayed["fix_eligible"] and replayed["release_action"] == "BLOCK"


def test_valid_signature_for_wrong_source_version_is_not_authoritative(observer_customer, monkeypatch):
    h = observer_customer
    approved = qualify(h)
    endpoint = targets.bounded_request
    def changed_source(*args, **kwargs):
        response = endpoint(*args, **kwargs)
        obs = Observation.model_validate_json(response["body"])
        obs = obs.model_copy(update={
            "witnesses": tuple(w.model_copy(update={"source_version": "unreviewed-v2"}) for w in obs.witnesses),
            "receipts": tuple(r.model_copy(update={"source_version": "unreviewed-v2"}) for r in obs.receipts)})
        obs = sign_observation(sign_observation(obs, h[4][0]), h[4][1], "ground_truth")
        return {**response, "body": obs.model_dump_json().encode()}
    monkeypatch.setattr(targets, "bounded_request", changed_source)
    result = execute(h, approved)
    assert result["security_verdict"] == "INCONCLUSIVE" and not result["witness_attested"]
    assert not result["fix_eligible"] and not result["candidate_observed"]


def test_observer_cannot_follow_a_new_property_without_qualification(observer_customer):
    h = observer_customer
    response = h[0].post("/v1/properties", json={"system_id": h[1]["system"]["id"],
        "title": "Separate immutable property", "definition": h[1]["property"]["definition"]})
    assert response.status_code == 201, response.text
    new_property = h[0].post(f"/v1/properties/{response.json()['id']}/approve").json()
    response = h[0].post("/v1/runs", json={"system_id": h[1]["system"]["id"],
        "property_id": new_property["id"], "target_id": h[2]["id"], "observer_id": h[3]["id"],
        "version": "candidate-v1", "trials": 1, "variant_count": 1,
        "qualification_case": "KNOWN_PERMITTED", "idempotency_key": str(uuid4()),
        "stimulus": {"path": "/test", "payload": {}}})
    assert response.status_code == 422 and "exact execution scope" in response.text


def test_changed_challenge_cannot_become_a_verified_fix(observer_customer):
    h = observer_customer
    approved = qualify(h)
    failed = execute(h, approved, "vulnerable")
    candidate = execute(h, approved, overrides={"stimulus": {
        "path": "/test", "payload": {"document": "a different, harmless security challenge"}}})
    assert candidate["fix_eligible"]
    fix = create_fix(h, failed, candidate)
    assert fix["verified"] is False and fix["baseline_id"] is None
    assert "variants" in fix["reason"]


def test_current_candidate_can_be_safe_while_historical_release_assurance_is_incompatible(observer_customer):
    h = observer_customer
    approved = qualify(h)
    failed = execute(h, approved, "vulnerable")
    baseline = create_fix(h, failed, execute(h, approved))["baseline_id"]
    assert baseline
    result = execute(h, approved, baseline=baseline, overrides={"stimulus": {
        "path": "/test", "payload": {"document": "a different, harmless security challenge"}}})
    assert result["security_verdict"] == "PASS" and result["fix_eligible"]
    assert result["comparison"]["applicability"] == "INCOMPATIBLE"
    assert result["release_action"] == "BLOCK"


def test_repeated_external_deterministic_failure_is_regression_without_statistics(observer_customer):
    h = observer_customer
    approved = qualify(h)
    failed = execute(h, approved, "vulnerable", candidate="candidate-v0")
    fixed = execute(h, approved, candidate="candidate-v1")
    baseline = create_fix(h, failed, fixed)["baseline_id"]
    assert baseline
    result = execute(h, approved, "regressed", candidate="candidate-v2", baseline=baseline)
    assert result["candidate_observed"] and result["comparison"]["compatible"]
    assert result["comparison"]["classification"] == "DETERMINISTIC_RECURRENCE"
    assert result["comparison"]["comparisons"] == []
    assert result["regression"] and result["release_action"] == "BLOCK"


def test_changed_reviewed_collector_scope_cannot_inherit_the_old_baseline(observer_customer):
    from threatveil.observers import ObserverInput
    h = observer_customer
    approved = qualify(h)
    failed = execute(h, approved, "vulnerable")
    fixed = execute(h, approved)
    baseline = create_fix(h, failed, fixed)["baseline_id"]
    registration = {key: h[3][key] for key in ObserverInput.model_fields}
    registration["fixture_reference"] = "test:new-reviewed-procurement-fixture"
    response = h[0].post("/v1/observers", json=registration)
    assert response.status_code == 201, response.text
    new_h = h[:3] + (response.json(), h[4])
    new_observer = qualify(new_h)
    result = execute(h, new_observer, baseline=baseline)
    assert result["candidate_observed"] and result["fix_eligible"]
    assert not result["comparison"]["compatible"]
    assert "Incompatible witness_binding" in result["comparison"]["reasons"]
    assert result["release_action"] == "BLOCK"
    fix = create_fix(h, failed, result)
    assert not fix["verified"] and fix["baseline_id"] is None
    assert "witness_binding" in fix["reason"]


def test_revoked_family_cannot_approve_already_completed_qualification(observer_customer):
    h = observer_customer
    observer = h[3]
    permitted = execute(h, observer, case="KNOWN_PERMITTED")
    prohibited = execute(h, observer, "vulnerable", "KNOWN_PROHIBITED")
    missing = execute(h, observer, "missing_witness", "MISSING_OBSERVATION")
    assert h[0].post(f"/v1/observers/{observer['id']}/revoke").status_code == 200
    response = h[0].post(f"/v1/observers/{observer['id']}/approve", json={
        "permitted_run_id": permitted["id"], "prohibited_run_id": prohibited["id"],
        "missing_run_id": missing["id"], "review_note": "Completed results do not undo an explicit source revocation."})
    assert response.status_code == 403 and "revoked" in response.text


def test_qualification_case_labels_cannot_be_reassigned_at_approval(observer_customer):
    h = observer_customer
    observer = h[3]
    permitted = execute(h, observer, case="KNOWN_PERMITTED")
    prohibited = execute(h, observer, "vulnerable", "KNOWN_PERMITTED")
    missing = execute(h, observer, "missing_witness", "MISSING_OBSERVATION")
    assert prohibited["security_verdict"] == "FAIL"
    response = h[0].post(f"/v1/observers/{observer['id']}/approve", json={
        "permitted_run_id": permitted["id"], "prohibited_run_id": prohibited["id"],
        "missing_run_id": missing["id"], "review_note": "A real FAIL cannot be relabeled as a different pre-assigned control."})
    assert response.status_code == 422
