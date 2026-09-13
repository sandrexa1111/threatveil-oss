"""Real PostgreSQL and committed finance SQL, no provider mocks."""

from uuid import uuid4

from threatveil.release_signing import signing_key
from threatveil.sdk.change_records import verify_change_record
from test_product import customer as customer


def prepare(c):
    response = c.post("/v1/change-assurance/finance/setup", json={
        "owner": "Finance security owner", "confirm_synthetic_scope": True})
    assert response.status_code == 201, response.text
    return response.json()


def assess(c, setup, version="fixed", key=None):
    response = c.post("/v1/change-assurance/finance/assess", json={
        "system_id": setup["system_id"], "version": version,
        "idempotency_key": key or str(uuid4())})
    assert response.status_code == 201, response.text
    return response.json()


def test_finance_three_properties_noncode_change_bad_fix_and_export(customer):
    setup = prepare(customer)
    first = assess(customer, setup)
    assert first["action"] == "ALLOW"
    regressed = assess(customer, setup, "regressed")
    assert regressed["security"] == "FAIL" and regressed["action"] == "BLOCK"
    bad = assess(customer, setup, "bad_fix")
    assert (bad["security"], bad["legitimate_task"], bad["action"]) == ("PASS", "FAILURE", "BLOCK")
    restored = assess(customer, setup)
    assert restored["action"] == "ALLOW"
    missing = assess(customer, setup, "missing_witness")
    assert missing["security"] == "INCONCLUSIVE" and missing["action"] != "ALLOW"
    decision = customer.get(f"/v1/change-assurance/decisions/{restored['authorization_id']}").json()
    assert decision["enforcement"] == "NOT_REQUESTED"
    verified = verify_change_record(decision["envelope"], signing_key().public_key(),
        organization_id=decision["organization_id"], system_id=setup["system_id"],
        environment_id=setup["environment_id"], state_digest=decision["state_digest"], audience=decision["audience"])
    assert verified["predicate"]["action"] == "ALLOW"
    journey = customer.get(f"/v1/change-assurance/systems/{setup['system_id']}").json()
    assert len(journey["properties"]) == 3
    changes = journey["environments"][0]["transitions"]
    assert any(c["change_type"] == "APPROVAL_POLICY_CHANGED" and not c["prevention_claim"] for c in changes)
    assert customer.get(f"/v1/change-assurance/decisions/{first['authorization_id']}").json()["action"] == "ALLOW"


def test_synthetic_enforcement_is_distinct_idempotent_and_bound(customer):
    setup = prepare(customer)
    result = assess(customer, setup)
    decision = customer.get(f"/v1/change-assurance/decisions/{result['authorization_id']}").json()
    assert decision["current_status"] == "CURRENT"
    body = {"authorization_id": decision["id"], **{k: decision[k] for k in (
        "environment_id", "state_digest", "audience", "expected_prior_epoch", "request_nonce")},
        "mechanism": "synthetic_compare_and_set"}
    wrong = customer.post("/v1/change-assurance/enforcement", json={**body, "audience": "somewhere-else"})
    assert wrong.status_code == 409
    response = customer.post("/v1/change-assurance/enforcement", json=body)
    assert response.status_code == 201, response.text
    repeat = customer.post("/v1/change-assurance/enforcement", json=body)
    assert repeat.json()["id"] == response.json()["id"]
    view = customer.get(f"/v1/change-assurance/decisions/{decision['id']}").json()
    assert view["enforcement"] == "ACKNOWLEDGED"
    assert view["acknowledgement"]["authority"] == "SYNTHETIC_LOCAL"
    current = customer.get(f"/v1/change-assurance/systems/{setup['system_id']}").json()
    assert current["environments"][0]["stage"] == "PROTECTED"
    newer = assess(customer, setup)
    next_decision = customer.get(f"/v1/change-assurance/decisions/{newer['authorization_id']}").json()
    assert next_decision["expected_prior_epoch"] == 1
    next_body = {"authorization_id": next_decision["id"], **{k: next_decision[k] for k in (
        "environment_id", "state_digest", "audience", "expected_prior_epoch", "request_nonce")},
        "mechanism": "synthetic_compare_and_set"}
    assert customer.post("/v1/change-assurance/enforcement", json=next_body).status_code == 201
    assert customer.get(f"/v1/change-assurance/decisions/{newer['authorization_id']}").json()["acknowledgement"]["applied_epoch"] == 2


def test_free_billing_upgrade_never_changes_assurance_truth(customer):
    setup = prepare(customer)
    failed = assess(customer, setup, "regressed")
    path = f"/v1/change-assurance/decisions/{failed['authorization_id']}"
    before = customer.get(path).json()
    assert customer.get("/v1/commercial").json()["plan"] == "free"
    response = customer.post("/v1/commercial/subscription", json={"action": "upgrade", "plan": "pro",
                                                               "idempotency_key": str(uuid4())})
    assert response.status_code == 200, response.text
    after = customer.get(path).json()
    assert before["envelope"] == after["envelope"]
    assert after["action"] == "BLOCK" and after["security"] == "FAIL"
    assert customer.get("/v1/commercial").json()["usage"]["consumed"] > 0


def test_assessment_resumes_exact_checkpoint_after_signing_failure(customer, monkeypatch):
    from fastapi import HTTPException
    from threatveil import change_assurance_api as api
    setup = prepare(customer)
    key = str(uuid4())
    real_decide = api.decide
    def unavailable(*args, **kwargs):
        raise HTTPException(503, "Signing service temporarily unavailable")
    monkeypatch.setattr(api, "decide", unavailable)
    payload = {"system_id": setup["system_id"], "version": "fixed", "idempotency_key": key}
    assert customer.post("/v1/change-assurance/finance/assess", json=payload).status_code == 503
    before = customer.get(f"/v1/change-assurance/systems/{setup['system_id']}").json()
    state_id = before["environments"][0]["state"]["id"]
    consumed = customer.get("/v1/commercial").json()["usage"]["consumed"]
    monkeypatch.setattr(api, "decide", real_decide)
    resumed = assess(customer, setup, key=key)
    assert resumed["state_id"] == state_id and resumed["action"] == "ALLOW"
    assert assess(customer, setup, key=key)["id"] == resumed["id"]
    assert customer.get("/v1/commercial").json()["usage"]["consumed"] == consumed
    assert customer.post("/v1/change-assurance/finance/assess", json={**payload, "version": "regressed"}).status_code == 409
