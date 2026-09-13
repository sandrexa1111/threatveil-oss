"""Real PostgreSQL, immutable signatures and scoped machine-issuer negatives."""

from copy import deepcopy
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from threatveil.api import app
from threatveil.db import now
from threatveil.release_signing import signing_key
from threatveil.sdk.client import ThreatVeilClient
from threatveil.sdk.receipts import verify_release_receipt

from test_product import customer as customer, setup, run, with_enforcement
from test_release_integrity import plan_for


def authority(customer):
    # A machine-issued BLOCK policy is a paid enforcement capability.
    with_enforcement(customer)
    data = setup(customer)
    first = run(customer, data, "fixed")
    # Two independently approved records make omission a meaningful nonempty subset.
    from threatveil.db import add_record, serialize, transaction
    with transaction(org_id=UUID(data["system"]["organization_id"])) as session:
        second = serialize(add_record(session, UUID(data["system"]["organization_id"]), "property", {
            **data["property"], "title": "Second reviewed complete release obligation",
        }))
    run(customer, {**data, "property": second}, "fixed")
    plan = plan_for(customer, data, first)
    policy_request = {"system_id": data["system"]["id"], "policy": {"mode": "BLOCK"},
        "reason": "Reviewed complete protected-system release scope"}
    policy = customer.post("/v1/release-policies", json=policy_request)
    assert policy.status_code == 201, policy.text
    policy = policy.json()
    grant = customer.post("/v1/release-authorizations", json={"plan_id": plan["id"], "policy_id": policy["id"]})
    assert grant.status_code == 201, grant.text
    grant = grant.json()
    assert "token_hash" not in grant
    binding = {"organization_id": data["system"]["organization_id"], "system_id": data["system"]["id"],
        "plan_id": plan["id"], "repository_id": None, "candidate": plan["candidate"],
        "candidate_fingerprint_digest": plan["candidate_fingerprint_digest"],
        "property_ids": list(grant["scope"]), "policy_id": policy["id"], "policy_epoch": policy["epoch"]}
    return data, plan, policy_request, grant, binding


def decide(grant, binding):
    with TestClient(app) as machine:
        return machine.post("/v1/release-machine/decide", json=binding,
            headers={"authorization": "Bearer " + grant["token"]})


def test_complete_scoped_machine_decision_and_historical_receipt(customer):
    _, _, policy_request, grant, binding = authority(customer)
    with TestClient(app) as transport:
        client = ThreatVeilClient("http://127.0.0.1", grant["token"], http_client=transport)
        result = client.decide_authorized_release(binding)
    assert result["release_action"] == result["underlying_action"] == "ALLOW"
    assert {p["property_id"] for p in result["properties"]} == set(binding["property_ids"])
    receipt = customer.get(f"/v1/releases/{result['id']}/receipt").json()
    saved_envelope = deepcopy(receipt["envelope"])
    verified = verify_release_receipt(saved_envelope, signing_key().public_key(),
        expected_candidate_fingerprint_digest=binding["candidate_fingerprint_digest"],
        expected_organization_id=binding["organization_id"])
    assert verified["predicate"]["machine_authority"]["policy_epoch"] == 1
    replay = decide(grant, binding)
    assert replay.status_code == 409 and replay.json()["detail"]["release_id"] == result["id"]
    # A new policy epoch changes only the current projection, never its signed history.
    assert customer.post("/v1/release-policies", json=policy_request).status_code == 201
    current = customer.get(f"/v1/releases/{result['id']}").json()
    assert current["release_action"] == "ALLOW" and current["current"]["release_action"] == "BLOCK"
    assert current["receipt"]["envelope"] == saved_envelope


@pytest.mark.parametrize("mutation", ["repository", "candidate", "tenant", "system", "fingerprint", "omitted", "epoch", "policy"])
def test_wrong_release_binding_never_issues(customer, mutation):
    _, _, _, grant, binding = authority(customer)
    if mutation == "repository":
        binding["repository_id"] = "99999"
    elif mutation == "candidate":
        binding["candidate"]["digest"] = "f" * 64
    elif mutation == "tenant":
        binding["organization_id"] = str(uuid4())
    elif mutation == "system":
        binding["system_id"] = str(uuid4())
    elif mutation == "fingerprint":
        binding["candidate_fingerprint_digest"] = "f" * 64
    elif mutation == "omitted":
        binding["property_ids"] = binding["property_ids"][:1]
    elif mutation == "epoch":
        binding["policy_epoch"] += 1
    else:
        binding["policy_id"] = str(uuid4())
    assert decide(grant, binding).status_code in {401, 403, 409, 422}


@pytest.mark.parametrize("condition", ["expired", "revoked", "changed_policy", "changed_scope", "authorizer_demoted"])
def test_stale_authority_fails_closed(customer, condition, monkeypatch):
    data, _, policy_request, grant, binding = authority(customer)
    if condition == "expired":
        monkeypatch.setattr("threatveil.release_machine.now", lambda: now() + timedelta(hours=2))
    elif condition == "revoked":
        assert customer.post(f"/v1/release-authorizations/{grant['id']}/revoke").status_code == 201
    elif condition == "changed_policy":
        policy_request["policy"]["mode"] = "WARN"
        assert customer.post("/v1/release-policies", json=policy_request).status_code == 201
    elif condition == "changed_scope":
        from threatveil.db import add_record, transaction
        with transaction(org_id=UUID(binding["organization_id"])) as session:
            add_record(session, UUID(binding["organization_id"]), "property", data["property"])
    else:
        from threatveil.db import Membership, transaction
        with transaction(org_id=UUID(binding["organization_id"])) as session:
            member = session.get(Membership, (UUID(binding["organization_id"]), UUID(grant["authorized_by"])))
            member.role = "developer"
    assert decide(grant, binding).status_code in {403, 409}


def test_execute_token_and_release_token_do_not_gain_admin_or_execution(customer):
    _, plan, policy_request, grant, binding = authority(customer)
    issued = customer.post("/v1/api-tokens", json={"name": "CI execution", "permission": "execute", "expires_in_days": 1})
    assert issued.status_code == 201, issued.text
    with TestClient(app) as machine:
        machine.headers["authorization"] = "Bearer " + issued.json()["token"]
        assert machine.post("/v1/releases", json={"plan_id": plan["id"]}).status_code == 403
        assert machine.post("/v1/release-policies", json=policy_request).status_code == 403
        assert machine.post("/v1/release-authorizations", json={"plan_id": plan["id"], "policy_id": binding["policy_id"]}).status_code == 403
        assert machine.post("/v1/release-machine/decide", json=binding).status_code == 401
        machine.headers["authorization"] = "Bearer " + grant["token"]
        assert machine.get("/v1/releases").status_code == 401
        assert machine.post("/v1/release-policies", json=policy_request).status_code == 401
        assert machine.post(f"/v1/proof-plans/{plan['id']}/execute", json={"runs": []}).status_code in {401, 422}
