"""Release narrative with real PostgreSQL and committed SQLite business-state evidence."""

from copy import deepcopy
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from threatveil.api import app
from threatveil.config import settings
from threatveil.core.contracts import digest
from threatveil.db import Membership, Record, now, transaction
from threatveil.release_signing import signing_key
from threatveil.sdk.receipts import ReceiptVerificationError, verify_release_receipt

from test_product import customer as customer, setup, run, with_enforcement


def plan_for(c, d, result, **extra):
    response = c.post("/v1/proof-plans", json={"system_id": d["system"]["id"],
        "candidate": result["candidate"], "fingerprint": result["fingerprint"],
        "trials_per_variant": 2, **extra})
    assert response.status_code == 201, response.text
    return response.json()


def release(c, plan, mode="BLOCK", **extra):
    if mode == "BLOCK" or "BLOCK" in extra.get("policy", {}).get("property_modes", {}).values():
        with_enforcement(c)
    r = c.post("/v1/releases", json={"plan_id": plan["id"], "policy": {"mode": mode}, **extra})
    assert r.status_code == 201, r.text
    return r.json()


def test_exact_release_change_void_reproof_regression_and_fix(customer):
    d = setup(customer)
    first = run(customer, d, "fixed")
    plan_a = plan_for(customer, d, first)
    assert not plan_a["obligations"] and plan_a["reused_evidence_ids"]
    a = release(customer, plan_a)
    assert a["release_action"] == "ALLOW"
    candidate_b = deepcopy(first)
    candidate_b["candidate"].update(version="regressed", digest=digest({"fixture": "procurement-v1", "version": "regressed"}))
    for component in candidate_b["fingerprint"]["components"]:
        if component["type"] in {"application", "permissions"}:
            component.update(version="regressed", digest=candidate_b["candidate"]["digest"] if component["type"] == "application" else digest("regressed"))
    plan_b = plan_for(customer, d, candidate_b, previous_fingerprint=first["fingerprint"])
    assert plan_b["invalidations"][0]["status"] == "VOID"
    assert len(plan_b["obligations"]) == 1
    result = customer.post(f"/v1/proof-plans/{plan_b['id']}/execute", json={"runs": [{
        "system_id": d["system"]["id"], "property_id": d["property"]["id"],
        "target_id": d["target"]["id"], "version": "regressed", "candidate": candidate_b["candidate"],
        "fingerprint": candidate_b["fingerprint"], "trials": 2, "variant_count": 1,
        "idempotency_key": str(uuid4()),
    }]})
    assert result.status_code == 202, result.text
    b = release(customer, plan_b)
    assert b["release_action"] == "BLOCK" and b["properties"][0]["security_verdict"] == "FAIL"
    fixed = run(customer, d, "fixed")
    c = release(customer, plan_for(customer, d, fixed, previous_fingerprint=candidate_b["fingerprint"]))
    assert c["release_action"] == "ALLOW"
    receipt = customer.get(f"/v1/releases/{c['id']}/receipt").json()
    statement = verify_release_receipt(receipt["envelope"], signing_key().public_key(),
        expected_candidate_fingerprint_digest=c["candidate_fingerprint_digest"],
        expected_organization_id=c["organization_id"], expected_candidate=c["candidate"])
    assert statement["predicate"]["release_action"] == "ALLOW"
    with pytest.raises(ReceiptVerificationError):
        verify_release_receipt(receipt["envelope"], signing_key().public_key(),
            expected_candidate_fingerprint_digest="0"*64, expected_organization_id=c["organization_id"])
    history = customer.get("/v1/releases", params={"system_id": d["system"]["id"], "limit": 1}).json()
    assert history["pagination"]["total"] == 3 and history["pagination"]["next_cursor"]
    assert customer.get(f"/v1/releases/{a['id']}").json()["release_action"] == "ALLOW"


@pytest.mark.parametrize("version", ["missing_witness", "bad_fix"])
def test_missing_observation_and_destroyed_utility_cannot_allow(customer, version):
    d = setup(customer)
    r = run(customer, d, version)
    plan = plan_for(customer, d, r)
    assert plan["obligations"]
    result = release(customer, plan)
    assert result["underlying_action"] == result["release_action"] == "BLOCK"
    warning = release(customer, plan, "WARN")
    assert warning["release_action"] == "WARN" and warning["underlying_action"] == "BLOCK"


def test_candidate_relabel_and_shortened_trial_budget_do_not_establish_proof(customer):
    d = setup(customer)
    r = run(customer, d, "fixed")
    plan = plan_for(customer, d, r, trials_per_variant=5)
    assert plan["obligations"] and release(customer, plan)["release_action"] == "BLOCK"
    fake = deepcopy(r)
    fake["candidate"]["digest"] = "f"*64
    assert release(customer, plan_for(customer, d, fake))["release_action"] == "BLOCK"


def test_revoked_target_changes_current_eligibility_without_mutating_history(customer):
    d = setup(customer)
    result = release(customer, plan_for(customer, d, run(customer, d, "fixed")))
    assert customer.post(f"/v1/targets/{d['target']['id']}/revoke").status_code == 200
    current = customer.get(f"/v1/releases/{result['id']}").json()
    assert current["release_action"] == "ALLOW"
    assert current["current"]["release_action"] == "BLOCK"
    assert not current["current"]["current"]


def test_exception_requires_second_security_approver_and_preserves_block(customer):
    d = setup(customer)
    p = plan_for(customer, d, run(customer, d, "regressed"))
    req = customer.post("/v1/release-exceptions", json={"plan_id": p["id"],
        "property_ids": [d["property"]["id"]], "reason": "Controlled emergency recovery of the staging system",
        "risk_acknowledgment": "I acknowledge this candidate has a confirmed authorization failure",
        "expires_at": (now()+timedelta(hours=1)).isoformat()})
    assert req.status_code == 201, req.text
    eid = req.json()["id"]
    assert customer.post(f"/v1/release-exceptions/{eid}/approve").status_code == 403
    assert customer.post("/v1/releases", json={"plan_id":p["id"], "exception_ids":[eid]}).status_code == 409
    with TestClient(app) as approver:
        login = approver.post("/v1/auth/local", json={"email":f"{uuid4()}@local.invalid"}, headers={"origin":"http://127.0.0.1:3000"}).json()
        approver.headers.update({"origin":"http://127.0.0.1:3000", "x-csrf-token":login["csrf_token"]})
        user = approver.get("/v1/auth/me").json()["user"]["id"]
        org = UUID(d["system"]["organization_id"])
        with transaction(org_id=org) as s:
            s.add(Membership(organization_id=org,user_id=UUID(user),role="security"))
        switched = approver.post("/v1/auth/switch", json={"organization_id":str(org)})
        assert switched.status_code == 200, switched.text
        assert approver.post(f"/v1/release-exceptions/{eid}/approve").status_code == 201
    result = release(customer,p,exception_ids=[eid])
    assert result["underlying_action"] == "BLOCK" and result["release_action"] == "WARN"
    assert result["properties"][0]["security_verdict"] == "FAIL"
    assert result["status_label"] == "BLOCK overridden by authorized exception"
    customer.post(f"/v1/release-exceptions/{eid}/revoke")
    assert customer.get(f"/v1/releases/{result['id']}").json()["current"]["release_action"] == "BLOCK"


def test_cross_tenant_and_append_only_evidence(customer):
    d = setup(customer)
    result = release(customer, plan_for(customer, d, run(customer, d, "fixed")))
    with TestClient(app) as other:
        other.post("/v1/auth/local",json={"email":f"{uuid4()}@local.invalid"},headers={"origin":"http://127.0.0.1:3000"})
        assert other.get(f"/v1/releases/{result['id']}").status_code == 404
        assert other.get(f"/v1/evidence-ledger/{result['properties'][0]['evidence_id']}").status_code == 404
    with transaction(org_id=UUID(result["organization_id"])) as s:
        assert s.scalar(select(Record).where(Record.id==UUID(result["id"])))
        with pytest.raises(DBAPIError):
            s.execute(text("UPDATE records SET payload='{}' WHERE id=:id"), {"id":UUID(result["id"])})


def test_nonlocal_without_signing_key_cannot_issue_receipt(customer, monkeypatch):
    d = setup(customer)
    p = plan_for(customer,d,run(customer,d,"fixed"))
    cfg=settings()
    monkeypatch.setattr(cfg,"env","dev")
    monkeypatch.setattr(cfg,"receipt_signing_private_key","")
    r=customer.post("/v1/releases",json={"plan_id":p["id"]})
    assert r.status_code == 503


def test_partial_reproof_retains_accepted_work_and_never_allows_missing_obligation(customer, monkeypatch):
    from fastapi import HTTPException
    from threatveil import api

    d = setup(customer)
    first = run(customer, d, 'fixed')
    draft = customer.post('/v1/properties', json={'system_id': d['system']['id'],
        'title': 'Second independently approved property', 'description': 'Synthetic release obligation',
        'definition': d['property']['definition']})
    assert draft.status_code == 201, draft.text
    assert customer.post(f"/v1/properties/{draft.json()['id']}/approve").status_code == 200
    changed = deepcopy(first)
    changed['candidate'].update(version='regressed', digest=digest({'fixture': 'procurement-v1', 'version': 'regressed'}))
    for component in changed['fingerprint']['components']:
        if component['type'] == 'application':
            component.update(version='regressed', digest=changed['candidate']['digest'])
    plan = plan_for(customer, d, changed)
    assert len(plan['obligations']) == 2
    real_create, calls = api.create_run, []

    def reject_second(*args):
        calls.append(True)
        if len(calls) == 2:
            raise HTTPException(402, 'Synthetic exhausted second-obligation budget')
        return real_create(*args)

    monkeypatch.setattr(api, 'create_run', reject_second)
    response = customer.post(f"/v1/proof-plans/{plan['id']}/execute", json={'runs': [
        {'system_id': d['system']['id'], 'property_id': obligation['property_id'],
         'target_id': d['target']['id'], 'version': 'regressed', 'candidate': changed['candidate'],
         'fingerprint': changed['fingerprint'], 'trials': 2, 'variant_count': 1,
         'idempotency_key': str(uuid4())} for obligation in plan['obligations']]})
    assert response.status_code == 202, response.text
    result = response.json()
    assert result['status'] == 'PARTIAL' and len(result['runs']) == len(result['failures']) == 1
    assert customer.get('/v1/runs/' + result['runs'][0]['id']).json()['status'] == 'COMPLETED'
    assert release(customer, plan)['release_action'] == 'BLOCK'
    with transaction(org_id=UUID(d['system']['organization_id'])) as session:
        row = session.get(Record, UUID(result['id']))
        assert row.payload['status'] == 'PARTIAL' and row.payload['run_ids'] == [result['runs'][0]['id']]
