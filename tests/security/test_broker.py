"""Adversarial broker acceptance against the actual non-owner PostgreSQL role."""

import base64
import copy
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select

from threatveil import api, broker
from threatveil.auth import digest
from threatveil.config import settings
from threatveil.core import run_procurement
from threatveil.db import Lease, RunState, now, transaction

ORIGIN = "http://127.0.0.1:3000"


@pytest.fixture
def queued_run(monkeypatch):
    monkeypatch.setenv("TV_ENV", "test")
    monkeypatch.setenv("TV_LOCAL_AUTH", "true")
    settings.cache_clear()
    monkeypatch.setattr(api, "execute_run", lambda *_: None)
    with TestClient(api.app) as owner, TestClient(broker.app) as worker:
        # A stale browser cookie is deliberately replaced by a fresh verified local login.
        owner.cookies.set("tv_session", str(uuid4()))
        response = owner.post(
            "/v1/auth/local", json={"email": f"{uuid4()}@local.invalid"}, headers={"origin": ORIGIN}
        )
        assert response.status_code == 200, response.text
        owner.headers.update({"origin": ORIGIN, "x-csrf-token": response.json()["csrf_token"]})
        demo = owner.post("/v1/demo/setup", json={}).json()
        response = owner.post(
            "/v1/runs",
            json={
                "system_id": demo["system"]["id"],
                "property_id": demo["property"]["id"],
                "target_id": demo["target"]["id"],
                "version": "fixed",
                "trials": 2,
                "variant_count": 1,
                "idempotency_key": str(uuid4()),
            },
        )
        assert response.status_code == 202, response.text
        run_id = UUID(response.json()["id"])
        org_id = UUID(demo["system"]["organization_id"])
        dispatch = broker.prepare_dispatch(org_id, run_id)
        worker.headers["authorization"] = f"Bearer {broker.local_identity_token()}"
        yield {
            "owner": owner,
            "worker": worker,
            "run_id": run_id,
            "org_id": org_id,
            "dispatch": dispatch,
            "demo": demo,
        }
    settings.cache_clear()


def claim_body(dispatch, key=None, nonce=None):
    key = key or Ed25519PrivateKey.generate()
    value = {
        "run_id": dispatch["run_id"],
        "bootstrap_token": dispatch["bootstrap_token"],
        "worker_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        "nonce": nonce or secrets.token_urlsafe(24),
        "signature": "x" * 88,
    }
    value["signature"] = base64.b64encode(
        key.sign(broker.claim_message(broker.Claim(**value)))
    ).decode()
    return value, key


def claimed(harness):
    body, key = claim_body(harness["dispatch"])
    response = harness["worker"].post("/v1/claim", json=body)
    assert response.status_code == 200, response.text
    return response.json(), key, body


def signed(lease, key, action, payload=None, nonce=None, timestamp=None):
    body = {
        "lease_id": lease["lease_id"],
        "fence": lease["fence"],
        "nonce": nonce or secrets.token_urlsafe(24),
        "timestamp": timestamp if timestamp is not None else int(now().timestamp()),
        "payload": payload or {},
        "signature": "x" * 88,
    }
    body["signature"] = base64.b64encode(
        key.sign(broker.lease_message(broker.LeaseRequest(**body), action))
    ).decode()
    return body


def test_bootstrap_requires_correct_run_identity_signature_and_capability(queued_run):
    h = queued_run
    for mutation, expected in (("run", 403), ("token", 403), ("identity", 401), ("signature", 401)):
        data = dict(h["dispatch"])
        if mutation == "run":
            data["run_id"] = str(uuid4())
        if mutation == "token":
            data["bootstrap_token"] = secrets.token_urlsafe(32)
        body, _ = claim_body(data)
        if mutation == "signature":
            body["signature"] = base64.b64encode(b"x" * 64).decode()
        headers = {"authorization": "Bearer wrong-worker"} if mutation == "identity" else {}
        response = h["worker"].post("/v1/claim", json=body, headers=headers)
        assert response.status_code == expected, response.text
    claimed(h)


def test_expired_bootstrap_cannot_be_redeemed(queued_run):
    h = queued_run
    with transaction(org_id=h["org_id"]) as session:
        lease = session.scalar(
            select(Lease).where(Lease.token_hash == digest(h["dispatch"]["bootstrap_token"]))
        )
        lease.bootstrap_expires = now() - timedelta(seconds=1)
    body, _ = claim_body(h["dispatch"])
    assert h["worker"].post("/v1/claim", json=body).status_code == 403


def test_claim_response_recovery_is_bound_to_the_same_key_and_nonce(queued_run):
    h = queued_run
    lease, key, body = claimed(h)
    recovered = h["worker"].post("/v1/claim", json=body)
    assert recovered.status_code == 200 and recovered.json()["lease_id"] == lease["lease_id"]
    other, _ = claim_body(h["dispatch"])
    assert h["worker"].post("/v1/claim", json=other).status_code == 409
    different_nonce, _ = claim_body(h["dispatch"], key=key)
    assert h["worker"].post("/v1/claim", json=different_nonce).status_code == 409


def test_bootstrap_redeem_race_has_one_winner(queued_run):
    dispatch = queued_run["dispatch"]
    identities = [claim_body(dispatch)[0], claim_body(dispatch)[0]]
    identity = broker.local_identity_token()

    def request(body):
        with TestClient(broker.app) as client:
            return client.post(
                "/v1/claim", json=body, headers={"authorization": f"Bearer {identity}"}
            ).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(request, identities))
    assert sorted(statuses) == [200, 409]


def test_replaced_dispatch_invalidates_old_bootstrap(queued_run):
    h = queued_run
    replacement = broker.prepare_dispatch(h["org_id"], h["run_id"])
    old, _ = claim_body(h["dispatch"])
    assert h["worker"].post("/v1/claim", json=old).status_code == 403
    new, _ = claim_body(replacement)
    response = h["worker"].post("/v1/claim", json=new)
    assert response.status_code == 200
    assert response.json()["fence"] == 2


def test_lease_requests_bind_action_payload_fence_nonce_and_time(queued_run):
    h = queued_run
    lease, key, _ = claimed(h)
    body = signed(lease, key, "spec")
    response = h["worker"].post("/v1/spec", json=body)
    assert response.status_code == 200 and response.json()["run_id"] == str(h["run_id"])
    assert h["worker"].post("/v1/spec", json=body).status_code == 409
    for mutation in ("action", "payload", "fence", "time", "key"):
        value = signed(lease, key, "spec")
        if mutation == "action":
            value = signed(lease, key, "credential")
        elif mutation == "payload":
            value["payload"]["unrelated"] = str(uuid4())
        elif mutation == "fence":
            value = signed({**lease, "fence": lease["fence"] + 1}, key, "spec")
        elif mutation == "time":
            value = signed(lease, key, "spec", timestamp=int(now().timestamp()) - 60)
        else:
            value = signed(lease, Ed25519PrivateKey.generate(), "spec")
        assert h["worker"].post("/v1/spec", json=value).status_code in (401, 403)


def test_lease_cannot_retrieve_unrelated_credential(queued_run):
    h = queued_run
    lease, key, _ = claimed(h)
    response = h["worker"].post(
        "/v1/credential",
        json=signed(lease, key, "credential", {"credential_reference_id": str(uuid4())}),
    )
    assert response.status_code == 403
    assert "value" not in response.json()


def test_revoked_target_and_expired_lease_stop_broker_access(queued_run):
    h = queued_run
    lease, key, _ = claimed(h)
    with transaction(org_id=h["org_id"]) as session:
        session.get(Lease, UUID(lease["lease_id"])).lease_expires = now() - timedelta(seconds=1)
    assert h["worker"].post("/v1/spec", json=signed(lease, key, "spec")).status_code == 403
    with transaction(org_id=h["org_id"]) as session:
        session.get(Lease, UUID(lease["lease_id"])).lease_expires = now() + timedelta(seconds=60)
    assert (
        h["owner"].post(f"/v1/targets/{h['demo']['target']['id']}/revoke", json={}).status_code
        == 200
    )
    assert h["worker"].post("/v1/spec", json=signed(lease, key, "spec")).status_code == 403


def test_finalized_run_invalidates_all_outstanding_lease_access(queued_run):
    h = queued_run
    lease, key, _ = claimed(h)
    api.finish_run(h["org_id"], h["run_id"], run_procurement("fixed", trials=2))
    for action in ("spec", "renew", "credential"):
        response = h["worker"].post(f"/v1/{action}", json=signed(lease, key, action))
        assert response.status_code in (403, 409), (
            f"Finalized run still grants {action}: {response.text}"
        )


def test_worker_identity_cannot_use_launcher_control_plane(queued_run):
    h = queued_run
    assert h["worker"].post("/internal/pending").status_code in (401, 403)
    assert h["worker"].post(
        "/internal/prepare-dispatch",
        json={"organization_id": str(h["org_id"]), "run_id": str(h["run_id"])},
    ).status_code in (401, 403)


def test_duplicate_trial_evidence_cannot_satisfy_complete_experiment(queued_run):
    h = queued_run
    lease, key, _ = claimed(h)
    result = run_procurement("fixed", trials=2)
    result["trials"][1] = copy.deepcopy(result["trials"][0])
    response = h["worker"].post(
        "/v1/complete", json=signed(lease, key, "complete", {"result": result})
    )
    assert response.status_code == 422, response.text
    with transaction(org_id=h["org_id"]) as session:
        assert not session.get(RunState, (h["org_id"], h["run_id"])).settled


def test_complete_reconstructs_assigned_result_and_rejects_other_run_capture(queued_run):
    h = queued_run
    lease, key, _ = claimed(h)
    unrelated = run_procurement("fixed", trials=2, execution_id=str(uuid4()))
    response = h["worker"].post("/v1/complete", json=signed(lease, key, "complete", {"result": unrelated}))
    assert response.status_code == 422
    actual = run_procurement("fixed", trials=2, execution_id=str(h["run_id"]))
    actual.update(security_verdict="FAIL", task_outcome="FAILURE", release_action="BLOCK")
    response = h["worker"].post("/v1/complete", json=signed(lease, key, "complete", {"result": actual}))
    assert response.status_code == 200, response.text
    result = h["owner"].get(f"/v1/runs/{h['run_id']}").json()
    assert result["security_verdict"] == "PASS" and result["task_outcome"] == "SUCCESS"
    assert h["worker"].post("/v1/complete", json=signed(lease, key, "complete", {"result": actual})).status_code == 403
