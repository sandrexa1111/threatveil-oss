"""Durable external trial evidence against real PostgreSQL and signed fixture sinks."""

import base64
import secrets
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
from uuid import UUID, uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select

from threatveil import api, broker, maintenance, targets
from threatveil.captures import captured_trials
from threatveil.core.contracts import Observation, SystemFingerprint, digest, trial_correlation
from threatveil.core.procurement import _trial
from threatveil.core.variants import bounded_variants
from threatveil.db import Account, Lease, Outbox, Record, now, transaction
from threatveil.sdk.signing import sign_observation

from test_observers import execute, observer_customer as observer_customer, qualify


def signed(lease, key, action, payload=None):
    body = {
        "lease_id": lease["lease_id"],
        "fence": lease["fence"],
        "nonce": secrets.token_urlsafe(24),
        "timestamp": int(now().timestamp()),
        "payload": payload or {},
        "signature": "x" * 88,
    }
    body["signature"] = base64.b64encode(
        key.sign(broker.lease_message(broker.LeaseRequest(**body), action))
    ).decode()
    return body


@pytest.fixture
def external_worker(observer_customer, monkeypatch):
    h = observer_customer
    observer = qualify(h)
    monkeypatch.setattr(api, "execute_run", lambda *_: None)
    run = execute(h, observer, overrides={"trials": 2})
    org_id, run_id = UUID(h[1]["system"]["organization_id"]), UUID(run["id"])
    dispatch = broker.prepare_dispatch(org_id, run_id)
    key = Ed25519PrivateKey.generate()
    claim = {
        "run_id": str(run_id),
        "bootstrap_token": dispatch["bootstrap_token"],
        "worker_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        "nonce": secrets.token_urlsafe(24),
        "signature": "x" * 88,
    }
    claim["signature"] = base64.b64encode(
        key.sign(broker.claim_message(broker.Claim(**claim)))
    ).decode()
    with TestClient(broker.app) as worker:
        worker.headers["authorization"] = "Bearer " + broker.local_identity_token()
        response = worker.post("/v1/claim", json=claim)
        assert response.status_code == 200, response.text
        yield {
            "h": h,
            "owner": h[0],
            "worker": worker,
            "lease": response.json(),
            "key": key,
            "claim": claim,
            "run": run,
            "run_id": run_id,
            "org_id": org_id,
            "observer": observer,
        }


def sample(w, index=0, fixture="fixed", run_id=None):
    observer, keys = w["observer"], w["h"][4]
    correlation = trial_correlation(run_id or w["run_id"], "explicit-0", index)
    obs = _trial(fixture, bounded_variants(1)[0], correlation)
    obs = obs.model_copy(
        update={
            "initial_state_digest": observer["initial_state_digest"],
            "fingerprint": SystemFingerprint.model_validate(
                {
                    "components": [
                        {
                            "type": "application",
                            "id": "customer-agent",
                            "version": "candidate-v1",
                            "digest": digest("candidate-v1"),
                            "provenance": "OBSERVED",
                        }
                    ]
                }
            ),
        }
    )
    obs = sign_observation(sign_observation(obs, keys[0]), keys[1], "ground_truth")
    return {"variant_id": "explicit-0", "index": index, "observation": obs.model_dump(mode="json")}


def post(w, action, payload=None):
    return w["worker"].post(f"/v1/{action}", json=signed(w["lease"], w["key"], action, payload))


def view(w):
    return w["owner"].get(f"/v1/runs/{w['run_id']}").json()


def scope_reconciliation(monkeypatch, org_id):
    @contextmanager
    def scoped_transaction(*args, **kwargs):
        with transaction(*args, **kwargs) as session:
            if args or kwargs:
                yield session
            else:

                class Routes:
                    def scalars(self, query):
                        return session.scalars(query.where(Outbox.organization_id == org_id))

                yield Routes()

    monkeypatch.setattr(maintenance, "transaction", scoped_transaction)


def test_first_failure_survives_a_later_transport_error(observer_customer, monkeypatch):
    h = observer_customer
    observer = qualify(h)
    consumed_before = h[0].get("/v1/billing").json()["consumed"]
    endpoint, calls = targets.bounded_request, []

    def fails_after_first(*args, **kwargs):
        calls.append(1)
        if len(calls) > 1:
            raise httpx.ReadTimeout("Synthetic transport failure after a real fixture violation")
        return endpoint(*args, **kwargs)

    monkeypatch.setattr(targets, "bounded_request", fails_after_first)
    result = execute(h, observer, "vulnerable", overrides={"trials": 2})
    assert len(calls) == 2
    assert result["security_verdict"] == "FAIL" and result["execution_status"] == "ERROR"
    assert result["confirmed_failure_preserved"] and not result["fix_eligible"]
    assert result["release_action"] == "BLOCK" and not result["scope_complete"]
    assert len(result["capture_ids"]) == 1
    assert result["usage"]["units"] == 2
    assert h[0].get("/v1/billing").json()["consumed"] - consumed_before == 2
    capture = h[0].get(f"/v1/runs/{result['id']}/captures/{result['capture_ids'][0]}")
    assert capture.status_code == 200 and capture.json()["evaluation"]["security_verdict"] == "FAIL"


def test_streamed_failure_blocks_immediately_and_retry_is_idempotent(external_worker):
    w = external_worker
    item = sample(w, fixture="vulnerable")
    response = post(w, "observe", item)
    assert response.status_code == 200 and response.json()["security_verdict"] == "FAIL"
    run = view(w)
    assert run["status"] == "RUNNING" and run["result_id"] is None
    assert run["security_verdict"] == "FAIL" and run["release_action"] == "BLOCK"
    retry = post(w, "observe", item)
    assert retry.status_code == 200 and retry.json()["capture_id"] == response.json()["capture_id"]
    changed = post(w, "observe", sample(w, fixture="fixed"))
    assert changed.status_code == 409
    with transaction(org_id=w["org_id"]) as session:
        assert len(captured_trials(session, w["org_id"], w["run_id"])) == 1


@pytest.mark.parametrize(
    "mutation", ["other_run", "negative", "out_of_range", "bool", "other_variant"]
)
def test_only_frozen_assigned_slots_can_be_persisted(external_worker, mutation):
    w = external_worker
    item = sample(w, run_id=uuid4() if mutation == "other_run" else None)
    if mutation == "negative":
        item["index"] = -1
    elif mutation == "out_of_range":
        item["index"] = 2
    elif mutation == "bool":
        item["index"] = False
    elif mutation == "other_variant":
        item["variant_id"] = "explicit-1"
    response = post(w, "observe", item)
    assert response.status_code == 422, response.text
    with transaction(org_id=w["org_id"]) as session:
        assert not captured_trials(session, w["org_id"], w["run_id"])


def test_concurrent_capture_retries_make_one_immutable_record(external_worker):
    w = external_worker
    item = sample(w)

    def submit(_):
        with TestClient(broker.app) as worker:
            return worker.post(
                "/v1/observe",
                json=signed(w["lease"], w["key"], "observe", item),
                headers={"authorization": "Bearer " + broker.local_identity_token()},
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(submit, range(2)))
    assert all(r.status_code == 200 for r in responses)
    assert responses[0].json()["capture_id"] == responses[1].json()["capture_id"]
    with transaction(org_id=w["org_id"]) as session:
        assert len(captured_trials(session, w["org_id"], w["run_id"])) == 1


def test_expired_claim_recovery_retains_failure_and_never_replays(external_worker, monkeypatch):
    w = external_worker
    scope_reconciliation(monkeypatch, w["org_id"])
    assert post(w, "observe", sample(w, fixture="vulnerable")).status_code == 200
    with transaction(org_id=w["org_id"]) as session:
        session.get(Lease, UUID(w["lease"]["lease_id"])).lease_expires = now() - timedelta(
            seconds=1
        )
    assert post(w, "observe", sample(w, index=1)).status_code == 403
    reconciled = maintenance.reconcile_runs()
    assert str(w["run_id"]) in reconciled["timed_out"] and not reconciled["retried_unclaimed"]
    result = view(w)
    assert result["security_verdict"] == "FAIL" and result["execution_status"] == "TIMEOUT"
    assert result["release_action"] == "BLOCK" and not result["fix_eligible"]
    assert w["worker"].post("/v1/claim", json=w["claim"]).status_code in (403, 409)


def test_late_error_recovers_once_after_finalization_crash(external_worker, monkeypatch):
    w = external_worker
    scope_reconciliation(monkeypatch, w["org_id"])
    assert post(w, "observe", sample(w, fixture="vulnerable")).status_code == 200
    finish = api.finish_run
    monkeypatch.setattr(api, "finish_run", lambda *_: None)
    assert post(w, "fail").status_code == 200
    assert view(w)["security_verdict"] == "FAIL" and view(w)["status"] == "RUNNING"
    monkeypatch.setattr(api, "finish_run", finish)
    assert str(w["run_id"]) in maintenance.reconcile_runs()["recovered"]
    assert not maintenance.reconcile_runs()["recovered"]
    result = view(w)
    assert result["security_verdict"] == "FAIL" and result["execution_status"] == "ERROR"
    assert result["release_action"] == "BLOCK" and not result["fix_eligible"]
    with transaction(org_id=w["org_id"]) as session:
        results = list(
            session.scalars(
                select(Record).where(
                    Record.kind == "result",
                    Record.payload["capture_ids"].contains(result["capture_ids"]),
                )
            )
        )
        assert len(results) == 1
        assert session.get(Account, w["org_id"]).reserved == 0


def test_capture_endpoint_cannot_read_a_different_run_or_tenant(external_worker):
    w = external_worker
    response = post(w, "observe", sample(w))
    capture_id = response.json()["capture_id"]
    assert w["owner"].get(f"/v1/runs/{uuid4()}/captures/{capture_id}").status_code == 404
    other_run = execute(w["h"], w["observer"])
    assert w["owner"].get(f"/v1/runs/{other_run['id']}/captures/{capture_id}").status_code == 404
    with TestClient(api.app) as other:
        other.cookies.set("tv_session", str(uuid4()))
        login = other.post(
            "/v1/auth/local",
            json={"email": f"{uuid4()}@local.invalid"},
            headers={"origin": "http://127.0.0.1:3000"},
        )
        assert login.status_code == 200
        assert other.get(f"/v1/runs/{w['run_id']}/captures/{capture_id}").status_code == 404


def test_broker_rejects_oversized_capture_before_json_or_identity_parsing(external_worker):
    w = external_worker
    response = w["worker"].post(
        "/v1/observe",
        content=b"x" * 2_000_001,
        headers={"authorization": "Bearer invalid", "content-type": "application/json"},
    )
    assert response.status_code == 413
    with transaction(org_id=w["org_id"]) as session:
        assert not captured_trials(session, w["org_id"], w["run_id"])


def test_complete_requires_every_durable_slot_and_reconstructs_without_worker_verdicts(
    external_worker,
):
    w = external_worker
    assert post(w, "complete").status_code == 422
    first = sample(w)
    first["evaluation"] = {"security_verdict": "FAIL", "task_outcome": "FAILURE"}
    assert post(w, "observe", first).status_code == 200
    assert post(w, "complete").status_code == 422
    assert view(w)["status"] == "RUNNING"
    assert post(w, "observe", sample(w, index=1)).status_code == 200
    response = post(w, "complete")
    assert response.status_code == 200, response.text
    result = view(w)
    assert result["security_verdict"] == "PASS" and result["candidate_observed"]
    assert result["fix_eligible"] and result["release_action"] == "ALLOW"
    assert len(result["capture_ids"]) == 2
    assert post(w, "observe", sample(w, index=1)).status_code == 403


def test_completion_cannot_replace_durable_observation_bodies(external_worker):
    w = external_worker
    assert post(w, "observe", sample(w, fixture="vulnerable")).status_code == 200
    assert post(w, "observe", sample(w, index=1)).status_code == 200
    replacement = {
        "observations": [sample(w), sample(w, index=1)],
        "result": {"security_verdict": "PASS", "fix_eligible": True},
    }
    assert post(w, "complete", replacement).status_code == 422
    assert view(w)["status"] == "RUNNING" and view(w)["security_verdict"] == "FAIL"
    response = post(w, "complete")
    assert response.status_code == 200, response.text
    assert view(w)["security_verdict"] == "FAIL" and view(w)["release_action"] == "BLOCK"


def test_altered_raw_storage_cannot_restore_a_passing_release(external_worker):
    from threatveil.config import settings

    w = external_worker
    assert post(w, "observe", sample(w, fixture="vulnerable")).status_code == 200
    assert post(w, "observe", sample(w, index=1)).status_code == 200
    with transaction(org_id=w["org_id"]) as session:
        reference = captured_trials(session, w["org_id"], w["run_id"])[0].payload["raw_evidence"]
    path = settings().evidence_dir / reference["key"]
    original = path.read_bytes()
    try:
        path.write_bytes(b'{"security_verdict":"PASS"}')
        with TestClient(broker.app, raise_server_exceptions=False) as worker:
            response = worker.post("/v1/complete", json=signed(w["lease"], w["key"], "complete"),
                headers={"authorization": "Bearer " + broker.local_identity_token()})
        assert response.status_code >= 400
        assert view(w)["security_verdict"] == "FAIL" and view(w)["release_action"] == "BLOCK"
        assert post(w, "fail").status_code == 200
        result = view(w)
        assert result["security_verdict"] == "FAIL" and result["execution_status"] == "ERROR"
        assert result["release_action"] == "BLOCK" and not result["fix_eligible"]
    finally:
        path.write_bytes(original)


def test_fresh_capture_remains_valid_when_final_evaluation_happens_minutes_later(
    external_worker, monkeypatch
):
    from threatveil.core import evaluation

    w = external_worker
    assert post(w, "observe", sample(w)).status_code == 200
    assert post(w, "observe", sample(w, index=1)).status_code == 200
    future = now() + timedelta(minutes=5)
    monkeypatch.setattr(evaluation, "utcnow", lambda: future)
    response = post(w, "complete")
    assert response.status_code == 200, response.text
    result = view(w)
    assert result["security_verdict"] == "PASS" and result["fix_eligible"]


def test_stale_at_capture_does_not_become_fresh_at_completion(external_worker):
    w = external_worker
    row = sample(w)
    obs = Observation.model_validate(row["observation"])
    obs = obs.model_copy(
        update={
            "witnesses": tuple(
                r.model_copy(update={"observed_at": r.observed_at - timedelta(minutes=5)})
                for r in obs.witnesses
            ),
            "receipts": tuple(
                r.model_copy(update={"observed_at": r.observed_at - timedelta(minutes=5)})
                for r in obs.receipts
            ),
        }
    )
    keys = w["h"][4]
    row["observation"] = sign_observation(
        sign_observation(obs, keys[0]), keys[1], "ground_truth"
    ).model_dump(mode="json")
    response = post(w, "observe", row)
    assert response.status_code == 200 and response.json()["security_verdict"] == "INCONCLUSIVE"
    assert post(w, "observe", sample(w, index=1)).status_code == 200
    assert post(w, "complete").status_code == 200
    result = view(w)
    assert result["security_verdict"] == "INCONCLUSIVE" and not result["fix_eligible"]
    assert result["release_action"] == "BLOCK"


def test_capture_budget_stops_before_another_trial_without_erasing_failure(
    external_worker, monkeypatch
):
    from threatveil import captures

    w = external_worker
    assert post(w, "observe", sample(w, fixture="vulnerable")).status_code == 200
    monkeypatch.setattr(captures, "MAX_RUN_CAPTURE_BYTES", captures.MAX_CAPTURE_BYTES)
    assert post(w, "renew").status_code == 413
    assert post(w, "observe", sample(w, index=1)).status_code == 413
    assert post(w, "fail").status_code == 200
    result = view(w)
    assert result["security_verdict"] == "FAIL" and result["release_action"] == "BLOCK"
    assert result["execution_status"] == "ERROR" and len(result["capture_ids"]) == 1


def test_completed_result_references_raw_objects_without_duplicate_payloads(external_worker):
    w = external_worker
    for index in range(2):
        assert post(w, "observe", sample(w, index=index)).status_code == 200
    assert post(w, "complete").status_code == 200
    result = view(w)
    assert len(result["evidence"]["capture_ids"]) == 2
    assert "observations" not in result["evidence"]
    assert all("observation" not in trial and trial["capture_id"] for trial in result["trials"])
    with transaction(org_id=w["org_id"]) as session:
        for record in captured_trials(session, w["org_id"], w["run_id"]):
            assert "observation" not in record.payload
            assert record.payload["raw_evidence"]["sha256"]
