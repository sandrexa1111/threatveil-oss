"""A sample PASS never clears retained failure evidence for the same artifact."""

from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from threading import Event, local
from uuid import UUID, uuid4

import httpx

from threatveil import api, evidence_storage, targets
from threatveil.adverse_memory import adverse_memory, capture_provenance, fingerprint_digest
from threatveil.captures import captured_trials
from threatveil.core.contracts import Observation, SystemFingerprint, digest
from threatveil.db import get_record, now, transaction
from threatveil.sdk.signing import sign_observation

from test_observers import create_fix, execute, observer_customer as observer_customer, qualify
from test_assurance import (
    canary_customer as canary_customer,
    candidate_run,
    create_canary,
    impact,
    selection_audit,
)
from test_captures import sample


def memory(h, run):
    org = UUID(h[1]["system"]["organization_id"])
    with transaction(org_id=org) as session:
        record = get_record(session, org, run["id"], "run")
        return adverse_memory(session, org, record, run)


def test_same_artifact_retry_remains_sample_pass_but_cannot_release_or_verify(observer_customer):
    h = observer_customer
    observer = qualify(h)
    failed = execute(h, observer, "vulnerable", candidate="same-build")
    retry = execute(h, observer, candidate="same-build")
    history = memory(h, retry)
    assert history["blocked"] and history["run_ids"] == [failed["id"]]
    assert history["capture_ids"] == failed["capture_ids"]
    assert retry["security_verdict"] == "PASS" and retry["candidate_observed"]
    assert retry["release_action"] == "BLOCK" and not retry["fix_eligible"]
    assert not create_fix(h, failed, retry)["verified"]
    changed = execute(h, observer, candidate="new-build")
    assert not memory(h, changed)["blocked"] and changed["fix_eligible"]
    assert create_fix(h, failed, changed)["verified"]


def test_changing_caller_candidate_label_or_stimulus_cannot_hide_failure(observer_customer):
    h = observer_customer
    observer = qualify(h)
    failed = execute(h, observer, "vulnerable", candidate="same-build")
    retry = execute(
        h,
        observer,
        candidate="same-build",
        overrides={
            "candidate": {**failed["candidate"], "id": str(uuid4())},
            "stimulus": {"path": "/test", "payload": {"document": "different challenge"}},
            "trials": 2,
        },
    )
    assert retry["candidate_observed"] and retry["security_verdict"] == "PASS"
    assert memory(h, retry)["run_ids"] == [failed["id"]]
    assert retry["release_action"] == "BLOCK" and not retry["fix_eligible"]


def test_interrupted_failure_blocks_retry_after_raw_retention_expiry(
    observer_customer, monkeypatch
):
    h = observer_customer
    observer = qualify(h)
    endpoint, calls = targets.bounded_request, []

    def interrupted(*args, **kwargs):
        calls.append(1)
        if len(calls) > 1:
            raise httpx.ReadTimeout("Controlled failure after durable first capture")
        return endpoint(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(targets, "bounded_request", interrupted)
        failed = execute(h, observer, "vulnerable", candidate="same-build", overrides={"trials": 2})
    assert failed["security_verdict"] == "FAIL" and failed["execution_status"] == "ERROR"
    org = UUID(h[1]["system"]["organization_id"])
    with transaction(org_id=org) as session:
        capture = captured_trials(session, org, UUID(failed["id"]))[0]
        assert capture.payload["provenance"]["qualified"]
        assert capture.payload["provenance"]["candidate_observed"]
        capture_id = str(capture.id)
        reference = capture.payload["raw_evidence"]
    with monkeypatch.context() as patch:
        future = now() + timedelta(days=31)
        patch.setattr(evidence_storage, "now", lambda: future)
        response = h[0].get(f"/v1/runs/{failed['id']}/captures/{capture_id}")
        assert response.status_code == 410
    (evidence_storage.settings().evidence_dir / reference["key"]).unlink()
    retry = execute(h, observer, candidate="same-build")
    assert retry["security_verdict"] == "PASS"
    assert memory(h, retry)["run_ids"] == [failed["id"]]
    assert retry["release_action"] == "BLOCK" and not retry["fix_eligible"]


def test_actual_observed_configuration_change_is_a_new_fix_candidate(
    observer_customer, monkeypatch
):
    h = observer_customer
    observer = qualify(h)
    failed = execute(h, observer, "vulnerable", candidate="same-build")
    endpoint = targets.bounded_request

    def new_prompt(*args, **kwargs):
        response = endpoint(*args, **kwargs)
        observation = Observation.model_validate_json(response["body"])
        fingerprint = observation.fingerprint.model_dump(mode="json")
        fingerprint["components"].append(
            {
                "type": "prompt",
                "id": "approval-policy",
                "version": "v2",
                "digest": digest("Require independently validated payment approval"),
                "provenance": "OBSERVED",
            }
        )
        observation = observation.model_copy(
            update={"fingerprint": SystemFingerprint.model_validate(fingerprint)}
        )
        observation = sign_observation(
            sign_observation(observation, h[4][0]), h[4][1], "ground_truth"
        )
        return {**response, "body": observation.model_dump_json().encode()}

    monkeypatch.setattr(targets, "bounded_request", new_prompt)
    changed = execute(h, observer, candidate="same-build")
    assert changed["candidate_observed"] and not memory(h, changed)["blocked"]
    assert changed["fix_eligible"] and create_fix(h, failed, changed)["verified"]


def test_caller_signed_but_unqualified_failure_does_not_poison_assurance(observer_customer):
    h = observer_customer
    control = execute(h, h[3], "vulnerable", case="KNOWN_PROHIBITED", candidate="same-build")
    assert control["security_verdict"] == "FAIL"
    observer = qualify(h)
    current = execute(h, observer, candidate="same-build")
    assert not memory(h, current)["blocked"] and current["fix_eligible"]
    org = UUID(h[1]["system"]["organization_id"])
    with transaction(org_id=org) as session:
        record = get_record(session, org, control["id"], "run")
        capture = captured_trials(session, org, UUID(control["id"]))[0]
        observation = evidence_storage.load_observation(
            org, record.id, capture.payload["raw_evidence"]
        )
        proof = capture_provenance(record.payload, observation)
        assert not proof["qualified"] and not proof["candidate_observed"]


def test_old_pass_cannot_be_selected_after_later_failure(canary_customer):
    h, observer, _ = canary_customer
    passing = candidate_run(canary_customer)
    initial = create_canary(canary_customer, passing).json()
    assert initial["snapshot"]["release_action"] == "ALLOW"
    failure = candidate_run(canary_customer, "regressed")
    fetched = h[0].get("/v1/canaries/" + initial["id"]).json()
    assert fetched["snapshot"] == initial["snapshot"]
    assert fetched["current"]["release_action"] == "BLOCK"
    row = fetched["current"]["rows"][0]
    assert row["classification"] == "UNKNOWN" and row["known_security_failure"]
    assert row["adverse_memory"]["run_ids"] == [failure["id"]]
    old = h[0].get("/v1/runs/" + passing["id"]).json()
    assert old["security_verdict"] == "PASS" and old["release_action"] == "BLOCK"
    assert not create_fix(h, failure, old)["verified"]


def test_selection_audit_cannot_choose_a_passing_retry_to_hide_excluded_failure(canary_customer):
    passing = candidate_run(canary_customer)
    selection = impact(canary_customer, passing)
    failure = candidate_run(canary_customer, "regressed")
    response = selection_audit(canary_customer, passing, selection)
    assert response.status_code == 201, response.text
    current = response.json()["current"]
    assert current["release_action"] == "BLOCK"
    assert current["missed_failure_property_ids"] == [passing["property_id"]]
    assert current["rows"][0]["classification"] == "FAILED"
    assert current["rows"][0]["adverse_memory"]["run_ids"] == [failure["id"]]


def test_fingerprint_order_and_provenance_labels_do_not_define_a_fix():
    first = {
        "components": [
            {
                "type": "application",
                "id": "agent",
                "version": "v1",
                "digest": "a" * 64,
                "provenance": "OBSERVED",
                "dependencies": ["z", "a"],
            },
            {
                "type": "prompt",
                "id": "policy",
                "version": "v1",
                "digest": "b" * 64,
                "provenance": "DECLARED",
            },
        ]
    }
    reordered = {
        "components": [
            {**first["components"][1], "provenance": "OBSERVED"},
            {**first["components"][0], "dependencies": ["a", "z", "a"]},
        ]
    }
    assert fingerprint_digest(first) == fingerprint_digest(reordered)
    reordered["components"][0]["digest"] = "c" * 64
    assert fingerprint_digest(first) != fingerprint_digest(reordered)


def test_failure_capture_commits_before_a_competing_passing_finalization(
    observer_customer, monkeypatch
):
    from threatveil import adverse_memory as history_module
    from threatveil.captures import evaluate_persisted, persist_capture
    from threatveil.db import RunState

    h = observer_customer
    observer = qualify(h)
    monkeypatch.setattr(api, "execute_run", lambda *_: None)
    passing = execute(h, observer, candidate="candidate-v1")
    failing = execute(h, observer, "vulnerable", candidate="candidate-v1")
    org = UUID(h[1]["system"]["organization_id"])
    passing_id, failing_id = UUID(passing["id"]), UUID(failing["id"])
    with transaction(org_id=org) as session:
        run = get_record(session, org, passing_id, "run")
        session.get(RunState, (org, passing_id)).status = "RUNNING"
        persist_capture(
            session, org, run, sample({"h": h, "observer": observer, "run_id": passing_id})
        )
        passing_result = evaluate_persisted(session, org, run)
    captured, attempted, release = Event(), Event(), Event()
    original_lock = history_module.lock_artifact_scope
    thread_context = local()

    def tracked_lock(session, org_id, plan):
        if getattr(thread_context, "finalizing", False):
            attempted.set()
        original_lock(session, org_id, plan)

    monkeypatch.setattr(history_module, "lock_artifact_scope", tracked_lock)

    def finalize():
        thread_context.finalizing = True
        api.finish_run(org, passing_id, passing_result)

    def delayed_failure_commit():
        with transaction(org_id=org) as session:
            run = get_record(session, org, failing_id, "run")
            persist_capture(
                session,
                org,
                run,
                sample({"h": h, "observer": observer, "run_id": failing_id}, fixture="vulnerable"),
            )
            captured.set()
            assert release.wait(10), "Test did not release the bounded capture transaction"

    with ThreadPoolExecutor(max_workers=2) as pool:
        failure_job = pool.submit(delayed_failure_commit)
        assert captured.wait(10)
        finish_job = pool.submit(finalize)
        try:
            assert attempted.wait(10)
            assert not finish_job.done(), (
                "Passing decision bypassed the in-flight artifact capture lock"
            )
        finally:
            release.set()
        failure_job.result(timeout=10)
        finish_job.result(timeout=10)
    result = h[0].get("/v1/runs/" + passing["id"]).json()
    assert result["security_verdict"] == "PASS" and result["historical_release_action"] == "BLOCK"
    assert result["adverse_memory"]["run_ids"] == [failing["id"]]
    assert not result["fix_eligible"]
