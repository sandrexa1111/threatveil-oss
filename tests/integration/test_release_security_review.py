"""Independent regression tests for candidate trust-boundary review findings."""

from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import timedelta
from threading import Event

import pytest

from threatveil import targets
from threatveil import release_integrity, release_signing
from threatveil.core.contracts import Observation, SystemFingerprint, digest
from threatveil.sdk.signing import sign_observation

from test_product import customer as customer, run, setup
from test_release_integrity import plan_for, release
from test_observers import observer_customer as observer_customer, qualify, execute


def test_reviewed_synthetic_proof_cannot_authorize_arbitrary_git_candidate(customer):
    d = setup(customer)
    fixed = run(customer, d, "fixed")
    reviewed = customer.post(
        "/v1/proof-scopes",
        json={
            "run_id": fixed["id"],
            "scope": {
                "coverage": "REVIEWED_DEPENDENCIES",
                "authority": "HUMAN_REVIEWED",
                "review_reason": "This test reviews unchanged ledger and authorization dependencies",
                "bindings": [
                    {"component": "tool:erp.beneficiary"},
                    {"component": "permissions:finance-approval"},
                ],
            },
        },
    )
    assert reviewed.status_code == 201, reviewed.text
    forged = deepcopy(fixed)
    forged["candidate"] = {
        "type": "git_commit",
        "id": "123456",
        "version": "a" * 40,
        "digest": "a" * 40,
    }
    for component in forged["fingerprint"]["components"]:
        if component["type"] == "application":
            component["version"] = "a" * 40
            component["provenance"] = "DECLARED"
    result = release(customer, plan_for(customer, d, forged))
    assert result["release_action"] == "BLOCK", (
        "Synthetic evidence must not authorize a Git candidate without a qualified current identity witness"
    )


def test_new_version_label_cannot_erase_failure_of_same_signed_content(
    observer_customer, monkeypatch
):
    h = observer_customer
    endpoint = targets.bounded_request
    content_digest = digest("one-identical-deployed-application-binary")

    def observed_content(*args, **kwargs):
        response = endpoint(*args, **kwargs)
        obs = Observation.model_validate_json(response["body"])
        fingerprint = obs.fingerprint.model_dump(mode="json")
        fingerprint["components"][0]["digest"] = content_digest
        fingerprint["components"] += [
            {
                "type": "tool",
                "id": "erp.beneficiary",
                "digest": digest("stable-tool"),
                "provenance": "OBSERVED",
            },
            {
                "type": "permissions",
                "id": "finance-approval",
                "digest": digest("stable-policy"),
                "provenance": "OBSERVED",
            },
        ]
        obs = obs.model_copy(update={"fingerprint": SystemFingerprint.model_validate(fingerprint)})
        obs = sign_observation(sign_observation(obs, h[4][0]), h[4][1], "ground_truth")
        return {**response, "body": obs.model_dump_json().encode()}

    monkeypatch.setattr(targets, "bounded_request", observed_content)
    observer = qualify(h)

    def observed_run(version, fixture):
        return execute(
            h,
            observer,
            fixture,
            candidate=version,
            overrides={
                "candidate": {
                    "type": "application_version",
                    "id": h[1]["system"]["id"],
                    "version": version,
                    "digest": content_digest,
                },
            },
        )

    failed = observed_run("release-v1", "vulnerable")
    assert failed["security_verdict"] == "FAIL" and failed["candidate_observed"]
    retry = observed_run("release-v1-alias", "fixed")
    assert retry["security_verdict"] == "PASS" and retry["candidate_observed"]
    candidate_plan = plan_for(h[0], h[1], retry, trials_per_variant=1)
    decision = release(h[0], candidate_plan)
    assert decision["release_action"] == "BLOCK", (
        "Changing a version label must not clear confirmed failure for the same signed content and tool/policy state"
    )


def test_target_revocation_serializes_with_receipt_generation(customer, monkeypatch):
    d = setup(customer)
    candidate_plan = plan_for(customer, d, run(customer, d, "fixed"))
    signing_started, continue_signing, revocation_requested = Event(), Event(), Event()
    real_sign, real_lock = release_signing.sign_decision, release_integrity.lock_system

    def pause_at_signing(decision):
        signing_started.set()
        assert continue_signing.wait(5), "Test did not resume receipt signing"
        return real_sign(decision)

    def observed_lock(*args):
        if signing_started.is_set() and not continue_signing.is_set():
            revocation_requested.set()
        return real_lock(*args)

    monkeypatch.setattr(release_signing, "sign_decision", pause_at_signing)
    monkeypatch.setattr(release_integrity, "lock_system", observed_lock)
    with ThreadPoolExecutor(max_workers=2) as pool:
        deciding = pool.submit(release, customer, candidate_plan)
        assert signing_started.wait(5)
        revoking = pool.submit(customer.post, f"/v1/targets/{d['target']['id']}/revoke")
        try:
            assert revocation_requested.wait(5)
            with pytest.raises(TimeoutError):
                revoking.result(timeout=0.1)
        finally:
            continue_signing.set()
        decision = deciding.result(timeout=5)
        assert decision["release_action"] == "ALLOW"
        assert revoking.result(timeout=5).status_code == 200
    current = customer.get(f"/v1/releases/{decision['id']}").json()
    assert current["release_action"] == "ALLOW" and current["current"]["release_action"] == "BLOCK"


def test_scope_rereview_does_not_refresh_expired_evidence(customer, monkeypatch):
    d = setup(customer)
    fixed = run(customer, d, "fixed")
    first = release(customer, plan_for(customer, d, fixed))
    assert first["release_action"] == "ALLOW"
    later = release_integrity.now() + timedelta(hours=25)
    monkeypatch.setattr(release_integrity, "now", lambda: later)
    current = customer.get(f"/v1/releases/{first['id']}").json()
    assert current["current"]["release_action"] == "BLOCK"
    reviewed = customer.post(
        "/v1/proof-scopes",
        json={
            "run_id": fixed["id"],
            "scope": {
                "coverage": "FULL_FINGERPRINT",
                "authority": "HUMAN_REVIEWED",
                "review_reason": "A scope review cannot create fresh evidence from an expired result",
            },
        },
    )
    assert reviewed.status_code == 201, reviewed.text
    subsequent = release(customer, plan_for(customer, d, fixed))
    assert subsequent["release_action"] == "BLOCK"
