import base64
from datetime import timedelta
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from threatveil.core import canonical_property
from threatveil.core.contracts import Observation, SystemFingerprint, digest
from threatveil.core.procurement import SINK, _trial
from threatveil.core.variants import bounded_variants
from threatveil.execution import evaluate_acquisition
from threatveil.observers import ObserverInput, attestations_valid
from threatveil.sdk.signing import sign_observation


def material(trials=1):
    keys = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
    binding = ObserverInput(system_id=uuid4(), property_id=uuid4(), target_id=uuid4(),
        source_id=SINK, source_version="sqlite-ledger-v1",
        candidate_component_id="customer-agent",
        public_key=base64.b64encode(keys[0].public_key().public_bytes_raw()).decode(),
        ground_truth_public_key=base64.b64encode(keys[1].public_key().public_bytes_raw()).decode(),
        initial_state_digest=digest({"account": "SYNTHETIC-ORIGINAL-ACCOUNT"}),
        fixture_reference="synthetic:vendor-1",
        independence_review="Synthetic test collectors; this is not customer evidence or independent deployment certification.").model_dump(mode="json")
    binding["approved"] = True
    plan = {"property_definition": canonical_property(), "observation_binding": binding,
            "version": "candidate-v1", "trials": trials, "variant_count": 1,
            "candidate": {"type": "application_version", "id": str(binding["system_id"]),
                          "version": "candidate-v1", "digest": digest("candidate-v1")},
            "stimulus": {"payload": {"invoice": "synthetic"}}}
    return keys, binding, plan


def capture(keys, binding, *, version="candidate-v1", candidate_digest=None, index=0):
    obs = _trial("fixed", bounded_variants()[0])
    obs = obs.model_copy(update={"initial_state_digest": binding["initial_state_digest"],
        "fingerprint": SystemFingerprint.model_validate({"components": [
            {"type": "application", "id": "customer-agent", "version": version,
             "digest": candidate_digest or digest(version), "provenance": "OBSERVED"}]})})
    obs = sign_observation(sign_observation(obs, keys[0]), keys[1], "ground_truth")
    return {"variant_id": "explicit-0", "index": index, "observation": obs.model_dump(mode="json")}


def test_distinct_public_key_strings_cannot_alias_one_private_key():
    _, binding, _ = material()
    canonical = binding["public_key"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    alternate = canonical[:-2] + alphabet[alphabet.index(canonical[-2])+1] + "="
    assert alternate != canonical
    assert base64.b64decode(alternate, validate=True) == base64.b64decode(canonical, validate=True)
    original = {k: v for k, v in binding.items() if k != "approved"}
    with pytest.raises(ValueError):
        ObserverInput.model_validate({**original, "ground_truth_public_key": alternate})


def test_attestations_bind_content_roles_and_both_collectors():
    keys, binding, _ = material()
    obs = capture(keys, binding)["observation"]
    assert attestations_valid(obs, binding)
    for mutation in ("correlation", "receipt", "fingerprint", "missing_role", "swapped_roles"):
        from copy import deepcopy
        changed = deepcopy(obs)
        if mutation == "correlation":
            changed["correlation_id"] = str(uuid4())
        elif mutation == "receipt":
            changed["receipts"][1]["action"]["after"]["account"] = "attacker-replacement"
        elif mutation == "fingerprint":
            changed["fingerprint"]["components"][0]["version"] = "other-candidate"
        elif mutation == "missing_role":
            changed["attestations"].pop("ground_truth")
        else:
            changed["attestations"]["ground_truth"] = changed["attestations"]["observer"]
        assert not attestations_valid(changed, binding)


def test_matching_version_with_wrong_signed_digest_is_not_the_candidate():
    keys, binding, plan = material()
    result = evaluate_acquisition(plan, [capture(keys, binding, candidate_digest=digest("different-build"))])
    assert result["security_verdict"] == "PASS"
    assert result["candidate_observed"] is False


@pytest.mark.parametrize("case", ["missing", "duplicate", "wrong_slot"])
def test_frozen_sample_coverage_cannot_be_satisfied_by_partial_or_duplicate_captures(case):
    keys, binding, plan = material(trials=2)
    rows = [capture(keys, binding)]
    if case == "duplicate":
        rows = rows * 2
    elif case == "wrong_slot":
        rows.append(capture(keys, binding, index=99))
    result = evaluate_acquisition(plan, rows)
    assert result["security_verdict"] == "INCONCLUSIVE"
    assert result["candidate_observed"] is False


def test_valid_but_stale_collector_signature_does_not_restore_fresh_evidence():
    keys, binding, plan = material()
    from threatveil.core.contracts import Observation
    row = capture(keys, binding)
    obs = Observation.model_validate(row["observation"])
    obs = obs.model_copy(update={
        "receipts": tuple(r.model_copy(update={"observed_at": r.observed_at-timedelta(hours=1)}) for r in obs.receipts),
        "witnesses": tuple(w.model_copy(update={"observed_at": w.observed_at-timedelta(hours=1)}) for w in obs.witnesses)})
    obs = sign_observation(sign_observation(obs, keys[0]), keys[1], "ground_truth")
    row["observation"] = obs.model_dump(mode="json")
    assert attestations_valid(obs, binding)
    assert evaluate_acquisition(plan, [row])["security_verdict"] == "INCONCLUSIVE"


def resign(row, keys, **updates):
    obs = Observation.model_validate(row["observation"]).model_copy(update=updates)
    obs = sign_observation(sign_observation(obs, keys[0]), keys[1], "ground_truth")
    return {**row, "observation": obs.model_dump(mode="json")}


@pytest.mark.parametrize("mutation", ["other_component", "declared", "missing_digest", "other_version", "no_candidate"])
def test_candidate_identity_requires_the_exact_observed_mapped_component(mutation):
    keys, binding, plan = material()
    row = capture(keys, binding)
    fingerprint = Observation.model_validate(row["observation"]).fingerprint
    component = fingerprint.components[0]
    if mutation == "other_component":
        component = component.model_copy(update={"id": "unrelated-agent"})
    elif mutation == "declared":
        component = component.model_copy(update={"provenance": "DECLARED"})
    elif mutation == "missing_digest":
        plan["candidate"].pop("digest")
    elif mutation == "other_version":
        component = component.model_copy(update={"version": "not-the-planned-version"})
    else:
        plan["candidate"] = None
    row = resign(row, keys, fingerprint=SystemFingerprint(components=(component,)))
    result = evaluate_acquisition(plan, [row])
    assert result["witness_attested"] and result["security_verdict"] == "PASS"
    assert result["candidate_observed"] is False


def test_identical_candidate_component_does_not_hide_different_sample_fingerprints():
    keys, binding, plan = material(trials=2)
    first, second = capture(keys, binding), capture(keys, binding, index=1)
    fingerprint = Observation.model_validate(second["observation"]).fingerprint
    second = resign(second, keys, fingerprint=SystemFingerprint.model_validate({"components": [
        *[component.model_dump(mode="json") for component in fingerprint.components],
        {"type": "permission", "id": "authorization", "version": "unexpected-policy-v2",
         "provenance": "OBSERVED", "digest": digest("changed-policy")},
    ]}))
    result = evaluate_acquisition(plan, [first, second])
    assert result["coverage_complete"] and result["witness_attested"]
    assert not result["candidate_observed"]


@pytest.mark.parametrize("mutation", [None, "unverified", "sha", "candidate_digest"])
def test_git_commit_content_identifier_requires_the_verified_workflow_binding(mutation):
    keys, binding, plan = material()
    sha = "abcdef0123456789" * 2 + "abcdef01"
    plan["version"] = sha
    plan["candidate"].update(type="git_commit", version=sha, digest=sha)
    plan["github"] = {"verified_workflow": True, "sha": sha}
    row = capture(keys, binding, version=sha, candidate_digest=digest({"commit": sha}))
    if mutation == "unverified":
        plan["github"]["verified_workflow"] = False
    elif mutation == "sha":
        plan["github"]["sha"] = "a" * 40
    elif mutation == "candidate_digest":
        plan["candidate"]["digest"] = "b" * 40
    result = evaluate_acquisition(plan, [row])
    assert result["candidate_observed"] is (mutation is None)


@pytest.mark.parametrize("scope", ["target_id", "property_id", "candidate_component_id", "public_key",
                                   "ground_truth_public_key", "source_version", "initial_state_digest"])
def test_changed_observer_scope_requires_a_new_historical_comparison(scope):
    from copy import deepcopy
    from threatveil.core.regression import compare_runs
    from threatveil.observers import observation_binding_digest
    keys, binding, plan = material()
    baseline = evaluate_acquisition(plan, [capture(keys, binding)])
    baseline["fix_eligible"] = True
    candidate = deepcopy(baseline)
    changed = {**binding, scope: str(uuid4())}
    candidate["qualification"]["binding_digest"] = observation_binding_digest(changed)
    result = compare_runs(baseline, candidate)
    assert not result["compatible"]
    assert "Incompatible witness_binding" in result["reasons"]


def test_recorded_capture_is_never_multiple_executions():
    keys, binding, plan = material(trials=2)
    row = {**capture(keys, binding), "variant_id": "recorded"}
    plan["observation"] = row["observation"]
    result = evaluate_acquisition(plan, [row])
    assert result["security_verdict"] == "INCONCLUSIVE"
    assert result["coverage_complete"] is False
