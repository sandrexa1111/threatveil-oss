import copy
from datetime import timedelta

import pytest
from pydantic import ValidationError

from threatveil.core import (
    analyze_change,
    canonical_property,
    evaluate_trace,
    compare_runs,
    run_procurement,
    suggest_templates,
    templates,
)
from threatveil.core.contracts import (
    Candidate,
    FingerprintComponent,
    PropertyDefinition,
    ReproductionCapsule,
    SystemFingerprint,
)
from threatveil.core.procurement import SINK, _trial, qualify_procurement_witness
from threatveil.core.statistics import binomial_interval, newcombe_difference
from threatveil.core.variants import bounded_variants


@pytest.mark.parametrize(
    "version,security,task,eligible",
    [
        ("vulnerable", "FAIL", "SUCCESS", False),
        ("fixed", "PASS", "SUCCESS", True),
        ("regressed", "FAIL", "SUCCESS", False),
        ("missing_witness", "INCONCLUSIVE", "UNKNOWN", False),
        ("bad_fix", "PASS", "FAILURE", False),
    ],
)
def test_real_procurement_loop(version, security, task, eligible):
    result = run_procurement(version, trials=2, variant_count=2)
    assert result["security_verdict"] == security
    assert result["task_outcome"] == task
    assert result["fix_eligible"] is eligible
    assert result["release_action"] == ("ALLOW" if eligible else "BLOCK")
    assert result["trial_count"] == 4
    assert len({t["observation"]["correlation_id"] for t in result["trials"]}) == 4
    if security == "FAIL":
        receipt = result["trials"][0]["observation"]["receipts"][0]
        assert receipt["action"]["after"]["account"] == "SYNTHETIC-ATTACKER-ACCOUNT"
        assert receipt["action"]["before"]["account"] == "SYNTHETIC-ORIGINAL-ACCOUNT"
        assert receipt["action"]["phase"] == "COMMITTED"


def test_history_uses_same_property_digest():
    original, fixed, regression = (
        run_procurement(v, trials=1) for v in ("vulnerable", "fixed", "regressed")
    )
    assert original["property_digest"] == fixed["property_digest"] == regression["property_digest"]
    assert original["fingerprint"] != fixed["fingerprint"] != regression["fingerprint"]


def test_compatible_fix_and_regression_do_not_need_statistical_significance():
    fixed = run_procurement("fixed", trials=1)
    regressed = run_procurement("regressed", trials=1)
    comparison = compare_runs(fixed, regressed)
    assert comparison["compatible"]
    assert comparison["regression"]
    assert comparison["classification"] == "DETERMINISTIC_RECURRENCE"
    assert comparison["comparisons"][0]["lower"] < 0.05
    assert comparison["release_action"] == "BLOCK"


def test_incompatible_protocol_or_useless_fix_cannot_be_baseline():
    fixed = run_procurement("fixed", trials=1)
    different_protocol = run_procurement("regressed", trials=2)
    assert not compare_runs(fixed, different_protocol)["compatible"]
    bad_fix = run_procurement("bad_fix", trials=1)
    assert not compare_runs(bad_fix, run_procurement("regressed", trials=1))["compatible"]


def test_witness_cannot_self_qualify():
    observation = _trial("fixed", bounded_variants()[0])
    result = evaluate_trace(canonical_property(), observation)
    assert result["security_verdict"] == "INCONCLUSIVE"
    assert not result["fix_eligible"]


def test_qualified_violations_override_incomplete_evidence():
    observation = _trial("vulnerable", bounded_variants()[0])
    witness = observation.witnesses[0].model_copy(update={"complete": False})
    observation = observation.model_copy(
        update={"witnesses": (witness,), "execution_status": "ERROR"}
    )
    result = evaluate_trace(canonical_property(), observation, qualified_witnesses=(SINK,))
    assert result["security_verdict"] == "FAIL"
    assert result["coverage_complete"] is False
    assert result["execution_status"] == "ERROR"


@pytest.mark.parametrize(
    "mutation", ["mocked", "old", "wrong_correlation", "wrong_version", "duplicate"]
)
def test_observation_integrity_gaps_never_pass(mutation):
    observation = _trial("fixed", bounded_variants()[0])
    if mutation == "mocked":
        observation = observation.model_copy(update={"boundary_mocked": True})
    elif mutation == "old":
        witness = observation.witnesses[0]
        witness = witness.model_copy(
            update={"observed_at": witness.observed_at - timedelta(hours=1)}
        )
        observation = observation.model_copy(update={"witnesses": (witness,)})
    elif mutation == "wrong_correlation":
        observation = observation.model_copy(update={"correlation_id": "unrelated-run"})
    elif mutation == "wrong_version":
        witness = observation.witnesses[0].model_copy(update={"source_version": "unknown-version"})
        observation = observation.model_copy(update={"witnesses": (witness,)})
    else:
        observation = observation.model_copy(
            update={"receipts": observation.receipts + observation.receipts}
        )
    result = evaluate_trace(canonical_property(), observation, qualified_witnesses=(SINK,))
    assert result["security_verdict"] == "INCONCLUSIVE"


def test_model_claim_cannot_become_authoritative_state():
    observation = _trial("vulnerable", bounded_variants()[0])
    witness = observation.witnesses[0].model_copy(update={"authority": "SELF_REPORTED"})
    observation = observation.model_copy(update={"witnesses": (witness,)})
    assert (
        evaluate_trace(canonical_property(), observation, qualified_witnesses=(SINK,))[
            "security_verdict"
        ]
        == "INCONCLUSIVE"
    )


def test_approval_string_is_not_approval_proof():
    observation = _trial("vulnerable", bounded_variants()[0])
    receipt = observation.receipts[0]
    action = receipt.action.model_copy(
        update={"approval_id": "attacker-invented", "approval_valid": False}
    )
    receipt = receipt.model_copy(update={"action": action})
    observation = observation.model_copy(update={"receipts": (receipt,) + observation.receipts[1:]})
    assert (
        evaluate_trace(canonical_property(), observation, qualified_witnesses=(SINK,))[
            "security_verdict"
        ]
        == "FAIL"
    )


def test_missing_mandatory_predicate_fields_cannot_pass():
    observation = _trial("fixed", bounded_variants()[0])
    receipt = observation.receipts[1]
    receipt = receipt.model_copy(
        update={"action": receipt.action.model_copy(update={"approval_valid": None})}
    )
    observation = observation.model_copy(update={"receipts": (observation.receipts[0], receipt)})
    assert (
        evaluate_trace(canonical_property(), observation, qualified_witnesses=(SINK,))[
            "security_verdict"
        ]
        == "INCONCLUSIVE"
    )


def test_sequence_gaps_and_changed_qualified_source_version_invalidate_pass():
    observation = _trial("fixed", bounded_variants()[0])
    gap = observation.receipts[1].model_copy(update={"sequence": 2})
    broken = observation.model_copy(update={"receipts": (observation.receipts[0], gap)})
    assert (
        evaluate_trace(canonical_property(), broken, qualified_witnesses=(SINK,))[
            "security_verdict"
        ]
        == "INCONCLUSIVE"
    )
    assert (
        evaluate_trace(
            canonical_property(),
            observation,
            qualified_witnesses={SINK: "different-qualified-version"},
        )["security_verdict"]
        == "INCONCLUSIVE"
    )


def test_fabricated_task_label_does_not_verify_disabled_fix():
    observation = _trial("bad_fix", bounded_variants()[0]).model_copy(
        update={"task_outcome": "SUCCESS"}
    )
    result = evaluate_trace(canonical_property(), observation, qualified_witnesses=(SINK,))
    assert result["task_outcome"] == "FAILURE"
    assert not result["fix_eligible"]


def test_required_operation_gap_and_empty_evaluator_rejected():
    prop = copy.deepcopy(canonical_property())
    prop["predicates"] = []
    with pytest.raises(ValidationError):
        PropertyDefinition.model_validate(prop)
    prop = canonical_property()
    prop["observation_contract"]["required_operations"].append("missing.operation")
    assert run_procurement("fixed", prop, trials=1)["security_verdict"] == "INCONCLUSIVE"


def test_qualification_and_bounds():
    assert qualify_procurement_witness()["qualified"]
    for kwargs in ({"trials": 0}, {"trials": 101}, {"variant_count": 6}):
        with pytest.raises(ValidationError):
            run_procurement("fixed", **kwargs)
    with pytest.raises(ValueError):
        run_procurement("unimplemented")
    assert bounded_variants(5) == bounded_variants(5)


def test_exact_binomial_and_independent_newcombe():
    zero = binomial_interval(0, 100)
    assert zero["rate"] == zero["lower"] == 0
    assert 0.035 < zero["upper"] < 0.037
    comparison = newcombe_difference(20, 100, 0, 100)
    reverse = newcombe_difference(0, 100, 20, 100)
    assert 0 < comparison["lower"] < comparison["difference"] < comparison["upper"]
    assert comparison["lower"] == pytest.approx(-reverse["upper"])
    adjusted = newcombe_difference(20, 100, 0, 100, comparisons=5)
    assert adjusted["lower"] < comparison["lower"]
    with pytest.raises(ValueError):
        newcombe_difference(1, 5, 0, 5, independent=False)
    with pytest.raises(ValueError):
        binomial_interval(0, 0)


def test_templates_are_distinct_validated_binding_proposals():
    library = templates()
    assert len(library) == len({p["id"] for p in library}) == 20
    for template in library:
        PropertyDefinition.model_validate(template["definition"])
        assert template["status"] == "REQUIRES_SYSTEM_BINDING"
    suggestions = suggest_templates(["payments"], ["transfer"])
    assert "payment-authorization" in [s["id"] for s in suggestions["recommendations"]]
    assert not suggest_templates([], [])["recommendations"]


def test_change_selection_unknowns_and_physical_extension():
    before = {
        "components": [
            {"type": "tool", "id": "erp.beneficiary", "version": "1", "provenance": "OBSERVED"}
        ]
    }
    after = copy.deepcopy(before)
    after["components"][0]["version"] = "2"
    result = analyze_change(before, after, [canonical_property()])
    assert result["selected_property_ids"] == [canonical_property()["id"]]
    assert not analyze_change(before, before, [canonical_property()])["selected"]
    physical = {
        "components": [
            {"type": "sensor_calibration", "id": "lidar", "version": "2", "provenance": "DECLARED"}
        ]
    }
    assert analyze_change(before, physical, [canonical_property()])["unknowns"]
    assert analyze_change(before, {}, [canonical_property()])["selected"]
    SystemFingerprint.model_validate(physical)
    Candidate(type="autonomy_policy", id="robot-policy", version="future", digest="demo")
    with pytest.raises(ValidationError):
        SystemFingerprint(components=(FingerprintComponent(type="tool", id="x"),) * 2)


def test_physical_execution_never_enabled_by_contract():
    capsule = ReproductionCapsule.model_validate(run_procurement("fixed", trials=1)["capsule"])
    for execution_class in (
        "SIMULATION",
        "HARDWARE_IN_THE_LOOP",
        "CONTROLLED_PHYSICAL_TEST",
        "PRODUCTION_OBSERVATION",
    ):
        with pytest.raises(ValueError):
            capsule.model_copy(
                update={"execution_class": execution_class}
            ).ensure_launch_supported()
