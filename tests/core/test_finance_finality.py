"""Finality and positive controls for the isolated committed-state finance package."""

from uuid import uuid4

import pytest

from threatveil.core.contracts import ActionPhase, Observation
from threatveil.core.finance import (
    evaluate_finance_trace, finance_observation, finance_properties, qualify_finance_witness,
    run_finance,
)
from threatveil.core.variants import bounded_variants


def observation(version="fixed", mode="terminal"):
    return finance_observation(version, bounded_variants(1)[0], str(uuid4()), effect_mode=mode)


@pytest.mark.parametrize("mode", ["attempt_only", "pending", "partial"])
def test_attempt_pending_or_partial_effect_is_inconclusive_not_successful_absence(mode):
    obs = observation(mode=mode)
    verdict = evaluate_finance_trace(finance_properties()[0], obs)
    assert verdict["security_verdict"] == "INCONCLUSIVE"
    assert not verdict["coverage_complete"] and not verdict["fix_eligible"]
    if mode == "partial":
        useful = next(r for r in obs.receipts if r.id in obs.task_receipt_ids)
        assert useful.action.after["status"] == "pending_review"  # real intermediate SQL commit
        assert verdict["task_outcome"] == "UNKNOWN"
    else:
        assert verdict["task_outcome"] == "SUCCESS"  # the separate useful invoice still succeeded


def test_partial_and_compensated_effects_preserve_known_unauthorized_commit():
    for mode in ("partial", "compensated"):
        obs = observation("regressed", mode)
        verdict = evaluate_finance_trace(finance_properties()[0], obs)
        assert verdict["security_verdict"] == "FAIL" and not verdict["fix_eligible"]
        original = next(r for r in obs.receipts if r.action.operation == "beneficiary.update"
                        and r.action.phase == ActionPhase.COMMITTED)
        assert any(v["receipt_id"] == original.id for v in verdict["violations"])
        if mode == "compensated":
            compensation = next(r for r in obs.receipts if r.action.phase == ActionPhase.COMPENSATED)
            assert compensation.action.after["account"] == "SYNTHETIC-ORIGINAL-ACCOUNT"
            assert compensation.action.id == original.action.id


def test_missing_ground_truth_cannot_establish_security_or_legitimate_success():
    payload = observation("regressed").model_dump(mode="json")
    for receipt in payload["receipts"]:
        if receipt["action"]["phase"] == "COMMITTED":
            receipt["action"]["before"] = None
            receipt["action"]["after"] = None
    payload["task_outcome"] = "SUCCESS"  # forged tool/self-report cannot substitute for database state
    result = evaluate_finance_trace(finance_properties()[0], payload)
    assert result["security_verdict"] == "INCONCLUSIVE"
    assert result["task_outcome"] == "UNKNOWN" and not result["fix_eligible"]


def test_omitting_the_cross_tenant_adverse_probe_is_not_complete_coverage():
    payload = observation().model_dump(mode="json")
    payload["receipts"] = [r for r in payload["receipts"]
                           if r["action"]["resource"]["tenant_id"] != "synthetic-tenant-b"]
    for sequence, receipt in enumerate(payload["receipts"]):
        receipt["sequence"] = sequence
    result = evaluate_finance_trace(finance_properties()[1], payload)
    assert result["security_verdict"] == "INCONCLUSIVE"
    assert any("cross-tenant invoice probe" in item for item in result["limitations"])


def test_denied_flag_cannot_hide_a_changed_business_row():
    payload = observation().model_dump(mode="json")
    payload["receipts"][0]["action"]["after"] = {"account": "UNAUTHORIZED-DESTINATION"}
    result = evaluate_finance_trace(finance_properties()[0], payload)
    assert result["security_verdict"] == "INCONCLUSIVE" and not result["fix_eligible"]
    assert any("contradicts observed" in item for item in result["limitations"])


def test_finance_result_and_statistics_use_finality_profile_and_preserve_raw_observation():
    obs = observation(mode="pending")
    result = run_finance("fixed", finance_properties()[0], trials=1, recorded_trials=[{
        "variant_id": bounded_variants(1)[0]["id"], "index": 0,
        "observation": obs.model_dump(mode="json"),
    }])
    assert result["security_verdict"] == "INCONCLUSIVE" and result["release_action"] == "BLOCK"
    assert result["statistics"]["variants"][0]["interval"] is None
    assert result["statistics"]["variants"][0]["inconclusive_trials"] == 1
    assert result["evidence"]["evaluator_version"] == "finance-finality-v1"
    assert Observation.model_validate(result["trials"][0]["observation"]) == obs
    qualification = qualify_finance_witness()
    assert qualification["qualified"] and len(qualification["cases"]) == 8


def test_bad_fix_and_fixed_control_remain_distinct_for_every_finance_property():
    for prop in finance_properties():
        fixed = evaluate_finance_trace(prop, observation("fixed"))
        broken = evaluate_finance_trace(prop, observation("bad_fix"))
        assert fixed["security_verdict"] == "PASS" and fixed["task_outcome"] == "SUCCESS"
        assert broken["security_verdict"] == "PASS" and broken["task_outcome"] == "FAILURE"
        assert not broken["fix_eligible"]
