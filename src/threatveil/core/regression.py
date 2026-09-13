"""Compatible historical comparison; no verdict inferred from candidate names."""

from .contracts import digest
from .statistics import newcombe_difference


def comparison_signature(run: dict) -> dict:
    capsule = run.get("capsule", {})
    evidence = run.get("evidence", {})
    qualification = run.get("qualification", {})
    variants = run.get("variants", [])
    statistics = run.get("statistics", {})
    return {
        "property": run.get("property_digest"),
        "evaluator": evidence.get("evaluator_version"),
        "experiment": evidence.get("experiment_digest"),
        "variants": [(v.get("id"), v.get("digest")) for v in variants],
        "boundary": capsule.get("boundary_under_test"),
        "mode": capsule.get("execution_class"),
        "fixtures": capsule.get("fixture_references"),
        "state": capsule.get("initial_state_digest"),
        "reset": capsule.get("reset_method"),
        "allowed_effects": capsule.get("allowed_effects"),
        "required_witnesses": capsule.get("required_witnesses"),
        "witness": (
            qualification.get("source_id"),
            qualification.get("source_version"),
            qualification.get("boundary"),
        ),
        "witness_binding": qualification.get("binding_digest"),
        "independent_resets": statistics.get("independent_resets"),
    }


def compare_runs(baseline: dict, candidate: dict, *, material_difference: float = 0.05) -> dict:
    if not 0 <= material_difference <= 1:
        raise ValueError("material_difference must be between 0 and 1")
    left, right = comparison_signature(baseline), comparison_signature(candidate)
    reasons = [f"Incompatible {key}" for key in left if left[key] != right[key]]
    if any(
        left[k] is None
        for k in ("property", "evaluator", "experiment", "boundary", "mode", "state")
    ):
        reasons.append("Baseline comparison metadata incomplete")
    if not baseline.get("fix_eligible") or baseline.get("security_verdict") != "PASS":
        reasons.append("Baseline is not a verified useful security fix")
    if baseline.get("task_outcome") != "SUCCESS":
        reasons.append("Baseline lacks successful legitimate task")
    if baseline.get("capsule", {}).get("mocked_boundaries"):
        reasons.append("Baseline contains mocked boundaries")
    if not baseline.get("qualification", {}).get("qualified"):
        reasons.append("Baseline witness was not qualified")
    if reasons:
        return {
            "compatible": False,
            "regression": False,
            "applicability": "INCOMPATIBLE",
            "reasons": reasons,
            "comparisons": [],
            "release_action": "WARN",
        }
    statistics = []
    baseline_variants = {v["variant_id"]: v for v in baseline["statistics"]["variants"]}
    candidate_variants = candidate["statistics"]["variants"]
    for variant in candidate_variants:
        old = baseline_variants.get(variant["variant_id"], {}).get("interval")
        new = variant.get("interval")
        if not old or not new or right["independent_resets"] is not True:
            continue
        comparison = newcombe_difference(
            new["failures"],
            new["usable_trials"],
            old["failures"],
            old["usable_trials"],
            comparisons=len(candidate_variants),
            independent=right["independent_resets"] is True,
        )
        statistics.append(
            {
                "variant_id": variant["variant_id"],
                **comparison,
                "material_degradation": comparison["lower"] > material_difference,
            }
        )
    deterministic = candidate.get("security_verdict") == "FAIL"
    degraded = any(s["material_degradation"] for s in statistics)
    return {
        "compatible": True,
        "regression": deterministic or degraded,
        "classification": "DETERMINISTIC_RECURRENCE"
        if deterministic
        else "STOCHASTIC_DEGRADATION"
        if degraded
        else "NO_CONFIRMED_REGRESSION",
        "applicability": "CURRENT",
        "comparisons": statistics,
        "material_difference": material_difference,
        "comparison_digest": digest(right),
        "release_action": candidate.get("release_action", "WARN"),
        "reasons": [
            "Same historical property and compatible experiment design; candidate fingerprint differs intentionally"
        ],
        "limitations": [
            "No confirmed regression is not proof of zero underlying risk.",
            *(
                []
                if right["independent_resets"] is True
                else [
                    "Stochastic comparison unavailable: independent trials have not been established."
                ]
            ),
        ],
    }
