"""Shared bounded acquisition for local execution and isolated workers."""

import asyncio
from collections.abc import Mapping
from datetime import datetime

from .adapters.base import AdapterContext, Stimulus
from .adapters.http import HTTPAgentAdapter
from .adapters.mcp import MCPAdapter
from .adapters.openai_compatible import OpenAICompatibleAdapter
from .core.contracts import Observation, digest, trial_correlation
from .core.evaluation import evaluate_trace
from .targets import SafeTransport


def evaluate_acquisition(
    plan,
    observations,
    *,
    trusted_evaluation_times: Mapping[tuple[str, int], datetime] | None = None,
):
    """Only server-selected, cryptographically verified sources can supply assurance.

    Evaluation times must come from immutable control-plane capture records, never
    a submitted observation or worker payload. This preserves freshness decisions
    made at acquisition while a longer experiment finishes.
    """
    from .observers import bound_source, attestations_valid, observation_binding_digest
    from .core.contracts import PropertyDefinition, ExperimentPlan, SystemFingerprint
    from .core.statistics import binomial_interval

    prop = PropertyDefinition.model_validate(plan["property_definition"])
    experiment = ExperimentPlan(
        trials_per_variant=plan["trials"],
        variant_count=plan["variant_count"],
        independent_resets=False,
    )
    binding = plan.get("observation_binding") or {}
    expected_slots = (
        {("recorded", 0)}
        if plan.get("observation")
        else {
            (f"explicit-{variant}", index)
            for variant in range(plan["variant_count"])
            for index in range(plan["trials"])
        }
    )
    actual_slots = [(item.get("variant_id"), item.get("index")) for item in observations]
    valid_indices = all(
        isinstance(index, int) and not isinstance(index, bool) and isinstance(variant, str)
        for variant, index in actual_slots
    )
    coverage_complete = bool(
        valid_indices
        and len(actual_slots) == len(expected_slots)
        and set(actual_slots) == expected_slots
    )
    if plan.get("observation") and (plan["trials"] != 1 or plan["variant_count"] != 1):
        coverage_complete = False
    results, parsed = [], []
    attested = bool(binding and observations and coverage_complete)
    for item in observations:
        observation = Observation.model_validate(item["observation"])
        parsed.append(observation)
        attested = attested and attestations_valid(observation, binding)
        evaluated = evaluate_trace(
            prop,
            observation,
            qualified_witnesses=bound_source(plan, observation),
            now=(trusted_evaluation_times or {}).get((item["variant_id"], item["index"])),
        )
        results.append({**item, **evaluated})
    if len({obs.correlation_id for obs in parsed}) != len(parsed):
        coverage_complete, attested = False, False
    verdict = (
        "FAIL"
        if any(r["security_verdict"] == "FAIL" for r in results)
        else "INCONCLUSIVE"
        if not coverage_complete
        or not results
        or any(r["security_verdict"] == "INCONCLUSIVE" for r in results)
        else "PASS"
    )
    task = (
        "FAILURE"
        if any(r["task_outcome"] == "FAILURE" for r in results)
        else "UNKNOWN"
        if not results or any(r["task_outcome"] == "UNKNOWN" for r in results)
        else "SUCCESS"
    )
    qualified = bool(binding.get("approved") and attested)
    fingerprints = [o.fingerprint for o in parsed]
    same_fingerprint = bool(
        fingerprints and fingerprints[0] and all(f == fingerprints[0] for f in fingerprints)
    )
    fingerprint = fingerprints[0] if same_fingerprint else SystemFingerprint()
    from .adverse_memory import exact_observed_candidate

    exact_candidate = exact_observed_candidate(plan, fingerprint)
    candidate_observed = bool(qualified and coverage_complete and exact_candidate)
    variants, summaries = [], []
    stimuli = (plan.get("stimulus") or {}).get("variants") or [
        (plan.get("stimulus") or {}).get("payload", (plan.get("stimulus") or {}).get("body", {}))
    ]
    for index in range(plan["variant_count"]):
        variant_id = "recorded" if plan.get("observation") else f"explicit-{index}"
        variants.append(
            {"id": variant_id, "digest": digest(stimuli[index] if index < len(stimuli) else {})}
        )
        rows = [r for r in results if r["variant_id"] == variant_id]
        usable = [r for r in rows if r["security_verdict"] in {"PASS", "FAIL"}]
        failures = sum(r["security_verdict"] == "FAIL" for r in usable)
        # Report sample counts. Independence of model/provider behavior remains an explicit limitation.
        summaries.append(
            {
                "variant_id": variant_id,
                "planned_trials": plan["trials"],
                "completed_trials": len(rows),
                "inconclusive_trials": len(rows) - len(usable),
                "interval": binomial_interval(
                    failures, len(usable), 1 - (1 - experiment.confidence) / plan["variant_count"]
                )
                if usable and coverage_complete
                else None,
            }
        )
    capsule = {
        "boundary_under_test": prop.observation_contract.boundary,
        "execution_class": "DIGITAL_STAGING",
        "fixture_references": [binding.get("fixture_reference", "UNKNOWN")],
        "initial_state_digest": binding.get("initial_state_digest"),
        "reset_method": "Signed initial-state digest checked for every sample"
        if qualified
        else "UNQUALIFIED",
        "allowed_effects": [prop.observation_contract.boundary],
        "required_witnesses": list(prop.observation_contract.required_witnesses),
        "mocked_boundaries": [],
    }
    return {
        "security_verdict": verdict,
        "task_outcome": task,
        "execution_status": "COMPLETED",
        "trials": results,
        "trial_count": len(results),
        "coverage_complete": coverage_complete,
        "property_digest": digest(prop),
        "witness_attested": bool(attested),
        "candidate_observed": candidate_observed,
        "fingerprint": fingerprint.model_dump(mode="json"),
        "capsule": capsule,
        "variants": variants,
        "qualification": {
            "qualified": qualified,
            "source_id": binding.get("source_id"),
            "source_version": binding.get("source_version"),
            "boundary": prop.observation_contract.boundary,
            "qualification_id": binding.get("qualification_id"),
            "binding_digest": observation_binding_digest(binding) if binding else None,
        },
        "evidence": {
            "observations": observations,
            "evaluator_version": "deterministic-v1",
            "experiment_digest": digest(experiment),
        },
        "statistics": {"independent_resets": False, "pooled_rate": None, "variants": summaries},
        "limitations": [
            "Collector signatures and reviewed controls establish scoped provenance; they do not certify an uncompromised collector.",
            "Binomial intervals are descriptive under an independence assumption. Cross-trial independence is not established; stochastic degradation is not asserted.",
            "Unqualified sources or missing candidate fingerprints cannot establish a verified fix.",
            *(
                []
                if coverage_complete
                else [
                    "Frozen sample coverage is incomplete, duplicated or mismatched; no complete-sample conclusion is supported."
                ]
            ),
        ],
    }


async def acquire(
    target, plan, run_id, headers=None, before_trial=None, after_trial=None, *, retain=True
):
    if target["adapter"] == "structured_trace":
        return [{"variant_id": "recorded", "index": 0, "observation": plan["observation"]}]
    stimulus = plan["stimulus"]
    transport = SafeTransport(target, headers)
    endpoint = target["origin"].rstrip("/") + stimulus["path"]
    adapter = (
        MCPAdapter(transport, tuple(target["allowed_tools"]))
        if target["adapter"] == "mcp"
        else OpenAICompatibleAdapter(transport, target["model"])
        if target["adapter"] == "openai_compatible"
        else HTTPAgentAdapter(transport)
    )
    kind = {"http": "structured_input", "mcp": "tool_call", "openai_compatible": "chat_messages"}[
        target["adapter"]
    ]
    variants = stimulus.get("variants") or [stimulus.get("payload", stimulus.get("body", {}))]
    if len(variants) != plan["variant_count"]:
        raise ValueError("Each external variant requires an explicit frozen stimulus")
    captures = []
    for variant_index, payload in enumerate(variants):
        variant_id = f"explicit-{variant_index}"
        for index in range(plan["trials"]):
            if before_trial:
                await asyncio.to_thread(before_trial)
            correlation = trial_correlation(run_id, variant_id, index)
            await adapter.prepare(AdapterContext(endpoint, "DIGITAL_STAGING", correlation))
            try:
                await adapter.stimulate(
                    Stimulus(type=kind, payload=payload, correlation_id=correlation)
                )
                observation = await adapter.observe()
                if after_trial:
                    await asyncio.to_thread(
                        after_trial,
                        {
                            "variant_id": variant_id,
                            "index": index,
                            "observation": observation.model_dump(mode="json"),
                        },
                    )
                if retain:
                    captures.append(
                        {
                            "variant_id": variant_id,
                            "index": index,
                            "observation": observation.model_dump(mode="json"),
                        }
                    )
            finally:
                await adapter.cleanup()
    return captures
