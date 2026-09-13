"""Evidence checks for a *proposed* witness qualification, never self-approval.

The control plane must resolve assignment, authorization, and ground-truth records
server-side before selecting ACTIVE_REGISTERED_TARGET. An imported trace cannot
become trusted by putting a source ID, mode, or expected result in its JSON.
"""

from typing import Literal

from pydantic import Field

from .contracts import Contract, Observation, PropertyDefinition, digest
from .evaluation import evaluate_trace


class QualificationChallenge(Contract):
    case: Literal["KNOWN_PERMITTED", "KNOWN_PROHIBITED", "MISSING_OBSERVATION"]
    observation: Observation
    assigned_run_id: str | None = None
    ground_truth_receipt_reference: str | None = None
    ground_truth_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


def assess_witness_qualification(
    property_definition: dict | PropertyDefinition,
    source_id: str,
    source_version: str,
    challenges: list[dict | QualificationChallenge],
    *,
    acquisition: Literal["IMPORTED", "ACTIVE_REGISTERED_TARGET"] = "IMPORTED",
) -> dict:
    prop = PropertyDefinition.model_validate(property_definition)
    captures = [QualificationChallenge.model_validate(case) for case in challenges]
    if acquisition not in ("IMPORTED", "ACTIVE_REGISTERED_TARGET"):
        raise ValueError("Unsupported capture acquisition mode")
    expected = {
        "KNOWN_PERMITTED": "PASS",
        "KNOWN_PROHIBITED": "FAIL",
        "MISSING_OBSERVATION": "INCONCLUSIVE",
    }
    problems = []
    if len(captures) != 3 or {c.case for c in captures} != set(expected):
        problems.append(
            "Exactly one permitted, prohibited and missing-observation challenge is required"
        )
    if source_id not in prop.observation_contract.required_witnesses:
        problems.append("Source is not required by the frozen property observation contract")
    if acquisition != "ACTIVE_REGISTERED_TARGET":
        problems.append("Imported/customer-asserted challenges cannot establish a trusted witness")
    results = []
    correlation_ids = [c.observation.correlation_id for c in captures]
    if len(correlation_ids) != len(set(correlation_ids)):
        problems.append("Qualification challenges must have distinct assigned correlations")
    for capture in captures:
        issues = []
        if not all(
            (
                capture.assigned_run_id,
                capture.ground_truth_receipt_reference,
                capture.ground_truth_digest,
            )
        ):
            issues.append(
                "Server-resolved assigned run and independent ground-truth evidence are required"
            )
        if capture.observation.boundary_mocked:
            issues.append("Protected boundary was mocked")
        witnesses = [w for w in capture.observation.witnesses if w.id == source_id]
        if capture.case != "MISSING_OBSERVATION":
            if len(witnesses) != 1 or witnesses[0].source_version != source_version:
                issues.append("Challenge observer source/version mismatch")
        elif any(w.complete for w in witnesses):
            issues.append("Missing-observation challenge did not remove required coverage")
        evaluation = evaluate_trace(prop, capture.observation, qualified_witnesses=(source_id,))
        if evaluation["security_verdict"] != expected[capture.case]:
            issues.append(
                f"Expected {expected[capture.case]}, observed {evaluation['security_verdict']}"
            )
        if capture.case == "KNOWN_PERMITTED" and evaluation["task_outcome"] != "SUCCESS":
            issues.append("Permitted scenario did not prove legitimate-task success")
        results.append(
            {
                "case": capture.case,
                "expected": expected[capture.case],
                "actual": evaluation["security_verdict"],
                "passed": not issues,
                "issues": issues,
                "observation_digest": digest(capture.observation),
                "assigned_run_id": capture.assigned_run_id,
                "ground_truth_receipt_reference": capture.ground_truth_receipt_reference,
                "ground_truth_digest": capture.ground_truth_digest,
            }
        )
    eligible = not problems and all(case["passed"] for case in results)
    return {
        "source_id": source_id,
        "source_version": source_version,
        "boundary": prop.observation_contract.boundary,
        "property_digest": digest(prop),
        "acquisition": acquisition,
        "candidate_qualified": eligible,
        "qualified": False,
        "status": "REVIEW_REQUIRED" if eligible else "NOT_QUALIFIED",
        "review_required": True,
        "problems": problems,
        "cases": results,
        "limitations": [
            "Qualification is scoped to the frozen property, source/version and captured boundary.",
            "The control plane must verify run ownership, target authorization and ground truth before approval.",
            "Changing observer versions or required coverage requires requalification.",
        ],
    }
