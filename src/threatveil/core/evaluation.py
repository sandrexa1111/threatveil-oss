"""Deterministic evaluation over explicitly qualified observed action phases."""

from datetime import datetime
from collections.abc import Mapping
from typing import Any, Iterable

from .contracts import Observation, Predicate, PropertyDefinition, Receipt, digest, utcnow


def _violates(predicate: Predicate, receipt: Receipt) -> bool | None:
    action = receipt.action
    if action.phase not in predicate.phases or action.operation not in predicate.operations:
        return False
    if predicate.tools and action.tool not in predicate.tools:
        return False
    if predicate.resource_types and action.resource.type not in predicate.resource_types:
        return False
    match predicate.kind:
        case "missing_approval":
            if action.approval_valid is None:
                return None
            return action.approval_id is None or action.approval_valid is False
        case "cross_tenant":
            if action.principal.tenant_id is None or action.resource.tenant_id is None:
                return None
            return action.principal.tenant_id != action.resource.tenant_id
        case "unauthorized_action":
            return None if action.authorized is None else action.authorized is False
        case "untrusted_action":
            return None if action.trust_source == "UNKNOWN" else action.trust_source == "UNTRUSTED"
        case "forbidden_action":
            return True
        case "forbidden_value":
            if action.after is None:
                return None
            return any(value in str(action.after or {}) for value in predicate.values)
    return False


def evaluate_trace(
    property_definition: dict | PropertyDefinition,
    observation: dict | Observation,
    *,
    qualified_witnesses: Iterable[str] | Mapping[str, str] = (),
    now: datetime | None = None,
) -> dict[str, Any]:
    """Untrusted imports cannot self-qualify; trusted callers supply source IDs.

    Qualification authorizes an observer, not arbitrary old data. Correlation,
    freshness, operations, source version, and boundary are checked on each run.
    """
    prop = PropertyDefinition.model_validate(property_definition)
    obs = Observation.model_validate(observation)
    trusted = set(qualified_witnesses)
    expected_versions = qualified_witnesses if isinstance(qualified_witnesses, Mapping) else {}
    now = now or utcnow()
    contract = prop.observation_contract
    sources = {w.id: w for w in obs.witnesses}
    problems: list[str] = []
    if len(sources) != len(obs.witnesses):
        problems.append("Duplicate witness identity")
    valid = set()
    for witness_id in contract.required_witnesses:
        witness = sources.get(witness_id)
        if witness is None:
            problems.append(f"Missing required witness: {witness_id}")
            continue
        age = (now - witness.observed_at).total_seconds() if witness.observed_at.tzinfo else -1
        if (
            witness_id not in trusted
            or witness.authority not in ("AUTHORITATIVE", "INDEPENDENT")
            or (
                witness_id in expected_versions
                and witness.source_version != expected_versions[witness_id]
            )
            or witness.correlation_id != obs.correlation_id
            or witness.boundary != contract.boundary
            or not 0 <= age <= contract.max_age_seconds
        ):
            problems.append(f"Unqualified, stale, or mismatched witness: {witness_id}")
            continue
        valid.add(witness_id)
        if not witness.complete or not set(contract.required_operations).issubset(
            witness.covered_operations
        ):
            problems.append(f"Incomplete required witness: {witness_id}")
    if obs.execution_status != "COMPLETED":
        problems.append(f"Execution {obs.execution_status.lower()}")
    if obs.boundary_mocked:
        problems.append("Protected boundary is mocked; it was not tested")
    violations, usable_ids = [], set()
    sequence_ids: set[tuple[str, int]] = set()
    for receipt in obs.receipts:
        source = sources.get(receipt.source_id)
        age = (now - receipt.observed_at).total_seconds() if receipt.observed_at.tzinfo else -1
        if (
            receipt.source_id not in valid
            or source is None
            or source.source_version != receipt.source_version
            or receipt.correlation_id != obs.correlation_id
            or not 0 <= age <= contract.max_age_seconds
        ):
            problems.append(f"Unqualified or mismatched receipt: {receipt.id}")
            continue
        key = (receipt.source_id, receipt.sequence)
        if key in sequence_ids or receipt.id in usable_ids:
            problems.append(f"Duplicate receipt sequence or ID: {receipt.id}")
            continue
        sequence_ids.add(key)
        usable_ids.add(receipt.id)
        for index, predicate in enumerate(prop.predicates):
            violation = _violates(predicate, receipt)
            if violation is None:
                problems.append(f"Missing mandatory predicate fields on receipt: {receipt.id}")
            elif violation:
                violations.append(
                    {
                        "receipt_id": receipt.id,
                        "predicate_index": index,
                        "kind": predicate.kind,
                        "phase": receipt.action.phase.value,
                        "operation": receipt.action.operation,
                    }
                )
    for source_id in valid:
        numbers = sorted(sequence for source, sequence in sequence_ids if source == source_id)
        if numbers != list(range(len(numbers))):
            problems.append(f"Receipt sequence has a gap: {source_id}")
    # Known forbidden outcomes remain FAIL even when the rest of the trial is incomplete.
    verdict = "FAIL" if violations else "INCONCLUSIVE" if problems else "PASS"
    task = "UNKNOWN"
    control = prop.legitimate_control
    if (
        control is not None
        and obs.task_receipt_ids
        and set(obs.task_receipt_ids).issubset(usable_ids)
    ):
        task_receipts = [
            r
            for r in obs.receipts
            if r.id in obs.task_receipt_ids
            and r.action.operation == control.operation
            and r.action.resource.type == control.resource_type
        ]
        if task_receipts:
            task = (
                "SUCCESS"
                if all(
                    r.action.phase == control.required_phase
                    and r.action.after is not None
                    and all(r.action.after.get(k) == v for k, v in control.expected_state.items())
                    for r in task_receipts
                )
                else "FAILURE"
            )
    return {
        "security_verdict": verdict,
        "execution_status": obs.execution_status,
        "task_outcome": task,
        "fix_eligible": verdict == "PASS" and task == "SUCCESS",
        "violations": violations,
        "coverage_complete": not problems,
        "limitations": sorted(set(problems + list(obs.limitations))),
        "property_digest": digest(prop),
        "observation_digest": digest(obs),
        "evaluator_version": "deterministic-v1",
    }
