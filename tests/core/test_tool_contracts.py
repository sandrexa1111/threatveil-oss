"""Real SQLite state/approval receipts exercise all six contract axes.

This is local conformance of a synthetic authoritative sink, not qualification
of any customer observer or external ERP integration.
"""

import json
import sqlite3
from datetime import timedelta
from uuid import uuid4

import pytest

from threatveil.core.contracts import ActionPhase, Observation, Principal, Witness, digest, utcnow
from threatveil.core.evaluation import evaluate_trace
from threatveil.core.tool_contracts import (
    AXES,
    ApprovalRecord,
    ToolContractBinding,
    compile_tool_contract,
    project_tool_receipts,
)


def binding():
    return ToolContractBinding(
        tool="erp.beneficiary",
        tool_version="v1",
        operation="beneficiary.update",
        boundary="beneficiary-approval",
        witness_id="erp-ledger",
        principal={"id": "agent", "tenant_id": "tenant-a", "authority": ["beneficiary.update"]},
        resource={"type": "beneficiary", "id": "vendor-1", "tenant_id": "tenant-a"},
        approver_id="finance-reviewer",
        initial_state={"account": "OLD", "status": "active"},
        allowed_state={"account": "APPROVED", "status": "active"},
    )


def sqlite_case(
    *,
    commit=True,
    policy=True,
    principal=None,
    approval_changes=None,
    failed=False,
    terminal="COMMITTED",
    after=None,
    missing=False,
    approval_complete=True,
    tool_version="v1",
    include_positive=True,
    binding_override=None,
):
    bound, correlation, observed_at = binding_override or binding(), str(uuid4()), utcnow()
    actor = principal or bound.principal
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE state (id TEXT PRIMARY KEY, value TEXT)")
    connection.execute("CREATE TABLE approvals (id TEXT PRIMARY KEY, value TEXT)")
    connection.execute(
        "CREATE TABLE audit (sequence INTEGER PRIMARY KEY, before_value TEXT, after_value TEXT, failed INTEGER)"
    )
    connection.execute(
        "INSERT INTO state VALUES (?, ?)", (bound.resource.id, json.dumps(bound.initial_state))
    )
    approved = ApprovalRecord(
        id="approval-1",
        approver_id=bound.approver_id,
        principal_id=bound.principal.id,
        principal_tenant_id=bound.principal.tenant_id,
        resource=bound.resource,
        operation=bound.operation,
        tool=bound.tool,
        tool_version=bound.tool_version,
        expected_state_digest=digest(bound.allowed_state),
        expires_at=observed_at + timedelta(minutes=5),
        status="ACTIVE",
    ).model_dump(mode="json")
    approved.update(approval_changes or {})
    connection.execute("INSERT INTO approvals VALUES (?, ?)", ("approval-1", json.dumps(approved)))

    def state():
        return json.loads(
            connection.execute(
                "SELECT value FROM state WHERE id=?", (bound.resource.id,)
            ).fetchone()[0]
        )

    try:
        before = state()
        if commit:
            connection.execute(
                "UPDATE state SET value=? WHERE id=?",
                (json.dumps(after or bound.allowed_state), bound.resource.id),
            )
        connection.execute(
            "INSERT INTO audit VALUES (?, ?, ?, ?)",
            (0, json.dumps(before), json.dumps(state()), int(failed)),
        )
        connection.commit()
        record = connection.execute(
            "SELECT before_value,after_value,failed FROM audit WHERE sequence=?", (0,)
        ).fetchone()
        receipt_approval = ApprovalRecord.model_validate_json(
            connection.execute(
                "SELECT value FROM approvals WHERE id=?", ("approval-1",)
            ).fetchone()[0]
        )
        common = dict(
            correlation_id=correlation,
            source_version="sqlite-tool-contract-v1",
            observed_tool_version=tool_version,
            principal=actor,
            resource=bound.resource,
            policy_authorized=policy,
            approval=receipt_approval,
            approval_lookup_complete=approval_complete,
            now=observed_at,
        )
        attempted = project_tool_receipts(
            bound,
            sequence=0,
            phase=ActionPhase.ATTEMPTED,
            before=before,
            after=before,
            failed=False,
            **common,
        )
        finished = project_tool_receipts(
            bound,
            sequence=len(attempted["receipts"]),
            phase=terminal,
            before=json.loads(record[0]),
            after=json.loads(record[1]),
            failed=bool(record[2]),
            **common,
        )
        receipts = attempted["receipts"] + finished["receipts"]
        task_ids = ()
        if include_positive:
            # A separate reset and valid approval-backed business control preserves usefulness.
            connection.execute(
                "UPDATE state SET value=? WHERE id=?",
                (json.dumps(bound.initial_state), bound.resource.id),
            )
            control_before = state()
            connection.execute(
                "UPDATE state SET value=? WHERE id=?",
                (json.dumps(bound.allowed_state), bound.resource.id),
            )
            connection.commit()
            positive = project_tool_receipts(
                bound,
                correlation_id=correlation,
                source_version="sqlite-tool-contract-v1",
                observed_tool_version="v1",
                sequence=len(receipts),
                phase=ActionPhase.COMMITTED,
                principal=bound.principal,
                resource=bound.resource,
                before=control_before,
                after=state(),
                policy_authorized=True,
                approval=ApprovalRecord.model_validate(
                    {
                        **approved,
                        "principal_id": bound.principal.id,
                        "resource": bound.resource.model_dump(mode="json"),
                        "operation": bound.operation,
                        "tool_version": "v1",
                        "approver_id": bound.approver_id,
                        "expected_state_digest": digest(bound.allowed_state),
                        "expires_at": observed_at + timedelta(minutes=5),
                        "status": "ACTIVE",
                    }
                ),
                approval_lookup_complete=True,
                failed=False,
                now=observed_at,
            )
            receipts += positive["receipts"]
            task_ids = (positive["receipts"][0].id,)
        witness = Witness(
            id=bound.witness_id,
            source_type="authoritative_sqlite_ledger",
            source_version="sqlite-tool-contract-v1",
            authority="AUTHORITATIVE",
            correlation_id=correlation,
            # The sink closes coverage after terminal observation; ATTEMPTED alone
            # is deliberately incomplete and never sufficient for a final witness.
            complete=finished["complete"],
            covered_operations=finished["covered_operations"],
            boundary=finished["boundary"],
            observed_at=observed_at,
        )
        observation = Observation(
            correlation_id=correlation,
            receipts=receipts,
            witnesses=() if missing else (witness,),
            task_receipt_ids=task_ids,
        )
        results = {
            entry["axis"]: evaluate_trace(
                entry["definition"],
                observation,
                qualified_witnesses={bound.witness_id: "sqlite-tool-contract-v1"},
                now=observed_at,
            )
            for entry in compile_tool_contract(bound)["properties"]
        }
        return results, observation
    finally:
        connection.close()


def test_approved_sql_mutation_preserves_all_six_axes_and_business_task():
    results, observation = sqlite_case()
    assert set(results) == set(AXES)
    assert observation.receipts[0].action.phase == "ATTEMPTED"
    assert all(
        r["security_verdict"] == "PASS" and r["task_outcome"] == "SUCCESS" for r in results.values()
    )


def test_denied_error_does_not_count_as_committed_side_effect():
    results, observation = sqlite_case(commit=False, policy=False, failed=True, terminal="DENIED")
    assert observation.receipts[1].action.phase == "DENIED"
    assert observation.receipts[1].action.before == observation.receipts[1].action.after
    assert all(r["security_verdict"] == "PASS" for r in results.values())


@pytest.mark.parametrize(
    ("axis", "arguments"),
    [
        ("authorization", {"policy": False}),
        (
            "identity",
            {
                "principal": Principal(
                    id="other-agent", tenant_id="tenant-a", authority=("beneficiary.update",)
                )
            },
        ),
        ("approval", {"approval_changes": {"tool_version": "old-version"}}),
        ("errors", {"failed": True}),
        ("side_effects", {"after": {"account": "APPROVED", "status": "deleted"}}),
        ("state_transitions", {"after": {"account": "ATTACKER", "status": "active"}}),
    ],
)
def test_authoritative_sql_failures_are_deterministic(axis, arguments):
    results, _ = sqlite_case(**arguments)
    assert results[axis]["security_verdict"] == "FAIL"
    assert results[axis]["violations"]
    assert results[axis]["task_outcome"] == "SUCCESS"


@pytest.mark.parametrize(
    "changes",
    [
        {"principal_id": "other-agent"},
        {"resource": {"type": "beneficiary", "id": "other-vendor", "tenant_id": "tenant-a"}},
        {"operation": "other.operation"},
        {"tool": "other.tool"},
        {"tool_version": "old-version"},
        {"approver_id": "untrusted-approver"},
        {"expected_state_digest": "0" * 64},
        {"expires_at": "2020-01-01T00:00:00Z"},
        {"status": "REVOKED"},
        {"status": "CONSUMED"},
    ],
)
def test_approval_ledger_binds_identity_resource_action_version_and_effect(changes):
    results, _ = sqlite_case(approval_changes=changes)
    assert results["approval"]["security_verdict"] == "FAIL"


def test_denied_response_cannot_hide_persisted_sql_mutation():
    results, observation = sqlite_case(policy=False, terminal="DENIED", failed=True)
    assert observation.receipts[1].action.phase == "COMMITTED"
    for axis in ("authorization", "errors", "side_effects"):
        assert results[axis]["security_verdict"] == "FAIL"


def test_no_observation_or_incomplete_approval_lookup_cannot_pass():
    missing, _ = sqlite_case(missing=True)
    assert all(r["security_verdict"] == "INCONCLUSIVE" for r in missing.values())
    incomplete, _ = sqlite_case(approval_complete=False)
    assert incomplete["approval"]["security_verdict"] == "INCONCLUSIVE"


def test_wrong_observed_tool_version_cannot_reuse_approval():
    results, _ = sqlite_case(tool_version="v2")
    assert results["approval"]["security_verdict"] == "FAIL"
    assert results["identity"]["security_verdict"] == "INCONCLUSIVE"


def test_another_binding_cannot_reuse_old_witness_or_self_qualify():
    _, observation = sqlite_case()
    changed = binding().model_copy(update={"approver_id": "different-reviewer"})
    prop = compile_tool_contract(changed)["properties"][0]["definition"]
    assert (
        evaluate_trace(prop, observation, qualified_witnesses=(binding().witness_id,))[
            "security_verdict"
        ]
        == "INCONCLUSIVE"
    )
    prop = compile_tool_contract(binding())["properties"][0]["definition"]
    assert evaluate_trace(prop, observation)["security_verdict"] == "INCONCLUSIVE"


def test_attempt_only_cannot_close_semantic_coverage():
    bound = binding()
    projection = project_tool_receipts(
        bound,
        correlation_id="attempt-only",
        source_version="test",
        observed_tool_version="v1",
        sequence=0,
        phase=ActionPhase.ATTEMPTED,
        principal=bound.principal,
        resource=bound.resource,
        before=bound.initial_state,
        after=bound.initial_state,
        policy_authorized=True,
        approval=None,
        approval_lookup_complete=True,
        failed=False,
    )
    assert projection["complete"] is False
    assert "terminal" in projection["limitations"][0]


def test_json_type_change_is_a_real_transition_violation():
    numeric = binding().model_copy(
        update={"initial_state": {"count": 0}, "allowed_state": {"count": 1}}
    )
    results, _ = sqlite_case(binding_override=numeric, after={"count": True})
    assert results["state_transitions"]["security_verdict"] == "FAIL"
    assert results["approval"]["security_verdict"] == "FAIL"


def test_null_field_addition_is_an_unapproved_side_effect():
    results, _ = sqlite_case(after={"account": "APPROVED", "status": "active", "new-field": None})
    assert results["side_effects"]["security_verdict"] == "FAIL"


def test_partial_state_read_cannot_establish_a_state_transition_or_pass():
    results, _ = sqlite_case(after={"account": "APPROVED"})
    assert all(result["security_verdict"] == "INCONCLUSIVE" for result in results.values())
