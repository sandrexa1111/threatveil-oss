"""Bounded automatic re-proof: re-running an already-approved verification, nothing more.

A policy is a standing, explicit permission to repeat one exact verification when its
clearance has been lost: one approved executable claim, one approved target, one
qualified observer, one environment, one authority scope and a bounded budget. The
planner refuses rather than improvises. It can never widen scope, change a claim, pick
a different target, or remediate anything: there is no remediation path in this module
at all.

Outside a sandbox it stays off unless the deployment explicitly enables it.
"""

from datetime import timedelta
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field

from .auth import SECURITY, Actor, actor, require
from .change_assurance import history, scoped
from .config import settings
from .db import add_record, audit, get_record, now, transaction
from .schemas import Input

router = APIRouter(tags=["auto-reproof"])
PROFILE = "auto-reproof/v1"
LEVEL = "LEVEL_2_3_ONLY"
DECISIONS = ("ELIGIBLE", "SKIPPED", "DISPATCHED", "COMPLETED")
REASONS = {
    "NOTHING_TO_REPROVE": "Clearance is current, so there is nothing to re-prove.",
    "FLAG_DISABLED_OUTSIDE_SANDBOX": "Automatic re-proof is disabled for this deployment outside a sandbox.",
    "POLICY_DISABLED": "This policy is not enabled.",
    "CLAIM_NOT_APPROVED": "The claim is no longer an approved executable claim.",
    "OBSERVER_NOT_QUALIFIED": "The observer that must witness the business effect is not QUALIFIED.",
    "AUTHORITY_SCOPE_CHANGED": "The reviewed authority boundary changed after this policy was approved.",
    "TARGET_CHANGED": "The approved target is not the one this policy was approved for.",
    "BUDGET_EXHAUSTED": "The policy's bounded run budget for this window is used up.",
    "NO_QUALIFIED_DISPATCHER": "No qualified automatic dispatcher exists for this environment.",
    "ELIGIBLE": "Every approved precondition still holds; the same verification may be repeated.",
}


class PolicyInput(Input):
    environment_id: UUID
    property_id: UUID
    target_id: UUID
    observer_definition_id: UUID
    trial_count: int = Field(default=1, ge=1, le=3)
    max_runs_per_window: int = Field(default=2, ge=1, le=24)
    window_hours: int = Field(default=24, ge=1, le=168)
    justification: str = Field(min_length=40, max_length=2000)
    # Re-proof repeats a verification. It never fixes anything, and the approver says so.
    confirm_no_remediation: Literal[True]


def _envelope_scope(ctx):
    envelope = ctx.envelope
    if envelope is None:
        raise HTTPException(409, "Approve an authority boundary before enabling automatic re-proof")
    return {"envelope_id": str(envelope.id), "policy_epoch": envelope.payload["policy_epoch"],
            "envelope_digest": ctx.state.payload["envelope_digest"] if ctx.state else None}


def policy_view(row, *, plan=None):
    payload = row.payload
    return {"id": str(row.id), "system_id": payload["system_id"], "environment_id": payload["environment_id"],
            "property_id": payload["property_id"], "target_id": payload["target_id"],
            "observer_definition_id": payload["observer_definition_id"], "level": payload["level"],
            "auto_reproof": True, "remediation": "NONE", "enabled": payload["enabled"],
            "trial_count": payload["trial_count"], "max_runs_per_window": payload["max_runs_per_window"],
            "window_hours": payload["window_hours"], "authority_scope": payload["authority_scope"],
            "environment_purpose": payload["environment_purpose"], "approved_by": payload["approved_by"],
            "justification": payload["justification"],
            "created_at": row.created_at.isoformat(), "plan": plan,
            "limitations": ["Repeats one already-approved verification; it can never widen scope.",
                            "No remediation, rollback or configuration change is possible through this path.",
                            "Outside a sandbox it requires an explicit deployment flag."]}


def plan(session, org, policy, *, at=None):
    """Whether this exact verification may be repeated right now, and why."""
    from .assurance_intelligence import clearance, load
    from .observer_platform import qualification_state

    at = at or now()
    payload = policy.payload
    ctx = load(session, org, UUID(payload["system_id"]), payload["environment_id"])
    scope = {"property_id": payload["property_id"], "target_id": payload["target_id"],
             "environment_id": payload["environment_id"],
             "envelope_digest": payload["authority_scope"]["envelope_digest"], "widened": False}

    def refuse(reason):
        return {"decision": "SKIPPED", "reason": reason, "reason_text": REASONS[reason], "scope": scope,
                "as_of": at.isoformat()}

    if not payload["enabled"]:
        return refuse("POLICY_DISABLED")
    sandbox = payload["environment_purpose"] == "SANDBOX"
    if not sandbox and not settings().auto_reproof_enabled:
        return refuse("FLAG_DISABLED_OUTSIDE_SANDBOX")
    prop = next((p for p in ctx.properties if str(p.id) == payload["property_id"]), None)
    if prop is None or not prop.payload.get("approved"):
        return refuse("CLAIM_NOT_APPROVED")
    observer = get_record(session, org, payload["observer_definition_id"], "observer_definition")
    if qualification_state(session, org, observer, at=at)["state"] != "QUALIFIED":
        return refuse("OBSERVER_NOT_QUALIFIED")
    current = _envelope_scope(ctx)
    if (current["envelope_id"] != payload["authority_scope"]["envelope_id"]
            or current["envelope_digest"] != payload["authority_scope"]["envelope_digest"]):
        return refuse("AUTHORITY_SCOPE_CHANGED")
    target = next((t for t in history(session, org, "target", UUID(payload["system_id"]))
                   if str(t.id) == payload["target_id"]), None)
    if target is None:
        return refuse("TARGET_CHANGED")
    window_start = at - timedelta(hours=payload["window_hours"])
    used = sum(1 for row in history(session, org, "auto_reproof_execution", UUID(payload["system_id"]))
               if row.payload.get("policy_id") == str(policy.id)
               and row.payload.get("decision") == "DISPATCHED"
               and row.created_at.timestamp() >= window_start.timestamp())
    if used >= payload["max_runs_per_window"]:
        return refuse("BUDGET_EXHAUSTED")
    if clearance(ctx)["state"] == "CLEARED":
        return refuse("NOTHING_TO_REPROVE")
    return {"decision": "ELIGIBLE", "reason": "ELIGIBLE", "reason_text": REASONS["ELIGIBLE"], "scope": scope,
            "runs_used_in_window": used, "budget": payload["max_runs_per_window"], "as_of": at.isoformat()}


def _record_execution(session, org, policy, decision, *, reason, scope, run_id=None, note=""):
    return add_record(session, org, "auto_reproof_execution", {
        "schema_version": PROFILE, "system_id": policy.payload["system_id"],
        "environment_id": policy.payload["environment_id"], "policy_id": str(policy.id),
        "decision": decision, "reason": reason, "reason_text": REASONS.get(reason, reason), "scope": scope,
        "widened_scope": False, "remediation": "NONE", "run_id": str(run_id) if run_id else None, "note": note,
    }, {"policy": policy.id})


@router.post("/v1/systems/{system_id}/auto-reproof-policies", status_code=201)
def create_policy(system_id: UUID, body: PolicyInput, a: Actor = Depends(actor)):
    """Approve repeating one exact verification. Every precondition must already be approved."""
    require(a, SECURITY)
    from .assurance_intelligence import load
    from .observer_platform import qualification_state
    from .release_integrity import lock_system

    with transaction(a.user_id, a.org_id) as session:
        get_record(session, a.org_id, system_id, "system")
        environment = scoped(session, a.org_id, body.environment_id, "environment", system_id)
        lock_system(session, a.org_id, system_id)
        prop = scoped(session, a.org_id, body.property_id, "property", system_id)
        if not prop.payload.get("approved"):
            raise HTTPException(422, "Automatic re-proof requires an approved executable claim")
        target = scoped(session, a.org_id, body.target_id, "target", system_id)
        observer = get_record(session, a.org_id, body.observer_definition_id, "observer_definition")
        if observer.payload["system_id"] != str(system_id):
            raise HTTPException(404, "Observer not found for this system")
        if qualification_state(session, a.org_id, observer)["state"] != "QUALIFIED":
            raise HTTPException(422, "Automatic re-proof requires a QUALIFIED business-effect observer")
        ctx = load(session, a.org_id, system_id, body.environment_id)
        row = add_record(session, a.org_id, "auto_reproof_policy", {
            **body.model_dump(mode="json"), "schema_version": PROFILE, "system_id": str(system_id),
            "environment_id": str(body.environment_id), "property_id": str(body.property_id),
            "target_id": str(target.id), "observer_definition_id": str(observer.id),
            "environment_purpose": environment.payload["purpose"], "authority_scope": _envelope_scope(ctx),
            "level": LEVEL, "enabled": True, "auto_reproof": True, "remediation": "NONE",
            "approved_by": str(a.user_id),
        }, {"system": system_id, "environment": body.environment_id, "property": body.property_id,
            "target": target.id, "observer_definition": observer.id})
        audit(session, a.org_id, a.user_id, "auto_reproof.policy_approved", row.id)
        return policy_view(row, plan=plan(session, a.org_id, row))


@router.get("/v1/systems/{system_id}/auto-reproof-policies")
def list_policies(system_id: UUID, a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        get_record(session, a.org_id, system_id, "system")
        rows = history(session, a.org_id, "auto_reproof_policy", system_id)[:20]
        return {"items": [policy_view(row, plan=plan(session, a.org_id, row)) for row in rows],
                "enabled_outside_sandbox": settings().auto_reproof_enabled, "reasons": REASONS}


@router.get("/v1/auto-reproof-policies/{policy_id}/plan")
def policy_plan(policy_id: UUID, a: Actor = Depends(actor)):
    """What would happen now, without doing it."""
    with transaction(a.user_id, a.org_id) as session:
        policy = get_record(session, a.org_id, policy_id, "auto_reproof_policy")
        return {"policy_id": str(policy.id), **plan(session, a.org_id, policy)}


@router.post("/v1/auto-reproof-policies/{policy_id}/run", status_code=201)
def run_policy(policy_id: UUID, a: Actor = Depends(actor)):
    """Repeat the approved verification if every precondition still holds."""
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        policy = get_record(session, a.org_id, policy_id, "auto_reproof_policy")
        decision = plan(session, a.org_id, policy)
        system = get_record(session, a.org_id, policy.payload["system_id"], "system")
        fixture = system.payload.get("fixture_profile")
        sandbox = policy.payload["environment_purpose"] == "SANDBOX"
        if decision["decision"] != "ELIGIBLE":
            row = _record_execution(session, a.org_id, policy, "SKIPPED", reason=decision["reason"],
                                    scope=decision["scope"])
            return {"id": str(row.id), **decision}
        if not (sandbox and fixture == "finance-v1"):
            row = _record_execution(session, a.org_id, policy, "SKIPPED", reason="NO_QUALIFIED_DISPATCHER",
                                    scope=decision["scope"])
            return {"id": str(row.id), "decision": "SKIPPED", "reason": "NO_QUALIFIED_DISPATCHER",
                    "reason_text": REASONS["NO_QUALIFIED_DISPATCHER"], "scope": decision["scope"],
                    "note": "The plan is eligible. Dispatch requires a qualified automatic dispatcher for this "
                            "environment, which this deployment does not have."}
        row = _record_execution(session, a.org_id, policy, "DISPATCHED", reason="ELIGIBLE",
                                scope=decision["scope"],
                                note="Labelled synthetic sandbox fixture; the ordinary verification path runs it.")
        execution_id, system_id = str(row.id), str(system.id)
    # The sandbox demonstration uses the same verification path a person would use.
    from fastapi import Response

    from .change_assurance_api import FinanceAssessment, finance_assess

    assessment = finance_assess(FinanceAssessment(system_id=UUID(system_id), version="fixed",
                                                  idempotency_key=f"auto-reproof-{execution_id}"),
                                Response(), a)
    with transaction(a.user_id, a.org_id) as session:
        policy = get_record(session, a.org_id, policy_id, "auto_reproof_policy")
        completed = _record_execution(
            session, a.org_id, policy, "COMPLETED", reason="ELIGIBLE", scope=decision["scope"],
            run_id=assessment.get("run_id") if isinstance(assessment, dict) else None,
            note="Repeated the approved verification; no remediation was attempted.")
        return {"id": str(completed.id), "dispatch_id": execution_id, "decision": "COMPLETED",
                "scope": decision["scope"], "remediation": "NONE",
                "assessment": {key: assessment.get(key) for key in ("action", "security", "legitimate_task",
                                                                    "authorization_id", "state_digest")}
                if isinstance(assessment, dict) else None}
