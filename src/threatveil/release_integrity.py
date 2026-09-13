"""Immutable proof scopes, evidence applicability, re-proof plans and release ledger.

Reuses the existing qualified execution plane and tenant-safe append-only records.
No submitted verdict or model-generated conclusion is accepted as evidence.
"""

from datetime import datetime, timedelta
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import Field, model_validator
from sqlalchemy import select, text

from .assurance import ExactCandidate, _candidate, _properties
from .auth import Actor, SECURITY, actor, require
from .core.contracts import SystemFingerprint, digest
from .core.validity import (
    ALGORITHM, ProofScope, canonical_fingerprint, change_set,
    configuration_digest, invalidate, proof_obligation,
)
from .db import Membership, Record, RunState, add_record, audit, get_record, now, serialize, transaction
from .schemas import Input, RunInput
from .workspace_reads import page

router = APIRouter(prefix="/v1", tags=["release-integrity"])


def lock_system(session, org_id, system_id):
    key = int(digest({"release_system": str(system_id), "org": str(org_id)})[:16], 16) & ((1 << 63) - 1)
    session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})


def lock_organization_systems(session, org_id):
    ids = session.scalars(select(Record.id).where(Record.organization_id == org_id, Record.kind == "system").order_by(Record.id))
    for identifier in ids:
        lock_system(session, org_id, identifier)


def _all(session, org, kind, system_id):
    return list(session.scalars(select(Record).where(
        Record.organization_id == org, Record.kind == kind,
        Record.payload["system_id"].astext == str(system_id),
    ).order_by(Record.created_at.desc(), Record.id.desc())))


def _matching_candidate(left, right):
    # Positive authority is exact; adverse-history lookup deliberately uses the
    # broader content identity and must never narrow to caller labels.
    return all(left.get(k) == right.get(k) for k in ("type", "id", "version", "digest"))


def _observed_candidate_anchor(session, org, evidence, candidate, fingerprint, stamp):
    """Declared candidate metadata is planning input, never deployment observation."""
    from .api import authorized_target
    from .observers import active_observer

    value = evidence.payload
    if value["synthetic"] and candidate["type"] != "application_version":
        return False
    expected = configuration_digest(fingerprint)
    for row in _all(session, org, "evidence_record", value["system_id"]):
        anchor = row.payload
        if not (anchor["qualified"] and anchor["candidate_observed"]
            and anchor["target_id"] == value["target_id"]
            and anchor.get("observer_id") == value.get("observer_id")
            and anchor["synthetic"] == value["synthetic"]
            and _matching_candidate(anchor["candidate"], candidate)
            and anchor["fingerprint_digest"] == expected
            and 0 <= (stamp-datetime.fromisoformat(anchor["established_at"])).total_seconds() <= 86400
            and stamp < datetime.fromisoformat(anchor["expires_at"])):
            continue
        if candidate["type"] == "git_commit":
            run = get_record(session, org, anchor["run_id"], "run")
            github = run.payload.get("github") or {}
            if not (github.get("verified_workflow") is True
                and str(github.get("repository_id")) == candidate["id"]
                and github.get("sha") == candidate["digest"] == candidate["version"]):
                continue
        try:
            authorized_target(session, org, anchor["target_id"])
            if anchor.get("observer_id"):
                active_observer(session, org, anchor["observer_id"])
        except HTTPException:
            continue
        return True
    return False


def snapshot_evidence(session, org, run, result_record, *, scope=None, reviewer=None):
    data, result = run.payload, result_record.payload
    target = get_record(session, org, data["target_id"], "target")
    synthetic = target.payload["adapter"] == "synthetic_procurement"
    fingerprint = canonical_fingerprint(result.get("fingerprint") or {"components": []})
    candidate = data["candidate"]
    components = fingerprint["components"]
    synthetic_observed = bool(synthetic and any(
        c["type"] == "application" and c["id"] == "procurement-agent"
        and c["version"] == candidate.get("version") == data["version"]
        and c["digest"] == candidate.get("digest") and c["provenance"] == "OBSERVED"
        for c in components
    ))
    observed = synthetic_observed if synthetic else result.get("candidate_observed") is True
    qualified = bool(result.get("qualification", {}).get("qualified") and observed
                     and not data.get("qualification_case"))
    definition = data["property_definition"]
    if scope is None:
        scope = ProofScope(bindings=tuple(
            {"component": k} for k in sorted(set(definition.get("dependencies", [])))
        )).model_dump(mode="json")
    scope = ProofScope.model_validate(scope).model_dump(mode="json")
    scope_row = add_record(session, org, "proof_scope", {
        "system_id": data["system_id"], "property_id": data["property_id"],
        "run_id": str(run.id), "definition": scope,
        "fingerprint_digest": configuration_digest(fingerprint),
        "reviewed_by": str(reviewer) if reviewer else None,
        "provenance": "Security-reviewed evidence binding" if reviewer else "Full observed fingerprint; declared property dependencies retained",
    }, {"run": run.id, "property": data["property_id"], "system": data["system_id"]})
    completed = result.get("execution_status") == "COMPLETED"
    coverage = bool(result.get("coverage_complete")) if not synthetic else bool(
        result.get("trials") and all(t.get("coverage_complete") is True for t in result["trials"])
    )
    payload = {
        "system_id": data["system_id"], "property_id": data["property_id"],
        "property_digest": digest(definition), "property_version": definition.get("version", 1),
        "run_id": str(run.id), "result_id": str(result_record.id), "target_id": data["target_id"],
        "observer_id": data.get("observer_id"), "candidate": candidate,
        "candidate_observed": observed, "fingerprint": fingerprint,
        "fingerprint_digest": configuration_digest(fingerprint), "proof_scope_id": str(scope_row.id),
        "security_verdict": result.get("security_verdict", "INCONCLUSIVE"),
        "task_outcome": result.get("task_outcome", "UNKNOWN"), "qualified": qualified,
        "coverage_complete": coverage, "execution_complete": completed,
        "execution_config_digest": data["spec_digest"],
        "qualified_witnesses": result.get("qualification", {}),
        "ground_truth": "Synthetic committed SQLite ledger" if synthetic else "Reviewed signed target-side observation",
        "evidence_digest": result.get("evidence_digest"),
        "raw_evidence_reference": {"run_id": str(run.id), "capture_ids": result.get("capture_ids", [])},
        "evaluator": result.get("evidence", {}).get("evaluator_version", "deterministic-v1"),
        "established_at": result_record.created_at.isoformat(),
        "expires_at": (result_record.created_at + timedelta(seconds=scope["max_age_seconds"])).isoformat(),
        "synthetic": synthetic,
        "limitations": result.get("limitations", []) + [
            "Evidence validity is scoped; it is not universal security or deployment attestation.",
        ],
    }
    row = add_record(session, org, "evidence_record", payload, {
        "run": run.id, "result": result_record.id, "proof_scope": scope_row.id,
        "property": data["property_id"], "target": data["target_id"], "system": data["system_id"],
    })
    return row


class ScopeReview(Input):
    run_id: UUID
    scope: ProofScope


@router.post("/proof-scopes", status_code=201)
def review_scope(body: ScopeReview, a: Actor = Depends(actor)):
    require(a, SECURITY)
    if body.scope.authority != "HUMAN_REVIEWED" or not body.scope.review_reason.strip():
        raise HTTPException(422, "A binding review requires HUMAN_REVIEWED authority and its rationale")
    with transaction(a.user_id, a.org_id) as session:
        run = get_record(session, a.org_id, body.run_id, "run")
        lock_system(session, a.org_id, run.payload["system_id"])
        state = session.get(RunState, (a.org_id, run.id))
        if not state or not state.result_id or run.payload.get("qualification_case"):
            raise HTTPException(409, "Completed assurance evidence is required before scope review")
        if body.scope.coverage == "REVIEWED_DEPENDENCIES" and not set(
            run.payload["property_definition"].get("dependencies", [])
        ) <= {b.component for b in body.scope.bindings}:
            raise HTTPException(422, "Reviewed scope cannot omit dependencies from the approved property version")
        evidence = snapshot_evidence(session, a.org_id, run,
            get_record(session, a.org_id, state.result_id, "result"),
            scope=body.scope, reviewer=a.user_id)
        audit(session, a.org_id, a.user_id, "proof_scope.reviewed", evidence.id)
        return {**serialize(get_record(session, a.org_id, evidence.payload["proof_scope_id"], "proof_scope")),
                "evidence_id": str(evidence.id)}


class PlanInput(Input):
    system_id: UUID
    candidate: ExactCandidate
    fingerprint: SystemFingerprint
    previous_fingerprint: SystemFingerprint | None = None
    trials_per_variant: int = Field(default=5, ge=1, le=100)
    variant_count: int = Field(default=1, ge=1, le=5)


def _assess_evidence(session, org, evidence, candidate, fingerprint, stamp):
    value = evidence.payload
    scope = get_record(session, org, value["proof_scope_id"], "proof_scope")
    decision = invalidate(scope.payload["definition"], value["fingerprint"], fingerprint,
        created_at=datetime.fromisoformat(value["established_at"]), evaluated_at=stamp)
    from .api import authorized_target, run_view
    from .observers import active_observer

    reasons = list(decision["reasons"])
    usable = bool(value["qualified"] and value["coverage_complete"] and value["execution_complete"]
                  and value["security_verdict"] == "PASS" and value["task_outcome"] == "SUCCESS")
    if not usable:
        reasons.append("A complete qualified security PASS plus legitimate SUCCESS is required")
    if not _observed_candidate_anchor(session, org, evidence, candidate, fingerprint, stamp):
        usable = False
        reasons.append("A fresh qualified observation of this candidate and complete fingerprint at the same target/source is required")
    try:
        authorized_target(session, org, value["target_id"])
        if value.get("observer_id"):
            active_observer(session, org, value["observer_id"])
    except HTTPException:
        usable = False
        reasons.append("Target or qualified observer authorization is no longer current")
    run = get_record(session, org, value["run_id"], "run")
    current = run_view(session, org, run)
    if current.get("adverse_memory", {}).get("blocked"):
        usable = False
        reasons.append("Retained adverse history prevents this sampled PASS from authorizing release")
    # A different claimed version with an unchanged fingerprint cannot relabel an
    # old candidate. A new exact application/model identity must occur in the manifest.
    if not _matching_candidate(value["candidate"], candidate) and configuration_digest(value["fingerprint"]) == configuration_digest(fingerprint):
        usable = False
        reasons.append("Candidate identity changed without a corresponding fingerprint change")
    status = decision["status"]
    if status == "STILL_VALID" and not usable:
        status = "UNKNOWN"
    return {**decision, "status": status, "reasons": reasons,
            "evidence_id": str(evidence.id), "property_id": value["property_id"],
            "usable": usable and status == "STILL_VALID"}


def _candidate_in_fingerprint(candidate, fingerprint):
    kind = "application" if candidate["type"] == "git_commit" else candidate["type"].removesuffix("_version")
    return any(c["type"] == kind and c["version"] == candidate["version"]
               and c["provenance"] in {"OBSERVED", "DECLARED"}
               and (candidate["type"] == "git_commit" or c["digest"] == candidate["digest"])
               for c in canonical_fingerprint(fingerprint)["components"])


def assess_plan(session, org, payload):
    system_id, candidate, fingerprint = payload["system_id"], payload["candidate"], payload["fingerprint"]
    properties = _properties(session, org, system_id)
    stamp = now()
    evidence = _all(session, org, "evidence_record", system_id)
    invalidations, reused, obligations, selected = [], [], [], {}
    by_property = {}
    seen_runs = set()
    for row in evidence:
        # A reviewed scope appends a new version for that run, never edits the old one.
        if row.payload["run_id"] in seen_runs:
            continue
        seen_runs.add(row.payload["run_id"])
        by_property.setdefault(row.payload["property_id"], []).append(row)
    candidate_bound = _candidate_in_fingerprint(candidate, fingerprint)
    for prop in properties:
        pid = str(prop.id)
        decisions = []
        for ev in by_property.get(pid, []):
            decision = _assess_evidence(session, org, ev, candidate, fingerprint, stamp)
            run = get_record(session, org, ev.payload["run_id"], "run")
            if run.payload["trials"] < payload.get("trials_per_variant", 5) or run.payload["variant_count"] < payload.get("variant_count", 1):
                decision.update(status="UNKNOWN", usable=False)
                decision["reasons"].append("Evidence does not meet the plan's minimum trial and variant budget")
            if not candidate_bound:
                decision.update(status="UNKNOWN", usable=False)
                decision["reasons"].append("Candidate identity is not present in the expected fingerprint")
            decisions.append(decision)
        invalidations.extend(decisions)
        chosen = next((d for d in decisions if d["usable"]), None)
        if chosen:
            reused.append(chosen["evidence_id"])
            selected[pid] = chosen["evidence_id"]
        else:
            reasons = [reason for d in decisions for reason in d["reasons"]]
            if not reasons:
                reasons = ["No scoped evidence exists for this approved property version"]
            obligations.append(proof_obligation(pid, prop.payload["definition"], reasons,
                trials=payload.get("trials_per_variant", 5), variants=payload.get("variant_count", 1)))
    return {
        "algorithm_version": ALGORITHM, "evaluated_at": stamp.isoformat(),
        "scope_property_ids": sorted(str(p.id) for p in properties),
        "invalidations": invalidations, "reused_evidence_ids": reused,
        "selected_evidence": selected, "obligations": obligations,
        "candidate_bound": candidate_bound,
        "limitations": ["Selective reuse requires reviewed dependency coverage; default scopes invalidate on every observed component change.",
                        "Plan creation does not execute tests or spend an execution budget."],
    }


@router.post("/proof-plans", status_code=201)
def create_plan(body: PlanInput, a: Actor = Depends(actor)):
    require(a)
    payload = body.model_dump(mode="json")
    payload["fingerprint"] = canonical_fingerprint(body.fingerprint)
    with transaction(a.user_id, a.org_id) as session:
        get_record(session, a.org_id, body.system_id, "system")
        lock_system(session, a.org_id, body.system_id)
        previous = body.previous_fingerprint
        if previous is None:
            prior = _all(session, a.org_id, "evidence_record", body.system_id)
            previous = prior[0].payload["fingerprint"] if prior else {"components": []}
        delta = add_record(session, a.org_id, "change_set", {
            "system_id": str(body.system_id), "candidate_identity": payload["candidate"],
            "previous": canonical_fingerprint(previous), "candidate": payload["fingerprint"],
            **change_set(previous, body.fingerprint),
        }, {"system": body.system_id})
        assessment = assess_plan(session, a.org_id, payload)
        plan = add_record(session, a.org_id, "proof_plan", {
            **payload, **assessment, "change_set_id": str(delta.id),
            "candidate_fingerprint_digest": configuration_digest(body.fingerprint),
        }, {"system": body.system_id, "change_set": delta.id,
            **{f"evidence:{i}": x["evidence_id"] for i, x in enumerate(assessment["invalidations"])}})
        audit(session, a.org_id, a.user_id, "proof_plan.created", plan.id)
        return serialize(plan)


class ReleasePolicy(Input):
    mode: Literal["OBSERVE", "WARN", "BLOCK"] = "WARN"
    property_modes: dict[str, Literal["OBSERVE", "WARN", "BLOCK"]] = Field(default_factory=dict, max_length=500)


class ReleaseInput(Input):
    plan_id: UUID
    policy: ReleasePolicy = Field(default_factory=ReleasePolicy)
    exception_ids: list[UUID] = Field(default_factory=list, max_length=100)


class ExceptionInput(Input):
    plan_id: UUID
    property_ids: list[UUID] = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=10, max_length=4000)
    risk_acknowledgment: str = Field(min_length=10, max_length=4000)
    expires_at: datetime

    @model_validator(mode="after")
    def bounded_expiry(self):
        if self.expires_at.tzinfo is None or not now() < self.expires_at <= now() + timedelta(hours=24):
            raise ValueError("Exception expiry must be timezone-aware, in the future, and within 24 hours")
        if len(set(self.property_ids)) != len(self.property_ids):
            raise ValueError("Duplicate exception property")
        return self


@router.post("/release-exceptions", status_code=201)
def request_exception(body: ExceptionInput, a: Actor = Depends(actor)):
    require(a)
    with transaction(a.user_id, a.org_id) as session:
        plan = get_record(session, a.org_id, body.plan_id, "proof_plan")
        ids = {str(v) for v in body.property_ids}
        if not ids <= set(plan.payload["scope_property_ids"]):
            raise HTTPException(422, "Exception properties must belong to this exact release plan")
        row = add_record(session, a.org_id, "release_exception", {
            **body.model_dump(mode="json"), "system_id": plan.payload["system_id"],
            "candidate": plan.payload["candidate"],
            "candidate_fingerprint_digest": plan.payload["candidate_fingerprint_digest"],
            "requested_by": str(a.user_id), "status": "REQUESTED",
        }, {"plan": plan.id, **{f"property:{i}": p for i, p in enumerate(body.property_ids)}})
        audit(session, a.org_id, a.user_id, "release_exception.requested", row.id)
        return serialize(row)


@router.post("/release-exceptions/{identifier}/approve", status_code=201)
def approve_exception(identifier: UUID, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        row = get_record(session, a.org_id, identifier, "release_exception")
        lock_system(session, a.org_id, row.payload["system_id"])
        if row.payload["requested_by"] == str(a.user_id):
            raise HTTPException(403, "A different security approver must acknowledge this bypass")
        if datetime.fromisoformat(row.payload["expires_at"]) <= now():
            raise HTTPException(409, "Exception request has expired")
        approval = add_record(session, a.org_id, "exception_approval", {
            "system_id": row.payload["system_id"], "exception_id": str(row.id),
            "approved_by": str(a.user_id), "approved_at": now().isoformat(),
        }, {"exception": row.id})
        audit(session, a.org_id, a.user_id, "release_exception.approved", row.id)
        return serialize(approval)


@router.post("/release-exceptions/{identifier}/revoke", status_code=201)
def revoke_exception(identifier: UUID, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        row = get_record(session, a.org_id, identifier, "release_exception")
        lock_system(session, a.org_id, row.payload["system_id"])
        revoked = add_record(session, a.org_id, "exception_revocation", {
            "system_id": row.payload["system_id"], "exception_id": str(row.id), "revoked_by": str(a.user_id),
        }, {"exception": row.id})
        audit(session, a.org_id, a.user_id, "release_exception.revoked", row.id)
        return serialize(revoked)


def active_exceptions(session, a, plan, identifiers):
    result = []
    for identifier in identifiers:
        row = get_record(session, a.org_id, identifier, "release_exception")
        value = row.payload
        if value["plan_id"] != str(plan.id) or value["candidate_fingerprint_digest"] != plan.payload["candidate_fingerprint_digest"]:
            raise HTTPException(422, "Exception is not bound to this exact plan and candidate")
        if datetime.fromisoformat(value["expires_at"]) <= now():
            raise HTTPException(409, "Exception expired")
        query = (Record.organization_id == a.org_id, Record.payload["exception_id"].astext == str(row.id))
        if session.scalar(select(Record.id).where(*query, Record.kind == "exception_revocation")):
            raise HTTPException(409, "Exception revoked")
        approvals = list(session.scalars(select(Record).where(*query, Record.kind == "exception_approval")))
        approved = next((r for r in approvals if (member := session.get(Membership,
            (a.org_id, UUID(r.payload["approved_by"])))) and member.role in SECURITY), None)
        if approved is None:
            raise HTTPException(409, "An active independent security approver is required")
        result.append({**serialize(row), "approval": serialize(approved), "status": "APPROVED"})
    return result


def _candidate_failures(session, org, system_id, candidate, fingerprint):
    """All history, including captures from interrupted executions; no latest-N cutoff."""
    from .api import run_view
    from .adverse_memory import fingerprint_digest
    failures = {}
    expected = fingerprint_digest(fingerprint)
    for run in _all(session, org, "run", system_id):
        old = run.payload.get("candidate", {})
        if run.payload.get("qualification_case") or not all(old.get(k) == candidate.get(k) for k in ("type", "digest")):
            continue
        result = run_view(session, org, run)
        # Unknown provenance widens the decision, never clears known adverse evidence.
        adverse = result.get("security_verdict") == "FAIL" or result.get("adverse_memory", {}).get("blocked")
        profiles = []
        if adverse:
            captures = session.scalars(select(Record).where(Record.organization_id == org,
                Record.kind == "trial_capture", Record.payload["run_id"].astext == str(run.id),
                Record.payload["evaluation"]["security_verdict"].astext == "FAIL"))
            profiles.extend(fingerprint_digest(c.payload.get("observed_fingerprint")) for c in captures)
            state = session.get(RunState, (org, run.id))
            if state and state.result_id:
                saved = get_record(session, org, state.result_id, "result")
                profiles.append(fingerprint_digest(saved.payload.get("fingerprint")))
        if adverse and (not profiles or any(p is None or p == expected for p in profiles)):
            failures.setdefault(run.payload["property_id"], []).append(str(run.id))
    return failures


@router.post("/releases", status_code=201)
def create_release(body: ReleaseInput, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        return issue_release(session, body, a)


def issue_release(session, body: ReleaseInput, a: Actor, *, machine_authority=None):
    """Shared canonical issuer. Callers authorize before entering this transaction."""
    plan = get_record(session, a.org_id, body.plan_id, "proof_plan")
    payload = plan.payload
    lock_system(session, a.org_id, payload["system_id"])
    # A blocking gate is a commercial boundary, not a label. Without the capability
    # a tenant may still observe and warn: the underlying security truth is
    # identical, only the authority to stop a candidate is withheld.
    if body.policy.mode == "BLOCK" or "BLOCK" in body.policy.property_modes.values():
        from .commercial import require_capability

        require_capability(session, a.org_id, "enforcement.ci")
    member = session.get(Membership, (a.org_id, a.user_id))
    if not member or member.role not in SECURITY:
        raise HTTPException(403, "Release issuer no longer has security authority")
    assessment = assess_plan(session, a.org_id, payload)
    props = _properties(session, a.org_id, payload["system_id"])
    if set(body.policy.property_modes) - {str(p.id) for p in props}:
        raise HTTPException(422, "Policy refers to properties outside this system")
    exceptions = active_exceptions(session, a, plan, body.exception_ids)
    exempt = {pid for e in exceptions for pid in e["property_ids"]}
    failures = _candidate_failures(session, a.org_id, payload["system_id"], payload["candidate"], payload["fingerprint"])
    rows = []
    for prop in props:
        pid = str(prop.id)
        eid = assessment["selected_evidence"].get(pid)
        evidence = get_record(session, a.org_id, eid, "evidence_record") if eid else None
        reasons = [r for d in assessment["invalidations"] if d["property_id"] == pid
                   and (not eid or d["evidence_id"] == eid) for r in d["reasons"]]
        underlying = "ALLOW" if evidence else "BLOCK"
        if pid in failures:
            underlying = "BLOCK"
            reasons.append("Confirmed or unresolved adverse evidence exists for this exact candidate")
        mode = body.policy.property_modes.get(pid, body.policy.mode)
        action = "ALLOW" if underlying == "ALLOW" else "BLOCK" if mode == "BLOCK" and pid not in exempt else "WARN"
        rows.append({
            "property_id": pid, "title": prop.payload.get("title"), "evidence_id": eid,
            "validity": "STILL_VALID" if evidence else "UNKNOWN",
            "security_verdict": "FAIL" if pid in failures else evidence.payload["security_verdict"] if evidence else "INCONCLUSIVE",
            "task_outcome": evidence.payload["task_outcome"] if evidence else "UNKNOWN",
            "release_action": action, "underlying_action": underlying, "mode": mode,
            "exception_applied": pid in exempt and underlying == "BLOCK",
            "adverse_run_ids": failures.get(pid, []),
            "reasons": sorted(set(reasons)) or ["No evidence establishes this property for the candidate"],
        })
    scope_changed = set(payload["scope_property_ids"]) != set(assessment["scope_property_ids"])
    underlying = "ALLOW" if rows and all(r["underlying_action"] == "ALLOW" for r in rows) else "BLOCK"
    action = "BLOCK" if any(r["release_action"] == "BLOCK" for r in rows) else "ALLOW" if rows and all(r["release_action"] == "ALLOW" for r in rows) else "WARN"
    if scope_changed or not assessment["candidate_bound"] or not rows:
        underlying = "BLOCK"
        action = "BLOCK" if body.policy.mode == "BLOCK" else "WARN"
    identifier = uuid4()
    decision = {
        "id": str(identifier), "organization_id": str(a.org_id), "system_id": payload["system_id"],
        "plan_id": str(plan.id), "candidate": payload["candidate"], "fingerprint": payload["fingerprint"],
        "candidate_fingerprint_digest": payload["candidate_fingerprint_digest"],
        "evaluated_at": assessment["evaluated_at"], "policy": body.policy.model_dump(mode="json"),
        "properties": rows, "exceptions": exceptions, "release_action": action,
        "underlying_action": underlying, "scope_changed": scope_changed,
        "gate_enforced": body.policy.mode == "BLOCK" or any(v == "BLOCK" for v in body.policy.property_modes.values()),
        "status_label": "BLOCK overridden by authorized exception" if any(r["exception_applied"] for r in rows) else action,
        "evaluated_by": str(a.user_id), "algorithm_version": ALGORITHM,
        "limitations": assessment["limitations"] + [
            "This is an immutable historical decision; refresh evidence and authorization before a later deployment.",
            "WARN and OBSERVE preserve failed/unknown results and do not certify a safe release.",
        ] + (["Approved property scope changed after planning; create a new plan"] if scope_changed else []),
    }
    if machine_authority is not None:
        decision["machine_authority"] = machine_authority
    from .release_signing import sign_decision
    receipt = sign_decision(decision)
    receipt_row = add_record(session, a.org_id, "assurance_receipt", {
        "system_id": payload["system_id"], "release_id": str(identifier), **receipt,
    }, {"plan": plan.id})
    release = add_record(session, a.org_id, "release", {
        **decision, "receipt_id": str(receipt_row.id), "decision_digest": digest(decision),
    }, {"plan": plan.id, "receipt": receipt_row.id, "system": payload["system_id"],
        **{f"evidence:{i}": r["evidence_id"] for i, r in enumerate(rows) if r["evidence_id"]},
        **{f"exception:{i}": e["id"] for i, e in enumerate(exceptions)}}, record_id=identifier)
    audit(session, a.org_id, a.user_id, "release.decided", release.id)
    from .integrations.github_release import enqueue_release_checks

    enqueue_release_checks(session, a.org_id, release)
    return serialize(release)


def current_release_assessment(session, org_id, release):
    """Revalidate historical authorization without rewriting or upgrading its receipt."""
    value = release.payload
    plan = get_record(session, org_id, value["plan_id"], "proof_plan")
    lock_system(session, org_id, value["system_id"])
    current_ids = {str(p.id) for p in _properties(session, org_id, value["system_id"])}
    scope_changed = current_ids != {p["property_id"] for p in value["properties"]}
    failures = _candidate_failures(session, org_id, value["system_id"], value["candidate"], value["fingerprint"])
    exempt, reasons = set(), []
    a = Actor(UUID(value["evaluated_by"]), org_id, "security", "", "", "", "historical_read")
    try:
        exceptions = active_exceptions(session, a, plan, [e["id"] for e in value["exceptions"]])
        exempt = {pid for e in exceptions for pid in e["property_ids"]}
    except HTTPException:
        reasons.append("A recorded exception is expired, revoked or no longer has an active approver")
    rows = []
    for original in value["properties"]:
        row = dict(original)
        evidence = get_record(session, org_id, row["evidence_id"], "evidence_record") if row["evidence_id"] else None
        current = _assess_evidence(session, org_id, evidence, value["candidate"], value["fingerprint"], now()) if evidence else None
        useful = bool(current and current["usable"] and row["property_id"] not in failures)
        mode = value["policy"]["property_modes"].get(row["property_id"], value["policy"]["mode"])
        row["underlying_action"] = "ALLOW" if useful else "BLOCK"
        row["validity"] = current["status"] if current else "UNKNOWN"
        row["security_verdict"] = "FAIL" if row["property_id"] in failures else evidence.payload["security_verdict"] if evidence else "INCONCLUSIVE"
        row["adverse_run_ids"] = failures.get(row["property_id"], [])
        row["release_action"] = "ALLOW" if useful else "BLOCK" if mode == "BLOCK" and row["property_id"] not in exempt else "WARN"
        row["reasons"] = (current or {}).get("reasons", ["No qualified evidence was recorded"])
        if row["adverse_run_ids"]:
            row["reasons"].append("Retained adverse evidence prevents current release authorization")
        rows.append(row)
    action = "BLOCK" if any(r["release_action"] == "BLOCK" for r in rows) else "WARN" if any(r["release_action"] == "WARN" for r in rows) else "ALLOW"
    if scope_changed or not rows:
        reasons.append("Current approved properties differ from the signed release scope")
        action = "BLOCK" if value["gate_enforced"] else "WARN"
    from .release_machine import current_machine_authority
    authority_reasons = current_machine_authority(session, org_id, value)
    if authority_reasons:
        reasons.extend(authority_reasons)
        action = "BLOCK" if value["gate_enforced"] else "WARN"
    rank = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}
    action = max((action, value["release_action"]), key=rank.__getitem__)
    underlying = "ALLOW" if rows and not scope_changed and not authority_reasons and all(r["underlying_action"] == "ALLOW" for r in rows) else "BLOCK"
    return {"release_action": action, "underlying_action": underlying,
            "current": action == value["release_action"] and underlying == value["underlying_action"] and not reasons,
            "scope_changed": scope_changed, "reasons": reasons, "properties": rows,
            "checked_at": now().isoformat()}


def _list(kind, system_id, limit, cursor, a):
    with transaction(a.user_id, a.org_id) as session:
        if system_id:
            get_record(session, a.org_id, system_id, "system")
        rows, pagination = page(session, a.org_id, kind, limit=limit, cursor=cursor, system_id=system_id)
        return {"items": [serialize(r) for r in rows], "pagination": pagination}


def _detail(kind, identifier, a):
    with transaction(a.user_id, a.org_id) as session:
        row = get_record(session, a.org_id, identifier, kind)
        value = serialize(row)
        if kind == "evidence_record":
            value["proof_scope"] = serialize(get_record(session, a.org_id, row.payload["proof_scope_id"], "proof_scope"))
            value["raw_retention_status"] = "Consult each capture's expiry; retained evidence metadata is immutable"
        if kind == "release":
            value["receipt"] = serialize(get_record(session, a.org_id, row.payload["receipt_id"], "assurance_receipt"))
            value["current"] = current_release_assessment(session, a.org_id, row)
        return value


# Distinct public routes retain typed validation and tenant-bound keyset pagination.
@router.get("/releases")
def releases(system_id: UUID | None = None, limit: int = Query(50, ge=1, le=200), cursor: str | None = None, a: Actor = Depends(actor)):
    return _list("release", system_id, limit, cursor, a)


@router.get("/releases/{identifier}")
def release_detail(identifier: UUID, a: Actor = Depends(actor)):
    return _detail("release", identifier, a)


@router.get("/releases/{identifier}/receipt")
def release_receipt(identifier: UUID, a: Actor = Depends(actor)):
    return _detail("release", identifier, a)["receipt"]


@router.get("/evidence-ledger")
def evidence_ledger(system_id: UUID | None = None, limit: int = Query(50, ge=1, le=200), cursor: str | None = None, a: Actor = Depends(actor)):
    return _list("evidence_record", system_id, limit, cursor, a)


@router.get("/evidence-ledger/{identifier}")
def evidence_detail(identifier: UUID, a: Actor = Depends(actor)):
    return _detail("evidence_record", identifier, a)


@router.get("/proof-scopes/{identifier}")
def scope_detail(identifier: UUID, a: Actor = Depends(actor)):
    return _detail("proof_scope", identifier, a)


@router.get("/change-sets")
def changes(system_id: UUID | None = None, limit: int = Query(50, ge=1, le=200), cursor: str | None = None, a: Actor = Depends(actor)):
    return _list("change_set", system_id, limit, cursor, a)


@router.get("/proof-plans")
def plans(system_id: UUID | None = None, limit: int = Query(50, ge=1, le=200), cursor: str | None = None, a: Actor = Depends(actor)):
    return _list("proof_plan", system_id, limit, cursor, a)


@router.get("/proof-plans/{identifier}")
def plan_detail(identifier: UUID, a: Actor = Depends(actor)):
    return _detail("proof_plan", identifier, a)


@router.get("/release-exceptions")
def exceptions(system_id: UUID | None = None, limit: int = Query(50, ge=1, le=200), cursor: str | None = None, a: Actor = Depends(actor)):
    return _list("release_exception", system_id, limit, cursor, a)


class PlanExecution(Input):
    runs: list[RunInput] = Field(min_length=1, max_length=100)


@router.post("/proof-plans/{identifier}/execute", status_code=202)
def execute_plan(identifier: UUID, body: PlanExecution, background: BackgroundTasks, a: Actor = Depends(actor)):
    require(a)
    from .api import create_run
    with transaction(a.user_id, a.org_id) as session:
        plan = get_record(session, a.org_id, identifier, "proof_plan")
        system_id = plan.payload["system_id"]
        obligations = {v["property_id"]: v for v in plan.payload["obligations"]}
        supplied = [str(r.property_id) for r in body.runs]
        if len(set(supplied)) != len(supplied) or set(supplied) != set(obligations):
            raise HTTPException(422, "Execution must cover exactly one run per planned obligation")
        for run in body.runs:
            if run.qualification_case:
                raise HTTPException(422, "Qualification controls cannot discharge release obligations")
            item = obligations[str(run.property_id)]
            if str(run.system_id) != plan.payload["system_id"] or _candidate(run.candidate or {}) != _candidate(plan.payload["candidate"]):
                raise HTTPException(422, "Run must identify the plan's exact system and candidate")
            if configuration_digest(run.fingerprint) != plan.payload["candidate_fingerprint_digest"]:
                raise HTTPException(422, "Execution fingerprint must match the planned candidate")
            if run.trials != item["trials_per_variant"] or run.variant_count != item["variant_count"]:
                raise HTTPException(422, "Execution cannot reduce planned trial coverage")
    results, failures = [], []
    for run in body.runs:
        try:
            results.append(create_run(run, background, a))
        except HTTPException as error:
            # Each run has its own durable idempotency and budget transaction.
            # Report accepted work even when another obligation cannot dispatch.
            failures.append({"property_id": str(run.property_id), "status_code": error.status_code,
                "detail": error.detail})
    with transaction(a.user_id, a.org_id) as session:
        row = add_record(session, a.org_id, "proof_execution", {
            "system_id": system_id, "plan_id": str(identifier),
            "run_ids": [r["id"] for r in results],
            "status": "PARTIAL" if failures and results else "REJECTED" if failures else "ACCEPTED",
            "failures": failures,
        }, {"plan": identifier, **{f"run:{i}": r["id"] for i, r in enumerate(results)}})
        audit(session, a.org_id, a.user_id, "proof_plan.executed", row.id)
        response = {"id": str(row.id), "runs": results, "status": row.payload["status"], "failures": failures}
    return response
