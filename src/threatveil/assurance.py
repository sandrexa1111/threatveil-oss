"""Bounded canaries and selection audits over existing, organization-bound evidence."""

from datetime import timedelta
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field, model_validator
from sqlalchemy import select

from .auth import Actor, actor, require
from .core.contracts import SystemFingerprint, digest
from .core.regression import compare_runs
from .db import Record, add_record, audit, get_record, now, serialize, transaction
from .schemas import Input

router = APIRouter(prefix="/v1", tags=["assurance"])
MAX_EVIDENCE_AGE_HOURS = 24
CLASSIFICATIONS = ("PRESERVED", "STALE", "INCOMPATIBLE", "REGRESSED", "UNKNOWN")


class ExactCandidate(Input):
    type: Literal["application_version", "model_version", "git_commit"]
    id: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=120)
    digest: str = Field(pattern=r"^[0-9a-f]{40,64}$")

    @model_validator(mode="after")
    def content_identity(self):
        if len(self.digest) not in (40, 64) or self.type != "git_commit" and len(self.digest) != 64:
            raise ValueError("Application/model candidates require a SHA-256 content digest")
        if self.type == "git_commit" and self.version != self.digest:
            raise ValueError("Git candidate version and content identifier must be identical")
        return self


class CanaryPair(Input):
    baseline_id: UUID
    candidate_run_id: UUID | None = None


class CanaryInput(Input):
    system_id: UUID
    candidate: ExactCandidate
    pairs: list[CanaryPair] = Field(min_length=1, max_length=25)


class SelectionAuditInput(Input):
    impact_id: UUID
    candidate: ExactCandidate
    candidate_run_ids: list[UUID] = Field(default_factory=list, max_length=500)


def _candidate(value):
    return {key: value.get(key) for key in ("type", "id", "version", "digest")}


def _scope(session, org, system_id, run, property_id=None, target_id=None):
    if (
        run.payload.get("system_id") != str(system_id)
        or (property_id and run.payload.get("property_id") != str(property_id))
        or (target_id and run.payload.get("target_id") != str(target_id))
    ):
        raise HTTPException(422, "Evidence belongs to a different system, property or target")
    target = get_record(session, org, run.payload["target_id"], "target")
    prop = get_record(session, org, run.payload["property_id"], "property")
    if target.payload["system_id"] != str(system_id) or prop.payload["system_id"] != str(system_id):
        raise HTTPException(422, "Evidence relationships do not match the requested system")
    return prop


def _run_state(session, org, run, candidate):
    from .api import authorized_target, run_view
    from .observers import active_observer
    from .adverse_memory import adverse_memory

    result = run_view(session, org, run)
    reasons, stale = [], False
    try:
        authorized_target(session, org, run.payload["target_id"])
        if run.payload.get("observer_id"):
            active_observer(session, org, run.payload["observer_id"])
    except HTTPException:
        stale = True
        reasons.append("Target authorization or reviewed observer is no longer active")
    age = now() - run.created_at
    if age < timedelta(0) or age > timedelta(hours=MAX_EVIDENCE_AGE_HOURS):
        stale = True
        reasons.append("Candidate evidence falls outside the explicit 24-hour assurance window")
    exact = _candidate(run.payload.get("candidate") or {}) == candidate
    if not exact:
        reasons.append("Run does not identify the exact requested candidate")
    qualified = bool(
        result.get("qualification", {}).get("qualified")
        and result.get("candidate_observed") is True
        and not run.payload.get("qualification_case")
    )
    if not qualified:
        reasons.append("Qualified observation of the exact candidate is unavailable")
    complete = bool(
        result.get("status") == "COMPLETED"
        and result.get("execution_status") == "COMPLETED"
        and result.get("coverage_complete") is True
        and result.get("security_verdict") in {"PASS", "FAIL"}
    )
    if not complete:
        reasons.append("Assigned candidate execution is incomplete or inconclusive")
    memory = adverse_memory(session, org, run, result)
    if memory["blocked"]:
        reasons.append(
            "Another capture records a confirmed or unresolved failure of this same scoped artifact; a successful retry cannot clear it"
        )
    return result, {
        "stale": stale,
        "exact": exact,
        "qualified": qualified,
        "complete": complete,
        "known_failure": result.get("security_verdict") == "FAIL" or bool(memory["run_ids"]),
        "adverse_memory": memory,
        "reasons": reasons,
    }


def _action(classification, policy, known_failure=False):
    if known_failure or classification == "REGRESSED":
        return "BLOCK"
    if classification == "PRESERVED":
        return "ALLOW"
    return "BLOCK" if policy == "BLOCK" else "WARN"


def _summary(rows):
    complete = bool(rows) and all(
        row["classification"] in {"PRESERVED", "REGRESSED", "FAILED"} for row in rows
    )
    action = (
        "BLOCK"
        if any(row["release_action"] == "BLOCK" for row in rows)
        else (
            "ALLOW"
            if rows and all(row["classification"] == "PRESERVED" for row in rows)
            else "WARN"
        )
    )
    return {
        "rows": rows,
        "counts": {
            status: sum(row["classification"] == status for row in rows)
            for status in (*CLASSIFICATIONS, "FAILED")
        },
        "complete": complete,
        "release_action": action,
        "checked_at": now().isoformat(),
        "max_evidence_age_hours": MAX_EVIDENCE_AGE_HOURS,
        "limitations": [
            "Assessment covers only the explicitly recorded property scope and exact candidate.",
            "Current means current authorization and recent observed evidence; no live deployment or opaque provider internals are inferred.",
            "This assessment launches no execution and does not replace a separately authorized GitHub release gate.",
        ],
    }


def assess_canary(session, org, payload):
    get_record(session, org, payload["system_id"], "system")
    rows, seen = [], set()
    candidate = _candidate(payload["candidate"])
    for pair in payload["pairs"]:
        baseline = get_record(session, org, pair["baseline_id"], "baseline")
        if baseline.payload["system_id"] != payload["system_id"]:
            raise HTTPException(422, "Baseline belongs to a different system")
        prop_id = baseline.payload["property_id"]
        if prop_id in seen:
            raise HTTPException(422, "A property cannot be counted more than once")
        seen.add(prop_id)
        previous = get_record(session, org, baseline.payload["run_id"], "run")
        prop = _scope(
            session, org, payload["system_id"], previous, prop_id, baseline.payload["target_id"]
        )
        classification, reasons, failure = (
            "UNKNOWN",
            ["No candidate run was supplied for this historical property"],
            False,
        )
        comparison = None
        if pair.get("candidate_run_id"):
            run = get_record(session, org, pair["candidate_run_id"], "run")
            _scope(session, org, payload["system_id"], run, prop_id, baseline.payload["target_id"])
            result, state = _run_state(session, org, run, candidate)
            from .api import run_view

            comparison = compare_runs(run_view(session, org, previous), result)
            reasons, failure = state["reasons"], state["known_failure"]
            if state["stale"]:
                classification = "STALE"
            elif not state["exact"] or not comparison["compatible"]:
                classification = "INCOMPATIBLE"
                reasons += comparison.get("reasons", []) if not comparison["compatible"] else []
            elif not state["qualified"] or not state["complete"]:
                classification = "UNKNOWN"
            elif state["adverse_memory"]["blocked"]:
                # The selected run is a PASS; do not invent a baseline-compatible
                # regression from another run's potentially different stimulus.
                classification = "UNKNOWN"
            elif failure or comparison.get("regression"):
                classification = "REGRESSED"
            elif (
                result.get("fix_eligible") is True
                and result.get("task_outcome") == "SUCCESS"
                and result.get("release_action") == "ALLOW"
            ):
                classification = "PRESERVED"
                reasons.append(
                    "Historical property is preserved for the qualified, useful candidate execution"
                )
            else:
                reasons.append("A useful, authorized candidate release has not been established")
        rows.append(
            {
                "property_id": prop_id,
                "baseline_id": str(baseline.id),
                "candidate_run_id": pair.get("candidate_run_id"),
                "classification": classification,
                "reasons": reasons,
                "known_security_failure": failure,
                "comparison": comparison,
                "adverse_memory": state["adverse_memory"] if pair.get("candidate_run_id") else None,
                "release_action": _action(
                    classification,
                    prop.payload["definition"].get("release_policy"),
                    failure
                    or bool(pair.get("candidate_run_id") and state["adverse_memory"]["blocked"]),
                ),
            }
        )
    return {**_summary(rows), "scope_property_ids": sorted(seen)}


def _properties(session, org, system_id):
    return list(
        session.scalars(
            select(Record).where(
                Record.organization_id == org,
                Record.kind == "property",
                Record.payload["system_id"].astext == str(system_id),
                Record.payload["approved"].astext == "true",
            )
        )
    )


def _configuration(fingerprint):
    value = SystemFingerprint.model_validate(fingerprint)
    return sorted((c.type, c.id, c.version or "", c.digest or "") for c in value.components)


def assess_selection(session, org, payload):
    impact = get_record(session, org, payload["impact_id"], "impact")
    system_id = impact.payload["system_id"]
    get_record(session, org, system_id, "system")
    change = get_record(session, org, impact.payload["change_id"], "change")
    selected = [item["property_id"] for item in impact.payload["selected"]]
    excluded = [item["property_id"] for item in impact.payload["excluded"]]
    full = selected + excluded
    if not full or len(full) > 500 or len(set(full)) != len(full):
        raise HTTPException(422, "Impact must contain one complete, bounded property partition")
    properties = _properties(session, org, system_id)
    historical = {str(prop.id) for prop in properties if prop.created_at <= impact.created_at}
    scope_valid = historical == set(full)
    new_properties = sorted({str(prop.id) for prop in properties} - historical)
    mapped = {}
    candidate = _candidate(payload["candidate"])
    for identifier in payload["candidate_run_ids"]:
        run = get_record(session, org, identifier, "run")
        _scope(session, org, system_id, run)
        prop_id = run.payload["property_id"]
        if prop_id not in full or prop_id in mapped:
            raise HTTPException(
                422, "Candidate runs must uniquely cover properties from this impact scope"
            )
        mapped[prop_id] = run
    expected_config = _configuration(change.payload["candidate"])
    rows, missed, selected_failures, missing = [], [], [], []
    for prop_id in full:
        prop = get_record(session, org, prop_id, "property")
        if prop.payload["system_id"] != system_id:
            raise HTTPException(422, "Impact contains a property from another system")
        run = mapped.get(prop_id)
        classification, reasons, verdict, failure = (
            "UNKNOWN",
            ["Full-suite candidate evidence is missing"],
            None,
            False,
        )
        if run:
            result, state = _run_state(session, org, run, candidate)
            reasons, verdict, failure = (
                state["reasons"],
                result.get("security_verdict"),
                state["known_failure"],
            )
            observed = SystemFingerprint.model_validate(result.get("fingerprint") or {})
            fingerprint_matches = bool(
                expected_config
                and _configuration(observed.model_dump(mode="json")) == expected_config
                and all(c.provenance == "OBSERVED" for c in observed.components)
            )
            if state["stale"]:
                classification = "STALE"
            elif not state["exact"] or not fingerprint_matches:
                classification = "INCOMPATIBLE"
                reasons.append(
                    "Observed candidate configuration does not match the impact's complete expected fingerprint"
                )
            elif not state["qualified"] or not state["complete"]:
                classification = "UNKNOWN"
            elif failure:
                classification = "FAILED"
                (missed if prop_id in excluded else selected_failures).append(prop_id)
            elif state["adverse_memory"]["blocked"]:
                classification = "UNKNOWN"
            elif result.get("fix_eligible") is True and result.get("release_action") == "ALLOW":
                classification = "PRESERVED"
                reasons.append(
                    "Qualified full-suite execution found no prohibited outcome for this property"
                )
        else:
            missing.append(prop_id)
        rows.append(
            {
                "property_id": prop_id,
                "candidate_run_id": str(run.id) if run else None,
                "selection": "SELECTED" if prop_id in selected else "EXCLUDED",
                "classification": classification,
                "security_verdict": verdict,
                "reasons": reasons,
                "adverse_memory": state["adverse_memory"] if run else None,
                "release_action": _action(
                    classification,
                    prop.payload["definition"].get("release_policy"),
                    failure or bool(run and state["adverse_memory"]["blocked"]),
                ),
            }
        )
    result = _summary(rows)
    if not scope_valid or new_properties:
        result.update(complete=False, release_action="BLOCK")
        result["limitations"].append(
            "Impact scope is incomplete or has changed; generate a new impact and audit the entire suite"
        )
    return {
        **result,
        "full_suite_property_ids": sorted(full),
        "missing_property_ids": missing,
        "missed_failure_property_ids": missed,
        "selected_failure_property_ids": selected_failures,
        "impact_scope_valid": scope_valid,
        "new_property_ids": new_properties,
        "limitations": result["limitations"]
        + [
            "FAILED is a confirmed property failure, not a historical regression claim; recurrence requires a compatible baseline comparison."
        ],
    }


def _create(session, a, kind, payload, assessment, refs):
    snapshot = assessment(session, a.org_id, payload)
    record = add_record(
        session,
        a.org_id,
        kind,
        {**payload, "snapshot": snapshot, "snapshot_digest": digest(snapshot)},
        refs,
    )
    audit(session, a.org_id, a.user_id, kind + ".created", record.id)
    return {**serialize(record), "current": snapshot}


@router.post("/canaries", status_code=201)
def create_canary(body: CanaryInput, a: Actor = Depends(actor)):
    require(a)
    payload = body.model_dump(mode="json")
    refs = {"system": body.system_id}
    for index, pair in enumerate(body.pairs):
        refs[f"baseline:{index}"] = pair.baseline_id
        if pair.candidate_run_id:
            refs[f"run:{index}"] = pair.candidate_run_id
    with transaction(a.user_id, a.org_id) as session:
        return _create(session, a, "canary", payload, assess_canary, refs)


@router.post("/selection-audits", status_code=201)
def create_selection_audit(body: SelectionAuditInput, a: Actor = Depends(actor)):
    require(a)
    with transaction(a.user_id, a.org_id) as session:
        impact = get_record(session, a.org_id, body.impact_id, "impact")
        payload = {**body.model_dump(mode="json"), "system_id": impact.payload["system_id"]}
        refs = {
            "impact": body.impact_id,
            "system": impact.payload["system_id"],
            **{f"run:{i}": identifier for i, identifier in enumerate(body.candidate_run_ids)},
        }
        return _create(session, a, "selection_audit", payload, assess_selection, refs)


def _detail(identifier, kind, assess, a):
    with transaction(a.user_id, a.org_id) as session:
        record = get_record(session, a.org_id, identifier, kind)
        return {**serialize(record), "current": assess(session, a.org_id, record.payload)}


@router.get("/canaries/{identifier}")
def get_canary(identifier: UUID, a: Actor = Depends(actor)):
    return _detail(identifier, "canary", assess_canary, a)


@router.get("/selection-audits/{identifier}")
def get_selection_audit(identifier: UUID, a: Actor = Depends(actor)):
    return _detail(identifier, "selection_audit", assess_selection, a)


def _list(kind, system_id, limit, a):
    with transaction(a.user_id, a.org_id) as session:
        query = select(Record).where(Record.organization_id == a.org_id, Record.kind == kind)
        if system_id:
            get_record(session, a.org_id, system_id, "system")
            query = query.where(Record.payload["system_id"].astext == str(system_id))
        rows = session.scalars(query.order_by(Record.created_at.desc()).limit(limit))
        return {"items": [serialize(row) for row in rows], "history_only": True}


@router.get("/canaries")
def list_canaries(
    system_id: UUID | None = None, limit: int = Query(20, ge=1, le=50), a: Actor = Depends(actor)
):
    return _list("canary", system_id, limit, a)


@router.get("/selection-audits")
def list_selection_audits(
    system_id: UUID | None = None, limit: int = Query(20, ge=1, le=50), a: Actor = Depends(actor)
):
    return _list("selection_audit", system_id, limit, a)
