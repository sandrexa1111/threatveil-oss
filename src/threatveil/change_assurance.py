"""Versioned change-assurance projections over the existing immutable evidence kernel.

The enduring subject is a system, not a repository. New schemas reference old
records; neither billing nor a submitted source verdict can establish support.
"""

from datetime import datetime, timedelta
from typing import Literal
from uuid import UUID

from fastapi import HTTPException
from pydantic import Field, model_validator
from sqlalchemy import select

from .assurance import ExactCandidate, _properties
from .core.contracts import SystemFingerprint, digest
from .core.validity import canonical_fingerprint, configuration_digest, change_set
from .db import Record, add_record, get_record, now
from .release_integrity import _all, _candidate_failures, assess_plan, lock_system
from .schemas import Input

PROFILE = "change-assurance/v1"
PROJECTION = "change-assurance-projection/v1"


class Versioned(Input):
    schema_version: Literal["change-assurance/v1"] = PROFILE


class EnvironmentInput(Versioned):
    system_id: UUID
    name: str = Field(min_length=1, max_length=120)
    purpose: Literal["SANDBOX", "STAGING", "PRODUCTION"] = "STAGING"
    boundary: str = Field(min_length=10, max_length=2000)
    owner: str = Field(min_length=1, max_length=200)


class EnvelopeInput(Versioned):
    system_id: UUID
    environment_id: UUID
    principals: list[str] = Field(min_length=1, max_length=50)
    actions: list[str] = Field(min_length=1, max_length=50)
    resources: list[str] = Field(min_length=1, max_length=50)
    constraints: list[str] = Field(min_length=1, max_length=50)
    expires_at: datetime
    supersedes_id: UUID | None = None

    @model_validator(mode="after")
    def expiry_and_bounds(self):
        if self.expires_at.tzinfo is None or not now() < self.expires_at <= now() + timedelta(days=366):
            raise ValueError("Envelope expiry must be aware, future and within 366 days")
        if any(not v.strip() or len(v) > 500 for k in (self.principals, self.actions, self.resources, self.constraints) for v in k):
            raise ValueError("Envelope entries require bounded nonempty text")
        return self


class TargetBindingInput(Versioned):
    system_id: UUID
    environment_id: UUID
    target_id: UUID
    review_note: str = Field(min_length=15, max_length=2000)


class StateInput(Versioned):
    system_id: UUID
    environment_id: UUID
    envelope_id: UUID
    candidate: ExactCandidate
    fingerprint: SystemFingerprint
    evidence_id: UUID | None = None
    coverage: str = Field(min_length=10, max_length=2000)
    unknowns: list[str] = Field(default_factory=list, max_length=100)


class TransitionInput(Versioned):
    system_id: UUID
    environment_id: UUID
    before_state_id: UUID | None = None
    after_state_id: UUID
    transition: Literal["PROPOSED", "OBSERVED"]
    change_type: str = Field(min_length=1, max_length=80)
    source_change_id: UUID | None = None
    reason: str = Field(min_length=10, max_length=2000)


class RelationshipInput(Versioned):
    system_id: UUID
    environment_id: UUID
    source_id: UUID
    target_id: UUID
    relationship: Literal["depends_on", "can_affect", "acts_as", "delegates_to", "supports", "contradicts"]
    review_note: str = Field(min_length=15, max_length=2000)


def scoped(session, org, identifier, kind, system_id, environment_id=None):
    row = get_record(session, org, identifier, kind)
    if row.payload.get("system_id") != str(system_id) or (
        environment_id and row.payload.get("environment_id") != str(environment_id)
    ):
        raise HTTPException(422, "Record belongs to a different system or environment")
    return row


def history(session, org, kind, system_id, environment_id=None):
    query = select(Record).where(Record.organization_id == org, Record.kind == kind,
        Record.payload["system_id"].astext == str(system_id))
    if environment_id:
        query = query.where(Record.payload["environment_id"].astext == str(environment_id))
    return list(session.scalars(query.order_by(Record.created_at.desc(), Record.id.desc())))


def save_environment(session, org, body, user):
    get_record(session, org, body.system_id, "system")
    lock_system(session, org, body.system_id)
    from .commercial import require_environment_capacity
    require_environment_capacity(session, org, body.system_id)
    return add_record(session, org, "environment", {**body.model_dump(mode="json"),
        "declared_by": str(user), "provenance": "DECLARED"}, {"system": body.system_id})


def save_envelope(session, org, body, user):
    scoped(session, org, body.environment_id, "environment", body.system_id)
    lock_system(session, org, body.system_id)
    refs = {"system": body.system_id, "environment": body.environment_id}
    if body.supersedes_id:
        prior = scoped(session, org, body.supersedes_id, "permission_envelope", body.system_id, body.environment_id)
        latest = history(session, org, "permission_envelope", body.system_id, body.environment_id)
        if latest and latest[0].id != prior.id:
            raise HTTPException(409, "Permission envelope changed; refresh before editing")
        refs["supersedes"] = prior.id
    elif history(session, org, "permission_envelope", body.system_id, body.environment_id):
        raise HTTPException(409, "An envelope exists; provide its supersedes_id")
    payload = {**body.model_dump(mode="json"), "reviewed_by": str(user),
               "authority_basis": "CUSTOMER_ACCEPTED", "grants_permissions": False,
               "policy_epoch": len(history(session, org, "permission_envelope", body.system_id, body.environment_id)) + 1}
    payload["envelope_digest"] = digest(payload)
    return add_record(session, org, "permission_envelope", payload, refs)


def save_state(session, org, body, user):
    environment = scoped(session, org, body.environment_id, "environment", body.system_id)
    envelope = scoped(session, org, body.envelope_id, "permission_envelope", body.system_id, body.environment_id)
    lock_system(session, org, body.system_id)
    fingerprint = canonical_fingerprint(body.fingerprint)
    candidate = body.candidate.model_dump(mode="json")
    refs = {"system": body.system_id, "environment": body.environment_id, "envelope": body.envelope_id}
    observed, expiry, target_id = False, None, None
    if body.evidence_id:
        evidence = scoped(session, org, body.evidence_id, "evidence_record", body.system_id)
        value = evidence.payload
        if value["candidate"] != candidate or value["fingerprint_digest"] != configuration_digest(fingerprint):
            raise HTTPException(422, "Evidence does not observe this exact candidate and state")
        bindings = history(session, org, "environment_target_binding", body.system_id, body.environment_id)
        if not any(b.payload["target_id"] == value["target_id"] for b in bindings):
            raise HTTPException(409, "Review the target's environment binding before using its observation")
        # A qualified test establishes its bounded test destination, not what is serving production.
        observed = bool(value["qualified"] and value["candidate_observed"] and environment.payload["purpose"] != "PRODUCTION")
        expiry, target_id = value["expires_at"], value["target_id"]
        refs["evidence"] = evidence.id
    payload = {**body.model_dump(mode="json"), "fingerprint": fingerprint,
        "candidate": candidate, "fingerprint_digest": configuration_digest(fingerprint),
        "envelope_digest": envelope.payload["envelope_digest"],
        "provenance": "QUALIFIED_TEST_EXECUTION" if observed else "DECLARED",
        "target_id": target_id, "observation_expires_at": expiry,
        "running_deployment_identified": False, "recorded_by": str(user),
        "limitations": ["A repository revision is not a deployed system state.",
                        "Qualified execution identifies the tested destination, not an unobserved production deployment."]}
    payload["state_digest"] = digest({"schema_version": PROFILE, "organization_id": str(org),
        "system_id": str(body.system_id), "environment_id": str(body.environment_id),
        "envelope_digest": envelope.payload["envelope_digest"], "candidate": candidate,
        "fingerprint_digest": payload["fingerprint_digest"], "coverage": body.coverage,
        "unknowns": body.unknowns})
    return add_record(session, org, "system_state", payload, refs)


def save_transition(session, org, body, user):
    after = scoped(session, org, body.after_state_id, "system_state", body.system_id, body.environment_id)
    lock_system(session, org, body.system_id)
    refs = {"system": body.system_id, "environment": body.environment_id, "after": after.id}
    previous = {"components": []}
    if body.before_state_id:
        before = scoped(session, org, body.before_state_id, "system_state", body.system_id, body.environment_id)
        previous = before.payload["fingerprint"]
        refs["before"] = before.id
    if body.source_change_id:
        source = scoped(session, org, body.source_change_id, "source_change", body.system_id, body.environment_id)
        refs["source"] = source.id
    delta = change_set(previous, after.payload["fingerprint"])
    impacts = []
    for prop in _properties(session, org, body.system_id):
        dependencies = set(prop.payload["definition"].get("dependencies", []))
        changed = sorted(dependencies & {c["component"] for c in delta["changes"]})
        impacts.append({"property_id": str(prop.id), "title": prop.payload["title"],
            "changed_dependencies": changed,
            "impact": "REASSESS" if changed or not dependencies else "ANCHOR_REQUIRED",
            "reason": "Reviewed dependency changed" if changed else
                      "No changed declared dependency; fresh candidate anchoring and scope coverage remain required"})
    return add_record(session, org, "change_event", {**body.model_dump(mode="json"),
        "recorded_by": str(user), "prevention_claim": False, "delta": delta, "impacts": impacts}, refs)


def save_mapping(session, org, user, *, system_id, environment_id, installation_id, subject, maps_to,
                 review_note, authority_basis="CUSTOMER_REVIEWED"):
    """Record a reviewed statement that a named source subject corresponds to claim dependencies.

    A mapping narrows which claims a later source change reaches. It never discharges
    a change, qualifies a source, grants a permission or maps a fact the source has
    not reported. Mappings are append-only; the latest per subject applies.
    """
    from .source_semantics import MCP_PARTS, pointer

    get_record(session, org, system_id, "system")
    scoped(session, org, environment_id, "environment", system_id)
    installation = get_record(session, org, installation_id, "connector_installation")
    if (installation.payload["system_id"] != str(system_id)
            or installation.payload["environment_id"] != str(environment_id)):
        raise HTTPException(422, "Source installation belongs to a different system or environment")
    lock_system(session, org, system_id)
    reviewed = {d for p in _properties(session, org, system_id) for d in p.payload["definition"].get("dependencies", [])}
    # Dependencies a customer declared for a not-yet-verified claim may also be named. Such
    # a mapping narrows only declared impact; executable claims keep their own reviewed set.
    reviewed |= {d for c in history(session, org, "claim_definition", system_id) if not c.payload.get("property_id")
                 for d in c.payload.get("declared_dependencies", [])}
    targets = sorted(set(maps_to))
    if not targets or not set(targets) <= reviewed:
        raise HTTPException(422, "Map only to reviewed dependencies of approved claims")
    known = {pointer("mcp", part) for part in MCP_PARTS} if installation.payload["connector_id"] == "mcp" else set()
    for batch in history(session, org, "source_batch", system_id, environment_id):
        if batch.payload.get("installation_id") == str(installation_id):
            known |= set(batch.payload.get("components") or {})
            known |= set((batch.payload.get("facts") or {}).get("authorization") or {})
    if subject not in known:
        raise HTTPException(422, "The subject must name a fact this source has reported")
    return add_record(session, org, "dependency_mapping", {
        "schema_version": PROFILE, "system_id": str(system_id), "environment_id": str(environment_id),
        "installation_id": str(installation_id), "subject": subject, "maps_to": targets,
        "review_note": review_note, "reviewed_by": str(user), "authority_basis": authority_basis,
        "grants_permissions": False, "discharges_changes": False},
        {"system": system_id, "environment": environment_id, "installation": installation_id})


def source_change_reconciled(change, captured_components, reviewed_dependencies, after_components,
                             *, synthetic_fixture=False):
    """A new test date cannot make omitted external state disappear.

    The synthetic package can discharge an imported hint only within its explicit
    fixture scope. Other sources require reviewed dependencies and observed exact
    after-values. This never grants source qualification or deployment authority.
    """
    if synthetic_fixture and change.get("acquisition") == "IMPORTED":
        return True
    changed = set(change.get("changed_components", []))
    if not changed or change.get("change_kind") in {"SOURCE_GAP", "CONNECTOR_CONFIGURATION"}:
        return False
    if not changed <= set(reviewed_dependencies) or not changed <= captured_components.keys():
        return False
    for key in changed:
        actual, expected = captured_components.get(key), after_components.get(key)
        if not actual or not expected or actual.get("provenance") != "OBSERVED":
            return False
        if not actual.get("digest") or actual["digest"] != expected.get("digest"):
            return False
        if actual.get("version") != expected.get("version"):
            return False
    return True


def assurance_obligations(rows, health, environment_reasons):
    """What the operator must do next, derived only from the assessment above.

    This is a restatement of existing semantics for a human reader. It creates no
    policy of its own, never proposes a remediation to a customer system, and
    never converts an unknown into an action ThreatVeil has not established.
    """
    obligations = []
    for row in rows:
        if row["supported"]:
            continue
        if row["security"] == "FAIL":
            kind, reason = "RE_ESTABLISH", "A prohibited outcome was observed and is retained."
        elif row["legitimate_task"] == "FAILURE":
            kind, reason = "RE_ESTABLISH", "The approved useful task did not succeed under this state."
        elif row["applicability"] in {"INVALID", "STALE"}:
            kind, reason = "RE_VERIFY", "Evidence was created for an earlier system state."
        else:
            kind, reason = "CONFIRM", "There is not enough evidence to support this claim."
        obligations.append({"kind": kind, "subject": row["title"], "property_id": row["property_id"],
                            "reason": reason, "detail": row["reasons"][:3]})
    for source in health:
        if source.get("status") == "IMPORTED":
            # An import never claimed a live connection; its provenance is shown with the source.
            continue
        if source.get("status") in {"STALE", "EXPIRED", "FAILED", "UNAVAILABLE"} or not source.get("connected"):
            obligations.append({"kind": "RECONNECT_SOURCE", "subject": source.get("name", source.get("connector_id")),
                                "property_id": None,
                                "reason": "This source is not currently supplying observations.",
                                "detail": list(source.get("limitations", []))[:3]})
    for reason in environment_reasons:
        obligations.append({"kind": "REVIEW", "subject": "Operating boundary", "property_id": None,
                            "reason": reason, "detail": []})
    if not obligations:
        obligations.append({"kind": "NONE", "subject": "This boundary", "property_id": None,
                            "reason": "Every approved claim is supported by evidence that still applies.",
                            "detail": []})
    return obligations


def projection(session, org, state):
    value = state.payload
    system, environment = value["system_id"], value["environment_id"]
    lock_system(session, org, system)
    stamp = now()
    approved = _properties(session, org, system)
    payload = {"system_id": system, "candidate": value["candidate"], "fingerprint": value["fingerprint"],
               "trials_per_variant": 2, "variant_count": 1}
    assessment = assess_plan(session, org, payload)
    reasons = []
    envelope = scoped(session, org, value["envelope_id"], "permission_envelope", system, environment)
    latest = history(session, org, "permission_envelope", system, environment)
    if latest and latest[0].id != envelope.id:
        reasons.append("Consequential authority changed; reassess the current permission envelope")
    if datetime.fromisoformat(envelope.payload["expires_at"]) <= stamp:
        reasons.append("Permission envelope expired")
    if value["provenance"] != "QUALIFIED_TEST_EXECUTION":
        reasons.append("The assessed environment has no qualified exact-state observation")
    if value.get("observation_expires_at") and datetime.fromisoformat(value["observation_expires_at"]) <= stamp:
        reasons.append("The exact-state observation is stale")
    if value["unknowns"]:
        reasons.append("The state has unresolved collection coverage: " + "; ".join(value["unknowns"]))
    covered_actions = {operation for prop in approved for predicate in prop.payload["definition"]["predicates"]
                       for operation in predicate["operations"]}
    if not set(envelope.payload["actions"]) <= covered_actions:
        reasons.append("The permission envelope includes actions without an approved governing security property")
    system_record = get_record(session, org, system, "system")
    if system_record.payload.get("fixture_profile") == "finance-v1" and (
        not set(envelope.payload["principals"]) <= {"synthetic-tenant-a/finance-agent"}
        or not set(envelope.payload["resources"]) <= {"synthetic-tenant-a/vendor-1", "synthetic-tenant-a/invoice-1"}
    ):
        reasons.append("The authority boundary exceeds the subjects covered by the synthetic finance observation package")
    exact = [r for r in _all(session, org, "evidence_record", system)
        if r.payload["candidate"] == value["candidate"]
        and r.payload["fingerprint_digest"] == value["fingerprint_digest"]
        and r.payload["target_id"] == value.get("target_id")]
    failures = _candidate_failures(session, org, system, value["candidate"], value["fingerprint"])
    bindings = {b.payload["target_id"] for b in history(session, org, "environment_target_binding", system, environment)}
    rows = []
    for prop in approved:
        pid = str(prop.id)
        decisions = [d for d in assessment["invalidations"] if d["property_id"] == pid]
        evidence_id = assessment["selected_evidence"].get(pid)
        evidence = get_record(session, org, evidence_id, "evidence_record") if evidence_id else None
        if evidence and (evidence.payload["target_id"] not in bindings or evidence.payload["target_id"] != value.get("target_id")):
            evidence, evidence_id = None, None
        local_reasons = list(reasons)
        if evidence:
            binding_times = [b.created_at for b in history(session, org, "environment_target_binding", system, environment)
                             if b.payload["target_id"] == evidence.payload["target_id"]]
            if evidence.created_at < envelope.created_at or not binding_times or evidence.created_at < min(binding_times):
                local_reasons.append("Evidence predates the approved authority or environment boundary; execute fresh checks")
                evidence, evidence_id = None, None
        same = [r for r in exact if r.payload["property_id"] == pid]
        security = "FAIL" if pid in failures else (same[0].payload["security_verdict"] if same else "INCONCLUSIVE")
        task = "FAILURE" if any(r.payload["task_outcome"] == "FAILURE" for r in same) else (
            same[0].payload["task_outcome"] if same else "UNKNOWN")
        applicability = "CURRENT" if evidence and not local_reasons else "STALE" if any(
            "expir" in reason.lower() or "stale" in reason.lower() for reason in local_reasons
        ) else "INVALID" if any(d["status"] == "VOID" for d in decisions) else "UNKNOWN"
        rows.append({"property_id": pid, "title": prop.payload["title"], "evidence_id": evidence_id,
            "dependencies": prop.payload["definition"].get("dependencies", []), "affected_by": [],
            "applicability": applicability, "security": security, "legitimate_task": task,
            "reasons": sorted(set(local_reasons + [r for d in decisions for r in d["reasons"]])),
            "historical_comparisons": decisions,
            "supported": bool(evidence and not local_reasons and security == "PASS" and task == "SUCCESS")})
    # The source layer can only reduce support. It cannot replace the execution anchor.
    from .connectors import source_health, source_changes
    health = source_health(session, org, system, environment)
    changes = source_changes(session, org, system, environment)
    # No history cutoff is allowed for a security projection. The bounded list
    # above is presentation only; delayed adverse/source events remain relevant.
    source_events = history(session, org, "source_change", system, environment)
    anchor_time = get_record(session, org, value["evidence_id"], "evidence_record").created_at if value.get("evidence_id") else state.created_at
    environment_record = get_record(session, org, environment, "environment")
    target_record = get_record(session, org, value["target_id"], "target") if value.get("target_id") else None
    synthetic_fixture = bool(
        system_record.payload.get("fixture_profile") == "finance-v1"
        and environment_record.payload["purpose"] == "SANDBOX"
        and target_record and target_record.payload.get("fixture_profile") == "finance-v1"
        and target_record.payload.get("adapter") == "synthetic_procurement"
        and value["provenance"] == "QUALIFIED_TEST_EXECUTION"
    )
    captured_components = {f"{c['type']}:{c['id']}": c for c in value["fingerprint"]["components"]}
    reviewed_dependencies = {key for prop in approved for key in prop.payload["definition"].get("dependencies", [])}
    # Reconcile historical A→B→C hints against the latest snapshot known at this
    # evidence boundary, not by incorrectly requiring the current state to equal
    # every intermediate revision. Late-arriving facts still trigger reassessment.
    batch_rows = history(session, org, "source_batch", system, environment)
    batches = {str(batch.id): batch.payload for batch in batch_rows}
    source_watermarks = {}
    for batch in batch_rows:
        if (batch.payload.get("projects_current") and batch.created_at <= state.created_at
            and datetime.fromisoformat(batch.payload["valid_at"]) <= anchor_time):
            source_watermarks.setdefault(batch.payload["installation_id"], batch)
    source_reconciliation = {}
    for event in source_events:
        data = event.payload
        if event.created_at <= state.created_at and datetime.fromisoformat(data["valid_at"]) <= anchor_time:
            batch = source_watermarks.get(data.get("installation_id"))
            source_reconciliation[event.id] = source_change_reconciled(
                data, captured_components, reviewed_dependencies,
                batch.payload["components"] if batch else {}, synthetic_fixture=synthetic_fixture,
            )
    # A reviewed dependency mapping may narrow which claims a later, unreconciled
    # source change reaches. It never discharges the change and never applies to an
    # unnamed fact: a single unmapped subject keeps the conservative meaning.
    from .source_semantics import explain_source_change, mapping_index, scope_change
    mapping_rows = history(session, org, "dependency_mapping", system, environment)
    scoped_changes = {}
    for event in source_events:
        if event.created_at > state.created_at and not source_reconciliation.get(event.id):
            data = event.payload
            explanation = explain_source_change(
                data, batches.get(str(data.get("before_batch_id"))), batches.get(str(data.get("batch_id"))))
            scoped_changes[event.id] = scope_change(
                explanation, mapping_index(mapping_rows, data.get("installation_id")))
    for row in rows:
        dependencies = set(row["dependencies"])
        for source in health:
            if source["status"] != "IMPORTED" and source["freshness"] != "CURRENT":
                row.update(supported=False, applicability="STALE" if source["freshness"] == "STALE" else "UNKNOWN")
                row["reasons"].append(f"Source {source['name']} requires reconciliation: {source['status']}")
        for event in source_events:
            data = event.payload
            late = event.created_at > state.created_at
            valid_at = datetime.fromisoformat(data["valid_at"])
            if source_reconciliation.get(event.id):
                continue
            changed = set(data.get("changed_components", []))
            unresolved_coverage = bool(not changed or changed - reviewed_dependencies
                                       or changed - captured_components.keys())
            if not late and valid_at <= anchor_time:
                row.update(supported=False, applicability="UNKNOWN")
                row["reasons"].append(
                    f"Source change {event.id} requires reviewed coverage and observed after-state; "
                    "fresh execution alone cannot reconcile omitted source facts"
                )
                row["affected_by"].append({"change_id": str(event.id),
                                           "recorded_at": event.created_at.isoformat(), "scoped": False})
                continue
            scope = scoped_changes.get(event.id) or {}
            if scope.get("fully_mapped"):
                changed = set(scope["dependencies"])
                unresolved_coverage = bool(not changed or changed - reviewed_dependencies
                                           or changed - captured_components.keys())
            # Unmapped source facts conservatively expand review; they never
            # silently assert independence from an approved property.
            if unresolved_coverage or not dependencies or changed & dependencies:
                row.update(supported=False, applicability="INVALID" if changed & dependencies else "UNKNOWN")
                narrowed = bool(scope.get("fully_mapped") and not unresolved_coverage)
                row["reasons"].append(
                    f"Source change {event.id} changed {', '.join(sorted(changed & dependencies))}, "
                    "which this claim depends on; fresh evidence is required"
                    if narrowed and changed & dependencies else
                    f"Source change {event.id} needs fresh evidence for this boundary")
                row["affected_by"].append({"change_id": str(event.id),
                                           "recorded_at": event.created_at.isoformat(), "scoped": narrowed})
    for row in rows:
        if row["supported"]:
            row["reasons"] = [
                "Fresh qualified security evidence and a successful legitimate task support this exact state."
            ]
    return {"schema_version": PROFILE, "projection_version": PROJECTION, "as_of": stamp.isoformat(),
        "system_id": system, "environment_id": environment, "state_id": str(state.id),
        "state_digest": value["state_digest"], "envelope_id": value["envelope_id"],
        "assurance_obligations": assurance_obligations(rows, health, reasons),
        "properties": rows, "all_supported": bool(rows and all(r["supported"] for r in rows)),
        "security": "FAIL" if any(r["security"] == "FAIL" for r in rows) else
                    "PASS" if rows and all(r["security"] == "PASS" for r in rows) else "INCONCLUSIVE",
        "legitimate_task": "FAILURE" if any(r["legitimate_task"] == "FAILURE" for r in rows) else
                           "SUCCESS" if rows and all(r["legitimate_task"] == "SUCCESS" for r in rows) else "UNKNOWN",
        "policy_action": "ALLOW" if rows and all(r["supported"] for r in rows) else "REQUIRE_APPROVAL",
        "enforcement": "NOT_REQUESTED", "exception": "NONE", "source_health": health,
        "source_changes": changes, "obligations": assessment["obligations"], "reasons": reasons,
        "limitations": assessment["limitations"] + value["limitations"]}
