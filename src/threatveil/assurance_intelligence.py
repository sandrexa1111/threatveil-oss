"""Assurance intelligence: deterministic, customer-language projections.

Every view here derives from one Context loaded per request from the immutable
record store: the System Map, Authority Map and Authority Diff, change
consequences, evidence currency, the clearance lifecycle, the re-establishment
plan, historical assurance memory, the protected-system summary and the
machine-consumable Assurance Gate. Nothing here writes security truth, calls a
model or infers authority: each relationship cites the record that established it,
and explanations are fixed templates over established facts, so an explanation
can never say more than the records do.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from statistics import median
from uuid import UUID

from fastapi import HTTPException

from .assurance import _properties
from .change_assurance import history, projection
from .change_assurance_api import clearance_status
from .db import Record, get_record, now
from .source_semantics import (
    CONTRACTED, EQUIVALENT, EXPANDED, UNKNOWN, combine, explain_source_change,
    mapping_index, scope_change,
)

INTELLIGENCE = "assurance-intelligence/v1"
GATE_PROFILE = "threatveil-assurance-gate/v1"
GATE_MAX_AGE_SECONDS = 60
PATTERN_MINIMUM = 3

CURRENCY = {
    "CURRENT": "The evidence still describes the system running now.",
    "STALE": "The evidence was created for an earlier system state.",
    "INVALID": "A change since this evidence was produced means it no longer supports the current state.",
    "UNKNOWN": "ThreatVeil does not currently have enough qualified evidence to support this conclusion.",
}
CLAIM_STATUS = {
    "SUPPORTED": "Supported by evidence that still applies",
    "NEEDS_FRESH_EVIDENCE": "Needs fresh evidence",
    "FAILED": "Failed its last verification",
    "UNKNOWN": "Not yet supported",
    "DEFINED": "Defined; not yet executable",
}
CLEARANCE = {
    "CLEARED": ("Cleared", "Every critical claim is supported by evidence that still describes this system."),
    "NEEDS_REASSESSMENT": ("Needs reassessment", "The latest clearance no longer speaks for the system as it is now."),
    "NOT_CLEARED": ("Not cleared", "The latest verification did not support this system's authority."),
    "REVOKED": ("Revoked", "The latest clearance was withdrawn explicitly."),
    "NOT_ESTABLISHED": ("No clearance yet", "No clearance has been issued for this boundary."),
}
CLASSIFICATION_TEXT = {
    EXPANDED: "ThreatVeil classifies this as an authority expansion: the new boundary is not contained in the previous one.",
    CONTRACTED: "ThreatVeil classifies this as an authority contraction: the new boundary is contained in the previous one.",
    EQUIVALENT: "Declared authority is unchanged by this change.",
    UNKNOWN: "ThreatVeil cannot establish the direction of this authority change from the facts it holds.",
}
_VERB_NOUNS = {
    "update": "update", "create": "creation", "delete": "deletion", "read": "read access",
    "write": "write", "send": "sending", "approve": "approval", "issue": "issuance",
    "deploy": "deployment", "modify": "modification", "execute": "execution", "transfer": "transfer",
    "publish": "publishing", "refund": "refund", "change": "change", "purchase": "purchase",
    "provision": "provisioning", "invoke": "invocation",
}
_KINDS = {
    "mcp": "MCP_SERVER", "tool": "TOOL", "permissions": "PERMISSION", "permission": "PERMISSION",
    "policy": "PERMISSION", "identity": "IDENTITY", "service_account": "IDENTITY", "model": "MODEL",
    "prompt": "PROMPT", "system_prompt": "PROMPT", "instructions": "PROMPT", "api": "API",
    "api_schema": "API", "memory": "MEMORY", "data_source": "DATA_SOURCE", "dataset": "DATA_SOURCE",
    "retrieval": "DATA_SOURCE", "deployment": "DEPLOYMENT", "cloud_configuration": "DEPLOYMENT",
    "code": "CODE", "git_commit": "CODE", "application_version": "CODE", "agent": "SUBAGENT",
    "subagent": "SUBAGENT", "connector_configuration": "CONFIGURATION", "graph": "CODE",
}
_PREDICATES = {
    "missing_approval": "{ops} without the required approval",
    "cross_tenant": "{ops} against another tenant's records",
    "unauthorized_action": "{ops} without authorization",
}


def action_label(action):
    """'beneficiary.update' -> 'Beneficiary update'. Presentation only."""
    parts = [p for p in re.split(r"[.:/_\s-]+", str(action)) if p]
    if not parts:
        return str(action)
    if len(parts) > 1 and parts[-1].lower() in _VERB_NOUNS:
        text = " ".join(parts[:-1]) + " " + _VERB_NOUNS[parts[-1].lower()]
    elif len(parts) > 1 and parts[0].lower() in _VERB_NOUNS:
        text = " ".join(parts[1:]) + " " + _VERB_NOUNS[parts[0].lower()]
    else:
        text = " ".join(parts)
    return text[:1].upper() + text[1:]


def component_kind(key):
    return _KINDS.get(str(key).partition(":")[0].lower(), "UNKNOWN")


def _humanize(value):
    text = str(value or "").replace("_", " ").strip().lower()
    return text[:1].upper() + text[1:]


def when(value):
    stamp = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    return stamp.astimezone(timezone.utc).strftime("%d %b %Y %H:%M UTC")


def _iso(value):
    return value.isoformat() if isinstance(value, datetime) else value


def forbidden_outcome(definition):
    parts = []
    for predicate in definition.get("predicates", []):
        operations = " or ".join(action_label(o).lower() for o in predicate.get("operations", [])) or "an action"
        operations = operations[:1].upper() + operations[1:]
        template = _PREDICATES.get(predicate.get("kind"))
        parts.append(template.format(ops=operations) if template else
                     f"A prohibited {_humanize(predicate.get('kind', 'outcome')).lower()} involving {operations.lower()}")
    return "; ".join(parts) or "A prohibited outcome defined by this claim"


def governs(prop):
    return sorted({op for predicate in prop.payload["definition"].get("predicates", [])
                   for op in predicate.get("operations", [])})


def dependencies(prop):
    return list(prop.payload["definition"].get("dependencies", []))


def claim_status(row):
    if row is None:
        return "UNKNOWN"
    if row["supported"]:
        return "SUPPORTED"
    if row["security"] == "FAIL" or row["legitimate_task"] == "FAILURE":
        return "FAILED"
    if row["applicability"] in {"STALE", "INVALID"} or row.get("affected_by"):
        return "NEEDS_FRESH_EVIDENCE"
    return "UNKNOWN"


@dataclass
class Context:
    session: object
    org: UUID
    stamp: datetime
    system: Record
    environments: list
    environment: Record | None = None
    properties: list = field(default_factory=list)
    envelopes: list = field(default_factory=list)
    states: list = field(default_factory=list)
    decisions: list = field(default_factory=list)
    transitions: list = field(default_factory=list)
    source_changes: list = field(default_factory=list)
    batch_rows: list = field(default_factory=list)
    installations: list = field(default_factory=list)
    mappings: list = field(default_factory=list)
    relationships: list = field(default_factory=list)
    status_events: list = field(default_factory=list)
    acknowledgements: list = field(default_factory=list)
    claim_definitions: list = field(default_factory=list)
    passports: list = field(default_factory=list)
    health: list = field(default_factory=list)
    current: dict | None = None
    _status: dict = field(default_factory=dict)
    _explained: dict = field(default_factory=dict)
    _cases: dict = field(default_factory=dict)
    _views: dict = field(default_factory=dict)

    @property
    def state(self):
        return self.states[0] if self.states else None

    @property
    def envelope(self):
        return self.envelopes[0] if self.envelopes else None

    @property
    def rows(self):
        return {r["property_id"]: r for r in (self.current or {}).get("properties", [])}

    @property
    def batch_map(self):
        if not hasattr(self, "_batch_map"):
            self._batch_map = {str(b.id): b.payload for b in self.batch_rows}
        return self._batch_map

    @property
    def installation_map(self):
        return {str(i.id): i for i in self.installations}

    def latest_batches(self):
        latest = {}
        for batch in self.batch_rows:
            if batch.payload.get("projects_current"):
                latest.setdefault(batch.payload["installation_id"], batch)
        return latest

    def tool_names(self):
        names = {}
        for batch in self.batch_rows:
            names.update((batch.payload.get("facts") or {}).get("tool_components") or {})
        return names

    @property
    def synthetic(self):
        return bool(self.system.payload.get("demo") or self.system.payload.get("fixture_profile"))


def _default_environment(session, org, system_id, environments):
    if not environments:
        return None
    states = history(session, org, "system_state", system_id)
    if states:
        chosen = states[0].payload["environment_id"]
        return next((e for e in environments if str(e.id) == chosen), environments[0])
    return environments[0]


def load(session, org, system_id, environment_id=None):
    system = get_record(session, org, system_id, "system")
    environments = history(session, org, "environment", system_id)
    ctx = Context(session=session, org=org, stamp=now(), system=system, environments=environments)
    ctx.properties = sorted(_properties(session, org, system_id), key=lambda p: (p.created_at, str(p.id)))
    # A definition bound to an approved executable claim is represented by that claim.
    ctx.claim_definitions = [c for c in history(session, org, "claim_definition", system_id)
                             if not c.payload.get("property_id")]
    ctx.passports = history(session, org, "assurance_passport", system_id)
    if environment_id:
        ctx.environment = next((e for e in environments if str(e.id) == str(environment_id)), None)
        if ctx.environment is None:
            raise HTTPException(404, "Environment not found for this system")
    else:
        ctx.environment = _default_environment(session, org, system_id, environments)
    if ctx.environment is None:
        return ctx
    eid = ctx.environment.id
    for attribute, kind in (
        ("envelopes", "permission_envelope"), ("states", "system_state"),
        ("decisions", "authorization_decision"), ("transitions", "change_event"),
        ("source_changes", "source_change"), ("batch_rows", "source_batch"),
        ("installations", "connector_installation"), ("mappings", "dependency_mapping"),
        ("relationships", "relationship_assertion"), ("status_events", "status_event"),
        ("acknowledgements", "enforcement_acknowledgement"),
    ):
        setattr(ctx, attribute, history(session, org, kind, system_id, eid))
    from .connectors import source_health
    ctx.health = source_health(session, org, system_id, eid)
    if ctx.states:
        ctx.current = projection(session, org, ctx.states[0])
    return ctx


def status_of(ctx, decision):
    """Recomputed clearance status, ignoring the signed statement's own lifetime."""
    if decision.id not in ctx._status:
        reuse = ctx.current if ctx.current and decision.payload["state_id"] == ctx.current["state_id"] else None
        ctx._status[decision.id] = clearance_status(ctx.session, ctx.org, decision, current=reuse)
    return ctx._status[decision.id]


def signature_live(ctx, decision):
    return datetime.fromisoformat(decision.payload["expires_at"]) > ctx.stamp


def decision_view(ctx, decision, *, status=True):
    value = decision.payload
    view = {"id": str(decision.id), "action": value["action"], "security": value["security"],
            "legitimate_task": value["legitimate_task"], "issued_at": decision.created_at.astimezone(timezone.utc).isoformat(),
            "state_id": value["state_id"], "state_digest": value["state_digest"],
            "signed_statement_expires_at": value["expires_at"],
            "signed_statement_live": signature_live(ctx, decision),
            "status_uri": value.get("status_uri"), "record_uri": f"/v1/change-assurance/decisions/{decision.id}"}
    if status:
        view["status"] = status_of(ctx, decision)
    return view


def _case_rows(ctx, decision):
    case_id = decision.payload.get("case_id")
    if case_id not in ctx._cases:
        try:
            case = get_record(ctx.session, ctx.org, case_id, "assurance_case")
            ctx._cases[case_id] = {r["property_id"]: r for r in case.payload["projection"]["properties"]}
        except HTTPException:
            ctx._cases[case_id] = {}
    return ctx._cases[case_id]


def _component_label(ctx, key, names=None):
    names = names if names is not None else ctx.tool_names()
    if key in names:
        return names[key]
    return str(key).partition(":")[2] or str(key)


# --- Clearance -----------------------------------------------------------------

def clearance(ctx):
    """The protected system's current clearance in customer language."""
    latest = ctx.decisions[0] if ctx.decisions else None
    last_allow = next((d for d in ctx.decisions if d.payload["action"] == "ALLOW"), None)
    if latest is None:
        key = "NOT_ESTABLISHED"
        status = None
    else:
        status = status_of(ctx, latest)
        moved = ctx.state is not None and latest.payload["state_id"] != str(ctx.state.id)
        if status == "REVOKED":
            key = "REVOKED"
        elif status != "CURRENT" or moved:
            key = "NEEDS_REASSESSMENT"
        elif latest.payload["action"] == "ALLOW" and ctx.current and ctx.current["all_supported"]:
            key = "CLEARED"
        elif latest.payload["action"] == "BLOCK":
            key = "NOT_CLEARED"
        else:
            key = "NEEDS_REASSESSMENT"
    label, meaning = CLEARANCE[key]
    return {"state": key, "label": label, "meaning": meaning,
            "decision": decision_view(ctx, latest) if latest else None,
            "decision_status": status,
            "last_current_clearance_at": last_allow.created_at.astimezone(timezone.utc).isoformat() if last_allow else None,
            "last_clearance_id": str(last_allow.id) if last_allow else None}


# --- Authority -----------------------------------------------------------------

def _source_conditions(ctx, action):
    """Authorization facts a source declared for a tool with exactly this name."""
    result = []
    for installation_id, batch in ctx.latest_batches().items():
        facts = batch.payload.get("facts") or {}
        authorization = facts.get("authorization") or {}
        prefix = f"authorization/tools/{action}/"
        conditions = {path[len(prefix):]: value for path, value in authorization.items()
                      if path.startswith(prefix) and "/" not in path[len(prefix):]}
        if conditions:
            installation = ctx.installation_map.get(installation_id)
            result.append({"source": installation.payload["name"] if installation else installation_id,
                           "installation_id": installation_id, "conditions": conditions,
                           "basis": "SOURCE_DECLARED", "qualification": "UNREVIEWED",
                           "valid_at": batch.payload.get("valid_at")})
    return result


def authority_map(ctx):
    rows = ctx.rows
    envelope = ctx.envelope
    names = ctx.tool_names()
    connected = {h["installation_id"]: h for h in ctx.health}
    entries = []
    declared = list(envelope.payload["actions"]) if envelope else []
    envelope_expired = bool(envelope and datetime.fromisoformat(envelope.payload["expires_at"]) <= ctx.stamp)
    for action in declared:
        claims = [p for p in ctx.properties if action in governs(p)]
        statuses = [claim_status(rows.get(str(p.id))) for p in claims]
        if not claims:
            assurance = "UNGOVERNED"
        elif all(s == "SUPPORTED" for s in statuses):
            assurance = "SUPPORTED"
        elif "FAILED" in statuses:
            assurance = "FAILED"
        elif "NEEDS_FRESH_EVIDENCE" in statuses:
            assurance = "NEEDS_FRESH_EVIDENCE"
        else:
            assurance = "UNKNOWN"
        interfaces = [{"component": dep, "label": _component_label(ctx, dep, names), "kind": component_kind(dep),
                       "basis": "GOVERNING_CLAIM_DEPENDENCY"}
                      for dep in sorted({d for p in claims for d in dependencies(p) if component_kind(d) == "TOOL"})]
        reported = [key for key, name in names.items() if name == action]
        interfaces += [{"component": key, "label": action, "kind": "TOOL", "basis": "SOURCE_NAME_MATCH",
                        "note": "Reported by a source under the same name; the association is not reviewed."}
                       for key in reported]
        source_conditions = _source_conditions(ctx, action)
        observed = any((rows.get(str(p.id)) or {}).get("security") in {"PASS", "FAIL"} for p in claims)
        live = any(connected.get(c["installation_id"], {}).get("connected") for c in source_conditions)
        if claims and assurance == "SUPPORTED":
            basis = "VERIFIED"
        elif observed:
            basis = "OBSERVED"
        elif live:
            basis = "CONNECTED"
        else:
            basis = "DECLARED"
        entries.append({
            "action": action, "label": action_label(action), "declared": True, "basis": basis,
            "resources": list(envelope.payload["resources"]), "principals": list(envelope.payload["principals"]),
            "environment": {"id": str(ctx.environment.id), "name": ctx.environment.payload["name"],
                            "purpose": ctx.environment.payload["purpose"]},
            "interfaces": interfaces,
            "conditions": {"declared_boundary": list(envelope.payload["constraints"]),
                           "source_declared": source_conditions},
            "source": {"record": "permission_envelope", "id": str(envelope.id),
                       "policy_epoch": envelope.payload["policy_epoch"], "authority_basis": envelope.payload.get("authority_basis"),
                       "reviewed_until": envelope.payload["expires_at"]},
            "freshness": "EXPIRED" if envelope_expired else "CURRENT",
            "claims": [{"property_id": str(p.id), "title": p.payload["title"], "status": s,
                        "status_text": CLAIM_STATUS[s]} for p, s in zip(claims, statuses, strict=True)],
            "claim_definitions": [{"id": str(c.id), "claim": c.payload["claim"]}
                                  for c in ctx.claim_definitions if c.payload.get("action") == action],
            "assurance": assurance,
        })
    undeclared = []
    for key, name in sorted(names.items(), key=lambda item: item[1]):
        if name not in declared:
            undeclared.append({"component": key, "label": name, "basis": "UNKNOWN",
                               "note": "Reported by a source but not in the declared authority boundary. "
                                       "ThreatVeil never treats a reported tool as a granted permission."})
    ungoverned_operations = sorted({op for p in ctx.properties for op in governs(p)} - set(declared))
    return {"schema_version": INTELLIGENCE, "as_of": ctx.stamp.isoformat(),
            "environment_id": str(ctx.environment.id) if ctx.environment else None,
            "boundary": {"id": str(envelope.id), "envelope_digest": envelope.payload["envelope_digest"],
                         "policy_epoch": envelope.payload["policy_epoch"], "reviewed_until": envelope.payload["expires_at"],
                         "grants_permissions": False} if envelope else None,
            "authorities": entries, "undeclared_interfaces": undeclared,
            "claim_operations_outside_boundary": ungoverned_operations,
            "basis_legend": {
                "DECLARED": "Declared in the customer-reviewed authority boundary.",
                "CONNECTED": "A live connected source reports an interface for it.",
                "OBSERVED": "Qualified execution exercised it for this state.",
                "VERIFIED": "Every claim governing it is currently supported.",
                "UNKNOWN": "Reported, but no reviewed statement covers it.",
            },
            "limitations": ["The authority boundary describes authority; it grants no permission.",
                            "A tool reported by a source is never treated as a granted permission.",
                            "Source-declared conditions are unreviewed declarations from that source."]}


def envelope_diff(before, after):
    dimensions = []
    for field_name, label in (("principals", "Principal"), ("actions", "Action"), ("resources", "Resource")):
        old, new = set(before.get(field_name, [])), set(after.get(field_name, []))
        for item in sorted(new - old):
            dimensions.append({"kind": "DECLARED", "subject": item, "subject_path": field_name, "condition": label.lower(),
                               "path": f"{field_name}/{item}", "before": None, "after": item, "direction": EXPANDED,
                               "reason": f"{label} added to the declared authority boundary."})
        for item in sorted(old - new):
            dimensions.append({"kind": "DECLARED", "subject": item, "subject_path": field_name, "condition": label.lower(),
                               "path": f"{field_name}/{item}", "before": item, "after": None, "direction": CONTRACTED,
                               "reason": f"{label} removed from the declared authority boundary."})
    old, new = set(before.get("constraints", [])), set(after.get("constraints", []))
    added, removed = sorted(new - old), sorted(old - new)
    for item in removed:
        dimensions.append({"kind": "DECLARED", "subject": "constraint", "subject_path": "constraints",
                           "condition": "constraint", "path": "constraints", "before": item, "after": None,
                           "direction": UNKNOWN if added else EXPANDED,
                           "reason": "Constraint wording changed; ThreatVeil does not compare natural-language constraints."
                           if added else "A declared constraint was removed."})
    for item in added:
        dimensions.append({"kind": "DECLARED", "subject": "constraint", "subject_path": "constraints",
                           "condition": "constraint", "path": "constraints", "before": None, "after": item,
                           "direction": UNKNOWN if removed else CONTRACTED,
                           "reason": "Constraint wording changed; ThreatVeil does not compare natural-language constraints."
                           if removed else "A declared constraint was added."})
    return {"classification": combine(d["direction"] for d in dimensions) if dimensions else EQUIVALENT,
            "subjects": [], "dimensions": dimensions,
            "reason": "Compared two versions of the customer-reviewed authority boundary."}


# --- Change intelligence -------------------------------------------------------

def _explain(ctx, change):
    if change.id not in ctx._explained:
        data = change.payload
        explanation = explain_source_change(data, ctx.batch_map.get(str(data.get("before_batch_id"))),
                                            ctx.batch_map.get(str(data.get("batch_id"))))
        explanation["scope"] = scope_change(explanation, mapping_index(ctx.mappings, data.get("installation_id")))
        ctx._explained[change.id] = explanation
    return ctx._explained[change.id]


def reached_claims(ctx, explanation):
    """Claims a source change can reach, judged by reviewed dependencies and mappings."""
    scope = explanation["scope"]
    reviewed = {d for p in ctx.properties for d in dependencies(p)}
    if scope["fully_mapped"] and set(scope["dependencies"]) <= reviewed:
        touched = set(scope["dependencies"])
        return [p for p in ctx.properties if not dependencies(p) or touched & set(dependencies(p))], True
    return list(ctx.properties), False


def declared_dependencies(definition):
    return list(definition.payload.get("declared_dependencies") or [])


def declared_reach(ctx, explanation):
    """Declared, not-yet-verified claims a source change reaches. Never evidence.

    Only definitions with declared dependencies can be reached. A change that is not
    fully mapped can reach every one of them, exactly as for executable claims.
    """
    declared = [c for c in ctx.claim_definitions if declared_dependencies(c)]
    if not declared or explanation.get("initial"):
        return [], None
    scope = explanation["scope"]
    if scope["fully_mapped"]:
        touched = set(scope["dependencies"])
        reached = [c for c in declared if touched & set(declared_dependencies(c))]
        return reached, "DECLARED_CLAIMS_AFFECTED" if reached else "NO_DECLARED_CLAIM_AFFECTED"
    return declared, "DECLARED_CLAIMS_AFFECTED"


VERIFICATION = {
    "DECLARED": "Stated in business language. ThreatVeil holds no evidence and has no dependency to watch.",
    "NOT_YET_VERIFIED": "Declared with dependencies, so ThreatVeil can say which changes reach it. No evidence supports it.",
    "QUALIFIED": "An approved executable claim with a qualified observer exists, so evidence can support it.",
    "CURRENT": "Supported by evidence produced for the system as it is now.",
}


def claim_ladder(ctx):
    """Every claim with its verification level. The four levels are never collapsed."""
    rows = ctx.rows
    items = []
    for prop in ctx.properties:
        row = rows.get(str(prop.id))
        level = ("CURRENT" if row and row["supported"] else
                 "QUALIFIED" if prop.payload.get("approved") else "NOT_YET_VERIFIED")
        items.append({"id": str(prop.id), "kind": "EXECUTABLE_CLAIM", "title": prop.payload["title"],
                      "verification": level, "meaning": VERIFICATION[level], "status": claim_status(row),
                      "dependencies": dependencies(prop), "approved": bool(prop.payload.get("approved")),
                      "next_step": None if level == "CURRENT" else "Produce fresh qualified evidence for this state."})
    for definition in ctx.claim_definitions:
        declared = declared_dependencies(definition)
        level = "NOT_YET_VERIFIED" if declared else "DECLARED"
        items.append({"id": str(definition.id), "kind": "DECLARED_CLAIM", "title": definition.payload["claim"],
                      "verification": level, "meaning": VERIFICATION[level], "status": "DEFINED",
                      "dependencies": declared, "approved": False,
                      "next_step": ("Now prove it: bind an approved executable claim with a qualified observer."
                                    if declared else "Declare which dependencies this claim relies on, then prove it.")})
    return {"schema_version": INTELLIGENCE, "as_of": ctx.stamp.isoformat(), "claims": items,
            "counts": {level: sum(1 for i in items if i["verification"] == level) for level in VERIFICATION},
            "levels": VERIFICATION,
            "principle": "DECLARED, NOT_YET_VERIFIED, QUALIFIED and CURRENT are different states and are never merged."}


def declared_view(definitions):
    return [{"definition_id": str(c.id), "claim": c.payload["claim"], "verification": "NOT_YET_VERIFIED"}
            for c in definitions]


def _prior_decision(ctx, moment):
    return next((d for d in ctx.decisions if d.created_at < moment), None)


def _value(value, present=True):
    if not present:
        return "absent"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def describe(dimension):
    if dimension["kind"] == "AUTHORIZATION":
        return (f"{dimension['subject']} {dimension['condition']} changed from "
                f"{_value(dimension['before'], dimension.get('present_before', True))} to "
                f"{_value(dimension['after'], dimension.get('present_after', True))}")
    if dimension["kind"] == "INTERFACE":
        verb = {EXPANDED: "was newly exposed", CONTRACTED: "was withdrawn"}.get(dimension["direction"], "changed its contract")
        return f"the interface {dimension['subject']} {verb}"
    if dimension["kind"] == "DECLARED":
        if dimension["after"] and not dimension["before"]:
            return f"{dimension['condition']} {dimension['after']} was added to the declared boundary"
        return f"{dimension['condition']} {dimension['before']} was removed from the declared boundary"
    return f"{dimension['subject']} changed"


def _authority_subject_labels(authority):
    subjects = [s["subject"] for s in (authority or {}).get("subjects", []) if s["subject"] != "authorization"]
    subjects += [d["subject"] for d in (authority or {}).get("dimensions", []) if d.get("kind") in {"INTERFACE", "DECLARED"}]
    seen = []
    for subject in subjects:
        if subject not in seen:
            seen.append(subject)
    return seen


def _headline(view):
    authority = view.get("authority") or {}
    classification = authority.get("classification")
    origin = view["origin"]["name"]
    labels = [action_label(s) if "." in s or "_" in s else s for s in _authority_subject_labels(authority)[:2]]
    named = " and ".join(labels) if labels else None
    if view["kind"] == "STATE_TRANSITION":
        return view["headline"]
    if view.get("initial"):
        return f"{origin} connected: first observation"
    if view.get("conservative"):
        return f"{origin}: continuity lost; the change cannot be scoped"
    if classification == EXPANDED:
        return f"{named or origin} authority expanded"
    if classification == CONTRACTED:
        return f"{named or origin} authority contracted"
    if classification == EQUIVALENT:
        return f"{origin} changed; declared authority unchanged"
    count = len(view.get("components", []))
    return f"{origin}: {count} component{'s' if count != 1 else ''} changed; authority impact unknown"


def _narrative(ctx, view):
    name = ctx.system.payload.get("name", "This system")
    lines = []
    prior = view.get("prior_clearance")
    if prior:
        lines.append(f"{name} was cleared at {when(prior['issued_at'])}." if prior["action"] == "ALLOW" else
                     f"The last decision for {name} before this change was {prior['action']} at {when(prior['issued_at'])}.")
    authority = view.get("authority") or {}
    dimensions = [d for d in authority.get("dimensions", []) if d["direction"] != EQUIVALENT]
    what = "; ".join(describe(d) for d in dimensions[:3]) if dimensions else (
        f"{len(view.get('components', []))} changed component(s)")
    lines.append(f"At {when(view['occurred_at'])} {view['origin']['name']} reported that {what}.")
    classification = authority.get("classification")
    if classification and not view.get("initial"):
        lines.append(CLASSIFICATION_TEXT[classification])
    affected = view["consequence"]["claims_affected"]
    for claim in affected[:3]:
        if claim.get("via"):
            lines.append(f"The claim “{claim['title']}” depends on {', '.join(claim['via'])}, "
                         "which a reviewed mapping links to what changed.")
    if affected and not view["consequence"]["scoped"]:
        lines.append("What changed is not fully mapped to reviewed claim dependencies, so every claim it "
                     "could reach needs fresh evidence.")
    if affected:
        boundary = "authority boundary" if classification in {EXPANDED, CONTRACTED, UNKNOWN} else "system state"
        lines.append(f"The evidence supporting {'that claim' if len(affected) == 1 else 'those claims'} was produced "
                     f"under the previous {boundary} and no longer supports the current state.")
    still = view["consequence"]["still_holds"]
    if affected:
        lines.append(f"{len(still)} other claim{'s' if len(still) != 1 else ''} "
                     f"remain{'s' if len(still) == 1 else ''} supported." if still else "No other claim is currently supported.")
    declared = view["consequence"].get("declared_claims_affected") or []
    if declared:
        lines.append(f"It reaches {len(declared)} declared claim{'s' if len(declared) != 1 else ''} not yet verified: "
                     + ", ".join(f"“{c['claim']}”" for c in declared[:3])
                     + ". A declared claim carries no evidence; prove it to make this consequence evidenced.")
    effect = view["consequence"]["effect"]
    if effect == "OPEN":
        lines.append("Re-establish " + ", ".join(f"“{c['title']}”" for c in affected[:3]) + " before restoring clearance.")
    elif effect == "COVERED_BY_LATER_VERIFICATION":
        lines.append("Verification recorded after this change covers it; it no longer affects current clearance.")
    elif effect == "NO_CLAIM_AFFECTED":
        lines.append("No approved claim depends on what changed; current clearance is unaffected.")
    return lines


def _consequence(ctx, reached, scoped, change_id, moment, via=None):
    rows = ctx.rows
    reached_ids = {str(p.id) for p in reached}
    open_ids = {pid for pid, row in rows.items()
                if any(entry["change_id"] == change_id for entry in row.get("affected_by", []))}
    prior = _prior_decision(ctx, moment)
    prior_rows = _case_rows(ctx, prior) if prior else {}
    affected = []
    for prop in ctx.properties:
        pid = str(prop.id)
        if pid not in reached_ids:
            continue
        before = prior_rows.get(pid) or {}
        affected.append({"property_id": pid, "title": prop.payload["title"],
                         "via": sorted(set(via or []) & set(dependencies(prop))) if scoped else [],
                         "evidence_relied_on": before.get("evidence_id"),
                         "open": pid in open_ids, "status": claim_status(rows.get(pid))})
    still = [{"property_id": pid, "title": row["title"]} for pid, row in rows.items()
             if row["supported"] and pid not in reached_ids]
    return affected, still, prior, open_ids


def _source_change_view(ctx, change):
    data = change.payload
    explanation = _explain(ctx, change)
    installation = ctx.installation_map.get(data.get("installation_id"))
    names = ctx.tool_names()
    reached, scoped = reached_claims(ctx, explanation)
    affected, still, prior, open_ids = _consequence(ctx, reached, scoped, str(change.id), change.created_at,
                                                     via=explanation["scope"]["dependencies"])
    late = ctx.state is not None and change.created_at > ctx.state.created_at
    if open_ids:
        effect = "OPEN"
    elif scoped and not affected:
        effect = "NO_CLAIM_AFFECTED"
    elif ctx.state is None:
        effect = "NO_BASELINE"
    elif not late:
        effect = "COVERED_BY_LATER_VERIFICATION"
    else:
        effect = "NO_CLAIM_AFFECTED"
    view = {
        "id": str(change.id), "kind": "SOURCE_CHANGE", "recorded_at": change.created_at.astimezone(timezone.utc).isoformat(),
        "occurred_at": data.get("valid_at") or change.created_at.astimezone(timezone.utc).isoformat(),
        "origin": {"kind": "SOURCE", "name": installation.payload["name"] if installation else "Connected source",
                   "connector": installation.payload["connector_id"] if installation else None,
                   "acquisition": data.get("acquisition"), "qualification": data.get("qualification", "UNREVIEWED"),
                   "installation_id": data.get("installation_id")},
        "change_kind": data.get("change_kind"), "initial": explanation["initial"],
        "conservative": explanation["conservative"],
        "components": [{"component": key, "label": _component_label(ctx, key, names), "kind": component_kind(key)}
                       for key in explanation["changed_components"]],
        "subjects": explanation["subjects"], "unexplained": explanation["unexplained"],
        "authority": explanation["authority"],
        "mapping": {"fully_mapped": explanation["scope"]["fully_mapped"],
                    "dependencies": explanation["scope"]["dependencies"],
                    "unmapped": explanation["scope"]["unmapped"], "mapping_ids": explanation["scope"]["mapping_ids"]},
        "consequence": {"scoped": scoped, "effect": effect, "claims_affected": affected, "still_holds": still,
                        "evidence_stale": sorted({c["evidence_relied_on"] for c in affected
                                                  if c["evidence_relied_on"] and c["open"]}),
                        "requires_reproof": [c["title"] for c in affected if c["open"]]},
        "prior_clearance": decision_view(ctx, prior, status=prior.payload["state_id"] == str(ctx.state.id)
                                         if ctx.state else False) if prior else None,
    }
    if view["prior_clearance"] and "status" not in view["prior_clearance"]:
        view["prior_clearance"]["status"] = "SUPERSEDED" if late or prior.payload["state_id"] != str(ctx.state.id) else None
    declared, declared_effect = declared_reach(ctx, explanation)
    view["consequence"]["declared_claims_affected"] = declared_view(declared)
    view["consequence"]["declared_effect"] = declared_effect
    view["headline"] = _headline(view)
    view["explanation"] = _narrative(ctx, view)
    return view


def _version(component):
    if not component:
        return None
    return component.get("version") or (str(component.get("digest") or "")[:12] or None)


def _transition_view(ctx, transition):
    data = transition.payload
    changes = (data.get("delta") or {}).get("changes", [])
    components = [{"component": c["component"], "label": str(c["component"]).partition(":")[2],
                   "kind": component_kind(c["component"]), "change": c["change_type"],
                   "before": _version(c.get("before")), "after": _version(c.get("after"))} for c in changes[:50]]
    impacts = data.get("impacts", [])
    reached = [p for p in ctx.properties
               if any(i["property_id"] == str(p.id) and i.get("impact") == "REASSESS" for i in impacts)]
    affected, still, prior, open_ids = _consequence(ctx, reached, True, str(transition.id), transition.created_at,
                                                     via=[c["component"] for c in changes])
    following = next((d for d in reversed(ctx.decisions) if d.payload["state_id"] == data["after_state_id"]), None)
    current_state = ctx.state is not None and data["after_state_id"] == str(ctx.state.id)
    permission_moved = any(c["kind"] == "PERMISSION" for c in components)
    view = {
        "id": str(transition.id), "kind": "STATE_TRANSITION", "recorded_at": transition.created_at.astimezone(timezone.utc).isoformat(),
        "occurred_at": transition.created_at.astimezone(timezone.utc).isoformat(),
        "origin": {"kind": "STATE", "name": "Recorded state transition", "acquisition": data["transition"],
                   "qualification": "RECORDED"},
        "change_kind": data.get("change_type"), "components": components, "initial": data.get("before_state_id") is None,
        "authority": {"classification": UNKNOWN, "subjects": [], "dimensions": [],
                      "reason": "A permission component revision changed; revision labels do not establish direction."}
        if permission_moved else None,
        "reason": data.get("reason"),
        "consequence": {"scoped": True, "effect": "CURRENT_STATE" if current_state else "SUPERSEDED_BY_LATER_STATE",
                        "claims_affected": affected, "still_holds": still, "evidence_stale": [],
                        "requires_reproof": [c["title"] for c in affected if c["open"]]},
        "prior_clearance": decision_view(ctx, prior, status=False) if prior else None,
        "outcome": decision_view(ctx, following, status=False) if following else None,
    }
    label = _humanize(data.get("change_type") or "State changed")
    outcome = f"; re-proof decision {following.payload['action']}" if following else ""
    view["headline"] = f"{label}: {len(components)} component revision{'s' if len(components) != 1 else ''} changed{outcome}"
    view["explanation"] = [
        f"A new {data['transition'].lower()} state was recorded at {when(transition.created_at)}. {data.get('reason', '')}".strip(),
        (f"{len(affected)} claim{'s' if len(affected) != 1 else ''} depended on a changed component and required fresh evidence."
         if affected else "No reviewed claim dependency changed; each claim still required fresh anchoring to the new state."),
    ] + ([f"The verification that followed concluded {following.payload['action']} "
          f"(security {following.payload['security']}, legitimate task {following.payload['legitimate_task']})."]
         if following else [])
    return view


def _declaration_view(ctx, envelope, previous):
    diff = envelope_diff(previous.payload, envelope.payload)
    current_boundary = ctx.state is not None and ctx.state.payload["envelope_id"] == str(envelope.id)
    reached = list(ctx.properties)
    affected, still, prior, _ = _consequence(ctx, reached, False, str(envelope.id), envelope.created_at)
    for claim in affected:
        claim["open"] = not current_boundary
    view = {
        "id": str(envelope.id), "kind": "AUTHORITY_DECLARATION", "recorded_at": envelope.created_at.astimezone(timezone.utc).isoformat(),
        "occurred_at": envelope.created_at.astimezone(timezone.utc).isoformat(),
        "origin": {"kind": "DECLARATION", "name": "Reviewed authority boundary", "acquisition": "DECLARED",
                   "qualification": envelope.payload.get("authority_basis", "CUSTOMER_ACCEPTED")},
        "change_kind": "AUTHORITY_BOUNDARY_REVISED", "components": [], "initial": False,
        "authority": diff, "policy_epoch": envelope.payload["policy_epoch"],
        "consequence": {"scoped": False, "effect": "COVERED_BY_LATER_VERIFICATION" if current_boundary else "OPEN",
                        "claims_affected": affected, "still_holds": [] if not current_boundary else still,
                        "evidence_stale": [], "requires_reproof": [c["title"] for c in affected if c["open"]]},
        "prior_clearance": decision_view(ctx, prior, status=False) if prior else None,
    }
    view["headline"] = _headline(view)
    view["explanation"] = _narrative(ctx, view)
    return view


def changes(ctx, limit=50):
    """Every recorded change, newest first, each with its assurance consequence."""
    key = ("changes", limit)
    if key not in ctx._views:
        views = [_source_change_view(ctx, c) for c in ctx.source_changes[:limit]]
        views += [_transition_view(ctx, t) for t in ctx.transitions[:limit]]
        views += [_declaration_view(ctx, e, ctx.envelopes[i + 1])
                  for i, e in enumerate(ctx.envelopes[:limit]) if i + 1 < len(ctx.envelopes)]
        views.sort(key=lambda v: v["recorded_at"], reverse=True)
        ctx._views[key] = views[:limit]
    return ctx._views[key]


def authority_changes(ctx, limit=50):
    """The Authority Diff: every change that moved declared or source-declared authority."""
    result = []
    for view in changes(ctx, limit=limit):
        authority = view.get("authority")
        if not authority or view.get("initial") or view["kind"] == "STATE_TRANSITION":
            continue
        consequence = view["consequence"]
        prior = view.get("prior_clearance") or {}
        result.append({
            "change_id": view["id"], "kind": view["kind"], "recorded_at": view["recorded_at"],
            "headline": view["headline"], "origin": view["origin"],
            "classification": authority["classification"], "subjects": authority.get("subjects", []),
            "dimensions": authority.get("dimensions", []), "reason": authority.get("reason"),
            "consequence": {
                "claims_affected": len(consequence["claims_affected"]),
                "claims": consequence["claims_affected"],
                "evidence_stale": len(consequence["evidence_stale"]),
                "still_holds": len(consequence["still_holds"]),
                "previous_clearance": {"id": prior.get("id"), "issued_at": prior.get("issued_at"),
                                       "action": prior.get("action"), "status": prior.get("status")} if prior else None,
                "required": [f"Re-establish “{title}”" for title in consequence["requires_reproof"]],
                "effect": consequence["effect"],
            },
            "explanation": view["explanation"],
        })
    return result


# --- Evidence currency, re-establishment ----------------------------------------

def evidence_currency(ctx):
    rows = ctx.rows
    change_heads = {view["id"]: view["headline"] for view in changes(ctx)}
    claims = []
    for prop in ctx.properties:
        row = rows.get(str(prop.id))
        definition = prop.payload["definition"]
        evidence = None
        if row and row.get("evidence_id"):
            record = get_record(ctx.session, ctx.org, row["evidence_id"], "evidence_record")
            evidence = {"id": row["evidence_id"], "produced_at": record.created_at.astimezone(timezone.utc).isoformat(),
                        "age_seconds": max(0, round((ctx.stamp - record.created_at).total_seconds())),
                        "for_current_state": record.payload.get("fingerprint_digest") == (ctx.state.payload["fingerprint_digest"] if ctx.state else None),
                        # What the record itself says about how it was observed; presented, never re-derived.
                        "ground_truth": record.payload.get("ground_truth"),
                        "observer_id": record.payload.get("observer_id"),
                        "qualified": record.payload.get("qualified"),
                        "coverage_complete": record.payload.get("coverage_complete"),
                        "synthetic": record.payload.get("synthetic"),
                        "expires_at": record.payload.get("expires_at"),
                        "run_id": record.payload.get("run_id"),
                        "evidence_digest": record.payload.get("evidence_digest"),
                        "limitations": list(record.payload.get("limitations") or [])[:8]}
        affected = []
        for entry in (row or {}).get("affected_by", []):
            affected.append({"change_id": entry["change_id"],
                             "headline": change_heads.get(entry["change_id"], "Observed source change"),
                             "scoped": entry.get("scoped", False)})
        status = claim_status(row)
        applicability = (row or {}).get("applicability", "UNKNOWN")
        claims.append({
            "property_id": str(prop.id), "title": prop.payload["title"], "statement": prop.payload.get("description"),
            "governs": [{"action": op, "label": action_label(op)} for op in governs(prop)],
            "depends_on": [{"component": d, "kind": component_kind(d)} for d in dependencies(prop)],
            "legitimate_task": definition.get("legitimate_task"), "forbidden_outcome": forbidden_outcome(definition),
            "status": status, "status_text": CLAIM_STATUS[status],
            "applicability": applicability, "currency": CURRENCY.get(applicability, CURRENCY["UNKNOWN"]),
            "security": (row or {}).get("security", "INCONCLUSIVE"),
            "legitimate_task_outcome": (row or {}).get("legitimate_task", "UNKNOWN"),
            "evidence": evidence, "affected_by": affected,
            "reasons": sorted(set((row or {}).get("reasons", [])))[:6],
        })
    for definition in ctx.claim_definitions:
        value = definition.payload
        claims.append({"property_id": None, "claim_definition_id": str(definition.id), "title": value["claim"],
                       "statement": value.get("forbidden_outcome"),
                       "governs": [{"action": value["action"], "label": action_label(value["action"])}],
                       "depends_on": [], "legitimate_task": value.get("legitimate_task"),
                       "forbidden_outcome": value.get("forbidden_outcome"), "status": "DEFINED",
                       "status_text": CLAIM_STATUS["DEFINED"], "applicability": "UNKNOWN",
                       "currency": "Defined in business language; it needs an executable, approved check before evidence can support it.",
                       "security": "INCONCLUSIVE", "legitimate_task_outcome": "UNKNOWN", "evidence": None,
                       "affected_by": [], "reasons": [], "ground_truth_source": value.get("ground_truth_source")})
    counts = {key: sum(1 for c in claims if c["status"] == key) for key in CLAIM_STATUS}
    return {"schema_version": INTELLIGENCE, "as_of": ctx.stamp.isoformat(), "claims": claims, "counts": counts,
            "principle": "Security evidence has a shelf life: a historical pass is not automatically a current pass."}


_CHECKS = "Attempt: {forbidden}. It must not commit a business effect."


def reestablishment(ctx):
    rows = ctx.rows
    view = clearance(ctx)
    last_allow = next((d for d in ctx.decisions if d.payload["action"] == "ALLOW"), None)
    recent = [c for c in changes(ctx)
              if (last_allow is None or c["recorded_at"] > last_allow.created_at.astimezone(timezone.utc).isoformat())
              and c["consequence"]["claims_affected"] and not c.get("initial")]
    affected = [p for p in ctx.properties if not (rows.get(str(p.id)) or {}).get("supported")]
    holding = [p for p in ctx.properties if (rows.get(str(p.id)) or {}).get("supported")]
    stale = [p for p in affected if claim_status(rows.get(str(p.id))) in {"NEEDS_FRESH_EVIDENCE", "UNKNOWN"}]
    latest = ctx.decisions[0] if ctx.decisions else None
    outcome = None
    if latest is not None:
        value = latest.payload
        if value["security"] == "FAIL":
            outcome = {"case": "SECURITY_FAILED", "cleared": False,
                       "text": "A prohibited business effect committed under this state. Not cleared."}
        elif value["security"] == "PASS" and value["legitimate_task"] == "FAILURE":
            outcome = {"case": "USEFUL_TASK_FAILED", "cleared": False,
                       "text": "The prohibited outcome was prevented, but the legitimate task also failed. "
                               "Breaking useful work is not a fix. Not cleared."}
        elif value["action"] == "ALLOW":
            outcome = {"case": "RESTORED" if len([d for d in ctx.decisions if d.payload["action"] == "ALLOW"]) > 1
                       or len(ctx.decisions) > 1 else "ESTABLISHED", "cleared": view["state"] == "CLEARED",
                       "text": "Security held and the legitimate task succeeded on this exact state."}
        else:
            outcome = {"case": "INCONCLUSIVE", "cleared": False,
                       "text": "The verification did not establish enough evidence to support clearance."}
        outcome["decision"] = decision_view(ctx, latest)
    synthetic = ctx.system.payload.get("fixture_profile") == "finance-v1"
    return {
        "schema_version": INTELLIGENCE, "as_of": ctx.stamp.isoformat(),
        "required": bool(affected) or view["state"] != "CLEARED",
        "clearance": view,
        "steps": [
            {"step": "WHAT_CHANGED", "title": "What changed",
             "items": [{"change_id": c["id"], "headline": c["headline"], "recorded_at": c["recorded_at"]} for c in recent[:5]]},
            {"step": "AFFECTED_CLAIMS", "title": "Which claims are affected",
             "items": [{"property_id": str(p.id), "title": p.payload["title"],
                        "status": claim_status(rows.get(str(p.id)))} for p in affected]},
            {"step": "STILL_HOLDS", "title": "Which evidence still holds",
             "items": [{"property_id": str(p.id), "title": p.payload["title"]} for p in holding]},
            {"step": "NEEDS_FRESH_EVIDENCE", "title": "What needs fresh evidence",
             "items": [{"property_id": str(p.id), "title": p.payload["title"],
                        "currency": CURRENCY.get((rows.get(str(p.id)) or {}).get("applicability", "UNKNOWN"))} for p in stale]},
            {"step": "SECURITY_CHECKS", "title": "Which security checks must run",
             "items": [{"property_id": str(p.id), "title": p.payload["title"],
                        "check": _CHECKS.format(forbidden=forbidden_outcome(p.payload["definition"]))} for p in affected]},
            {"step": "LEGITIMATE_TASKS", "title": "Which legitimate task must still succeed",
             "items": [{"property_id": str(p.id), "title": p.payload["title"],
                        "task": p.payload["definition"].get("legitimate_task")} for p in affected]},
            {"step": "RESTORES_CLEARANCE", "title": "What restores current clearance",
             "items": [{"criterion": "Security PASS for every affected claim on the current state."},
                       {"criterion": "The legitimate task succeeds for every affected claim; blocking useful work is not a fix."},
                       {"criterion": "Every approved claim is supported by evidence produced for this exact state."},
                       {"criterion": "A fresh clearance is issued for that exact state."}]},
        ],
        "latest_outcome": outcome,
        "execution": {"mode": "SYNTHETIC_SANDBOX" if synthetic else "ASSISTED",
                      "note": "ThreatVeil coordinates re-proof and records its result. It never changes your system "
                              "and never proposes a remediation to it."},
    }


# --- Lifecycle and memory ------------------------------------------------------

def _loss_moments(ctx):
    """Moments at which an observed change or a failing verification ended a clearance."""
    moments = []
    for change in ctx.source_changes:
        explanation = _explain(ctx, change)
        reached, scoped = reached_claims(ctx, explanation)
        if reached and not explanation["initial"]:
            moments.append((change.created_at, "SOURCE_CHANGE", str(change.id)))
    for transition in ctx.transitions:
        # A re-run that changed no component is re-proof, not a change.
        if (transition.payload.get("transition") == "OBSERVED" and transition.payload.get("before_state_id")
                and (transition.payload.get("delta") or {}).get("changes")):
            moments.append((transition.created_at, "STATE_TRANSITION", str(transition.id)))
    for index, envelope in enumerate(ctx.envelopes):
        if index + 1 < len(ctx.envelopes):
            moments.append((envelope.created_at, "AUTHORITY_DECLARATION", str(envelope.id)))
    for event in ctx.status_events:
        moments.append((event.created_at, "REVOCATION", str(event.id)))
    return sorted((stamp.astimezone(timezone.utc), kind, identifier) for stamp, kind, identifier in moments)


def cycles(ctx):
    """Clearance cycles in time order: cleared, lost (by a change or a failed
    verification), re-proven, restored. One chronological pass over decisions and
    loss moments, so a clearance lost only through an observed change still counts."""
    events = [(d.created_at.astimezone(timezone.utc), 1, "DECISION", d) for d in ctx.decisions]
    events += [(stamp, 0, kind, identifier) for stamp, kind, identifier in _loss_moments(ctx)]
    result, open_cycle = [], None
    for stamp, _, kind, item in sorted(events, key=lambda event: (event[0], event[1])):
        if kind != "DECISION":
            if open_cycle and not open_cycle["lost_at"]:
                open_cycle.update(lost_at=stamp.isoformat(), cause=kind, cause_id=item)
            continue
        if item.payload["action"] == "ALLOW":
            if open_cycle and open_cycle["lost_at"]:
                open_cycle.update(restored_at=stamp.isoformat(), restored_by=str(item.id), restore_seconds=round(
                    (stamp - datetime.fromisoformat(open_cycle["lost_at"])).total_seconds()))
                result.append(open_cycle)
                open_cycle = None
            if open_cycle is None:
                open_cycle = {"cleared_at": stamp.isoformat(), "cleared_by": str(item.id), "lost_at": None,
                              "cause": None, "cause_id": None, "attempts": 0}
            continue
        if open_cycle is not None:
            open_cycle["attempts"] += 1
            if not open_cycle["lost_at"]:
                open_cycle.update(lost_at=stamp.isoformat(), cause="FAILED_VERIFICATION", cause_id=str(item.id))
    return result, open_cycle


def lifecycle(ctx):
    view = clearance(ctx)
    completed, open_cycle = cycles(ctx)
    first_allow = next((d for d in sorted(ctx.decisions, key=lambda d: d.created_at) if d.payload["action"] == "ALLOW"), None)
    lost = bool(open_cycle and open_cycle.get("lost_at")) or view["state"] in {"NEEDS_REASSESSMENT", "NOT_CLEARED", "REVOKED"}
    attempts = open_cycle["attempts"] if open_cycle else 0
    restored = bool(completed) and not lost

    def stage(key, title, reached, at=None, detail=None, current=False):
        return {"stage": key, "title": title, "reached": bool(reached), "at": _iso(at), "detail": detail, "current": current}

    stages = [
        stage("BASELINE_ESTABLISHED", "Baseline established", first_allow, first_allow.created_at if first_allow else None),
        stage("CURRENT", "Current", first_allow, open_cycle["cleared_at"] if open_cycle else None,
              current=view["state"] == "CLEARED"),
        stage("RELEVANT_CHANGE", "Relevant change", lost, open_cycle.get("lost_at") if open_cycle else None,
              detail=(open_cycle or {}).get("cause")),
        stage("CLEARANCE_SUPERSEDED", "Clearance superseded", lost, open_cycle.get("lost_at") if open_cycle else None,
              detail=view.get("decision_status") if lost else None),
        stage("REASSESSMENT_REQUIRED", "Reassessment required", lost, detail=None,
              current=lost and attempts == 0),
        stage("RE_PROOF", "Re-proof", lost and attempts > 0,
              detail=f"{attempts} attempt{'s' if attempts != 1 else ''}" if attempts else None,
              current=lost and attempts > 0),
        stage("CLEARANCE_RESTORED", "Clearance restored", restored, completed[-1]["restored_at"] if restored else None),
    ]
    timeline = [{"at": d.created_at.astimezone(timezone.utc).isoformat(), "kind": "DECISION", "id": str(d.id), "action": d.payload["action"],
                 "security": d.payload["security"], "legitimate_task": d.payload["legitimate_task"]}
                for d in ctx.decisions[:50]]
    timeline += [{"at": m[0].isoformat(), "kind": m[1], "id": m[2]} for m in _loss_moments(ctx)[-50:]]
    timeline.sort(key=lambda e: e["at"], reverse=True)
    return {"schema_version": INTELLIGENCE, "as_of": ctx.stamp.isoformat(), "clearance": view, "stages": stages,
            "current_cycle": open_cycle, "completed_cycles": completed[-20:], "timeline": timeline[:60],
            "principle": "Historical decisions are immutable; only their current status is recomputed."}


def assurance_memory(ctx):
    """What accumulated history shows, without manufacturing conclusions."""
    completed, _ = cycles(ctx)
    durations = [c["restore_seconds"] for c in completed if c.get("restore_seconds") is not None]
    classifications = {key: 0 for key in (EXPANDED, CONTRACTED, EQUIVALENT, UNKNOWN)}
    claim_memory = {str(p.id): {"property_id": str(p.id), "title": p.payload["title"], "reached": 0, "survived": 0}
                    for p in ctx.properties}
    subject_hits = {}
    observed = 0
    for change in ctx.source_changes:
        explanation = _explain(ctx, change)
        if explanation["initial"]:
            continue
        observed += 1
        authority = explanation.get("authority") or {}
        if authority.get("classification") in classifications:
            classifications[authority["classification"]] += 1
        reached, _ = reached_claims(ctx, explanation)
        reached_ids = {str(p.id) for p in reached}
        for pid, item in claim_memory.items():
            item["reached" if pid in reached_ids else "survived"] += 1
        for subject in explanation["subjects"]:
            for pid in reached_ids:
                subject_hits.setdefault((subject, pid), 0)
                subject_hits[(subject, pid)] += 1
    for index, envelope in enumerate(ctx.envelopes):
        if index + 1 < len(ctx.envelopes):
            observed += 1
            classifications[envelope_diff(ctx.envelopes[index + 1].payload, envelope.payload)["classification"]] += 1
    stale_sources = {}
    for health in ctx.health:
        if health.get("status") not in {"CURRENT", "IMPORTED"}:
            stale_sources[health["name"]] = health["status"]
    titles = {str(p.id): p.payload["title"] for p in ctx.properties}
    patterns = [{"pattern": "REPEATED_INVALIDATION", "subject": subject, "claim": titles.get(pid, pid), "observations": count,
                 "text": f"Changes to {subject} reached “{titles.get(pid, pid)}” {count} times."}
                for (subject, pid), count in sorted(subject_hits.items(), key=lambda item: -item[1]) if count >= PATTERN_MINIMUM]
    allows = sum(1 for d in ctx.decisions if d.payload["action"] == "ALLOW")
    return {
        "schema_version": INTELLIGENCE, "as_of": ctx.stamp.isoformat(),
        "history_began_at": min([ctx.system.created_at] + [d.created_at for d in ctx.decisions]).astimezone(timezone.utc).isoformat(),
        "counts": {"observed_changes": observed, "state_transitions": len(ctx.transitions),
                   "authority_changes": classifications, "decisions": len(ctx.decisions), "clearances_issued": allows,
                   "restorations": len(completed), "reproof_attempts": sum(c["attempts"] for c in completed),
                   "passports_issued": len(ctx.passports), "dependency_mappings": len({(m.payload["installation_id"], m.payload["subject"]) for m in ctx.mappings})},
        "restoration": {"samples": len(durations),
                        "median_seconds": round(median(durations)) if len(durations) >= PATTERN_MINIMUM else None,
                        "insufficient_history": len(durations) < PATTERN_MINIMUM},
        "claims": list(claim_memory.values()),
        "patterns": patterns,
        "sources_not_current": stale_sources,
        "insufficient_history": observed < PATTERN_MINIMUM,
        "note": (f"ThreatVeil reports a pattern only after at least {PATTERN_MINIMUM} comparable observations. "
                 "Accepted history compounds with every change, re-proof and decision; it cannot be recreated later."),
    }


# --- System map ----------------------------------------------------------------

GUIDANCE = {
    "NO_LIVE_SOURCE": ("No live source", "LIMITS_SCOPE",
                       "Every source for this system is an import, so ThreatVeil sees changes only when you send them.",
                       "ThreatVeil will not claim it is watching this system.",
                       "Connect a source ThreatVeil can read itself, or keep importing on a schedule you control."),
    "SOURCE_OUTAGE": ("A source is not current", "LIMITS_SCOPE",
                      "A connected source reported a gap, a partial snapshot or nothing recently.",
                      "A gap is never read as 'nothing changed'.",
                      "Reconcile the source, then re-establish the claims its facts support."),
    "BASELINE_MISSING": ("No baseline yet", "BLOCKING_VALUE",
                         "No qualified verification has produced a state for this environment.",
                         "Without a baseline there is nothing for a change to invalidate.",
                         "Run the approved verification once to establish a baseline."),
    "UNMAPPED_CHANGE": ("An observed change could not be scoped", "LIMITS_SCOPE",
                        "Part of what changed is not mapped to a reviewed claim dependency.",
                        "An unnamed fact is never assumed harmless.",
                        "Review the mapping suggestions for the unmapped facts, then approve the ones that are right."),
    "NO_QUALIFIED_OBSERVER": ("No qualified business-effect observer", "BLOCKING_VALUE",
                              "No observer for this environment has passed qualification, so a committed business "
                              "effect cannot be witnessed independently.",
                              "Missing evidence is never read as 'no effect'.",
                              "Declare an observer contract and qualify it against the harness."),
    "CLAIM_NOT_EXECUTABLE": ("Declared claims are not yet verified", "LIMITS_SCOPE",
                             "Claims are declared in business language but no approved executable check is bound "
                             "to them.",
                             "A declared claim is never reported as supported.",
                             "Now prove it: bind an approved executable claim with a qualified observer."),
    "EVIDENCE_STALE": ("Evidence no longer describes this state", "BLOCKING_VALUE",
                       "Evidence behind at least one claim was produced for an earlier state.",
                       "A historical pass is never a current pass.",
                       "Re-establish the affected claims against the current state."),
    "CLEARANCE_EXPIRED": ("Clearance has passed its window", "BLOCKING_VALUE",
                          "The reviewed authority boundary or the last clearance has expired.",
                          "An expired clearance never speaks for the system as it is now.",
                          "Review the authority boundary and re-establish clearance."),
    "PASSPORT_AUTHENTIC_BUT_SUPERSEDED": ("A shared passport is superseded", "INFORMATIONAL",
                                          "A passport you issued is still authentic but no longer describes the "
                                          "current system.",
                                          "Authenticity is never presented as current status.",
                                          "Issue a fresh passport, or let the recipient's status check show it."),
}


def guidance(ctx):
    """Named failure states, what ThreatVeil refuses to claim in each, and the next step."""
    items = []

    def add(code, evidence=(), detail=None):
        title, severity, meaning, refused, step = GUIDANCE[code]
        items.append({"code": code, "title": title, "severity": severity, "meaning": meaning,
                      "not_claimed": refused, "next_step": step, "detail": detail,
                      "evidence": [str(identifier) for identifier in evidence][:5]})

    if not any(i.payload.get("mode") in {"POLL", "PUSH"} for i in ctx.installations):
        add("NO_LIVE_SOURCE", [i.id for i in ctx.installations])
    # Health rows are computed views: an import reads IMPORTED, a healthy live source reads CURRENT.
    stale_sources = [h for h in ctx.health[:10] if h.get("status") not in {"CURRENT", "IMPORTED"} or h.get("failure")]
    if stale_sources:
        add("SOURCE_OUTAGE", [h["installation_id"] for h in stale_sources],
            detail=", ".join(sorted({h.get("status") or "UNKNOWN" for h in stale_sources})))
    if ctx.state is None:
        add("BASELINE_MISSING")
    unscoped = [view for view in changes(ctx, limit=20)
                if view["kind"] == "SOURCE_CHANGE" and not view.get("initial")
                and not view["mapping"]["fully_mapped"]]
    if unscoped:
        add("UNMAPPED_CHANGE", [view["id"] for view in unscoped],
            detail=f"{len(unscoped)} change(s); unmapped facts: "
                   + ", ".join(sorted({subject for view in unscoped for subject in view["mapping"]["unmapped"]})[:5]))
    if not _qualified_observers(ctx):
        add("NO_QUALIFIED_OBSERVER")
    declared = [c for c in ctx.claim_definitions]
    if declared:
        add("CLAIM_NOT_EXECUTABLE", [c.id for c in declared], detail=f"{len(declared)} declared claim(s)")
    rows = ctx.rows
    stale_rows = [row for row in rows.values()
                  if row["applicability"] in {"STALE", "INVALID"} or row.get("affected_by")]
    if stale_rows:
        add("EVIDENCE_STALE", [row["property_id"] for row in stale_rows], detail=f"{len(stale_rows)} claim(s)")
    view = clearance(ctx)
    if view.get("decision_status") == "EXPIRED" or (
            ctx.envelope is not None and datetime.fromisoformat(ctx.envelope.payload["expires_at"]) <= ctx.stamp):
        add("CLEARANCE_EXPIRED", [ctx.envelope.id] if ctx.envelope else [])
    superseded = [p for p in ctx.passports[:10]
                  if ctx.state is not None and p.payload.get("state_id", p.payload.get("passport", {})
                                                             .get("state", {}).get("id")) not in {str(ctx.state.id), None}]
    if superseded:
        add("PASSPORT_AUTHENTIC_BUT_SUPERSEDED", [p.id for p in superseded], detail=f"{len(superseded)} passport(s)")
    order = {"BLOCKING_VALUE": 0, "LIMITS_SCOPE": 1, "INFORMATIONAL": 2}
    items.sort(key=lambda item: (order[item["severity"]], item["code"]))
    return {"schema_version": INTELLIGENCE, "as_of": ctx.stamp.isoformat(), "items": items,
            "clear": not items, "codes": sorted(GUIDANCE),
            "principle": "Every limitation is named, with what ThreatVeil refuses to claim because of it."}


def _qualified_observers(ctx):
    from .observer_platform import qualification_state

    definitions = [d for d in history(ctx.session, ctx.org, "observer_definition", ctx.system.id,
                                      ctx.environment.id if ctx.environment else None)]
    return [d for d in definitions
            if qualification_state(ctx.session, ctx.org, d, at=ctx.stamp)["state"] == "QUALIFIED"]


def system_map(ctx):
    nodes, edges = {}, []
    names = ctx.tool_names()
    rows = ctx.rows

    def node(identifier, kind, label, **extra):
        if identifier not in nodes:
            nodes[identifier] = {"id": identifier, "kind": kind, "label": label, **extra}
        else:
            for key, value in extra.items():
                if key == "established_by":
                    nodes[identifier].setdefault("established_by", [])
                    nodes[identifier]["established_by"] = sorted(set(nodes[identifier]["established_by"]) | set(value))
                else:
                    nodes[identifier].setdefault(key, value)
        return identifier

    def edge(source, target, relation, record, identifier, **extra):
        edges.append({"source": source, "target": target, "relation": relation,
                      "basis": {"record": record, "id": str(identifier)}, **extra})

    system = node(f"system:{ctx.system.id}", "AGENT", ctx.system.payload.get("name", "System"),
                  provenance="DECLARED", established_by=["system"])
    for item in ctx.system.payload.get("access", []) or []:
        key = node(f"access:{item}", "DATA_SOURCE", str(item), provenance="DECLARED", established_by=["system"])
        edge(system, key, "DECLARES_ACCESS", "system", ctx.system.id)
    if ctx.state:
        for component in ctx.state.payload["fingerprint"].get("components", []):
            key = f"{component['type']}:{component['id']}"
            node(key, component_kind(key), _component_label(ctx, key, names), version=component.get("version"),
                 provenance="OBSERVED" if component.get("provenance") == "OBSERVED" else component.get("provenance", "UNKNOWN"),
                 established_by=["qualified state"])
            edge(system, key, "HAS_COMPONENT", "system_state", ctx.state.id)
            for dependency in component.get("dependencies", []):
                node(dependency, component_kind(dependency), _component_label(ctx, dependency, names), provenance="UNKNOWN")
                edge(key, dependency, "DEPENDS_ON", "system_state", ctx.state.id)
        for unknown in ctx.state.payload.get("unknowns", []):
            node(f"unknown:{unknown}", "UNKNOWN", str(unknown), provenance="UNKNOWN", established_by=["declared coverage gap"])
    health = {h["installation_id"]: h for h in ctx.health}
    for installation_id, batch in ctx.latest_batches().items():
        installation = ctx.installation_map.get(installation_id)
        state = health.get(installation_id, {})
        source = node(f"source:{installation_id}", "SOURCE", installation.payload["name"] if installation else "Source",
                      connector=installation.payload["connector_id"] if installation else None,
                      status=state.get("status"), freshness=state.get("freshness"), connected=state.get("connected", False),
                      provenance="CONNECTED" if state.get("connected") else batch.payload.get("acquisition", "IMPORTED"))
        provenance = "CONNECTED" if state.get("connected") else batch.payload.get("acquisition", "IMPORTED")
        for key, component in (batch.payload.get("components") or {}).items():
            node(key, component_kind(key), _component_label(ctx, key, names), provenance=provenance,
                 established_by=[installation.payload["name"] if installation else "source"])
            edge(source, key, "REPORTS", "source_batch", batch.id)
            for dependency in component.get("dependencies", []):
                node(dependency, component_kind(dependency), _component_label(ctx, dependency, names), provenance=provenance)
                edge(key, dependency, "DEPENDS_ON", "source_batch", batch.id)
    seen_mappings = set()
    for mapping in ctx.mappings:
        value = mapping.payload
        marker = (value["installation_id"], value["subject"])
        if marker in seen_mappings:
            continue
        seen_mappings.add(marker)
        subject = value["subject"]
        if subject.startswith("authorization/"):
            parts = subject.split("/")
            label = " · ".join(parts[-2:]) if len(parts) > 2 else subject
            subject_node = node(f"fact:{value['installation_id']}:{subject}", "AUTHORITY_FACT", label,
                                provenance="SOURCE_DECLARED", subject=subject)
            edge(f"source:{value['installation_id']}", subject_node, "DECLARES", "dependency_mapping", mapping.id)
        else:
            subject_node = node(subject, component_kind(subject), _component_label(ctx, subject, names), provenance="UNKNOWN")
        for dependency in value.get("maps_to", []):
            node(dependency, component_kind(dependency), _component_label(ctx, dependency, names), provenance="UNKNOWN")
            edge(subject_node, dependency, "MAPPED_TO", "dependency_mapping", mapping.id,
                 authority_basis=value.get("authority_basis"))
    envelope = ctx.envelope
    if envelope:
        value = envelope.payload
        boundary = node(f"envelope:{envelope.id}", "AUTHORITY_BOUNDARY", f"Authority boundary · epoch {value['policy_epoch']}",
                        provenance="DECLARED", reviewed_until=value["expires_at"], grants_permissions=False)
        edge(system, boundary, "BOUND_BY", "permission_envelope", envelope.id)
        for principal in value["principals"]:
            edge(node(f"principal:{principal}", "IDENTITY", principal, provenance="DECLARED"), boundary, "HOLDS",
                 "permission_envelope", envelope.id)
        for action in value["actions"]:
            edge(boundary, node(f"action:{action}", "AUTHORITY", action_label(action), action=action, declared=True,
                                provenance="DECLARED"), "PERMITS", "permission_envelope", envelope.id)
        for resource in value["resources"]:
            edge(boundary, node(f"resource:{resource}", "BUSINESS_RESOURCE", resource, provenance="DECLARED"), "COVERS",
                 "permission_envelope", envelope.id)
    for prop in ctx.properties:
        row = rows.get(str(prop.id))
        status = claim_status(row)
        claim = node(f"claim:{prop.id}", "CLAIM", prop.payload["title"], status=status,
                     applicability=(row or {}).get("applicability", "UNKNOWN"), provenance="VERIFIED" if status == "SUPPORTED" else "DECLARED")
        for dependency in dependencies(prop):
            node(dependency, component_kind(dependency), _component_label(ctx, dependency, names), provenance="UNKNOWN",
                 note="Declared claim dependency")
            edge(claim, dependency, "DEPENDS_ON", "property", prop.id)
        for operation in governs(prop):
            node(f"action:{operation}", "AUTHORITY", action_label(operation), action=operation, declared=False,
                 provenance="UNKNOWN")
            edge(claim, f"action:{operation}", "GOVERNS", "property", prop.id)
        definition = prop.payload["definition"]
        edge(claim, node(f"effect:{prop.id}:forbidden", "BUSINESS_EFFECT", forbidden_outcome(definition),
                         polarity="FORBIDDEN", provenance="DECLARED"), "PREVENTS", "property", prop.id)
        if definition.get("legitimate_task"):
            edge(claim, node(f"effect:{prop.id}:useful", "BUSINESS_EFFECT", definition["legitimate_task"],
                             polarity="PERMITTED", provenance="DECLARED"), "PRESERVES", "property", prop.id)
        if row and row.get("evidence_id"):
            evidence = node(f"evidence:{row['evidence_id']}", "EVIDENCE", "Qualified evidence",
                            currency=row["applicability"], provenance="OBSERVED")
            edge(evidence, claim, "SUPPORTS" if row["supported"] else "NO_LONGER_SUPPORTS", "evidence_record",
                 row["evidence_id"], currency=row["applicability"])
        for entry in (row or {}).get("affected_by", []):
            change = node(f"change:{entry['change_id']}", "CHANGE", "Observed source change", provenance="OBSERVED")
            edge(change, claim, "INVALIDATES" if entry.get("scoped") else "REQUIRES_REVIEW_OF", "source_change", entry["change_id"])
    for definition in ctx.claim_definitions:
        value = definition.payload
        claim = node(f"claim-definition:{definition.id}", "CLAIM", value["claim"], status="DEFINED", provenance="DECLARED",
                     verifiable=False)
        node(f"action:{value['action']}", "AUTHORITY", action_label(value["action"]), action=value["action"],
             declared=False, provenance="UNKNOWN")
        edge(claim, f"action:{value['action']}", "GOVERNS", "claim_definition", definition.id)
    if ctx.decisions:
        latest = ctx.decisions[0]
        status = status_of(ctx, latest)
        decision = node(f"decision:{latest.id}", "DECISION", f"{latest.payload['action']} · {status}",
                        action=latest.payload["action"], status=status, provenance="VERIFIED")
        for prop in ctx.properties:
            edge(decision, f"claim:{prop.id}", "COVERS", "authorization_decision", latest.id)
    def endpoint(identifier, relation):
        if str(identifier) == str(ctx.system.id):
            return system
        try:
            record = get_record(ctx.session, ctx.org, identifier)
        except HTTPException:
            return node(f"record:{identifier}", "UNKNOWN", "Unavailable record", provenance="UNKNOWN")
        kind = "SUBAGENT" if relation == "delegates_to" else component_kind(record.kind)
        return node(f"record:{identifier}", kind, str(record.payload.get("name") or record.payload.get("title") or record.kind),
                    provenance="DECLARED")

    for relationship in ctx.relationships:
        value = relationship.payload
        edge(endpoint(value["source_id"], value["relationship"]), endpoint(value["target_id"], value["relationship"]),
             value["relationship"].upper(),
             "relationship_assertion", relationship.id, grants_permissions=False,
             inert=value["relationship"] == "delegates_to",
             note="Recorded for traceability; no authority or evidence reuse is derived from it.")
    ordered = list(nodes.values())
    kinds = {}
    for item in ordered:
        kinds[item["kind"]] = kinds.get(item["kind"], 0) + 1
    return {"schema_version": INTELLIGENCE, "as_of": ctx.stamp.isoformat(),
            "system_id": str(ctx.system.id), "environment_id": str(ctx.environment.id) if ctx.environment else None,
            "nodes": ordered[:800], "edges": edges[:2000], "counts": kinds,
            "truncated": len(ordered) > 800 or len(edges) > 2000,
            "chain": ["COMPONENT", "AUTHORITY", "CLAIM", "EVIDENCE", "CHANGE", "DECISION"],
            "limitations": ["Every relationship cites the record that established it; nothing is inferred.",
                            "A node marked UNKNOWN is referenced but not observed by any connected source.",
                            "Delegation relationships are inert: no authority is derived from them.",
                            "This is a projection of the immutable record store, not a separate graph database."]}


# --- Summary and gate ----------------------------------------------------------

def summary(ctx):
    view = clearance(ctx)
    rows = ctx.rows
    authority = authority_map(ctx) if ctx.envelope else {"authorities": []}
    recent = changes(ctx, limit=20)
    why = view["meaning"]
    top = next((c for c in recent if c["consequence"]["effect"] == "OPEN"), None)
    latest = ctx.decisions[0] if ctx.decisions else None
    if view["state"] == "CLEARED":
        supported = sum(1 for row in rows.values() if row["supported"])
        why = (f"{supported} of {len(ctx.properties)} critical claims are supported by evidence produced for this "
               f"exact state, and no observed change since {when(view['last_current_clearance_at'])} affects them.")
    elif view["state"] == "NEEDS_REASSESSMENT" and top:
        why = top["headline"]
    elif view["state"] == "NOT_CLEARED" and latest:
        failing = [row["title"] for row in rows.values() if row["security"] == "FAIL"]
        broken = [row["title"] for row in rows.values() if row["legitimate_task"] == "FAILURE"]
        why = (f"A prohibited outcome was observed: {failing[0]}" if failing else
               f"Security held, but the legitimate task failed: {broken[0]}" if broken else view["meaning"])
    statuses = [claim_status(rows.get(str(p.id))) for p in ctx.properties]
    counts = {"total": len(ctx.properties), "supported": statuses.count("SUPPORTED"),
              "needs_fresh_evidence": statuses.count("NEEDS_FRESH_EVIDENCE"), "failed": statuses.count("FAILED"),
              "unknown": statuses.count("UNKNOWN"), "defined_not_executable": len(ctx.claim_definitions)}
    next_action = ("Establish a baseline for this boundary." if not ctx.decisions else
                   "Re-establish the affected claims before this authority continues." if view["state"] in {"NEEDS_REASSESSMENT", "NOT_CLEARED"} else
                   "Share a Current Assurance Passport or connect a consumer to the Assurance Gate." if view["state"] == "CLEARED" else
                   "Review the revocation and establish a new clearance.")
    return {
        "schema_version": INTELLIGENCE, "as_of": ctx.stamp.isoformat(),
        "system": {"id": str(ctx.system.id), "name": ctx.system.payload.get("name"),
                   "description": ctx.system.payload.get("description"), "synthetic": ctx.synthetic},
        "environment": {"id": str(ctx.environment.id), "name": ctx.environment.payload["name"],
                        "purpose": ctx.environment.payload["purpose"]} if ctx.environment else None,
        "environments": [{"id": str(e.id), "name": e.payload["name"], "purpose": e.payload["purpose"]} for e in ctx.environments],
        "clearance": view, "why": why,
        "powers": [{"action": a["action"], "label": a["label"], "assurance": a["assurance"], "basis": a["basis"]}
                   for a in authority["authorities"]],
        "claims": counts,
        "open_changes": [{"id": c["id"], "headline": c["headline"], "recorded_at": c["recorded_at"]}
                         for c in recent if c["consequence"]["effect"] == "OPEN"][:5],
        "obligations": (ctx.current or {}).get("assurance_obligations", []),
        "passport_available": bool(ctx.state),
        "next_action": next_action,
    }


def gate(ctx, *, action=None, expected_state_digest=None):
    """The machine-consumable answer to: is this system still cleared to act?

    ThreatVeil supplies assurance truth; the consumer decides its own availability
    policy. UNKNOWN never means authorization, and no response grants permission.
    """
    body = {"schema_version": GATE_PROFILE, "issuer": "threatveil", "profile": GATE_PROFILE,
            "evaluated_at": ctx.stamp.isoformat(),
            "system": {"id": str(ctx.system.id), "name": ctx.system.payload.get("name")},
            "environment": None, "state": None, "authority": None, "status": "UNKNOWN", "action": None,
            "cleared": False, "authorizes": False, "decision": None, "claims": None, "scope": None,
            "obligations": [], "reasons": [],
            "freshness": {"evaluated_at": ctx.stamp.isoformat(), "max_age_seconds": GATE_MAX_AGE_SECONDS,
                          "valid_until": (ctx.stamp + timedelta(seconds=GATE_MAX_AGE_SECONDS)).isoformat()},
            "consumer_contract": {
                "UNKNOWN": "ThreatVeil cannot establish clearance. Never treat UNKNOWN as authorization.",
                "cleared": "True only when status is CURRENT and the decision action is ALLOW.",
                "cache": f"Do not rely on a response past freshness.valid_until (at most {GATE_MAX_AGE_SECONDS}s).",
                "availability": "If ThreatVeil is unreachable, apply your own fail-open or fail-closed policy.",
                "offline": "Verify decision.record_uri's signed record offline for historical authenticity; "
                           "that never establishes current status."}}
    if ctx.environment is None:
        body["reasons"].append("No environment is defined for this system.")
        return body
    body["environment"] = {"id": str(ctx.environment.id), "name": ctx.environment.payload["name"],
                           "purpose": ctx.environment.payload["purpose"]}
    if ctx.envelope:
        body["authority"] = {"envelope_digest": ctx.envelope.payload["envelope_digest"],
                             "policy_epoch": ctx.envelope.payload["policy_epoch"],
                             "reviewed_until": ctx.envelope.payload["expires_at"]}
    if ctx.state is None or ctx.current is None:
        body["reasons"].append("No system state has been established for this environment.")
        return body
    body["state"] = {"id": str(ctx.state.id), "digest": ctx.state.payload["state_digest"],
                     "envelope_digest": ctx.state.payload["envelope_digest"]}
    rows = ctx.rows
    statuses = {pid: claim_status(row) for pid, row in rows.items()}
    body["claims"] = {"total": len(rows), "supported": sum(1 for s in statuses.values() if s == "SUPPORTED"),
                      "affected": [{"property_id": pid, "title": rows[pid]["title"], "status": status,
                                    "applicability": rows[pid]["applicability"]}
                                   for pid, status in statuses.items() if status != "SUPPORTED"]}
    body["obligations"] = [{"kind": o["kind"], "subject": o["subject"], "reason": o["reason"]}
                           for o in ctx.current.get("assurance_obligations", []) if o["kind"] != "NONE"]
    decision = next((d for d in ctx.decisions if d.payload["state_id"] == str(ctx.state.id)), None)
    if decision is None:
        if ctx.decisions:
            body["status"] = "SUPERSEDED"
            body["reasons"].append("The latest clearance was issued for an earlier system state.")
            body["decision"] = decision_view(ctx, ctx.decisions[0], status=False)
        else:
            body["reasons"].append("No clearance has been issued for this boundary.")
    else:
        status = status_of(ctx, decision)
        body["status"] = status
        body["action"] = decision.payload["action"]
        body["decision"] = decision_view(ctx, decision, status=False)
        body["cleared"] = status == "CURRENT" and decision.payload["action"] == "ALLOW"
        if status != "CURRENT":
            body["reasons"].append({"EXPIRED": "The reviewed authority or exact-state observation behind this clearance lapsed.",
                                    "SUPERSEDED": "The system changed after this clearance was issued.",
                                    "REASSESS": "The evidence behind this clearance moved; it must be re-established.",
                                    "REVOKED": "This clearance was withdrawn explicitly."}.get(status, "Status unknown."))
        elif decision.payload["action"] != "ALLOW":
            body["reasons"].append(f"The current decision for this exact state is {decision.payload['action']}.")
        valid_until = [ctx.stamp + timedelta(seconds=GATE_MAX_AGE_SECONDS),
                       datetime.fromisoformat(ctx.envelope.payload["expires_at"])] if ctx.envelope else [
            ctx.stamp + timedelta(seconds=GATE_MAX_AGE_SECONDS)]
        if ctx.state.payload.get("observation_expires_at"):
            valid_until.append(datetime.fromisoformat(ctx.state.payload["observation_expires_at"]))
        body["freshness"]["valid_until"] = min(valid_until).isoformat()
    if expected_state_digest and expected_state_digest != ctx.state.payload["state_digest"]:
        body["status"], body["cleared"] = "SUPERSEDED", False
        body["reasons"].append("The state digest you hold is no longer the current state of this system.")
    if action:
        declared = bool(ctx.envelope and action in ctx.envelope.payload["actions"])
        claims = [p for p in ctx.properties if action in governs(p)]
        states = [statuses.get(str(p.id), "UNKNOWN") for p in claims]
        scope_status = ("UNDECLARED" if not declared else "UNGOVERNED" if not claims else
                        "SUPPORTED" if all(s == "SUPPORTED" for s in states) else
                        "FAILED" if "FAILED" in states else "NEEDS_FRESH_EVIDENCE")
        body["scope"] = {"action": action, "label": action_label(action), "declared": declared,
                         "status": scope_status, "claims": [{"property_id": str(p.id), "title": p.payload["title"],
                                                             "status": s} for p, s in zip(claims, states, strict=True)],
                         "cleared": bool(body["cleared"] and scope_status == "SUPPORTED")}
        if not declared:
            body["reasons"].append("This action is outside the declared authority boundary.")
    return body


# --- The operating centre ---------------------------------------------------------

HOME = "assurance-home/v1"
ATTENTION = {"NEEDS_REASSESSMENT", "NOT_CLEARED", "REVOKED"}


def _home_change(view):
    consequence = view["consequence"]
    return {"id": view["id"], "headline": view["headline"], "recorded_at": view["recorded_at"],
            "effect": consequence["effect"], "connector": (view.get("origin") or {}).get("connector"),
            "classification": (view.get("authority") or {}).get("classification"),
            "claims_affected": len(consequence["claims_affected"]),
            "still_holds": len(consequence["still_holds"])}


def home_row(ctx):
    """One protected system, reduced to what an operator must decide about it.

    Every field is the same projection the system workspace shows; nothing new is
    concluded here, and a system without a baseline is never called cleared.
    """
    view = clearance(ctx)
    rows = ctx.rows
    statuses = [claim_status(rows.get(str(p.id))) for p in ctx.properties]
    recent = changes(ctx, limit=10)
    open_changes = [c for c in recent if c["consequence"]["effect"] == "OPEN"]
    latest = recent[0] if recent else None
    needs_evidence = statuses.count("NEEDS_FRESH_EVIDENCE") + statuses.count("FAILED") + statuses.count("UNKNOWN")
    stale_sources = [h for h in ctx.health if h.get("status") not in {"CURRENT", "IMPORTED"} or h.get("failure")]
    # A system with no baseline is never filed as current: nothing has been established for it.
    attention = bool(view["state"] in ATTENTION or open_changes or ctx.state is None or needs_evidence)
    reason = view["meaning"]
    if open_changes:
        reason = open_changes[0]["headline"]
    elif view["state"] == "NOT_CLEARED":
        failing = [row["title"] for row in rows.values() if row["security"] == "FAIL"]
        broken = [row["title"] for row in rows.values() if row["legitimate_task"] == "FAILURE"]
        if failing:
            reason = f"A prohibited outcome was observed: {failing[0]}"
        elif broken:
            reason = f"Security held, but the legitimate task failed: {broken[0]}"
    action = ("SET_UP" if ctx.state is None else "REVIEW_CHANGE" if open_changes
              else "RESTORE" if view["state"] in ATTENTION
              else "RE_ESTABLISH" if needs_evidence else "SHARE")
    return {
        "id": str(ctx.system.id), "name": ctx.system.payload.get("name"),
        "description": ctx.system.payload.get("description"), "synthetic": ctx.synthetic,
        "environment": {"id": str(ctx.environment.id), "name": ctx.environment.payload["name"],
                        "purpose": ctx.environment.payload["purpose"]} if ctx.environment else None,
        "clearance": {"state": view["state"], "label": view["label"], "meaning": view["meaning"],
                      "decision_status": view["decision_status"],
                      "last_current_clearance_at": view["last_current_clearance_at"]},
        "why": reason,
        "claims": {"total": len(ctx.properties), "supported": statuses.count("SUPPORTED"),
                   "needs_fresh_evidence": statuses.count("NEEDS_FRESH_EVIDENCE"),
                   "failed": statuses.count("FAILED"), "unknown": statuses.count("UNKNOWN"),
                   "declared_not_executable": len(ctx.claim_definitions)},
        "baseline": ctx.state is not None,
        "open_changes": [_home_change(c) for c in open_changes[:3]],
        "latest_change": _home_change(latest) if latest else None,
        "sources": {"total": len(ctx.health), "needs_attention": len(stale_sources),
                    "live": sum(1 for i in ctx.installations if i.payload.get("mode") in {"POLL", "PUSH"})},
        "passports": len(ctx.passports),
        "needs_attention": attention, "next_action": action,
    }


def home(session, org, system_rows, limit=25):
    """The organization's attention queue, derived from the same per-system projections.

    One read, one transaction: the alternative is one request per protected system.
    """
    from .change_assurance import history as _history

    rows, activity, review_queue = [], [], 0
    for record in system_rows[:limit]:
        try:
            ctx = load(session, org, record.id)
        except HTTPException:  # pragma: no cover - a system removed between reads
            continue
        row = home_row(ctx)
        rows.append(row)
        for view in changes(ctx, limit=5):
            activity.append({"kind": "CHANGE", "id": view["id"], "system_id": row["id"], "system": row["name"],
                             "connector": (view.get("origin") or {}).get("connector"),
                             "at": view["recorded_at"], "headline": view["headline"],
                             "detail": view["consequence"]["effect"],
                             "claims_affected": len(view["consequence"]["claims_affected"])})
        for decision in ctx.decisions[:5]:
            action = decision.payload["action"]
            activity.append({"kind": "CLEARANCE", "system_id": row["id"], "system": row["name"],
                             "at": decision.created_at.astimezone(timezone.utc).isoformat(),
                             "headline": "Assurance restored" if action == "ALLOW" else "Assurance not established",
                             "detail": action, "claims_affected": 0})
        review_queue += sum(1 for proposal in _history(session, org, "dependency_mapping_proposal", record.id)
                            if proposal.payload.get("status") == "PROPOSED")
        for passport in ctx.passports[:3]:
            activity.append({"kind": "PASSPORT", "system_id": row["id"], "system": row["name"],
                             "at": passport.created_at.astimezone(timezone.utc).isoformat(),
                             "headline": f"Passport issued for {passport.payload.get('audience', 'an external party')}",
                             "detail": "ISSUED", "claims_affected": 0})
    activity.sort(key=lambda item: item["at"], reverse=True)
    attention = [row for row in rows if row["needs_attention"]]
    return {
        "schema_version": HOME, "as_of": now().isoformat(),
        "counts": {
            "systems": len(system_rows), "shown": len(rows),
            "needs_attention": len(attention),
            "claims_needing_evidence": sum(row["claims"]["needs_fresh_evidence"] + row["claims"]["failed"]
                                           for row in rows),
            "open_changes": sum(len(row["open_changes"]) for row in rows),
            "sources_needing_attention": sum(row["sources"]["needs_attention"] for row in rows),
            "awaiting_review": review_queue,
        },
        "attention": attention, "current": [row for row in rows if not row["needs_attention"]],
        "systems": rows, "activity": activity[:20],
        "truncated": len(system_rows) > len(rows),
        "note": "Derived from the same per-system projections the system workspace shows. "
                "It concludes nothing new and grants no authority.",
    }


# --- System stack and reliance ------------------------------------------------------

ECOSYSTEM_ORDER = ("github", "claude_code", "claude_agent_sdk", "openai_agents", "mcp", "langgraph", "crewai",
                   "cloud_run", "opentelemetry")
ECOSYSTEM_LABEL = {"github": "GitHub", "claude_code": "Claude Code", "claude_agent_sdk": "Claude Agent SDK",
                   "openai_agents": "OpenAI Agents SDK", "mcp": "MCP", "langgraph": "LangGraph", "crewai": "CrewAI",
                   "cloud_run": "Cloud Run", "opentelemetry": "OpenTelemetry"}
CONNECTOR_ECOSYSTEM = {"github": "github", "mcp": "mcp", "gcp_cloud_run": "cloud_run", "otel": "opentelemetry",
                       "openai_agents": "openai_agents", "anthropic_hooks": "claude_agent_sdk"}
FORMAT_ECOSYSTEM = {"claude_settings": "claude_code", "claude_subagent": "claude_code", "mcp_json": "mcp",
                    "langgraph": "langgraph", "crewai": "crewai"}
FORMAT_LABEL = {"claude_settings": "Claude Code settings.json", "claude_subagent": "Claude subagent definition",
                "mcp_json": ".mcp.json", "langgraph": "langgraph.json", "crewai": "CrewAI agents.yaml",
                "manifest": "ThreatVeil agent manifest"}
RELATIONSHIP_RANK = {"LIVE_SOURCE": 0, "INSTRUMENTED": 1, "IMPORTED": 2, "DECLARED": 3}


def stack(ctx):
    """The technologies ThreatVeil has established for this system, and exactly how.

    Every item carries its basis: a source ThreatVeil reads itself (LIVE_SOURCE), one
    that sends observations (INSTRUMENTED), an imported snapshot (IMPORTED), or a
    declaration inside an imported definition (DECLARED). Nothing is inferred from a
    model string, a host, a tool name or a URL, and an import is never called connected.
    """
    installations = getattr(ctx, "installations", None) or []
    health = {h["installation_id"]: h for h in (getattr(ctx, "health", None) or [])}
    latest = {}
    for batch in getattr(ctx, "batch_rows", None) or []:
        latest.setdefault(batch.payload.get("installation_id"), batch)
    found = {}

    def add(identity, relationship, basis, installation=None):
        state = health.get(str(installation.id)) if installation else None
        entry = {"id": identity, "label": ECOSYSTEM_LABEL[identity], "relationship": relationship, "basis": basis,
                 "installation_id": str(installation.id) if installation else None,
                 "connected": bool(state and state.get("connected")),
                 "status": state.get("status") if state else None,
                 "last_valid_at": state.get("last_valid_at") if state else None, "also": []}
        current = found.get(identity)
        if current is None:
            found[identity] = entry
        elif RELATIONSHIP_RANK[relationship] < RELATIONSHIP_RANK[current["relationship"]]:
            entry["also"] = [current["basis"], *current["also"]]
            found[identity] = entry
        elif basis not in current["also"] and basis != current["basis"]:
            current["also"].append(basis)

    for installation in installations:
        payload = installation.payload
        connector, mode = payload.get("connector_id"), payload.get("mode")
        batch = latest.get(str(installation.id))
        facts = (batch.payload.get("facts") or {}) if batch else {}
        if connector == "agent_definition":
            fmt = facts.get("definition_format")
            if FORMAT_ECOSYSTEM.get(fmt):
                add(FORMAT_ECOSYSTEM[fmt], "IMPORTED", f"Imported {FORMAT_LABEL[fmt]}", installation)
            servers = facts.get("mcp_servers") or []
            if servers and fmt != "mcp_json":
                add("mcp", "DECLARED", f"{len(servers)} MCP server{'s' if len(servers) != 1 else ''} declared in an "
                                       "imported definition", installation)
            continue
        identity = CONNECTOR_ECOSYSTEM.get(connector)
        if not identity:
            continue
        if mode == "POLL":
            add(identity, "LIVE_SOURCE", f"{payload.get('name')}: ThreatVeil reads this source", installation)
        elif mode == "PUSH":
            add(identity, "INSTRUMENTED", f"{payload.get('name')}: observations are sent to ThreatVeil", installation)
        else:
            tools = facts.get("tool_names") or []
            detail = (f"Imported tool catalog snapshot · {len(tools)} tool{'s' if len(tools) != 1 else ''}"
                      if connector == "mcp" else "Imported trace export" if identity in {"openai_agents", "claude_agent_sdk"}
                      else "Imported snapshot")
            add(identity, "IMPORTED", detail, installation)
    return {"items": [found[key] for key in ECOSYSTEM_ORDER if key in found],
            "principle": "Only technologies a source or an imported definition establishes. Nothing is inferred, "
                         "and an imported snapshot is never presented as a live connection."}


def reliance(ctx):
    """Who has relied on this system's answer: machine Gate reads and external Passport checks.

    Read from minimized, server-observed service records, which are written at most once
    per consumer per hour. It counts reliance and concludes nothing about assurance.
    """
    from sqlalchemy import select

    sid = str(ctx.system.id)
    gate_rows = list(ctx.session.scalars(select(Record).where(
        Record.organization_id == ctx.org, Record.kind == "service_metric",
        Record.payload["name"].astext == "assurance_gate.checked", Record.payload["system"].astext == sid,
        Record.payload["consumer"].astext.like("machine:%"),
    ).order_by(Record.created_at.desc()).limit(500)))
    passport_ids = [str(p.id) for p in ctx.passports] or [""]
    external = list(ctx.session.scalars(select(Record.created_at).where(
        Record.organization_id == ctx.org, Record.kind == "service_metric",
        Record.payload["name"].astext == "passport.status_checked",
        Record.payload["passport"].astext.in_(passport_ids),
    ).order_by(Record.created_at.desc()).limit(500)))
    consumers = sorted({row.payload["consumer"].removeprefix("machine:") for row in gate_rows})
    return {
        "machine_check_windows": len(gate_rows),
        "last_machine_check_at": _iso(gate_rows[0].created_at) if gate_rows else None,
        "machine_consumers": consumers[:20],
        "external_check_windows": len(external),
        "last_external_check_at": _iso(external[0]) if external else None,
        "bucket_seconds": 3600,
        "note": "Recorded at most once per consumer per hour, so a time is the start of the latest recorded hour.",
    }
