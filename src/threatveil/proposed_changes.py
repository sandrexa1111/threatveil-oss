"""Proposed-change assurance: what would this change break?

A dry run computes the consequence a proposed agent change would have for current
assurance, without applying it. It is read-only with respect to current clearance:
nothing here writes a source batch, a system state, a decision or a status event.
The only write is one append-only proposed_change_assessment record, labelled
PROPOSED, NON-ACTIVE and NOT CURRENT STATE, so the answer is auditable and
idempotent. The same evaluation replays real configuration history (REPLAYED),
which is shown to the customer and never counted as activation.
"""

import time
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Literal
from uuid import UUID, uuid5

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field, field_validator
from sqlalchemy import select

from .auth import Actor, actor, require
from .schemas import Input
from .change_assurance import history
from .core.contracts import digest
from .db import Record, add_record, audit, get_record, now, transaction
from .source_semantics import CLASSES, EXPANDED, UNKNOWN, explain_source_change, mapping_index, scope_change

router = APIRouter(tags=["proposed-change-assurance"])
PROFILE = "proposed-change-assessment/v1"
CHECK_NAME = "ThreatVeil — Change Assurance"
LABEL = "PROPOSED · NON-ACTIVE · NOT CURRENT STATE"
# Sources whose proposed configuration ThreatVeil can parse deterministically.
EVALUABLE = frozenset({"mcp", "agent_definition"})
PER_MINUTE = 30
MAX_REPLAY = 20
EFFECTS = {
    "WOULD_REQUIRE_REPROOF": "Claims this change reaches would need fresh evidence before clearance could be current again.",
    "NO_CLAIM_AFFECTED": "No approved claim depends on what this change touches; current conclusions would still hold.",
    "NO_CHANGE": "The proposed configuration matches what ThreatVeil last observed from this source.",
    "NO_BASELINE": "ThreatVeil has no observation of this source yet, so there is nothing to compare against.",
    "NO_CLAIMS": "No claims are defined for this system, so no conclusion can be affected.",
    "DECLARED_CLAIMS_AFFECTED": "This change reaches claims you declared. They are not yet verified, so ThreatVeil "
                                "holds no evidence for them: prove them to turn this into an evidenced answer.",
    "NO_DECLARED_CLAIM_AFFECTED": "No declared claim depends on what this change touches. Declared claims are not "
                                  "yet verified.",
}
LIMITATIONS = [
    "A dry run compares declared configuration. It does not execute the agent, a tool or a test.",
    "Nothing here changes the current clearance, evidence or authority; the result is not current state.",
    "Unmapped subjects stay conservative: every claim they could reach is reported as needing fresh evidence.",
]


Strict = Input


class Reference(Strict):
    type: Literal["PULL_REQUEST", "COMMIT", "BRANCH", "MANUAL"] = "MANUAL"
    id: str | None = Field(default=None, max_length=120, pattern=r"^[A-Za-z0-9._/#:-]+$")
    url: str | None = Field(default=None, max_length=500)
    revision: str | None = Field(default=None, pattern=r"^[0-9a-f]{7,64}$")

    @field_validator("id")
    @classmethod
    def plain_label(cls, value):
        # A reference is a label, never a path. Nothing here ever opens a file or a URL.
        if value is not None and (".." in value or value.startswith("/")):
            raise ValueError("Reference must be a plain label, not a path")
        return value

    @field_validator("url")
    @classmethod
    def https_label(cls, value):
        # A label for people. ThreatVeil never fetches it.
        if value is not None and (not value.startswith("https://") or any(c.isspace() or c in "<>\"'" for c in value)):
            raise ValueError("Reference URL must be an https link")
        return value


class ProposedChange(Strict):
    installation_id: UUID
    payload: dict[str, Any]
    reference: Reference = Field(default_factory=Reference)
    idempotency_key: str = Field(min_length=8, max_length=120)


class Revision(Strict):
    revision: str = Field(pattern=r"^[0-9a-f]{7,64}$")
    committed_at: datetime | None = None
    payload: dict[str, Any]


class Replay(Strict):
    installation_id: UUID
    revisions: list[Revision] = Field(min_length=2, max_length=MAX_REPLAY)
    idempotency_key: str = Field(min_length=8, max_length=120)


def _limit(session, org):
    from sqlalchemy.dialects.postgresql import insert

    from .db import RateBucket

    key = sha256(f"proposed-change|{org}".encode()).hexdigest()
    statement = insert(RateBucket).values(key=key, window=int(time.time() // 60), count=1)
    count = session.execute(statement.on_conflict_do_update(
        index_elements=["key", "window"], set_={"count": RateBucket.count + 1}).returning(RateBucket.count)).scalar_one()
    if count > PER_MINUTE:
        raise HTTPException(429, "Proposed-change evaluation rate limit reached; try again shortly")


def snapshot_of(installation, payload):
    from .connectors.collectors import imported_snapshot

    connector = installation.payload["connector_id"]
    if connector not in EVALUABLE:
        raise HTTPException(422, "ThreatVeil cannot parse a proposed configuration for this source deterministically")
    from .agent_definitions import DefinitionError

    try:
        return imported_snapshot(connector, payload, installation.payload["source_identity"], now())
    except HTTPException:
        raise
    except DefinitionError as error:
        raise HTTPException(422, str(error)) from None  # content-free by construction
    except (ValueError, TypeError, KeyError, RecursionError):
        # Never echo customer configuration back in an error.
        raise HTTPException(422, "The proposed configuration could not be parsed") from None


def as_batch(installation, snapshot, prior=None):
    """The comparable shape of a snapshot, as persist_batch would have recorded it."""
    old = (prior or {}).get("components", {})
    components = snapshot.components if snapshot.complete else {**old, **snapshot.components}
    return {"components": components, "facts": snapshot.facts, "complete": snapshot.complete,
            "source_identity": installation.payload["source_identity"], "snapshot_digest": digest(snapshot)}


def evaluate(ctx, installation, before, after):
    """The consequence of moving this source from `before` to `after`, for current claims."""
    from .assurance_intelligence import claim_status, declared_reach, declared_view, describe, reached_claims

    rows = ctx.rows
    changed = sorted(key for key in (before or {}).get("components", {}).keys() | after["components"].keys()
                     if digest((before or {}).get("components", {}).get(key)) != digest(after["components"].get(key)))
    explanation, reached, scoped, declared, declared_effect = None, [], False, [], None
    if before is None:
        effect = "NO_BASELINE"
    elif not changed:
        effect = "NO_CHANGE"
    else:
        event = {"changed_components": changed, "change_kind": "COMPONENT_CHANGE",
                 "source_identity": installation.payload["source_identity"]}
        explanation = explain_source_change(event, before, after)
        explanation["scope"] = scope_change(explanation, mapping_index(ctx.mappings, installation.id))
        declared, declared_effect = declared_reach(ctx, explanation)
        if ctx.properties:
            reached, scoped = reached_claims(ctx, explanation)
            effect = "WOULD_REQUIRE_REPROOF" if reached else "NO_CLAIM_AFFECTED"
        else:
            # A declared claim is a real answer on the free tier; it is never evidence.
            effect = declared_effect or "NO_CLAIMS"
    reached_ids = {str(p.id) for p in reached}
    claims = []
    for prop in ctx.properties:
        pid = str(prop.id)
        status = claim_status(rows.get(pid))
        if pid in reached_ids:
            outcome = "WOULD_NEED_FRESH_EVIDENCE" if status == "SUPPORTED" else "NOT_CURRENTLY_SUPPORTED"
        else:
            outcome = "WOULD_STILL_HOLD" if status == "SUPPORTED" else "UNCHANGED"
        claims.append({"property_id": pid, "title": prop.payload["title"], "current_status": status,
                       "outcome": outcome, "reached": pid in reached_ids})
    authority = (explanation or {}).get("authority") or None
    classification = authority["classification"] if authority else None
    dimensions = [d for d in (authority or {}).get("dimensions", []) if d["direction"] != "AUTHORITY_EQUIVALENT"]
    affected = [c for c in claims if c["reached"]]
    subject = next((s["subject"] for s in (authority or {}).get("subjects", [])
                    if s["subject"] != "authorization" and s["direction"] in {EXPANDED, UNKNOWN}), None)
    headline = {
        "WOULD_REQUIRE_REPROOF": f"{len(affected)} claim{'s' if len(affected) != 1 else ''} would need fresh evidence",
        "NO_CLAIM_AFFECTED": "No claim would be affected",
        "NO_CHANGE": "No change from the last observation",
        "NO_BASELINE": "No observation to compare against yet",
        "NO_CLAIMS": "No claims defined yet",
        "DECLARED_CLAIMS_AFFECTED": f"{len(declared)} declared claim{'s' if len(declared) != 1 else ''} would be "
                                    "affected · not yet verified",
        "NO_DECLARED_CLAIM_AFFECTED": "No declared claim would be affected",
    }[effect]
    if classification == EXPANDED:
        headline = f"{subject or 'Authority'} would expand · " + headline
    summary = {"kind": "PROPOSED_CHANGE", "headline": headline, "effect": effect, "classification": classification,
               "scoped": bool(scoped), "claims_affected": [{"property_id": c["property_id"], "title": c["title"]}
                                                           for c in affected],
               "declared_claims_affected": [{"definition_id": c["definition_id"], "claim": c["claim"]}
                                            for c in declared_view(declared)],
               "declared_effect": declared_effect,
               "still_holds": sum(1 for c in claims if c["outcome"] == "WOULD_STILL_HOLD")}
    explanation_lines = [EFFECTS[effect]] + [describe(d)[:1].upper() + describe(d)[1:] + "." for d in dimensions[:5]]
    if explanation and not explanation["scope"]["fully_mapped"] and affected:
        explanation_lines.append("Part of what changed is not mapped to a reviewed claim dependency, so every claim it "
                                 "could reach is listed.")
    return {"summary": summary, "claims": claims, "declared_claims": declared_view(declared),
            "changed_components": changed[:200],
            "authority": authority, "explanation": explanation_lines,
            "mapping": (explanation or {}).get("scope") or {"fully_mapped": False, "dependencies": [], "unmapped": [],
                                                           "mapping_ids": []}}


def check_render(summary, claims, clearance_state):
    """The GitHub check body. WARN only: a dry run never blocks by default."""
    effect = summary["effect"]
    conclusion = "success" if effect in {"NO_CLAIM_AFFECTED", "NO_CHANGE", "NO_DECLARED_CLAIM_AFFECTED"} else "neutral"
    lines = [f"**{summary['headline']}**", "", EFFECTS[effect], "",
             f"Current clearance: **{clearance_state}** (unchanged by this check)."]
    affected = [c for c in claims if c["reached"]]
    if affected:
        lines += ["", "| Claim | Now | If merged |", "|---|---|---|"]
        lines += [f"| {c['title'][:120]} | {c['current_status']} | {c['outcome']} |" for c in affected[:20]]
    declared = summary.get("declared_claims_affected") or []
    if declared:
        lines += ["", "| Declared claim | Now | If merged |", "|---|---|---|"]
        lines += [f"| {c['claim'][:120]} | NOT_YET_VERIFIED | WOULD_NEED_EVIDENCE |" for c in declared[:20]]
    lines += ["", f"_{LABEL}. ThreatVeil evaluated declared configuration only._"]
    return {"name": CHECK_NAME, "mode": "WARN", "blocking": False, "conclusion": conclusion,
            "title": summary["headline"][:120], "summary": "\n".join(lines)[:60000]}


def assessment_view(row):
    data = row.payload
    return {"id": str(row.id), "status": data["status"], "mode": data["mode"], "label": data["label"],
            "active": False, "current_state": False, "system_id": data["system_id"],
            "environment_id": data["environment_id"], "installation_id": data["installation_id"],
            "reference": data["reference"], "summary": data["summary"], "claims": data["claims"],
            "authority": data["authority"], "mapping": data["mapping"], "explanation": data["explanation"],
            "changed_components": data["changed_components"], "clearance": data["clearance"], "check": data["check"],
            "consumer": data.get("consumer"), "created_at": row.created_at.astimezone(timezone.utc).isoformat(),
            "limitations": data["limitations"]}


def _installation(session, org, system, installation_id):
    installation = get_record(session, org, installation_id, "connector_installation")
    if installation.payload["system_id"] != str(system.id):
        raise HTTPException(404, "Source not found for this system")
    return installation


def _record(session, org, a, system, installation, result, *, mode, reference, request_digest, identifier,
            consumer, baseline_batch_id, ctx):
    from .assurance_intelligence import clearance

    state = clearance(ctx)["state"]
    would = ("NEEDS_REASSESSMENT" if state == "CLEARED" and result["summary"]["effect"] == "WOULD_REQUIRE_REPROOF"
             else state)
    payload = {
        "schema_version": PROFILE, "mode": mode, "status": mode, "label": LABEL, "active": False,
        "current_state": False, "system_id": str(system.id), "environment_id": installation.payload["environment_id"],
        "installation_id": str(installation.id), "connector_id": installation.payload["connector_id"],
        "reference": reference, "request_digest": request_digest, "baseline_batch_id": baseline_batch_id,
        **result, "clearance": {"current": state, "unchanged": True, "if_applied": would},
        "check": check_render(result["summary"], result["claims"], state), "consumer": consumer,
        "submitted_by": str(a.user_id), "limitations": LIMITATIONS,
    }
    row = add_record(session, org, "proposed_change_assessment", payload,
                     {"system": system.id, "installation": installation.id}, record_id=identifier)
    audit(session, org, a.user_id, f"proposed_change.{mode.lower()}", row.id)
    return row


@router.post("/v1/systems/{system_id}/proposed-changes", status_code=201)
def propose(system_id: UUID, body: ProposedChange, request: Request, a: Actor = Depends(actor)):
    """What would this change break? Evaluated against current claims; nothing current changes."""
    from .assurance_api import consumer_label
    from .assurance_intelligence import load
    from .connectors import previous_batch

    require(a)
    with transaction(a.user_id, a.org_id) as session:
        system = get_record(session, a.org_id, system_id, "system")
        installation = _installation(session, a.org_id, system, body.installation_id)
        request_digest = digest({"installation_id": str(body.installation_id), "payload": body.payload,
                                 "reference": body.reference.model_dump(mode="json")})
        identifier = uuid5(a.org_id, f"proposed-change:{system.id}:{body.idempotency_key}")
        existing = session.get(Record, identifier)
        if existing is not None:
            if existing.payload["request_digest"] != request_digest:
                raise HTTPException(409, "Idempotency key already evaluated a different proposed change")
            return {**assessment_view(existing), "duplicate": True}
        _limit(session, a.org_id)
        snapshot = snapshot_of(installation, body.payload)
        prior = previous_batch(session, a.org_id, installation.id)
        ctx = load(session, a.org_id, system.id, installation.payload["environment_id"])
        after = as_batch(installation, snapshot, prior.payload if prior else None)
        result = evaluate(ctx, installation, prior.payload if prior else None, after)
        row = _record(session, a.org_id, a, system, installation, result, mode="PROPOSED",
                      reference=body.reference.model_dump(mode="json"), request_digest=request_digest,
                      identifier=identifier, consumer=consumer_label(request, a),
                      baseline_batch_id=str(prior.id) if prior else None, ctx=ctx)
        return assessment_view(row)


@router.post("/v1/systems/{system_id}/history-replay", status_code=201)
def replay(system_id: UUID, body: Replay, request: Request, a: Actor = Depends(actor)):
    """Consequences of real past configuration changes, judged by today's claims. REPLAYED; never activation."""
    from .assurance_api import consumer_label
    from .assurance_intelligence import load

    require(a)
    with transaction(a.user_id, a.org_id) as session:
        system = get_record(session, a.org_id, system_id, "system")
        installation = _installation(session, a.org_id, system, body.installation_id)
        request_digest = digest(body.model_dump(mode="json"))
        base = uuid5(a.org_id, f"history-replay:{system.id}:{body.idempotency_key}")
        existing = session.get(Record, uuid5(base, "1"))
        if existing is not None:
            if existing.payload["request_digest"] != request_digest:
                raise HTTPException(409, "Idempotency key already replayed different history")
            rows = [session.get(Record, uuid5(base, str(i))) for i in range(1, len(body.revisions))]
            return {"mode": "REPLAYED", "items": [assessment_view(r) for r in rows if r is not None], "duplicate": True}
        _limit(session, a.org_id)
        ordered = sorted(body.revisions, key=lambda r: r.committed_at or datetime.min.replace(tzinfo=timezone.utc))
        ctx = load(session, a.org_id, system.id, installation.payload["environment_id"])
        previous, items = None, []
        for index, revision in enumerate(ordered):
            snapshot = snapshot_of(installation, revision.payload)
            current = as_batch(installation, snapshot, previous)
            if index:
                result = evaluate(ctx, installation, previous, current)
                row = _record(session, a.org_id, a, system, installation, result, mode="REPLAYED",
                              reference={"type": "COMMIT", "id": None, "url": None, "revision": revision.revision,
                                         "previous_revision": ordered[index - 1].revision,
                                         "committed_at": revision.committed_at.isoformat() if revision.committed_at else None},
                              request_digest=request_digest, identifier=uuid5(base, str(index)),
                              consumer=consumer_label(request, a), baseline_batch_id=None, ctx=ctx)
                items.append(assessment_view(row))
            previous = current
        return {"mode": "REPLAYED", "items": items,
                "note": "Replayed history is judged by today's claims and mappings. It is never counted as activation."}


@router.get("/v1/systems/{system_id}/proposed-changes")
def list_proposed(system_id: UUID, a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        system = get_record(session, a.org_id, system_id, "system")
        rows = history(session, a.org_id, "proposed_change_assessment", system.id)[:50]
        return {"items": [assessment_view(r) for r in rows], "label": LABEL, "classifications": list(CLASSES)}


@router.get("/v1/proposed-changes/{assessment_id}")
def get_proposed(assessment_id: UUID, a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        return assessment_view(get_record(session, a.org_id, assessment_id, "proposed_change_assessment"))


def latest(session, org, system_id):
    return session.scalars(select(Record).where(
        Record.organization_id == org, Record.kind == "proposed_change_assessment",
        Record.payload["system_id"].astext == str(system_id)).order_by(Record.created_at.desc()).limit(1)).first()
