"""Dependency mapping as a reviewed decision, with deterministic help.

A mapping states that a named source fact corresponds to a claim dependency. Only an
approved mapping narrows which claims a change can reach, so everything here is a
proposal until a person reviews it: deterministic suggestions, a customer's own entry
and (when explicitly enabled) a model's suggestion all land in the same queue, carry
the evidence behind them, and change nothing on their own.
"""

import re
from datetime import timezone
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field

from .auth import SECURITY, Actor, actor, require
from .change_assurance import history, save_mapping
from .db import add_record, audit, get_record, transaction
from .schemas import Input
from .source_semantics import MCP_PARTS, pointer, split_pointer

router = APIRouter(tags=["dependency-mapping"])
PROFILE = "dependency-mapping-proposal/v1"
REASONS = {
    "TOOL_NAME_MATCH": "The source reports a tool whose name corresponds to this dependency.",
    "ACTION_NAME_MATCH": "The changed fact governs an action whose name corresponds to this dependency.",
    "SCHEMA_FIELD_MATCH": "The declared condition field corresponds to this dependency.",
    "PERMISSION_SCOPE_MATCH": "A declared permission or scope corresponds to this permission dependency.",
    "CONFIG_KEY_MATCH": "The configuration key corresponds to this dependency.",
    "RESOURCE_NAME_MATCH": "The resource this action governs corresponds to this dependency.",
}
# Confidence is a category, never a number: nothing here measures probability.
CONFIDENCE_ORDER = ("EXACT_NAME", "NORMALIZED_NAME", "TOKEN_OVERLAP")
ORIGINS = ("DETERMINISTIC", "CUSTOMER", "AI_PROPOSED")
MAX_SUGGESTIONS_PER_SUBJECT = 5
PERMISSION_CONDITIONS = frozenset({"scopes", "permissions", "roles", "allow", "deny", "ask", "tools",
                                   "allowed_actions", "actions", "tenants", "servers"})


def tokens(value):
    return [part for part in re.split(r"[^a-z0-9]+", str(value).lower()) if part]


def _confidence(left, right):
    if str(left).lower() == str(right).lower():
        return "EXACT_NAME"
    first, second = tokens(left), tokens(right)
    if first and first == second:
        return "NORMALIZED_NAME"
    return "TOKEN_OVERLAP" if set(first) & set(second) else None


def _dependency_name(dependency):
    return str(dependency).partition(":")[2] or str(dependency)


def _dependency_kind(dependency):
    return str(dependency).partition(":")[0].lower()


def subjects_of(ctx, installation_id):
    """Every mappable fact this source has actually reported, with what it names."""
    names, result = ctx.tool_names(), {}
    for batch in ctx.batch_rows:
        payload = batch.payload
        if payload.get("installation_id") != str(installation_id):
            continue
        for key in (payload.get("components") or {}):
            kind = key.partition(":")[0]
            result.setdefault(key, {"subject": key, "kind": kind.upper(), "names": [],
                                    "source_record": str(batch.id)})
            label = names.get(key) or key.partition(":")[2]
            if label and label not in result[key]["names"]:
                result[key]["names"].append(label)
        for path in ((payload.get("facts") or {}).get("authorization") or {}):
            parts = split_pointer(path)
            entry = result.setdefault(path, {"subject": path, "kind": "AUTHORIZATION", "names": [],
                                             "source_record": str(batch.id)})
            entry["condition"] = parts[-1]
            entry["governs"] = parts[-2] if len(parts) > 2 else None
            for value in (entry.get("governs"), parts[-1]):
                if value and value not in entry["names"]:
                    entry["names"].append(value)
        if payload.get("connector_id") == "mcp" or (payload.get("facts") or {}).get("catalog_parts"):
            for part in MCP_PARTS:
                key = pointer("mcp", part)
                result.setdefault(key, {"subject": key, "kind": "CATALOG_PART", "names": [part],
                                        "source_record": str(batch.id)})
    return result


def candidates(ctx):
    """Dependencies a mapping may point at: reviewed claim dependencies and declared ones."""
    from .assurance_intelligence import declared_dependencies, dependencies

    result = {}
    for prop in ctx.properties:
        for dependency in dependencies(prop):
            entry = result.setdefault(dependency, {"dependency": dependency, "basis": "APPROVED_CLAIM", "claims": []})
            entry["claims"].append({"id": str(prop.id), "title": prop.payload["title"]})
    for definition in ctx.claim_definitions:
        for dependency in declared_dependencies(definition):
            entry = result.setdefault(dependency, {"dependency": dependency, "basis": "DECLARED_CLAIM", "claims": []})
            if entry["basis"] == "DECLARED_CLAIM":
                entry["claims"].append({"id": str(definition.id), "title": definition.payload["claim"]})
    return result


def _resource_names(ctx):
    from .assurance_intelligence import authority_map

    mapping = {}
    for authority in authority_map(ctx)["authorities"]:
        mapping[authority["action"]] = list(authority.get("resources") or [])
    return mapping


def suggest(ctx, installation_id):
    """Deterministic mapping suggestions. Every one carries its reason and its evidence."""
    known = subjects_of(ctx, installation_id)
    available = candidates(ctx)
    resources = _resource_names(ctx)
    mapped = {row.payload["subject"] for row in ctx.mappings
              if row.payload.get("installation_id") == str(installation_id)}
    suggestions = []
    for subject, entry in sorted(known.items()):
        if subject in mapped:
            continue
        found = []
        for dependency, candidate in available.items():
            name, kind = _dependency_name(dependency), _dependency_kind(dependency)
            best = None
            for label in entry["names"]:
                confidence = _confidence(label, name)
                if confidence is None:
                    continue
                if entry["kind"] == "TOOL":
                    reason = "TOOL_NAME_MATCH"
                elif entry["kind"] == "AUTHORIZATION":
                    if label == entry.get("condition"):
                        reason = ("PERMISSION_SCOPE_MATCH" if label in PERMISSION_CONDITIONS
                                  else "SCHEMA_FIELD_MATCH")
                    else:
                        reason = "ACTION_NAME_MATCH"
                else:
                    reason = "CONFIG_KEY_MATCH"
                proposal = {"dependency": dependency, "reason": reason, "reason_text": REASONS[reason],
                            "confidence": confidence, "matched": label, "dependency_name": name}
                if best is None or CONFIDENCE_ORDER.index(confidence) < CONFIDENCE_ORDER.index(best["confidence"]):
                    best = proposal
            governs = entry.get("governs")
            if best is None and governs and kind in {"tool", "resource"}:
                for resource in resources.get(governs, []):
                    confidence = _confidence(resource, name)
                    if confidence is not None:
                        best = {"dependency": dependency, "reason": "RESOURCE_NAME_MATCH",
                                "reason_text": REASONS["RESOURCE_NAME_MATCH"], "confidence": confidence,
                                "matched": resource, "dependency_name": name}
                        break
            if best is not None:
                found.append({**best, "basis": candidate["basis"], "claims": candidate["claims"][:5]})
        found.sort(key=lambda item: (CONFIDENCE_ORDER.index(item["confidence"]), item["dependency"]))
        suggestions.append({
            "subject": subject, "kind": entry["kind"], "names": entry["names"],
            "source_record": entry["source_record"], "condition": entry.get("condition"),
            "governs": entry.get("governs"),
            "suggestions": found[:MAX_SUGGESTIONS_PER_SUBJECT],
            "note": "A suggestion is a name correspondence, not a reviewed fact. Nothing applies until approved.",
        })
    return {"schema_version": PROFILE, "installation_id": str(installation_id),
            "unmapped_subjects": len(suggestions), "items": suggestions,
            "reasons": REASONS, "confidence_categories": list(CONFIDENCE_ORDER),
            "principle": "Only an approved mapping narrows which claims a change reaches."}


def overview(ctx):
    """Mapped and unmapped facts per source: why, who approved it, when, and the source record."""
    reviews = {}
    for row in history(ctx.session, ctx.org, "dependency_mapping_review", ctx.system.id):
        reviews.setdefault(row.payload.get("mapping_id"), row.payload)
    sources = []
    for installation in ctx.installations:
        known = subjects_of(ctx, installation.id)
        rows = [r for r in ctx.mappings if r.payload.get("installation_id") == str(installation.id)]
        latest = {}
        for row in rows:  # newest first
            latest.setdefault(row.payload["subject"], row)
        mapped = [{
            "subject": subject, "maps_to": row.payload["maps_to"], "authority_basis": row.payload["authority_basis"],
            "review_note": row.payload["review_note"], "approved_by": row.payload["reviewed_by"],
            "approved_at": row.created_at.astimezone(timezone.utc).isoformat(), "mapping_id": str(row.id),
            "source_record": known.get(subject, {}).get("source_record"),
            "from_proposal": (reviews.get(str(row.id)) or {}).get("proposal_id"),
            "affects_scoping": True,
        } for subject, row in sorted(latest.items())]
        unmapped = [{
            "subject": entry["subject"], "kind": entry["kind"], "names": entry["names"],
            "source_record": entry["source_record"], "affects_scoping": False,
            "consequence": "A change to this fact cannot be scoped, so every claim it could reach needs "
                           "fresh evidence.",
        } for subject, entry in sorted(known.items()) if subject not in latest]
        sources.append({"installation_id": str(installation.id), "name": installation.payload.get("name"),
                        "connector_id": installation.payload.get("connector_id"),
                        "mapped": mapped, "unmapped": unmapped,
                        "fully_mapped": not unmapped and bool(mapped)})
    return {"schema_version": PROFILE, "as_of": ctx.stamp.isoformat(), "sources": sources,
            "candidates": sorted(candidates(ctx).values(), key=lambda item: item["dependency"]),
            "principle": "Mappings are append-only customer statements. The latest approved one per subject applies."}


class ProposalInput(Input):
    environment_id: UUID
    installation_id: UUID
    subject: str = Field(min_length=3, max_length=500)
    maps_to: list[str] = Field(min_length=1, max_length=20)
    reason: Literal["TOOL_NAME_MATCH", "ACTION_NAME_MATCH", "SCHEMA_FIELD_MATCH", "PERMISSION_SCOPE_MATCH",
                    "CONFIG_KEY_MATCH", "RESOURCE_NAME_MATCH", "CUSTOMER_JUDGEMENT"]
    confidence: Literal["EXACT_NAME", "NORMALIZED_NAME", "TOKEN_OVERLAP", "STATED"] = "STATED"
    origin: Literal["DETERMINISTIC", "CUSTOMER", "AI_PROPOSED"] = "CUSTOMER"
    evidence: str = Field(min_length=5, max_length=1000)
    note: str = Field(default="", max_length=1000)


class ReviewInput(Input):
    decision: Literal["APPROVED", "REJECTED", "EDITED"]
    maps_to: list[str] | None = Field(default=None, max_length=20)
    review_note: str = Field(min_length=15, max_length=2000)


def proposal_view(row, *, review=None):
    payload = row.payload
    return {"id": str(row.id), "subject": payload["subject"], "maps_to": payload["maps_to"],
            "reason": payload["reason"], "reason_text": payload.get("reason_text"),
            "confidence": payload["confidence"], "origin": payload["origin"], "evidence": payload["evidence"],
            "note": payload.get("note", ""), "installation_id": payload["installation_id"],
            "environment_id": payload["environment_id"], "model": payload.get("model"),
            "provider": payload.get("provider"), "ai_usage_id": payload.get("ai_usage_id"),
            "status": (review or {}).get("decision", "PROPOSED"),
            "affects_scoping": bool(review and review["decision"] in {"APPROVED", "EDITED"}),
            "mapping_id": (review or {}).get("mapping_id"),
            "reviewed_by": (review or {}).get("reviewed_by"),
            "created_at": row.created_at.astimezone(timezone.utc).isoformat(),
            "proposed_by": payload.get("proposed_by")}


def _reviews(session, org, system_id):
    result = {}
    for row in history(session, org, "dependency_mapping_review", system_id):
        result.setdefault(row.payload["proposal_id"], row.payload)
    return result


@router.get("/v1/systems/{system_id}/mapping-suggestions")
def mapping_suggestions(system_id: UUID, installation_id: UUID, environment_id: UUID | None = None,
                        a: Actor = Depends(actor)):
    """Deterministic suggestions for facts this source reported and nobody has mapped yet."""
    from .assurance_intelligence import load

    with transaction(a.user_id, a.org_id) as session:
        installation = get_record(session, a.org_id, installation_id, "connector_installation")
        if installation.payload["system_id"] != str(system_id):
            raise HTTPException(404, "Source not found for this system")
        ctx = load(session, a.org_id, system_id, environment_id or installation.payload["environment_id"])
        return suggest(ctx, installation.id)


@router.get("/v1/systems/{system_id}/mappings-overview")
def mappings_overview(system_id: UUID, environment_id: UUID | None = None, a: Actor = Depends(actor)):
    from .assurance_intelligence import load

    with transaction(a.user_id, a.org_id) as session:
        return overview(load(session, a.org_id, system_id, environment_id))


@router.post("/v1/systems/{system_id}/mapping-proposals", status_code=201)
def create_proposal(system_id: UUID, body: ProposalInput, a: Actor = Depends(actor)):
    """Queue a mapping for review. A proposal never narrows anything by itself."""
    require(a)
    from .change_assurance import scoped

    with transaction(a.user_id, a.org_id) as session:
        get_record(session, a.org_id, system_id, "system")
        scoped(session, a.org_id, body.environment_id, "environment", system_id)
        installation = get_record(session, a.org_id, body.installation_id, "connector_installation")
        if installation.payload["system_id"] != str(system_id):
            raise HTTPException(404, "Source not found for this system")
        row = add_record(session, a.org_id, "dependency_mapping_proposal", {
            **body.model_dump(mode="json"), "schema_version": PROFILE, "system_id": str(system_id),
            "environment_id": str(body.environment_id), "installation_id": str(body.installation_id),
            "reason_text": REASONS.get(body.reason, "A reviewer's own judgement."),
            "proposed_by": str(a.user_id), "affects_scoping": False, "status": "PROPOSED",
        }, {"system": system_id, "environment": body.environment_id, "installation": body.installation_id})
        audit(session, a.org_id, a.user_id, "mapping.proposed", row.id)
        return proposal_view(row)


@router.get("/v1/systems/{system_id}/mapping-proposals")
def list_proposals(system_id: UUID, a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        get_record(session, a.org_id, system_id, "system")
        reviews = _reviews(session, a.org_id, system_id)
        rows = history(session, a.org_id, "dependency_mapping_proposal", system_id)[:100]
        items = [proposal_view(row, review=reviews.get(str(row.id))) for row in rows]
        return {"items": items, "open": sum(1 for item in items if item["status"] == "PROPOSED"),
                "origins": list(ORIGINS),
                "principle": "Only an approved mapping affects which claims a change reaches."}


@router.post("/v1/mapping-proposals/{proposal_id}/review", status_code=201)
def review_proposal(proposal_id: UUID, body: ReviewInput, a: Actor = Depends(actor)):
    """Approve, edit or reject. Approval is the only path to an effective mapping."""
    require(a, SECURITY)
    from .release_integrity import lock_system

    with transaction(a.user_id, a.org_id) as session:
        proposal = get_record(session, a.org_id, proposal_id, "dependency_mapping_proposal")
        system_id = proposal.payload["system_id"]
        lock_system(session, a.org_id, system_id)
        if str(proposal.id) in _reviews(session, a.org_id, system_id):
            raise HTTPException(409, "This proposal has already been reviewed")
        if body.decision == "EDITED" and not body.maps_to:
            raise HTTPException(422, "An edited mapping must state the dependencies it maps to")
        mapping_id, targets = None, body.maps_to or proposal.payload["maps_to"]
        if body.decision in {"APPROVED", "EDITED"}:
            mapping = save_mapping(
                session, a.org_id, a.user_id, system_id=UUID(system_id),
                environment_id=UUID(proposal.payload["environment_id"]),
                installation_id=UUID(proposal.payload["installation_id"]), subject=proposal.payload["subject"],
                maps_to=targets, review_note=body.review_note)
            mapping_id = str(mapping.id)
        review = add_record(session, a.org_id, "dependency_mapping_review", {
            "schema_version": PROFILE, "system_id": system_id, "environment_id": proposal.payload["environment_id"],
            "proposal_id": str(proposal.id), "decision": body.decision, "maps_to": targets,
            "review_note": body.review_note, "reviewed_by": str(a.user_id), "mapping_id": mapping_id,
        }, {"system": UUID(system_id), "proposal": proposal.id})
        audit(session, a.org_id, a.user_id, f"mapping.{body.decision.lower()}", review.id)
        return {"id": str(review.id), "decision": body.decision, "mapping_id": mapping_id,
                "affects_scoping": mapping_id is not None, "proposal": proposal_view(proposal, review=review.payload)}
