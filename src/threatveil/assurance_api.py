"""System intelligence, the Assurance Gate, Current Assurance Passports and
design-partner definitions.

Read endpoints are deterministic projections from `assurance_intelligence`. Writes
are limited to reviewed dependency mappings, business-language claim definitions,
passport issuance, sharing and revocation, and minimized consumption records. None
of them can change a security conclusion.
"""

import re
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import Field

from . import assurance_intelligence as intel
from . import passports
from .auth import Actor, SECURITY, actor, require
from .change_assurance import PROFILE, history, save_mapping, scoped
from .db import add_record, audit, get_record, serialize, transaction
from .release_integrity import lock_system
from .schemas import Input

router = APIRouter(tags=["assurance-intelligence"])
SYSTEM = "/v1/systems/{system_id}"
CONSUMER = re.compile(r"[a-z0-9][a-z0-9_.-]{0,39}")


def consumer_label(request, a):
    """A bounded, self-declared consumer label; never free text or an identity claim."""
    label = (request.headers.get("x-threatveil-consumer") or "").strip().lower()
    return ("machine:" if a.mode == "api_token" else "person:") + (label if CONSUMER.fullmatch(label) else "unspecified")


def _read(system_id, environment_id, a, build):
    with transaction(a.user_id, a.org_id) as session:
        return build(intel.load(session, a.org_id, system_id, environment_id))


@router.get(SYSTEM + "/assurance/current")
def assurance_gate(system_id: UUID, request: Request, environment_id: UUID | None = None,
                   action: str | None = Query(default=None, min_length=1, max_length=200),
                   expected_state_digest: str | None = Query(default=None, pattern=r"^[0-9a-f]{64}$"),
                   a: Actor = Depends(actor)):
    """The Assurance Gate: is this system still cleared to act? It never authorizes."""
    with transaction(a.user_id, a.org_id) as session:
        ctx = intel.load(session, a.org_id, system_id, environment_id)
        body = intel.gate(ctx, action=action, expected_state_digest=expected_state_digest)
        passports.record_check(session, a.org_id, "assurance_gate.checked", system=system_id,
                               environment=(body["environment"] or {}).get("id"), consumer=consumer_label(request, a))
        return body


@router.get("/v1/home")
def home(limit: int = Query(default=25, ge=1, le=50), a: Actor = Depends(actor)):
    """What needs my attention? The organization's protected systems in one read.

    A read-only projection over the same per-system records the workspace shows,
    scoped to the caller's organization. It concludes nothing new.
    """
    from .db import Record
    from sqlalchemy import select

    with transaction(a.user_id, a.org_id) as session:
        rows = list(session.scalars(
            select(Record).where(Record.organization_id == a.org_id, Record.kind == "system")
            .order_by(Record.created_at.desc(), Record.id.desc()).limit(200)))
        return intel.home(session, a.org_id, rows, limit=limit)


@router.get(SYSTEM + "/intelligence")
def intelligence(system_id: UUID, environment_id: UUID | None = None, a: Actor = Depends(actor)):
    """Everything the protected-system workspace shows, from one consistent snapshot."""
    from .activation import upgrade_moments

    with transaction(a.user_id, a.org_id) as session:
        ctx = intel.load(session, a.org_id, system_id, environment_id)
        return {"schema_version": intel.INTELLIGENCE, "as_of": ctx.stamp.isoformat(),
                "fixture_profile": ctx.system.payload.get("fixture_profile"),
                "summary": intel.summary(ctx), "system_map": intel.system_map(ctx),
                "authority": intel.authority_map(ctx), "authority_changes": intel.authority_changes(ctx),
                "changes": intel.changes(ctx), "evidence": intel.evidence_currency(ctx),
                "lifecycle": intel.lifecycle(ctx), "reestablishment": intel.reestablishment(ctx),
                "memory": intel.assurance_memory(ctx), "gate": intel.gate(ctx), "sources": ctx.health,
                "stack": intel.stack(ctx), "reliance": intel.reliance(ctx),
                "passports": [passports.list_item(session, a.org_id, row, with_status=index < 3)
                              for index, row in enumerate(ctx.passports[:10])],
                "upgrade_moments": upgrade_moments(session, a.org_id)}


@router.get(SYSTEM + "/summary")
def system_summary(system_id: UUID, environment_id: UUID | None = None, a: Actor = Depends(actor)):
    return _read(system_id, environment_id, a, intel.summary)


@router.get(SYSTEM + "/system-map")
def system_map(system_id: UUID, environment_id: UUID | None = None, a: Actor = Depends(actor)):
    return _read(system_id, environment_id, a, intel.system_map)


@router.get(SYSTEM + "/authority")
def authority(system_id: UUID, environment_id: UUID | None = None, a: Actor = Depends(actor)):
    return _read(system_id, environment_id, a, intel.authority_map)


@router.get(SYSTEM + "/authority/changes")
def authority_diff(system_id: UUID, environment_id: UUID | None = None, a: Actor = Depends(actor)):
    return _read(system_id, environment_id, a, lambda ctx: {"items": intel.authority_changes(ctx)})


@router.get(SYSTEM + "/changes")
def change_intelligence(system_id: UUID, environment_id: UUID | None = None, a: Actor = Depends(actor)):
    return _read(system_id, environment_id, a, lambda ctx: {"items": intel.changes(ctx)})


@router.get(SYSTEM + "/evidence-currency")
def evidence_currency(system_id: UUID, environment_id: UUID | None = None, a: Actor = Depends(actor)):
    return _read(system_id, environment_id, a, intel.evidence_currency)


@router.get(SYSTEM + "/lifecycle")
def clearance_lifecycle(system_id: UUID, environment_id: UUID | None = None, a: Actor = Depends(actor)):
    return _read(system_id, environment_id, a, intel.lifecycle)


@router.get(SYSTEM + "/reestablishment")
def reestablishment(system_id: UUID, environment_id: UUID | None = None, a: Actor = Depends(actor)):
    return _read(system_id, environment_id, a, intel.reestablishment)


@router.get(SYSTEM + "/history")
def assurance_history(system_id: UUID, environment_id: UUID | None = None, a: Actor = Depends(actor)):
    return _read(system_id, environment_id, a, intel.assurance_memory)


@router.get(SYSTEM + "/guidance")
def system_guidance(system_id: UUID, environment_id: UUID | None = None, a: Actor = Depends(actor)):
    """Named failure states, what ThreatVeil refuses to claim in each, and the next step."""
    return _read(system_id, environment_id, a, intel.guidance)


@router.get(SYSTEM + "/claims")
def claim_verification(system_id: UUID, environment_id: UUID | None = None, a: Actor = Depends(actor)):
    """Every claim with its verification level: DECLARED, NOT_YET_VERIFIED, QUALIFIED or CURRENT."""
    return _read(system_id, environment_id, a, intel.claim_ladder)


class MappingInput(Input):
    environment_id: UUID
    installation_id: UUID
    subject: str = Field(min_length=3, max_length=500)
    maps_to: list[str] = Field(min_length=1, max_length=20)
    review_note: str = Field(min_length=15, max_length=2000)


@router.post(SYSTEM + "/dependency-mappings", status_code=201)
def create_mapping(system_id: UUID, body: MappingInput, a: Actor = Depends(actor)):
    """A reviewer states which claim dependencies a named source fact controls."""
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        row = save_mapping(session, a.org_id, a.user_id, system_id=system_id,
                           environment_id=body.environment_id, installation_id=body.installation_id,
                           subject=body.subject, maps_to=body.maps_to, review_note=body.review_note)
        audit(session, a.org_id, a.user_id, "assurance.mapping_reviewed", row.id)
        return serialize(row)


@router.get(SYSTEM + "/dependency-mappings")
def list_mappings(system_id: UUID, a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        get_record(session, a.org_id, system_id, "system")
        return {"items": [serialize(r) for r in history(session, a.org_id, "dependency_mapping", system_id)[:500]]}


class ClaimDefinitionInput(Input):
    environment_id: UUID | None = None
    action: str = Field(min_length=1, max_length=200)
    claim: str = Field(min_length=10, max_length=300)
    permitted_outcome: str = Field(min_length=5, max_length=1000)
    forbidden_outcome: str = Field(min_length=5, max_length=1000)
    legitimate_task: str = Field(min_length=5, max_length=1000)
    ground_truth_source: str = Field(min_length=3, max_length=300)
    property_id: UUID | None = None
    # Claim builder fields. Declared dependencies let ThreatVeil say which changes reach a
    # declared claim; they never make it supported.
    resource: str | None = Field(default=None, max_length=200)
    expected_conditions: list[Annotated[str, Field(min_length=2, max_length=200)]] = Field(
        default_factory=list, max_length=10)
    declared_dependencies: list[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,39}:[A-Za-z0-9._:/@*-]{1,160}$")]] = Field(
        default_factory=list, max_length=20)
    template_id: str | None = Field(default=None, pattern=r"^[a-z0-9_]{2,60}$")


@router.post(SYSTEM + "/claim-definitions", status_code=201)
def define_claim(system_id: UUID, body: ClaimDefinitionInput, a: Actor = Depends(actor)):
    """A design partner states a critical claim in business language.

    A definition establishes no evidence. It stays DEFINED until an approved,
    executable claim with a qualified observer is bound to it.
    """
    require(a)
    with transaction(a.user_id, a.org_id) as session:
        get_record(session, a.org_id, system_id, "system")
        references = {"system": system_id}
        if body.environment_id:
            scoped(session, a.org_id, body.environment_id, "environment", system_id)
            references["environment"] = body.environment_id
        if body.property_id:
            prop = scoped(session, a.org_id, body.property_id, "property", system_id)
            if not prop.payload.get("approved"):
                raise HTTPException(422, "Bind a definition only to an approved executable claim")
            references["property"] = body.property_id
        lock_system(session, a.org_id, system_id)
        row = add_record(session, a.org_id, "claim_definition", {
            **body.model_dump(mode="json"), "schema_version": PROFILE, "system_id": str(system_id),
            "defined_by": str(a.user_id), "authority_basis": "CUSTOMER_DECLARED", "establishes_evidence": False},
            references)
        return serialize(row)


class PassportInput(Input):
    environment_id: UUID | None = None
    audience: str = Field(default="Enterprise security review", min_length=3, max_length=120)
    valid_days: int = Field(default=passports.DEFAULT_DAYS, ge=1, le=passports.MAX_DAYS)
    # What the signed document may contain. STANDARD is safe to share outside the organization.
    disclosure: Literal["STANDARD", "INTERNAL"] = "STANDARD"


@router.post(SYSTEM + "/passports", status_code=201)
def issue_passport(system_id: UUID, body: PassportInput, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        row = passports.issue(session, a.org_id, a.user_id, system_id, environment_id=body.environment_id,
                              audience=body.audience, days=body.valid_days, disclosure=body.disclosure)
        audit(session, a.org_id, a.user_id, "passport.issued", row.id)
        return passports.detail(session, a.org_id, row)


@router.get(SYSTEM + "/passports")
def list_passports(system_id: UUID, a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        get_record(session, a.org_id, system_id, "system")
        rows = history(session, a.org_id, "assurance_passport", system_id)[:20]
        return {"items": [passports.list_item(session, a.org_id, row, with_status=index < 5)
                          for index, row in enumerate(rows)]}


@router.get("/v1/passports/{passport_id}")
def passport_detail(passport_id: UUID, a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        return passports.detail(session, a.org_id, get_record(session, a.org_id, passport_id, "assurance_passport"))


@router.get("/v1/passports/{passport_id}/disclosure-preview")
def passport_disclosure(passport_id: UUID, a: Actor = Depends(actor)):
    """Exactly what an external recipient would see. Review this before creating a link."""
    with transaction(a.user_id, a.org_id) as session:
        row = get_record(session, a.org_id, passport_id, "assurance_passport")
        return passports.disclosure_preview(session, a.org_id, row)


class ShareInput(Input):
    label: str = Field(min_length=3, max_length=120)
    valid_days: int = Field(default=14, ge=1, le=passports.MAX_DAYS)
    # Sharing sends data outside the organization: the discloser confirms the reviewed preview.
    confirm_disclosure: Literal[True]


@router.post("/v1/passports/{passport_id}/share", status_code=201)
def share_passport(passport_id: UUID, body: ShareInput, a: Actor = Depends(actor)):
    """Create a capability link for one external party. The token is shown once."""
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        row = get_record(session, a.org_id, passport_id, "assurance_passport")
        lock_system(session, a.org_id, row.payload["system_id"])
        share, token = passports.share(session, a.org_id, a.user_id, row, label=body.label, days=body.valid_days)
        audit(session, a.org_id, a.user_id, "passport.shared", share.id)
        return {"share_id": str(share.id), "token": token, "page_path": f"/passport/{token}",
                "api_path": f"/v1/public/passports/{token}", "expires_at": share.payload["expires_at"],
                "note": "This link is shown once. ThreatVeil sends nothing to the recipient."}


class RevocationInput(Input):
    reason: str = Field(min_length=10, max_length=2000)


@router.post("/v1/passports/{passport_id}/revoke", status_code=201)
def revoke_passport(passport_id: UUID, body: RevocationInput, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        row = get_record(session, a.org_id, passport_id, "assurance_passport")
        lock_system(session, a.org_id, row.payload["system_id"])
        return serialize(passports.revoke(session, a.org_id, a.user_id, row, body.reason))


@router.post("/v1/passports/shares/{share_id}/revoke", status_code=201)
def revoke_share(share_id: UUID, body: RevocationInput, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        row = get_record(session, a.org_id, share_id, "passport_share")
        return serialize(passports.revoke_share(session, a.org_id, a.user_id, row, body.reason))


@router.get("/v1/public/passports/{token}")
def public_passport(token: str):
    """Unauthenticated, capability-scoped: one shared passport and its current status."""
    return passports.public_view(token)
