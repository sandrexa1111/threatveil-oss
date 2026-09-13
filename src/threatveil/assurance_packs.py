"""Assurance packs: a reviewed starting point for one archetype.

A pack carries claims, dependency mapping proposals, observer requirements, its
compatibility and its own limitations. Applying one declares claims and queues
proposals: it approves nothing, creates no observer and establishes no evidence.

Every pack shipped here is DRAFT, which means ThreatVeil wrote it and no customer has
validated it yet. The example gallery presents packs as templates and keeps the one
runnable demonstration clearly labelled as synthetic.
"""

import json
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .auth import Actor, actor, require
from .change_assurance import PROFILE as CHANGE_PROFILE
from .change_assurance import scoped
from .db import add_record, audit, get_record, transaction
from .schemas import Input

router = APIRouter(tags=["assurance-packs"])
PROFILE = "assurance-pack/v1"
DIRECTORY = Path(__file__).with_name("data") / "assurance_packs"
STATUSES = ("DRAFT", "INTERNAL_VALIDATED", "CUSTOMER_VALIDATED", "DEPRECATED")
STATUS_MEANING = {
    "DRAFT": "ThreatVeil wrote it; no customer has validated it.",
    "INTERNAL_VALIDATED": "Exercised end to end against ThreatVeil's own fixtures.",
    "CUSTOMER_VALIDATED": "A customer confirmed its claims and mappings for their own system.",
    "DEPRECATED": "Superseded; kept for systems already using it.",
}
TEMPLATE_LABEL = "TEMPLATE · NOT RUNNABLE · NOT VERIFIED FOR YOUR SYSTEM"
RUNNABLE_LABEL = "RUNNABLE · SYNTHETIC DATA ONLY"


class PackClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    template_id: str = Field(pattern=r"^[a-z0-9_]{2,60}$")
    resource: str = Field(min_length=2, max_length=120)
    action: str = Field(pattern=r"^[a-z][a-z0-9_.\-]{1,60}$")
    declared_dependencies: list[str] = Field(default_factory=list, max_length=10)


class PackProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject_pattern: str = Field(min_length=1, max_length=200)
    maps_to: list[str] = Field(min_length=1, max_length=10)
    reason: Literal["TOOL_NAME_MATCH", "ACTION_NAME_MATCH", "SCHEMA_FIELD_MATCH", "PERMISSION_SCOPE_MATCH",
                    "CONFIG_KEY_MATCH", "RESOURCE_NAME_MATCH"]
    evidence: str = Field(min_length=10, max_length=500)


class ObserverRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")
    resource: str
    system_of_record: str
    observed_effects: list[str]
    correlation: str
    note: str


class Compatibility(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sources: list[str]
    requires_live_source: bool
    environments: list[str]
    note: str


class Pack(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["assurance-pack/v1"]
    id: str = Field(pattern=r"^[a-z0-9_]{2,60}$")
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    archetype: str = Field(min_length=2, max_length=60)
    name: str = Field(min_length=2, max_length=120)
    status: Literal["DRAFT", "INTERNAL_VALIDATED", "CUSTOMER_VALIDATED", "DEPRECATED"]
    author: str = Field(min_length=2, max_length=120)
    runnable: bool
    summary: str = Field(min_length=20, max_length=600)
    compatibility: Compatibility
    claims: list[PackClaim] = Field(min_length=1, max_length=20)
    dependency_proposals: list[PackProposal] = Field(default_factory=list, max_length=30)
    observer_requirements: list[ObserverRequirement] = Field(min_length=1, max_length=10)
    limitations: list[str] = Field(min_length=1, max_length=20)


@lru_cache
def packs() -> dict[str, Pack]:
    result = {}
    for path in sorted(DIRECTORY.glob("*.json")):
        pack = Pack.model_validate(json.loads(path.read_text()))
        result[pack.id] = pack
    return result


def pack_view(pack: Pack):
    return {**pack.model_dump(mode="json"), "status_meaning": STATUS_MEANING[pack.status],
            "label": RUNNABLE_LABEL if pack.runnable else TEMPLATE_LABEL,
            "applies": "Declares these claims and queues these mapping proposals for review. It approves nothing, "
                       "creates no observer and establishes no evidence."}


class ApplyInput(Input):
    environment_id: UUID
    installation_id: UUID | None = None


@router.get("/v1/assurance-packs")
def list_packs(a: Actor = Depends(actor)):
    value = packs()
    return {"schema_version": PROFILE, "statuses": STATUS_MEANING,
            "items": [pack_view(pack) for pack in value.values()],
            "note": "Every pack is DRAFT: a reviewed starting point, not a validated product for your system.",
            "organization_id": str(a.org_id)}


@router.get("/v1/example-gallery")
def gallery(a: Actor = Depends(actor)):
    """What a new customer can look at. Exactly one card is runnable, and it is synthetic."""
    cards = [{
        "id": "finance_sandbox", "title": "Finance agent", "archetype": "FINANCE", "runnable": True,
        "synthetic": True, "status": "RUNNABLE_SYNTHETIC_DEMONSTRATION", "label": RUNNABLE_LABEL,
        "shows": "A cleared system, a change to a synthetic tool gateway, the exact claim that stopped holding, "
                 "re-proof and restored clearance.",
        "start_path": "/v1/change-assurance/finance/setup",
        "counts_as_customer_activity": False,
    }]
    cards += [{
        "id": pack.id, "title": pack.name, "archetype": pack.archetype, "runnable": False, "synthetic": False,
        "status": pack.status, "label": TEMPLATE_LABEL, "shows": pack.summary,
        "start_path": f"/v1/systems/{{system_id}}/assurance-packs/{pack.id}/apply",
        "counts_as_customer_activity": True,
    } for pack in packs().values()]
    return {
        "primary_action": {"id": "connect_my_own_agent", "title": "Connect my own agent",
                           "detail": "Import or connect your agent's declared configuration and get a real answer "
                                     "about your own system.",
                           "path": "/v1/connectors"},
        "secondary_action": {"id": "explore_an_example", "title": "Explore an example",
                             "detail": "Look at a template for your archetype, or run the synthetic demonstration."},
        "cards": cards, "organization_id": str(a.org_id),
        "note": "Only the Finance card runs. It uses synthetic data and never counts as customer activity.",
    }


@router.post("/v1/systems/{system_id}/assurance-packs/{pack_id}/apply", status_code=201)
def apply_pack(system_id: UUID, pack_id: str, body: ApplyInput, a: Actor = Depends(actor)):
    """Declare a pack's claims and queue its mapping proposals. Nothing is approved."""
    require(a)
    from .assurance_intelligence import load
    from .claim_builder import DraftInput, draft
    from .dependency_mapping import PROFILE as MAPPING_PROFILE
    from .dependency_mapping import REASONS, subjects_of
    from .release_integrity import lock_system

    pack = packs().get(pack_id)
    if pack is None:
        raise HTTPException(404, "Unknown assurance pack")
    with transaction(a.user_id, a.org_id) as session:
        get_record(session, a.org_id, system_id, "system")
        environment = scoped(session, a.org_id, body.environment_id, "environment", system_id)
        lock_system(session, a.org_id, system_id)
        installation = None
        if body.installation_id is not None:
            installation = get_record(session, a.org_id, body.installation_id, "connector_installation")
            if installation.payload["system_id"] != str(system_id):
                raise HTTPException(404, "Source not found for this system")
        declared = []
        for claim in pack.claims:
            value = draft(DraftInput(template_id=claim.template_id, resource=claim.resource, action=claim.action,
                                     declared_dependencies=claim.declared_dependencies))
            row = add_record(session, a.org_id, "claim_definition", {
                "schema_version": CHANGE_PROFILE, "system_id": str(system_id),
                "environment_id": str(environment.id), "action": value["action"], "claim": value["claim"],
                "permitted_outcome": value["permitted_outcome"], "forbidden_outcome": value["forbidden_outcome"],
                "legitimate_task": value["legitimate_task"], "ground_truth_source": value["ground_truth_source"],
                "resource": value["resource"], "expected_conditions": value["expected_conditions"],
                "declared_dependencies": value["declared_dependencies"], "template_id": claim.template_id,
                "pack_id": pack.id, "pack_version": pack.version, "pack_status": pack.status,
                "defined_by": str(a.user_id), "authority_basis": "CUSTOMER_DECLARED", "establishes_evidence": False,
            }, {"system": system_id, "environment": environment.id})
            declared.append({"id": str(row.id), "claim": value["claim"], "verification": "NOT_YET_VERIFIED",
                             "declared_dependencies": value["declared_dependencies"]})
        proposals, unmatched = [], []
        known = {}
        if installation is not None:
            ctx = load(session, a.org_id, system_id, environment.id)
            known = subjects_of(ctx, installation.id)
        for proposal in pack.dependency_proposals:
            matches = [subject for subject in sorted(known) if fnmatchcase(subject, proposal.subject_pattern)]
            if not matches:
                unmatched.append({"subject_pattern": proposal.subject_pattern, "maps_to": proposal.maps_to,
                                  "reason": "No fact matching this pattern has been reported by this source yet."})
                continue
            for subject in matches[:20]:
                row = add_record(session, a.org_id, "dependency_mapping_proposal", {
                    "schema_version": MAPPING_PROFILE, "system_id": str(system_id),
                    "environment_id": str(environment.id), "installation_id": str(installation.id),
                    "subject": subject, "maps_to": proposal.maps_to, "reason": proposal.reason,
                    "reason_text": REASONS[proposal.reason], "confidence": "STATED", "origin": "DETERMINISTIC",
                    "evidence": f"{pack.name} {pack.version} ({pack.status}): {proposal.evidence}"[:1000],
                    "note": f"Matched pattern {proposal.subject_pattern} against "
                            f"{known[subject]['source_record']}",
                    "pack_id": pack.id, "proposed_by": str(a.user_id), "affects_scoping": False,
                    "status": "PROPOSED",
                }, {"system": system_id, "installation": installation.id})
                proposals.append({"id": str(row.id), "subject": subject, "maps_to": proposal.maps_to,
                                  "status": "PROPOSED", "affects_scoping": False})
        audit(session, a.org_id, a.user_id, "assurance_pack.applied", None)
        return {"pack": {"id": pack.id, "version": pack.version, "status": pack.status,
                         "status_meaning": STATUS_MEANING[pack.status], "archetype": pack.archetype},
                "declared_claims": declared, "mapping_proposals": proposals, "unmatched_proposals": unmatched,
                "observer_requirements": [item.model_dump(mode="json") for item in pack.observer_requirements],
                "created_observers": [], "approved_anything": False,
                "limitations": pack.limitations,
                "next_steps": ["Edit each declared claim so it states what is actually true for your system.",
                               "Review the queued mapping proposals; only approval narrows anything.",
                               "Provide and qualify a business-effect observer for each requirement, then prove "
                               "the claims you care about."]}
