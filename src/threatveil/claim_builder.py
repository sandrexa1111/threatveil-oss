"""The guided claim builder and its starter template library.

No model is involved. A template is a fixed, reviewed pattern in business language; a
draft is a filled-in template the customer edits and submits. Both are labelled
STARTER TEMPLATE / NOT VERIFIED FOR YOUR SYSTEM, because a claim establishes nothing
until an approved executable check with a qualified observer is bound to it.
"""

import json
from functools import lru_cache
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .auth import Actor, actor
from .schemas import Input

router = APIRouter(tags=["claim-builder"])
PROFILE = "claim-templates/v1"
CATALOG = Path(__file__).with_name("data") / "claim_templates.json"
FIELDS = ("claim", "permitted_outcome", "forbidden_outcome", "legitimate_task", "ground_truth_source")


class Template(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z0-9_]{2,60}$")
    label: str
    title: str
    archetype: str
    action: str
    resource: str
    claim: str
    permitted_outcome: str
    forbidden_outcome: str
    legitimate_task: str
    ground_truth_source: str
    expected_conditions: list[str]
    suggested_dependencies: list[str]


class StarterAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(pattern=r"^[a-z][a-z0-9_.]{1,39}$")
    label: str
    consequential: bool
    hint: str


class TemplateCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["claim-templates/v1"]
    version: str
    status_label: str
    note: str
    starter_actions: list[StarterAction]
    templates: list[Template]


@lru_cache
def catalog() -> TemplateCatalog:
    return TemplateCatalog.model_validate(json.loads(CATALOG.read_text()))


class DraftInput(Input):
    template_id: str = Field(pattern=r"^[a-z0-9_]{2,60}$")
    resource: str = Field(min_length=2, max_length=120)
    action: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_.\-]{1,60}$")
    declared_dependencies: list[str] = Field(default_factory=list, max_length=20)


def draft(body: DraftInput):
    """A filled template. It is a draft: nothing is recorded and nothing is established."""
    template = next((t for t in catalog().templates if t.id == body.template_id), None)
    if template is None:
        raise HTTPException(404, "Unknown claim template")
    resource = body.resource.strip()
    filled = {field: getattr(template, field).format(resource=resource) for field in FIELDS}
    return {
        "schema_version": PROFILE, "template_id": template.id, "label": template.label,
        "status": catalog().status_label, "action": body.action or template.action, "resource": resource,
        **filled,
        "expected_conditions": [c.format(resource=resource) for c in template.expected_conditions],
        "declared_dependencies": body.declared_dependencies or list(template.suggested_dependencies),
        "establishes_evidence": False,
        "next_steps": [
            "Edit every line so it says what is actually true for your system.",
            "Declare the dependencies this claim relies on, so ThreatVeil can say which changes reach it.",
            "Submit it as a claim definition. It stays NOT_YET_VERIFIED until an approved executable check "
            "with a qualified observer is bound to it.",
        ],
        "not_claims": ["This draft is not evidence.", "A template is not verified for your system.",
                       "Submitting it grants no permission and changes no clearance."],
    }


@router.get("/v1/claim-templates")
def list_templates(a: Actor = Depends(actor)):
    """The starter template library and the neutral starter actions, for any domain."""
    value = catalog()
    return {"schema_version": value.schema_version, "version": value.version, "status_label": value.status_label,
            "note": value.note, "starter_actions": [item.model_dump() for item in value.starter_actions],
            "templates": [item.model_dump() for item in value.templates], "organization_id": str(a.org_id)}


@router.post("/v1/claim-templates/draft")
def build_draft(body: DraftInput, a: Actor = Depends(actor)):
    """Turn a template into an editable draft. Nothing is recorded."""
    return {**draft(body), "organization_id": str(a.org_id), "recorded": False}
