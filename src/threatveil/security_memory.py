"""Retain qualified security relationships without retaining arbitrary raw state values."""

from uuid import UUID
from fastapi import APIRouter, Depends
from pydantic import Field

from .auth import Actor, actor
from .core.contracts import digest
from .db import Record, transaction
from .schemas import Input
from .workspace_reads import page

router = APIRouter(prefix="/v1/memory", tags=["security-memory"])


def entity_reference(org_id, entity_type, identifier):
    return digest(
        {"organization_id": str(UUID(str(org_id))), "type": entity_type, "identifier": identifier}
    )


def security_facts(org_id, observation, evaluation):
    violations = {item["receipt_id"] for item in evaluation["violations"]}
    successful = (
        set(observation.task_receipt_ids) if evaluation["task_outcome"] == "SUCCESS" else set()
    )
    facts = []
    for receipt in observation.receipts:
        if receipt.id not in violations | successful:
            continue
        action = receipt.action
        facts.append(
            {
                "receipt_id": receipt.id,
                "violation": receipt.id in violations,
                "legitimate_control": receipt.id in successful,
                "source_id": receipt.source_id,
                "source_version": receipt.source_version,
                "tool": action.tool,
                "operation": action.operation,
                "phase": action.phase.value,
                "resource_type": action.resource.type,
                "principal_ref": entity_reference(org_id, "principal", action.principal.id),
                "principal_tenant_ref": entity_reference(
                    org_id, "tenant", action.principal.tenant_id
                ),
                "resource_ref": entity_reference(org_id, "resource", action.resource.id),
                "resource_tenant_ref": entity_reference(
                    org_id, "tenant", action.resource.tenant_id
                ),
                "approval_valid": action.approval_valid,
                "authorized": action.authorized,
                "before_digest": digest(action.before) if action.before is not None else None,
                "after_digest": digest(action.after) if action.after is not None else None,
            }
        )
    return facts


class MemoryQuery(Input):
    tool: str | None = Field(default=None, max_length=200)
    operation: str | None = Field(default=None, max_length=200)
    principal_id: str | None = Field(default=None, max_length=200)
    resource_id: str | None = Field(default=None, max_length=200)
    resource_type: str | None = Field(default=None, max_length=200)
    limit: int = Field(default=50, ge=1, le=200)
    cursor: str | None = Field(default=None, max_length=512)


@router.post("/query")
def query_memory(body: MemoryQuery, a: Actor = Depends(actor)):
    # Read-only POST keeps queried identities out of URL/request-access logs.
    criteria = {"violation": True}
    for field in ("tool", "operation", "resource_type"):
        if getattr(body, field) is not None:
            criteria[field] = getattr(body, field)
    if body.principal_id is not None:
        criteria["principal_ref"] = entity_reference(a.org_id, "principal", body.principal_id)
    if body.resource_id is not None:
        criteria["resource_ref"] = entity_reference(a.org_id, "resource", body.resource_id)
    with transaction(a.user_id, a.org_id) as session:
        rows, pagination = page(
            session,
            a.org_id,
            "trial_capture",
            limit=body.limit,
            cursor=body.cursor,
            extra_conditions=(
                Record.payload["security_facts"].contains([criteria]),
                Record.payload["purpose"].astext == "ASSURANCE",
            ),
        )
        items = [
            {
                "capture_id": str(row.id),
                "run_id": row.payload["run_id"],
                "created_at": row.created_at.isoformat(),
                "observation_digest": row.payload["observation_digest"],
                "raw_evidence_expires_at": row.payload["raw_evidence"]["expires_at"],
                "facts": [
                    fact
                    for fact in row.payload["security_facts"]
                    if all(fact.get(k) == v for k, v in criteria.items())
                ],
            }
            for row in rows
        ]
    return {
        "items": items,
        "pagination": pagination,
        "scope": "Qualified external captures recorded with retained semantic facts; qualification controls are excluded.",
        "limitations": [
            "Entity references are pseudonymous and organization-bound, not anonymous.",
            "Raw values are not retained in semantic facts. Missing historical indexing does not prove absence of failure.",
        ],
    }
