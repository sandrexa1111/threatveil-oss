"""Tenant-owned data policy and explicit erasure requests; no pooled customer data."""

from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field, model_validator
from sqlalchemy import select

from .auth import Actor, OWNERS, actor, require
from .config import settings
from .db import (
    Account, ApiToken, GitHubBinding, Lease, Organization, Outbox, Record,
    Schedule, TargetState, add_record, audit, now, serialize, transaction,
)
from .schemas import Input

router = APIRouter(prefix="/v1/governance", tags=["data-governance"])


class DataPolicy(Input):
    raw_retention_days: int = Field(default=30, ge=1, le=30)
    abstract_features_opt_in: bool = False
    model_training_opt_in: bool = False
    contract_reference: str | None = Field(default=None, max_length=200)
    reason: str = Field(min_length=10, max_length=2000)

    @model_validator(mode="after")
    def explicit_rights(self):
        if (self.abstract_features_opt_in or self.model_training_opt_in) and not (
            self.contract_reference and self.contract_reference.strip()
        ):
            raise ValueError("Any data-use opt-in requires an explicit contract reference")
        return self


def current_policy(session, org):
    row = session.scalar(select(Record).where(Record.organization_id == org,
        Record.kind == "data_policy").order_by(Record.created_at.desc(), Record.id.desc()).limit(1))
    return serialize(row) if row else {"raw_retention_days": 30, "abstract_features_opt_in": False,
        "model_training_opt_in": False, "contract_reference": None, "id": None}


def pending_deletion(session, org):
    requests = session.scalars(select(Record).where(Record.organization_id == org,
        Record.kind == "organization_deletion").order_by(Record.created_at.desc()))
    for row in requests:
        canceled = session.scalar(select(Record.id).where(Record.organization_id == org,
            Record.kind == "deletion_cancelled", Record.payload["request_id"].astext == str(row.id)))
        if not canceled:
            return row
    return None


def ensure_active(session, org):
    if pending_deletion(session, org):
        raise HTTPException(423, "Organization erasure requested; new execution and writes are frozen")


@router.get("/policy")
def get_policy(a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        value = current_policy(session, a.org_id)
        deletion = pending_deletion(session, a.org_id)
        return {**value, "organization_id": str(a.org_id),
            "residency": settings().cloud_region or "LOCAL_OR_UNCONFIGURED",
            "deletion_request_id": str(deletion.id) if deletion else None,
            "cross_customer_processing_enabled": False, "model_training_enabled": False,
            "data_classes": {
                "PRIVATE_CUSTOMER": "Raw findings, traces, prompts, resources, code, identities and evidence; tenant-only",
                "CUSTOMER_DERIVED_ABSTRACT": "Permission-gated abstractions; no global learning pipeline is enabled",
                "GLOBAL_PUBLIC": "Public property specifications and library templates only",
            },
            "limitations": ["Consent records do not activate training or cross-customer data transfer.",
                "A shorter retention policy applies to new raw captures; existing immutable expiry remains visible.",
                "Backup, provider and exported-copy erasure requires the documented operator process."]}


@router.post("/policy", status_code=201)
def set_policy(body: DataPolicy, a: Actor = Depends(actor)):
    require(a, OWNERS)
    if not settings().is_local and body.raw_retention_days != 30:
        raise HTTPException(409, "Provision and verify the cloud retention lifecycle before enabling a shorter policy")
    with transaction(a.user_id, a.org_id) as session:
        session.get(Account, a.org_id, with_for_update=True)
        ensure_active(session, a.org_id)
        row = add_record(session, a.org_id, "data_policy", {
            **body.model_dump(mode="json"), "approved_by": str(a.user_id),
            "cross_customer_processing_enabled": False, "model_training_enabled": False,
        })
        audit(session, a.org_id, a.user_id, "data_policy.changed", row.id)
        return serialize(row)


class DeletionRequest(Input):
    organization_name: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=10, max_length=2000)
    export_acknowledged: Literal[True]


@router.post("/deletion-requests", status_code=201)
def request_deletion(body: DeletionRequest, a: Actor = Depends(actor)):
    require(a, OWNERS)
    with transaction(a.user_id, a.org_id) as session:
        from .release_integrity import lock_organization_systems

        lock_organization_systems(session, a.org_id)
        session.get(Account, a.org_id, with_for_update=True)
        organization = session.get(Organization, a.org_id)
        if body.organization_name != organization.name:
            raise HTTPException(422, "Organization name must match exactly")
        existing = pending_deletion(session, a.org_id)
        if existing:
            return serialize(existing)
        row = add_record(session, a.org_id, "organization_deletion", {
            "requested_by": str(a.user_id), "reason": body.reason,
            "export_acknowledged": True, "status": "AWAITING_OPERATOR_ERASURE",
            "backup_erasure": "PENDING_OPERATOR_REVIEW", "provider_erasure": "PENDING_OPERATOR_REVIEW",
            "requested_at": now().isoformat(),
        })
        # Stop new consequential work immediately. Canceling the erasure request
        # never silently reinstates revoked authorization or credentials.
        for target in session.scalars(select(TargetState).where(TargetState.organization_id == a.org_id)):
            target.revoked_at = now()
        for lease in session.scalars(select(Lease).where(Lease.organization_id == a.org_id)):
            lease.revoked = True
        for schedule in session.scalars(select(Schedule).where(Schedule.organization_id == a.org_id)):
            schedule.enabled = False
        for token in session.scalars(select(ApiToken).where(ApiToken.organization_id == a.org_id)):
            token.revoked_at = now()
        for binding in session.scalars(select(GitHubBinding).where(GitHubBinding.organization_id == a.org_id)):
            binding.enabled = False
        for pending in session.scalars(select(Outbox).where(Outbox.organization_id == a.org_id,
                Outbox.status.in_(["pending", "active", "retry", "claimed"]))):
            pending.status = "disabled"
        audit(session, a.org_id, a.user_id, "organization.erasure_requested", row.id)
        return serialize(row)


@router.post("/deletion-requests/{identifier}/cancel", status_code=201)
def cancel_deletion(identifier: UUID, a: Actor = Depends(actor)):
    require(a, OWNERS)
    from .db import get_record

    with transaction(a.user_id, a.org_id) as session:
        session.get(Account, a.org_id, with_for_update=True)
        get_record(session, a.org_id, identifier, "organization_deletion")
        row = add_record(session, a.org_id, "deletion_cancelled", {
            "request_id": str(identifier), "cancelled_by": str(a.user_id),
            "authorization_restored": False,
        }, {"request": identifier})
        audit(session, a.org_id, a.user_id, "organization.erasure_cancelled", row.id)
        return serialize(row)
