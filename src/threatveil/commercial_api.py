"""Tenant-bound local commercial workflow; no request confers security truth."""

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .auth import Actor, OWNERS, actor, require
from .commercial import Entitlements, catalog_view, mutate, overview, plan_version
from .db import transaction

router = APIRouter(prefix="/v1/commercial", tags=["commercial"])


class Command(BaseModel):
    model_config = ConfigDict(extra="forbid")
    idempotency_key: str = Field(min_length=8, max_length=120)
    expected_revision: int | None = Field(default=None, ge=1)


class SubscriptionCommand(Command):
    action: Literal["upgrade", "downgrade", "cancel", "payment_failed", "payment_recovered", "renew", "start_trial"]
    plan: str | None = Field(default=None, max_length=20)


class ExpiringCommand(Command):
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def timezone_required(cls, value):
        if value.tzinfo is None:
            raise ValueError("Expiry requires an explicit timezone")
        return value


class PromotionCommand(ExpiringCommand):
    code: str = Field(min_length=1, max_length=80)
    kind: Literal["startup", "student", "open_source", "partner", "education", "custom"]
    percent_off: int = Field(ge=0, le=100)


class OverrideCommand(ExpiringCommand):
    entitlements: dict = Field(min_length=1, max_length=6)
    contract_reference: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=10, max_length=500)

    @field_validator("entitlements")
    @classmethod
    def known_commercial_allowances_only(cls, value):
        Entitlements.model_validate({**plan_version("enterprise")["entitlements"], **value})
        return value


@router.get("/catalog")
def plans():
    return catalog_view()


@router.get("")
def subscription(a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        return overview(session, a.org_id)


def _apply(a, body, action=None):
    require(a, OWNERS)
    with transaction(a.user_id, a.org_id) as session:
        data = body.model_dump(mode="json")
        if action:
            data["action"] = action
        return mutate(session, a.org_id, data, a.user_id)


@router.post("/subscription")
def change_subscription(body: SubscriptionCommand, a: Actor = Depends(actor)):
    return _apply(a, body)


@router.post("/promotion")
def promotion(body: PromotionCommand, a: Actor = Depends(actor)):
    return _apply(a, body, "promotion")


@router.post("/override")
def override(body: OverrideCommand, a: Actor = Depends(actor)):
    return _apply(a, body, "override")
