"""Integrity Launch operations over the existing immutable engagement scope.

Human review and measured effort never manufacture evidence, a live gate, or revenue.
"""

from datetime import date
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field, field_validator
from sqlalchemy import Integer, func, select

from .auth import SECURITY, Actor, actor, require
from .db import (
    Account,
    GitHubBinding,
    Record,
    add_record,
    audit,
    get_record,
    now,
    serialize,
    transaction,
)
from .schemas import Input
from .workspace_reads import page

router = APIRouter(prefix="/v1/integrity-launches", tags=["integrity-launches"])


class LaunchEvent(Input):
    event: Literal["scope_reviewed", "implementation_note", "blocker", "handoff_reviewed"]
    note: str = Field(min_length=10, max_length=4000)
    reviewed: Literal[True]
    idempotency_key: str = Field(min_length=8, max_length=120)


class LaunchTime(Input):
    work_date: date
    minutes: int = Field(ge=1, le=720)
    category: Literal["scope", "observation", "integration", "reproof", "remediation", "support"]
    note: str = Field(min_length=5, max_length=2000)
    idempotency_key: str = Field(min_length=8, max_length=120)

    @field_validator("work_date")
    @classmethod
    def no_future_time(cls, value):
        if value > now().date():
            raise ValueError("Only completed work may be recorded")
        return value


def _launch_conditions(org, launch_id, kind):
    return (
        Record.organization_id == org,
        Record.kind == kind,
        Record.payload["launch_id"].astext == str(launch_id),
    )


def _recent(session, org, launch_id, kind, limit=50, cursor=None):
    rows, window = page(
        session,
        org,
        kind,
        limit=limit,
        cursor=cursor,
        extra_conditions=(Record.payload["launch_id"].astext == str(launch_id),),
    )
    return {"items": [serialize(r) for r in rows], "pagination": window}


def launch_view(session, org, launch):
    # Reuse the verified, scoped run aggregation; the old VERIFIED status describes
    # that scope's execution results, never commercial or installation completion.
    from .api import gauntlet_view

    value = gauntlet_view(session, org, launch)
    system_id = launch.payload["system_id"]
    scope = set(launch.payload["property_ids"])
    account = session.get(Account, org)
    reviewed = (
        session.scalar(
            select(Record.id)
            .where(
                *_launch_conditions(org, launch.id, "launch_event"),
                Record.payload["event"].astext == "scope_reviewed",
            )
            .limit(1)
        )
        is not None
    )
    approved = (
        set(
            session.scalars(
                select(Record.id).where(
                    Record.organization_id == org,
                    Record.kind == "property",
                    Record.id.in_([UUID(p) for p in scope]),
                    Record.payload["approved"].astext == "true",
                )
            )
        )
        if scope
        else set()
    )
    evidence_properties = (
        set(
            session.scalars(
                select(Record.payload["property_id"].astext).where(
                    Record.organization_id == org,
                    Record.kind == "evidence_record",
                    Record.payload["system_id"].astext == system_id,
                    Record.payload["property_id"].astext.in_(scope),
                    Record.payload["qualified"].astext == "true",
                    Record.created_at >= launch.created_at,
                )
            )
        )
        if scope
        else set()
    )
    bindings = list(
        session.scalars(
            select(GitHubBinding).where(
                GitHubBinding.organization_id == org,
                GitHubBinding.enabled.is_(True),
                GitHubBinding.run_template["system_id"].astext == system_id,
            )
        )
    )
    releases = list(
        session.scalars(
            select(Record)
            .where(
                Record.organization_id == org,
                Record.kind == "release",
                Record.payload["system_id"].astext == system_id,
                Record.payload["policy"]["mode"].astext == "WARN",
                Record.created_at >= launch.created_at,
            )
            .order_by(Record.created_at.desc())
            .limit(200)
        )
    )
    receipt_ids = [UUID(r.payload["receipt_id"]) for r in releases if r.payload.get("receipt_id")]
    receipts = (
        set(
            session.scalars(
                select(Record.id).where(
                    Record.organization_id == org,
                    Record.kind == "assurance_receipt",
                    Record.id.in_(receipt_ids),
                    Record.payload["release_id"].astext.in_([str(r.id) for r in releases]),
                )
            )
        )
        if receipt_ids
        else set()
    )
    from .integrations.github_release import active_installation
    from .release_integrity import current_release_assessment

    # Delivery acknowledgements originate only in the GitHub reconciler. A
    # manually reviewed milestone or configured repository is never sufficient.
    publications = list(
        session.scalars(
            select(Record)
            .where(
                Record.organization_id == org,
                Record.kind == "github_check_publication",
                Record.payload["system_id"].astext == system_id,
                Record.payload["policy_mode"].astext == "WARN",
                Record.created_at >= launch.created_at,
            )
            .order_by(Record.created_at.desc())
            .limit(200)
        )
    )
    release_by_id = {str(r.id): r for r in releases}
    live_publication = None
    for publication in publications:
        data = publication.payload
        release = release_by_id.get(data.get("release_id"))
        if (
            not release
            or not data.get("current_applicable")
            or data.get("receipt_id") != release.payload.get("receipt_id")
            or UUID(data["receipt_id"]) not in receipts
            or data.get("sha") != release.payload["candidate"].get("digest")
        ):
            continue
        installation = active_installation(session, org, data.get("repository_id"))
        if (
            not installation
            or str(installation.id) != data.get("installation_record_id")
            or str(installation.payload.get("installation_id")) != str(data.get("installation_id"))
            or installation.payload.get("system_id") != system_id
        ):
            continue
        if current_release_assessment(session, org, release)["current"]:
            live_publication = serialize(publication)
            break
    total_minutes = session.scalar(
        select(func.coalesce(func.sum(Record.payload["minutes"].astext.cast(Integer)), 0)).where(
            *_launch_conditions(org, launch.id, "launch_time")
        )
    )
    category_expression = Record.payload["category"].astext
    by_category = session.execute(
        select(
            category_expression,
            func.sum(Record.payload["minutes"].astext.cast(Integer)),
        )
        .where(*_launch_conditions(org, launch.id, "launch_time"))
        .group_by(category_expression)
    ).all()
    milestones = {
        "scope_reviewed": reviewed,
        "properties_approved": bool(scope) and len(approved) == len(scope),
        "qualified_evidence_recorded": bool(scope) and evidence_properties >= scope,
        "github_route_configured": bool(bindings),
        "warn_decision_recorded": bool(releases),
        "signed_receipt_recorded": bool(receipts),
        "live_gate_delivery_verified": live_publication is not None,
    }
    return {
        **value,
        "product_name": "ThreatVeil Integrity Launch",
        "execution_status": value["status"],
        "installation_status": "LIVE_WARN_DELIVERY_VERIFIED"
        if live_publication
        else "DELIVERY_NOT_VERIFIED"
        if bindings
        else "NOT_CONFIGURED",
        "live_publication": live_publication,
        "milestones": milestones,
        "scope_recommendation": "8–12 meaningful properties for one consequential system; agreed scope may differ.",
        "conversion": {
            "paid": bool(account and account.paid),
            "status": "PROVIDER_CONFIRMED_PAID"
            if account and account.paid
            else "NO_CONFIRMED_PAYMENT",
            "source": "Current reconciled billing account; launch notes cannot set payment state",
        },
        "effort": {
            "minutes": int(total_minutes),
            "hours": round(int(total_minutes) / 60, 2),
            "by_category_minutes": {category: int(minutes) for category, minutes in by_category},
        },
        "events": _recent(session, org, launch.id, "launch_event"),
        "time_entries": _recent(session, org, launch.id, "launch_time"),
        "limitations": [
            "Execution status describes the agreed property scope, not an installed release gate.",
            "Live delivery is checked against the latest 200 WARN releases and publications; branch-protection enforcement is not attested.",
            "Customer acceptance and commercial value are not inferred from local execution.",
        ],
    }


@router.get("")
def launches(
    system_id: UUID | None = None,
    limit: int = Query(25, ge=1, le=100),
    cursor: str | None = None,
    a: Actor = Depends(actor),
):
    with transaction(a.user_id, a.org_id) as session:
        if system_id:
            get_record(session, a.org_id, system_id, "system")
        rows, window = page(
            session, a.org_id, "gauntlet", limit=limit, cursor=cursor, system_id=system_id
        )
        return {"items": [launch_view(session, a.org_id, r) for r in rows], "pagination": window}


@router.get("/{identifier}")
def launch_detail(identifier: UUID, a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        return launch_view(session, a.org_id, get_record(session, a.org_id, identifier, "gauntlet"))


def _append(identifier, body, kind, a):
    with transaction(a.user_id, a.org_id) as session:
        launch = get_record(session, a.org_id, identifier, "gauntlet")
        # Serialize idempotency claims with the existing tenant account lock.
        session.get(Account, a.org_id, with_for_update=True)
        payload = {
            **body.model_dump(mode="json"),
            "launch_id": str(identifier),
            "system_id": launch.payload["system_id"],
            "actor_id": str(a.user_id),
        }
        existing = session.scalar(
            select(Record).where(
                *_launch_conditions(a.org_id, identifier, kind),
                Record.payload["idempotency_key"].astext == body.idempotency_key,
            )
        )
        if existing:
            if existing.payload != payload:
                raise HTTPException(
                    409, "Idempotency key already belongs to different recorded work"
                )
            return serialize(existing)
        record = add_record(
            session,
            a.org_id,
            kind,
            payload,
            {"launch": launch.id, "system": launch.payload["system_id"]},
        )
        audit(session, a.org_id, a.user_id, kind + ".recorded", record.id)
        return serialize(record)


@router.post("/{identifier}/events", status_code=201)
def append_event(identifier: UUID, body: LaunchEvent, a: Actor = Depends(actor)):
    require(a, SECURITY)
    return _append(identifier, body, "launch_event", a)


@router.post("/{identifier}/time", status_code=201)
def append_time(identifier: UUID, body: LaunchTime, a: Actor = Depends(actor)):
    require(a)
    return _append(identifier, body, "launch_time", a)


def _history(identifier, kind, limit, cursor, a):
    with transaction(a.user_id, a.org_id) as session:
        get_record(session, a.org_id, identifier, "gauntlet")
        return _recent(session, a.org_id, identifier, kind, limit, cursor)


@router.get("/{identifier}/events")
def event_history(
    identifier: UUID,
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = None,
    a: Actor = Depends(actor),
):
    return _history(identifier, "launch_event", limit, cursor, a)


@router.get("/{identifier}/time")
def time_history(
    identifier: UUID,
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = None,
    a: Actor = Depends(actor),
):
    return _history(identifier, "launch_time", limit, cursor, a)
