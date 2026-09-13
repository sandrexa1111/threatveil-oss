"""Tenant-safe append-only domain records and constrained operational state."""

from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from fastapi import HTTPException
from .config import settings


def now():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    subject: Mapped[str] = mapped_column(String(255), unique=True)
    email: Mapped[str] = mapped_column(String(320))
    name: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(120))
    owner_user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Membership(Base):
    __tablename__ = "memberships"
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), primary_key=True)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), primary_key=True)
    role: Mapped[str] = mapped_column(String(20))
    __table_args__ = (
        __import__("sqlalchemy").CheckConstraint(
            "role IN ('owner','admin','security','developer','viewer')"
        ),
    )


class LoginSession(Base):
    __tablename__ = "login_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"))
    csrf: Mapped[str] = mapped_column(String(100))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    identity_mode: Mapped[str] = mapped_column(String(20))


class Record(Base):
    __tablename__ = "records"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"))
    kind: Mapped[str] = mapped_column(String(40))
    payload: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    __table_args__ = (
        UniqueConstraint("organization_id", "id"),
        Index("ix_records_org_kind", "organization_id", "kind", "created_at"),
    )


class Edge(Base):
    __tablename__ = "record_edges"
    organization_id: Mapped[UUID] = mapped_column(primary_key=True)
    source_id: Mapped[UUID] = mapped_column(primary_key=True)
    target_id: Mapped[UUID] = mapped_column(primary_key=True)
    relation: Mapped[str] = mapped_column(String(40), primary_key=True)
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "source_id"], ["records.organization_id", "records.id"]
        ),
        ForeignKeyConstraint(
            ["organization_id", "target_id"], ["records.organization_id", "records.id"]
        ),
    )


class TargetState(Base):
    __tablename__ = "target_state"
    organization_id: Mapped[UUID] = mapped_column(primary_key=True)
    target_id: Mapped[UUID] = mapped_column(primary_key=True)
    challenge_hash: Mapped[str] = mapped_column(String(64))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "target_id"], ["records.organization_id", "records.id"]
        ),
    )


class RunState(Base):
    __tablename__ = "run_state"
    organization_id: Mapped[UUID] = mapped_column(primary_key=True)
    run_id: Mapped[UUID] = mapped_column(primary_key=True)
    idempotency_key: Mapped[str] = mapped_column(String(120))
    spec_digest: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="QUEUED")
    result_id: Mapped[UUID | None] = mapped_column(nullable=True)
    reserved: Mapped[int] = mapped_column(Integer)
    settled: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (
        UniqueConstraint("organization_id", "idempotency_key"),
        ForeignKeyConstraint(
            ["organization_id", "run_id"], ["records.organization_id", "records.id"]
        ),
        ForeignKeyConstraint(
            ["organization_id", "result_id"], ["records.organization_id", "records.id"]
        ),
    )


class Account(Base):
    __tablename__ = "accounts"
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"), primary_key=True)
    plan: Mapped[str] = mapped_column(String(20), default="unassigned")
    status: Mapped[str] = mapped_column(String(30), default="unassigned")
    trial_limit: Mapped[int] = mapped_column(Integer, default=0)
    reserved: Mapped[int] = mapped_column(Integer, default=0)
    consumed: Mapped[int] = mapped_column(Integer, default=0)
    max_systems: Mapped[int] = mapped_column(Integer, default=1)
    stripe_customer: Mapped[str | None] = mapped_column(String(100), unique=True, nullable=True)
    stripe_subscription: Mapped[str | None] = mapped_column(String(100), nullable=True)
    paid: Mapped[bool] = mapped_column(Boolean, default=False)
    period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    event_created: Mapped[int] = mapped_column(Integer, default=0)
    __table_args__ = (
        __import__("sqlalchemy").CheckConstraint(
            "reserved >= 0 AND consumed >= 0 AND trial_limit >= 0"
        ),
    )


class WebhookEvent(Base):
    __tablename__ = "webhook_events"
    id: Mapped[str] = mapped_column(String(160), primary_key=True)
    provider: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Invite(Base):
    __tablename__ = "invitations"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"))
    email: Mapped[str] = mapped_column(String(320))
    role: Mapped[str] = mapped_column(String(20))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Outbox(Base):
    __tablename__ = "outbox"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True
    )
    topic: Mapped[str] = mapped_column(String(40))
    payload: Mapped[dict] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Lease(Base):
    __tablename__ = "run_leases"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"))
    run_id: Mapped[UUID] = mapped_column()
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    bootstrap_expires: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    worker_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    nonce: Mapped[str | None] = mapped_column(String(100), nullable=True)
    fence: Mapped[int] = mapped_column(Integer, default=1)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    spec_digest: Mapped[str] = mapped_column(String(64))
    identity: Mapped[str] = mapped_column(String(255))
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "run_id"], ["records.organization_id", "records.id"]
        ),
    )


@lru_cache
def engine():
    return create_engine(settings().database_url, pool_pre_ping=True, pool_size=8, max_overflow=8)


def context(s: Session, user_id=None, org_id=None):
    s.execute(
        text("SELECT set_config('tv.user_id', :u, true), set_config('tv.org_id', :o, true)"),
        {"u": str(user_id) if user_id else "", "o": str(org_id) if org_id else ""},
    )


@contextmanager
def transaction(user_id=None, org_id=None):
    with Session(engine()) as s, s.begin():
        context(s, user_id, org_id)
        yield s


def serialize(r: Record):
    return {
        **r.payload,
        "id": str(r.id),
        "organization_id": str(r.organization_id),
        "kind": r.kind,
        "created_at": r.created_at.isoformat(),
    }


def get_record(s, org_id, record_id, kind=None):
    try:
        record_id = UUID(str(record_id))
    except (ValueError, TypeError):
        raise HTTPException(404, "Record not found") from None
    r = s.scalar(select(Record).where(Record.id == record_id, Record.organization_id == org_id))
    if r is None or (kind and r.kind != kind):
        raise HTTPException(404, "Record not found")
    return r


def add_record(s, org_id, kind, payload, references=None, record_id=None):
    r = Record(id=record_id or uuid4(), organization_id=org_id, kind=kind, payload=payload)
    s.add(r)
    s.flush()
    for relation, target in (references or {}).items():
        get_record(s, org_id, target)
        s.add(
            Edge(
                organization_id=org_id,
                source_id=r.id,
                target_id=UUID(str(target)),
                relation=relation,
            )
        )
    s.flush()
    return r


def records(s, org_id, kind, limit=200):
    return list(
        s.scalars(
            select(Record)
            .where(Record.organization_id == org_id, Record.kind == kind)
            .order_by(Record.created_at.desc())
            .limit(limit)
        )
    )


def audit(s, org_id, user_id, action, reference=None):
    return add_record(
        s,
        org_id,
        "audit",
        {
            "actor_id": str(user_id),
            "action": action,
            "reference": str(reference) if reference else None,
        },
    )


class CapabilityRoute(Base):
    __tablename__ = "capability_routes"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    lease_id: Mapped[UUID] = mapped_column(ForeignKey("run_leases.id"), unique=True)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"))


class LeaseNonce(Base):
    __tablename__ = "lease_nonces"
    lease_id: Mapped[UUID] = mapped_column(ForeignKey("run_leases.id"), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(100), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class RateBucket(Base):
    __tablename__ = "rate_buckets"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    window: Mapped[int] = mapped_column(primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=1)


class CustomerRoute(Base):
    __tablename__ = "customer_routes"
    customer_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"))


class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"))
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(120))
    permission: Mapped[str] = mapped_column(String(20))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Schedule(Base):
    __tablename__ = "schedules"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"))
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(120))
    run_template: Mapped[dict] = mapped_column(JSONB)
    interval_hours: Mapped[int] = mapped_column(Integer)
    next_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class GitHubBinding(Base):
    """Operator-verified installation route. Never selected by a caller's organization ID."""

    __tablename__ = "github_bindings"
    repository_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    repository: Mapped[str] = mapped_column(String(300))
    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id"))
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    owner_id: Mapped[str] = mapped_column(String(40))
    workflow_ref: Mapped[str] = mapped_column(String(500))
    allowed_ref: Mapped[str] = mapped_column(String(200))
    run_template: Mapped[dict] = mapped_column(JSONB)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
