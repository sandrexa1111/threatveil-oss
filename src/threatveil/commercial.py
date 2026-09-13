"""Versioned commercial policy. This module never evaluates or rewrites assurance.

Immutable subscription snapshots and billing events use the existing tenant/RLS
record store. Account is the locked operational projection used by the runner.
Entitlements authorize capacity; they do not qualify observations or evidence.
"""

from calendar import monthrange
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid5

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select

from .config import settings
from .db import Account, Record, add_record, get_record, now, serialize


class Entitlements(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protected_system_limit: int = Field(ge=0, le=100000)
    environments_per_system_limit: int = Field(ge=0, le=1000)
    approved_property_limit: int = Field(ge=0, le=100000)
    monthly_verification_budget: int = Field(ge=0, le=100000000)
    retention_days: int = Field(ge=1, le=36500)
    capabilities: list[str] = Field(max_length=100)


class PlanVersion(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,19}$")
    name: str = Field(min_length=1, max_length=80)
    tagline: str = Field(min_length=1, max_length=150)
    monthly_usd: int | None = Field(default=None, ge=0)
    currency: str = "USD"
    billing_interval: Literal["month", "annual_contract"] = "month"
    sales_assisted: bool = False
    # How a customer can get this plan. "contact" plans are never offered self-service.
    availability: Literal["self_serve", "contact"] = "self_serve"
    stripe_price_id: str | None = None
    entitlements: Entitlements


class PlanCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["commercial-catalog-v1"]
    version: str = Field(min_length=1, max_length=80)
    trial_days: int = Field(ge=1, le=90)
    grace_days: int = Field(ge=0, le=30)
    plans: list[PlanVersion]

    @model_validator(mode="after")
    def validate_plans(self):
        ids = [plan.id for plan in self.plans]
        if len(ids) != len(set(ids)) or not {"free", "pro", "team", "business", "enterprise"} <= set(ids):
            raise ValueError("Catalog must contain unique FREE/PRO/TEAM/BUSINESS/ENTERPRISE plans")
        if next(p for p in self.plans if p.id == "free").monthly_usd != 0:
            raise ValueError("The free plan must remain free")
        return self


def catalog():
    path = getattr(settings(), "commercial_catalog_path", "")
    return PlanCatalog.model_validate_json(
        (Path(path) if path else Path(__file__).with_name("data") / "commercial_plans.json").read_text()
    )


def plan_version(plan_id):
    cat = catalog()
    plan = next((p for p in cat.plans if p.id == str(plan_id).lower()), None)
    if plan is None:
        raise HTTPException(422, "Unknown commercial plan")
    return {**plan.model_dump(mode="json"), "catalog_version": cat.version}


def provider_name():
    configured = getattr(settings(), "billing_provider", "disabled")
    if configured == "mock" and not settings().is_local:
        raise HTTPException(503, "Mock billing is prohibited outside local/test")
    # No external payment call is made by this local provider.
    return "mock" if settings().is_local and configured == "disabled" else configured


def catalog_view():
    cat = catalog()
    provider = provider_name()
    return {"catalog_version": cat.version, "billing_provider": provider,
            "mock_available": settings().is_local and provider == "mock",
            "plans": [{**p.model_dump(mode="json", exclude={"stripe_price_id"}),
                       "price_hypothesis": True,
                       "checkout_configured": bool(not p.sales_assisted and p.id != "free" and (
                           provider == "mock" or (provider == "stripe" and settings().stripe_secret_key and
                           (settings().stripe_secret_key.startswith("sk_test_") or getattr(settings(), "stripe_live_charges_enabled", False)) and
                           settings().stripe_trial_allowances.get(p.id) and
                           (settings().stripe_prices.get(p.id) or p.stripe_price_id))))}
                      for p in cat.plans],
            "value_unit": "Protected system with a bounded environment and authority scope",
            "note": "Initial price and usage hypotheses; hosted economics require measurement. Capability allowances do not assert technical integration readiness."}


def _next_month(value):
    year, month = value.year + (value.month == 12), value.month % 12 + 1
    return value.replace(year=year, month=month,
                         day=min(value.day, monthrange(year, month)[1]))


def _stamp(value):
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def _latest(s, org_id):
    row = s.scalar(select(Record).where(Record.organization_id == org_id,
                                       Record.kind == "commercial_subscription")
                   .order_by(Record.payload["revision"].as_integer().desc()).limit(1))
    return deepcopy(row.payload) if row else None


def _hash(payload):
    return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _event_id(org_id, key):
    return uuid5(UUID(str(org_id)), "commercial-event:" + key)


def _append(s, account, state, action, key, request, actor_id=None):
    """Called under Account FOR UPDATE; event and projection commit atomically."""
    state["revision"] += 1
    state["updated_at"] = now().isoformat()
    event_id = _event_id(account.organization_id, key)
    event = add_record(s, account.organization_id, "billing_event", {
        "schema_version": "billing-event-v1", "action": action,
        "idempotency_key": key, "request_digest": _hash(request),
        "revision": state["revision"], "plan": state["plan"], "status": state["status"],
        "provider": state["provider"], "actor_id": str(actor_id) if actor_id else None,
        "paid": False, "assurance_history_changed": False,
        "meaning": "Commercial entitlement transition; not evidence or payment confirmation.",
    }, record_id=event_id)
    state["event_id"] = str(event.id)
    add_record(s, account.organization_id, "commercial_subscription", state,
               {"billing_event": event.id})
    _project(account, state)
    return state


def _effective(state):
    result = deepcopy(state["plan_version"]["entitlements"])
    if state.get("override"):
        result.update(state["override"]["entitlements"])
    return Entitlements.model_validate(result).model_dump()


def _project(account, state):
    effective = _effective(state)
    account.plan, account.status = state["plan"], state["status"]
    account.max_systems = effective["protected_system_limit"]
    account.trial_limit = effective["monthly_verification_budget"]
    account.period_end = _stamp(state["period_end"])
    # A local mock activation must never masquerade as money collected.
    account.paid = False


def provision_free(s, org_id):
    """Only called for a newly created organization; never migrates an old contract."""
    account = s.get(Account, org_id, with_for_update=True)
    if account:
        return account
    account = Account(organization_id=org_id, plan="free", status="free",
                      consumed=0, reserved=0, paid=False)
    s.add(account)
    s.flush()
    clock = now()
    state = {"schema_version": "subscription-v1", "organization_id": str(org_id),
             "revision": 0, "plan": "free", "status": "free", "provider": "none",
             "plan_version": plan_version("free"), "period_start": clock.isoformat(),
             "period_end": _next_month(clock).isoformat(), "scheduled_change": None,
             "trial": None, "promotion": None, "override": None, "grace_until": None}
    _append(s, account, state, "organization.free_provisioned", "free-provision-v1", {})
    return account


def _reconcile(s, account, state, clock):
    """Expiry is deterministic on reads/mutations; no billing scheduler needed locally."""
    if not state or state["plan"] != account.plan:
        return state
    changes = []
    for field in ("promotion", "override"):
        if state.get(field) and _stamp(state[field]["expires_at"]) <= clock:
            if field == "override":
                state["plan_version"] = state["fallback_plan_version"]
                state["plan"], state["status"] = state["plan_version"]["id"], "free"
            state[field] = None
            changes.append(field + ".expired")
    trial_expired = state.get("trial") and _stamp(state["trial"]["expires_at"]) <= clock
    grace_expired = state.get("grace_until") and _stamp(state["grace_until"]) <= clock
    boundary = _stamp(state["period_end"]) if state.get("period_end") else None
    if trial_expired or grace_expired:
        state["plan_version"] = state["fallback_plan_version"]
        state["plan"] = state["plan_version"]["id"]
        state["status"] = "free"
        state["trial"], state["grace_until"], state["scheduled_change"] = None, None, None
        # Grace failure terminates contract overrides; history is retained.
        state["override"] = None
        changes.append("trial.expired" if trial_expired else "grace.expired")
    if boundary is not None and boundary <= clock and not state["provider"].startswith("stripe"):
        if state.get("scheduled_change"):
            state["plan_version"] = state["scheduled_change"]["plan_version"]
            state["plan"] = state["plan_version"]["id"]
            state["status"] = "free" if state["plan"] == "free" else "active"
            state["scheduled_change"], state["override"] = None, None
            changes.append("subscription.scheduled_change_applied")
        # Mock subscriptions are intentionally test-only. Stripe is reconciled
        # from its provider, never blindly renewed by this clock.
        while boundary <= clock:
            state["period_start"] = boundary.isoformat()
            boundary = _next_month(boundary)
        state["period_end"] = boundary.isoformat()
        account.consumed = 0
        # Reservations remain charged until execution settles.
        changes.append("usage.period_started")
    if changes:
        previous = state["revision"]
        _append(s, account, state, ";".join(changes), f"reconcile:{previous}",
                {"previous_revision": previous, "changes": changes})
    return state


def _legacy_entitlements(account):
    configured = settings().commercial_plans.get(account.plan)
    properties = configured.properties if configured else {
        "unassigned": 20, "pilot": 20, "starter": 20, "growth": 100, "pro": 500,
    }.get(account.plan, 0)
    return Entitlements(protected_system_limit=(configured.systems if configured else account.max_systems),
                        environments_per_system_limit=1000, approved_property_limit=properties,
                        monthly_verification_budget=account.trial_limit, retention_days=365,
                        capabilities=["legacy.contract", "record.export", "api.cli"]).model_dump()


def resolve(s, org_id):
    account = s.get(Account, org_id, with_for_update=True)
    if account is None:
        raise HTTPException(404, "Organization billing account not found")
    state = _reconcile(s, account, _latest(s, org_id), now())
    modern = bool(state and state["plan"] == account.plan)
    return account, state if modern else None, _effective(state) if modern else _legacy_entitlements(account)


def entitlements(s, org_id):
    return resolve(s, org_id)[2]


def record_provider_subscription(s, account, event_id, provider="stripe", period_start=None, period_end=None):
    """Adapt reconciled provider state, preserving old non-catalog contracts.

    The caller has verified webhook authenticity, tenant/customer mapping and
    independently retrieved the provider subscription. No event body is an
    assurance authority. Operational usage has already been reconciled by it.
    """
    if account.plan not in {p.id for p in catalog().plans}:
        return
    previous = _latest(s, account.organization_id)
    if previous is None:
        # A pre-catalog `pro` contract meant 15 systems/500 properties. Never
        # reinterpret its provider events as the new 3-system Pro contract.
        return
    frozen = (previous["plan_version"] if previous and previous["plan"] == account.plan
              else plan_version(account.plan))
    frozen = deepcopy(frozen)
    # An explicitly measured Stripe execution allowance remains authoritative.
    frozen["entitlements"]["monthly_verification_budget"] = account.trial_limit
    account.max_systems = frozen["entitlements"]["protected_system_limit"]
    stamp = now()
    state = {"schema_version": "subscription-v1", "organization_id": str(account.organization_id),
             "revision": (previous["revision"] if previous else 0) + 1,
             "plan": account.plan, "status": account.status, "provider": provider,
             "plan_version": frozen,
             "period_start": datetime.fromtimestamp(period_start, tz=timezone.utc).isoformat() if period_start else None,
             "period_end": datetime.fromtimestamp(period_end, tz=timezone.utc).isoformat() if period_end else (
                 account.period_end.isoformat() if account.period_end else None),
             "scheduled_change": None, "trial": None, "promotion": None, "override": None,
             "grace_until": None, "updated_at": stamp.isoformat()}
    event = add_record(s, account.organization_id, "billing_event", {
        "schema_version": "billing-event-v1", "action": "provider.subscription_reconciled",
        "idempotency_key": "stripe:" + event_id, "request_digest": _hash({"provider_event_id": event_id}),
        "revision": state["revision"], "plan": account.plan, "status": account.status,
        "provider": provider, "paid": account.paid, "assurance_history_changed": False,
        "meaning": "Subscription independently reconciled with provider; security records unchanged.",
    }, record_id=_event_id(account.organization_id, "stripe:" + event_id))
    state["event_id"] = str(event.id)
    add_record(s, account.organization_id, "commercial_subscription", state, {"billing_event": event.id})


def _count(s, org_id, kind, system_id=None):
    query = select(func.count()).select_from(Record).where(Record.organization_id == org_id,
                                                         Record.kind == kind)
    if system_id:
        query = query.where(Record.payload["system_id"].as_string() == str(system_id))
    return s.scalar(query) or 0


def _limit_error(resource, used, limit, org_id=None, plan=None):
    if org_id is not None:
        from .measurements import QuotaExceeded

        raise QuotaExceeded(resource, used, limit, org_id, plan)
    raise HTTPException(402, {"code": "entitlement_limit", "resource": resource,
                             "used": used, "limit": limit, "upgrade_url": "/app/settings?tab=billing",
                             "message": "Plan allowance reached. Existing records and security conclusions are retained."})


def require_system_capacity(s, org_id):
    account, _, allowed = resolve(s, org_id)
    allowance = allowed["protected_system_limit"]
    used = _count(s, org_id, "system")
    if used >= allowance:
        _limit_error("protected_systems", used, allowance, org_id, account.plan)


def require_environment_capacity(s, org_id, system_id):
    get_record(s, org_id, system_id, "system")
    account, _, allowed = resolve(s, org_id)
    allowance = allowed["environments_per_system_limit"]
    used = _count(s, org_id, "environment", system_id)
    if used >= allowance:
        _limit_error("environments_per_system", used, allowance, org_id, account.plan)


def require_verification_capacity(s, org_id, reserve):
    if reserve < 1:
        raise HTTPException(422, "Verification reservation must be positive")
    account, state, allowance = resolve(s, org_id)
    active = account.status in ({"free", "active", "trialing", "grace"} if state else {"active", "manual_pilot"})
    used = account.consumed + account.reserved
    limit = allowance["monthly_verification_budget"]
    if not active or used + reserve > limit:
        _limit_error("verification_executions", used, limit, org_id, account.plan)


def has_capability(s, org_id, capability):
    allowed = entitlements(s, org_id)["capabilities"]
    return capability in allowed or "legacy.contract" in allowed


def can_use_connector_role(s, org_id, connector, role):
    capability_id = {"gcp_cloud_run": "gcp"}.get(connector.lower(), connector.lower())
    return has_capability(s, org_id, f"connector.{capability_id}.{role.lower()}")


def require_capability(s, org_id, capability):
    if not has_capability(s, org_id, capability):
        _limit_error(capability, 0, 0, org_id, s.get(Account, org_id).plan)


def overview(s, org_id):
    from .entitlements import property_usage

    account, state, allowed = resolve(s, org_id)
    properties = property_usage(s, org_id, account, allowance=allowed["approved_property_limit"])
    usage = {"protected_systems": _count(s, org_id, "system"), **properties,
             "consumed": account.consumed, "reserved": account.reserved,
             "remaining": max(0, account.trial_limit - account.consumed - account.reserved)}
    events = list(s.scalars(select(Record).where(Record.organization_id == org_id,
                         Record.kind == "billing_event").order_by(Record.created_at.desc()).limit(50)))
    base_price = state["plan_version"].get("monthly_usd") if state else None
    discount = (state.get("promotion") or {}).get("percent_off", 0) if state else 0
    return {"plan": account.plan, "status": account.status, "paid": account.paid,
            "provider": state["provider"] if state else "legacy", "revision": state["revision"] if state else 0,
            "mock_available": settings().is_local and provider_name() == "mock",
            "entitlements": allowed, "usage": usage, "subscription": state,
            "pricing": {"base_monthly_usd": base_price, "percent_off": discount,
                        "effective_monthly_usd": base_price * (100 - discount) / 100 if base_price is not None else None,
                        "invoice_estimate_only": True, "currency": "USD"},
            "offers": catalog_view()["plans"], "events": [serialize(e) for e in events],
            "limitations": ["Mock billing cannot collect money or prove payment.",
                            "Retention is a configured allowance; commercial transitions do not delete history.",
                            "A capability allowance never qualifies an observer or grants external authority."]}


def mutate(s, org_id, command, actor_id=None):
    """Local provider state machine. Authenticated ownership is checked at API edge."""
    if not settings().is_local or provider_name() != "mock":
        raise HTTPException(403, "Mock billing is available only in local/test")
    account = s.get(Account, org_id, with_for_update=True)
    if not account:
        raise HTTPException(404, "Organization billing account not found")
    if account.stripe_subscription or account.paid:
        raise HTTPException(409, "A provider-managed contract cannot be replaced by mock billing")
    key = command["idempotency_key"]
    existing = s.get(Record, _event_id(org_id, key))
    if existing:
        if existing.organization_id != org_id or existing.payload["request_digest"] != _hash(command):
            raise HTTPException(409, "Idempotency key was used for another commercial request")
        return {**overview(s, org_id), "duplicate": True}
    account, state, _ = resolve(s, org_id)
    if state is None:
        raise HTTPException(409, "Legacy contract requires explicit operator migration")
    expected = command.get("expected_revision")
    if expected is not None and state["revision"] != expected:
        raise HTTPException(409, "Subscription revision changed; refresh before applying this change")
    action, clock = command["action"], now()
    state["provider"] = "mock"
    state.setdefault("fallback_plan_version", plan_version("free"))
    if action in {"upgrade", "downgrade", "cancel", "start_trial"}:
        selected = plan_version("free" if action == "cancel" else command.get("plan"))
        if selected["sales_assisted"]:
            raise HTTPException(422, "Enterprise requires a contract override, not self-service checkout")
        if action in {"downgrade", "cancel"}:
            if selected["entitlements"]["protected_system_limit"] > state["plan_version"]["entitlements"]["protected_system_limit"]:
                raise HTTPException(422, "Use upgrade to increase the subscribed scope")
            state["scheduled_change"] = {"plan": selected["id"], "plan_version": selected,
                                         "effective_at": state["period_end"]}
        else:
            if selected["id"] == "free":
                raise HTTPException(422, "Use downgrade to return to Free at the period boundary")
            if action == "start_trial" and (state.get("trial_used") or state["plan"] != "free"):
                raise HTTPException(409, "A trial is available once for a Free organization")
            if action == "upgrade" and selected["entitlements"]["protected_system_limit"] < state["plan_version"]["entitlements"]["protected_system_limit"]:
                raise HTTPException(422, "Use downgrade to reduce the subscribed scope at period end")
            state["plan"], state["plan_version"] = selected["id"], selected
            state["status"] = "trialing" if action == "start_trial" else "active"
            state["scheduled_change"], state["grace_until"], state["override"] = None, None, None
            state["trial"] = None
            if action == "start_trial":
                state["trial_used"] = True
                state["trial"] = {"started_at": clock.isoformat(),
                                  "expires_at": (clock + timedelta(days=catalog().trial_days)).isoformat()}
    elif action == "payment_failed":
        if state["plan"] == "free":
            raise HTTPException(409, "Free has no payment to fail")
        state["status"] = "grace"
        # Duplicate or repeated provider failures cannot extend a grace deadline.
        state["grace_until"] = state.get("grace_until") or (clock + timedelta(days=catalog().grace_days)).isoformat()
    elif action == "payment_recovered":
        if state["status"] != "grace":
            raise HTTPException(409, "There is no active failed-payment grace period")
        state["status"], state["grace_until"] = "active", None
    elif action == "renew":
        # Prevent repeated synthetic renewal calls from laundering consumed units.
        raise HTTPException(409, "Usage renews only when the current period expires")
    elif action == "promotion":
        expires = _stamp(command["expires_at"])
        if expires <= clock:
            raise HTTPException(422, "Promotion expiry must be in the future")
        state["promotion"] = {k: command[k] for k in ("code", "kind", "percent_off", "expires_at")}
    elif action == "override":
        if _stamp(command["expires_at"]) <= clock:
            raise HTTPException(422, "Contract expiry must be in the future")
        allowed = deepcopy(state["plan_version"]["entitlements"])
        allowed.update(command["entitlements"])
        Entitlements.model_validate(allowed)
        state["plan"], state["plan_version"], state["status"] = "enterprise", plan_version("enterprise"), "active"
        state["override"] = {k: command[k] for k in ("entitlements", "expires_at", "contract_reference", "reason")}
        state["override"]["entitlements"] = allowed
        state["scheduled_change"], state["trial"], state["grace_until"] = None, None, None
    else:
        raise HTTPException(422, "Unknown commercial transition")
    _append(s, account, state, action, key, command, actor_id)
    return overview(s, org_id)
