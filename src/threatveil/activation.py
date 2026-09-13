"""Activation, time to value, product-qualified signals and upgrade moments.

Everything here is derived from records the service already keeps: no browser
tracker, no invasive analytics and no automatic outreach. Synthetic demonstration
systems are counted separately from customer systems, so a demo can never
masquerade as activation.

Business activation is FIRST_CONFIRMED_CONSEQUENCE: on a non-synthetic system a
customer confirmed a consequence of a real change, or re-established clearance
after one. FIRST_MEANINGFUL_ASSURANCE_EVENT remains the system-side event: after a
current clearance, ThreatVeil observed a change and established its consequence
for at least one claim. A synthetic track can never be activated.
"""

from datetime import timedelta
from typing import Literal
from uuid import uuid5

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select

from .auth import Actor, actor, require
from .business_measurement import DEFINITIONS, first_confirmed, first_proposed
from .business_measurement import synthetic as _synthetic
from .db import Account, Membership, Organization, Record, add_record, now, transaction

router = APIRouter(tags=["activation"])
MILESTONES = ("SIGNUP", "FIRST_SYSTEM", "FIRST_SOURCE", "FIRST_BASELINE", "FIRST_CURRENT_CLEARANCE",
              "FIRST_OBSERVED_CHANGE", "FIRST_MEANINGFUL_ASSURANCE_EVENT", "FIRST_CONFIRMED_CONSEQUENCE",
              "FIRST_REESTABLISHMENT", "FIRST_PASSPORT_SHARE")
# Reported beside the funnel: a proposed change can be evaluated before any clearance.
EXTRA_MILESTONES = ("FIRST_PROPOSED_CONSEQUENCE",)
ACTIVATION_EVENT = "FIRST_CONFIRMED_CONSEQUENCE"
SYSTEM_EVENT = "FIRST_MEANINGFUL_ASSURANCE_EVENT"
INTEREST_TOPICS = ("private_deployment", "enterprise_retention", "production_enforcement",
                   "qualified_observer", "design_partner", "integrity_launch")


def _first(session, org, kind, system_ids, *conditions):
    if not system_ids:
        return None
    return session.scalar(select(func.min(Record.created_at)).where(
        Record.organization_id == org, Record.kind == kind,
        Record.payload["system_id"].astext.in_(system_ids), *conditions))


def _cycles_for(session, org, systems):
    """First consequence and first restoration, from the deterministic lifecycle."""
    from .assurance_intelligence import cycles, load
    from .change_assurance import history

    meaningful, restored = [], []
    for system in systems[:50]:
        environments = {d.payload["environment_id"] for d in history(session, org, "authorization_decision", system.id)}
        for environment_id in sorted(environments):
            ctx = load(session, org, system.id, environment_id)
            completed, open_cycle = cycles(ctx)
            for cycle in completed + ([open_cycle] if open_cycle else []):
                if cycle.get("lost_at") and cycle.get("cause") in {"SOURCE_CHANGE", "STATE_TRANSITION", "AUTHORITY_DECLARATION"}:
                    meaningful.append(cycle["lost_at"])
                if cycle.get("restored_at"):
                    restored.append(cycle["restored_at"])
    return min(meaningful, default=None), min(restored, default=None)


def _track(session, org, systems, signup, *, demonstration=False):
    ids = [str(s.id) for s in systems]
    times = {"SIGNUP": signup, "FIRST_SYSTEM": min((s.created_at for s in systems), default=None),
             "FIRST_SOURCE": _first(session, org, "connector_installation", ids),
             "FIRST_BASELINE": _first(session, org, "system_state", ids,
                                      Record.payload["provenance"].astext == "QUALIFIED_TEST_EXECUTION"),
             "FIRST_CURRENT_CLEARANCE": _first(session, org, "authorization_decision", ids,
                                               Record.payload["action"].astext == "ALLOW")}
    cleared = times["FIRST_CURRENT_CLEARANCE"]
    observed = []
    if cleared:
        observed.append(_first(session, org, "source_change", ids, Record.created_at > cleared, or_(
            Record.payload["before_batch_id"].astext.isnot(None),
            Record.payload["change_kind"].astext != "COMPONENT_CHANGE")))
        observed.append(_first(session, org, "change_event", ids, Record.created_at > cleared,
                               Record.payload["before_state_id"].astext.isnot(None),
                               Record.payload["delta"]["changes"].astext != "[]"))
    times["FIRST_OBSERVED_CHANGE"] = min((t for t in observed if t), default=None)
    meaningful, restored = _cycles_for(session, org, systems) if cleared else (None, None)
    from datetime import datetime

    times[SYSTEM_EVENT] = datetime.fromisoformat(meaningful) if meaningful else None
    # A demonstration track can show the whole journey but can never be activated.
    confirmed = None if demonstration else first_confirmed(session, org, systems)
    times[ACTIVATION_EVENT] = confirmed["at"] if confirmed else None
    proposed = first_proposed(session, org, systems, include_synthetic=demonstration)
    times["FIRST_PROPOSED_CONSEQUENCE"] = proposed.created_at if proposed else None
    times["FIRST_REESTABLISHMENT"] = datetime.fromisoformat(restored) if restored else None
    times["FIRST_PASSPORT_SHARE"] = _first(session, org, "passport_share", ids)
    milestones = {}
    for name in MILESTONES + EXTRA_MILESTONES:
        stamp = times.get(name)
        milestones[name] = {"reached": stamp is not None, "at": stamp.isoformat() if stamp else None,
                            "seconds_from_signup": max(0, round((stamp - signup).total_seconds()))
                            if stamp and signup else None}
    funnel = []
    for previous, following in zip(MILESTONES, MILESTONES[1:], strict=False):
        start, end = times.get(previous), times.get(following)
        funnel.append({"from": previous, "to": following, "converted": bool(start and end),
                       "seconds": max(0, round((end - start).total_seconds())) if start and end else None})
    result = {"systems": len(systems), "milestones": milestones, "funnel": funnel,
              "activated": milestones[ACTIVATION_EVENT]["reached"] and not demonstration,
              "activation_basis": confirmed["basis"] if confirmed else None}
    if demonstration:
        result["demonstration_complete"] = milestones[SYSTEM_EVENT]["reached"]
    return result


def _count(session, org, kind, *conditions):
    return session.scalar(select(func.count()).select_from(Record).where(
        Record.organization_id == org, Record.kind == kind, *conditions)) or 0


def product_signals(session, org, systems):
    customer = [s for s in systems if not _synthetic(s)]
    customer_ids = [str(s.id) for s in customer]
    account = session.get(Account, org)
    quota = lambda resource: _count(session, org, "service_metric", Record.payload["name"].astext == "quota.reached",  # noqa: E731
                                     Record.payload["resource"].astext == resource)
    interest = {topic: _count(session, org, "commercial_interest", Record.payload["topic"].astext == topic)
                for topic in INTEREST_TOPICS}
    members = session.scalar(select(func.count()).select_from(Membership).where(Membership.organization_id == org)) or 0
    budget = account.trial_limit if account else 0
    used = (account.consumed + account.reserved) if account else 0
    signals = {
        "production_environment_created": _count(session, org, "environment",
                                                 Record.payload["purpose"].astext == "PRODUCTION",
                                                 Record.payload["system_id"].astext.in_(customer_ids or [""])),
        "third_system_requested": int(len(systems) >= 3 or quota("protected_systems") > 0),
        "block_policy_attempted": quota("enforcement.ci") + _count(session, org, "release",
                                                                     Record.payload["policy"]["mode"].astext == "BLOCK"),
        "external_passport_shared": _count(session, org, "passport_share"),
        "collaborators_active": int(members >= 2),
        "collaboration_requested": quota("team.collaboration"),
        "high_verification_usage": int(bool(budget) and used >= 0.8 * budget),
        "qualified_observer_requested": session.scalar(select(func.count()).select_from(Record).where(
            Record.organization_id == org, Record.kind.like("observer%"))) or 0,
        "external_assurance_consumer_attempted": _count(
            session, org, "service_metric", Record.payload["name"].astext == "assurance_gate.checked",
            Record.payload["consumer"].astext.like("machine:%")) + _count(session, org, "consumer_acceptance"),
        "private_deployment_requested": interest["private_deployment"],
        "enterprise_retention_requested": interest["enterprise_retention"],
        "production_enforcement_requested": interest["production_enforcement"],
        "design_partner_requested": interest["design_partner"],
    }
    return [{"signal": name, "present": bool(value), "count": int(value)} for name, value in signals.items()]


def upgrade_moments(session, org):
    """Value-boundary prompts from capabilities and facts, never plan-name branches.

    The suggested plan is the least expensive self-service catalog plan that
    carries the missing capability or allowance; names and prices are catalog data.
    """
    from .commercial import catalog, resolve

    account, _, allowed = resolve(session, org)
    plans = sorted((p for p in catalog().plans if p.monthly_usd is not None and not p.sales_assisted
                    and p.availability == "self_serve" and p.id != account.plan), key=lambda p: p.monthly_usd)

    def offer(predicate):
        return next((p for p in plans if predicate(p.entitlements)), None)

    capabilities = set(allowed["capabilities"])
    systems = _count(session, org, "system")
    moments = []

    def add(identifier, trigger, plan, message, capability=None):
        if plan is not None:
            moments.append({"id": identifier, "trigger": trigger, "capability": capability, "plan": plan.id,
                            "plan_name": plan.name, "monthly_usd": plan.monthly_usd,
                            "message": message.format(plan=plan.name, systems=plan.entitlements.protected_system_limit),
                            "note": "A plan changes what ThreatVeil may do for you. It never changes a security conclusion."})

    if _count(session, org, "authorization_decision", Record.payload["action"].astext == "ALLOW") and "enforcement.ci" not in capabilities:
        add("first_clearance", "FIRST_CURRENT_CLEARANCE", offer(lambda e: "enforcement.ci" in e.capabilities),
            "You've protected your first system. {plan} enables blocking CI enforcement and up to {systems} protected systems.",
            "enforcement.ci")
    if systems >= allowed["protected_system_limit"]:
        add("system_allowance", "PROTECTED_SYSTEM_LIMIT",
            offer(lambda e: e.protected_system_limit > allowed["protected_system_limit"]),
            "Every protected system in your allowance is in use. {plan} protects up to {systems} systems.")
    if _count(session, org, "environment", Record.payload["purpose"].astext == "PRODUCTION") and "enforcement.production" not in capabilities:
        add("production_assurance", "PRODUCTION_ENVIRONMENT", offer(lambda e: "enforcement.production" in e.capabilities),
            "You're adding production assurance. {plan} supports qualified production enforcement "
            "where a qualified enforcer exists for your environment.", "enforcement.production")
    members = session.scalar(select(func.count()).select_from(Membership).where(Membership.organization_id == org)) or 0
    collaboration = _count(session, org, "service_metric", Record.payload["name"].astext == "quota.reached",
                           Record.payload["resource"].astext == "team.collaboration")
    if (members >= 2 or collaboration) and "approval.workflow" not in capabilities:
        add("shared_review", "MULTIPLE_REVIEWERS", offer(lambda e: "approval.workflow" in e.capabilities),
            "Multiple reviewers are now participating. {plan} supports shared approvals and ownership.",
            "approval.workflow")
    budget = allowed["monthly_verification_budget"]
    if budget and account.consumed + account.reserved >= 0.8 * budget:
        add("verification_budget", "VERIFICATION_USAGE", offer(lambda e: e.monthly_verification_budget > budget),
            "Most of this period's verification allowance is used. {plan} raises it for repeated re-proof.")
    return moments


def activation_summary(session, org):
    organization = session.get(Organization, org)
    signup = organization.created_at if organization else None
    systems = list(session.scalars(select(Record).where(Record.organization_id == org, Record.kind == "system")
                                   .order_by(Record.created_at)))
    customer = [s for s in systems if not _synthetic(s)]
    synthetic = [s for s in systems if _synthetic(s)]
    horizon = now() - timedelta(days=30)
    recent = lambda kind, *conditions: _count(session, org, kind, Record.created_at >= horizon, *conditions)  # noqa: E731
    support = 0
    for payload in session.scalars(select(Record.payload["measurement"]).where(
            Record.organization_id == org, Record.kind == "product_metric")):
        if payload.get("name") == "support.work_recorded":
            support += int(payload.get("minutes") or 0)
    return {
        "schema_version": "activation-v2", "as_of": now().isoformat(), "activation_event": ACTIVATION_EVENT,
        "definition": DEFINITIONS[ACTIVATION_EVENT], "system_event": SYSTEM_EVENT,
        "system_event_definition": DEFINITIONS[SYSTEM_EVENT],
        "customer": _track(session, org, customer, signup),
        "synthetic": _track(session, org, synthetic, signup, demonstration=True),
        "product_qualified_signals": product_signals(session, org, systems),
        "upgrade_moments": upgrade_moments(session, org),
        "consumption_last_30_days": {
            "assurance_gate_active_hours": recent("service_metric", Record.payload["name"].astext == "assurance_gate.checked"),
            "machine_gate_active_hours": recent("service_metric", Record.payload["name"].astext == "assurance_gate.checked",
                                                Record.payload["consumer"].astext.like("machine:%")),
            "external_passport_status_checks": recent("service_metric", Record.payload["name"].astext == "passport.status_checked"),
            "passports_issued": recent("assurance_passport"), "passport_shares": recent("passport_share"),
            "observed_changes": recent("source_change"), "decisions": recent("authorization_decision"),
        },
        "expansion": {"protected_systems": len(customer), "synthetic_systems": len(synthetic),
                      "environments": _count(session, org, "environment",
                                             Record.payload["system_id"].astext.in_([str(s.id) for s in customer] or [""])),
                      "members": session.scalar(select(func.count()).select_from(Membership).where(Membership.organization_id == org)) or 0},
        "reported_support_minutes": support,
        "limitations": ["Derived from service records inside this tenant; no cross-customer aggregation.",
                        "Synthetic demonstration systems never count toward customer activation.",
                        "Signals are recorded for follow-up only; ThreatVeil contacts no one automatically."],
    }


@router.get("/v1/measurements/activation")
def get_activation(a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        return activation_summary(session, a.org_id)


class Interest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    topic: Literal["private_deployment", "enterprise_retention", "production_enforcement",
                   "qualified_observer", "design_partner", "integrity_launch"]
    idempotency_key: str = Field(min_length=8, max_length=120)


@router.post("/v1/commercial/interest", status_code=201)
def register_interest(body: Interest, a: Actor = Depends(actor)):
    """Record an explicit request for follow-up. Nothing is sent to anyone."""
    require(a)
    with transaction(a.user_id, a.org_id) as session:
        identifier = uuid5(a.org_id, "commercial-interest:" + body.idempotency_key)
        existing = session.get(Record, identifier)
        if existing:
            return {"id": str(identifier), "topic": existing.payload["topic"], "recorded": True,
                    "contacted": False, "duplicate": True}
        account = session.get(Account, a.org_id)
        add_record(session, a.org_id, "commercial_interest", {
            "schema_version": "commercial-interest-v1", "topic": body.topic, "requested_by": str(a.user_id),
            "plan": account.plan if account else None, "contacted": False,
            "note": "Recorded for follow-up. ThreatVeil sends no message automatically."}, record_id=identifier)
        return {"id": str(identifier), "topic": body.topic, "recorded": True, "contacted": False}
