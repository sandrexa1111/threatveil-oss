"""Internal operator store and the founder business report.

Operator-only by construction. It connects with the migration identity
(TV_ADMIN_DATABASE_URL), which the runtime API never holds. The only cross-tenant
read is the organization listing, through SELECT-only policies switched on per
transaction (tv.operator_read). Each organization is then measured inside its own
tenant context, exactly as a tenant request would be.

Operator records are append-only and never visible to customers. They never enter
a security conclusion. Nothing here contacts anyone, charges anyone or invents a
number: every commercial value is entered by the operator, and zero is a valid
answer.
"""

import csv
import io
from contextlib import contextmanager
from datetime import date, datetime, timezone
from typing import Literal
from uuid import UUID, uuid4

from pydantic import Field, model_validator
from sqlalchemy import Column, DateTime, MetaData, String, Table, create_engine, insert, select, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from .config import settings
from .db import Account, Membership, Organization, User, now
from .schemas import Input

PROFILE = "founder-business-report/v1"
metadata = MetaData()
operator_records = Table(
    "operator_records", metadata,
    Column("id", PGUUID(as_uuid=True), primary_key=True),
    Column("kind", String(40), nullable=False),
    Column("organization_id", PGUUID(as_uuid=True), nullable=True),
    Column("payload", JSONB, nullable=False),
    Column("created_by", String(120), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)
STAFF_CATEGORIES = ("SYSTEM_MODELING", "CLAIM_AUTHORING", "OBSERVER_SETUP", "DEPENDENCY_MAPPING", "BASELINE",
                    "DEBUGGING", "SUPPORT", "CUSTOM_INTEGRATION", "OTHER")
EXTERNAL = ("CUSTOMER", "DESIGN_PARTNER", "UNREVIEWED")
PROSPECT_HANDLE = r"^[a-z0-9][a-z0-9-]{1,62}$"
VANITY_EXCLUDED = ("signups", "page views", "sessions", "synthetic demonstration runs", "API calls",
                   "passports issued without an external check")


class OperatorError(RuntimeError):
    pass


Strict = Input


class StaffTime(Strict):
    organization_id: UUID
    work_date: date
    minutes: int = Field(ge=1, le=720)
    category: Literal["SYSTEM_MODELING", "CLAIM_AUTHORING", "OBSERVER_SETUP", "DEPENDENCY_MAPPING", "BASELINE",
                      "DEBUGGING", "SUPPORT", "CUSTOM_INTEGRATION", "OTHER"]
    stage: Literal["QUALIFICATION", "KICKOFF", "MODELING", "OBSERVATION", "BASELINE", "WATCH", "REESTABLISH",
                   "CONVERSION", "SUPPORT", "OTHER"]
    system_id: UUID | None = None
    observer: str | None = Field(default=None, max_length=120)
    support_event: str | None = Field(default=None, max_length=120)
    note: str = Field(default="", max_length=500)


class Classification(Strict):
    organization_id: UUID
    classification: Literal["CUSTOMER", "DESIGN_PARTNER", "INTERNAL", "TEST"]
    reason: str = Field(min_length=5, max_length=300)


class Prospect(Strict):
    """A pseudonymous handle only. Never a person's name, an email address or a phone number."""
    prospect: str = Field(pattern=PROSPECT_HANDLE)
    archetype: str = Field(min_length=2, max_length=80)
    source: Literal["FOUNDER_NETWORK", "INBOUND", "OUTBOUND", "REFERRAL", "COMMUNITY", "OTHER"]
    note: str = Field(default="", max_length=500)


class ProofEvent(Strict):
    prospect: str = Field(pattern=PROSPECT_HANDLE)
    event: Literal["QUALIFIED", "DISQUALIFIED", "PAIN_CONFIRMED", "OFFER_MADE", "OFFER_ACCEPTED", "OFFER_REJECTED",
                   "CONTRACT_SIGNED", "KICKOFF", "GATE_INSTALLED", "PASSPORT_CHECKED", "CONVERTED", "CHURNED"]
    occurred_on: date
    organization_id: UUID | None = None
    offer: Literal["ASSURANCE_LAUNCH", "SELF_SERVE_PRO", "SELF_SERVE_TEAM", "BUSINESS", "ENTERPRISE",
                   "DESIGN_PARTNER"] | None = None
    price_usd: int | None = Field(default=None, ge=0, le=10_000_000)
    price_variant: str | None = Field(default=None, max_length=40)
    contract_value_usd: int | None = Field(default=None, ge=0, le=100_000_000)
    reason: str = Field(default="", max_length=300)

    @model_validator(mode="after")
    def complete(self):
        if self.event in {"OFFER_MADE", "OFFER_ACCEPTED", "OFFER_REJECTED"} and (self.offer is None or self.price_usd is None):
            raise ValueError("Offer events require the offer and its price")
        if self.event == "OFFER_REJECTED" and len(self.reason) < 3:
            raise ValueError("A rejected offer requires the stated reason")
        if self.event == "CONTRACT_SIGNED" and self.contract_value_usd is None:
            raise ValueError("A signed contract requires its contract value")
        if self.event in {"GATE_INSTALLED", "PASSPORT_CHECKED", "KICKOFF", "CONVERTED"} and self.organization_id is None:
            raise ValueError("This event requires the customer organization")
        return self


def _engine():
    config = settings()
    if not config.admin_database_url:
        raise OperatorError("Operator access requires TV_ADMIN_DATABASE_URL (the migration identity)")
    if config.admin_database_url == config.database_url:
        raise OperatorError("Operator access must not use the runtime identity")
    return create_engine(config.admin_database_url, poolclass=NullPool)


@contextmanager
def operator_session():
    engine = _engine()
    try:
        with Session(engine) as session, session.begin():
            yield session
    finally:
        engine.dispose()


def _cross_tenant(session, enabled):
    session.execute(text("SELECT set_config('tv.operator_read', :v, true), set_config('tv.org_id', '', true)"),
                    {"v": "on" if enabled else "off"})


def _tenant(session, org):
    session.execute(text("SELECT set_config('tv.operator_read', 'off', true), set_config('tv.org_id', :o, true)"),
                    {"o": str(org)})


def append(session, kind, payload, *, operator, organization_id=None):
    identifier = uuid4()
    session.execute(insert(operator_records).values(
        id=identifier, kind=kind, organization_id=organization_id, created_by=operator[:120], created_at=now(),
        payload={"schema_version": "operator-record/v1", **payload}))
    return str(identifier)


def rows(session, kind, organization_id=None):
    query = select(operator_records).where(operator_records.c.kind == kind)
    if organization_id is not None:
        query = query.where(operator_records.c.organization_id == organization_id)
    return list(session.execute(query.order_by(operator_records.c.created_at)).mappings())


def record(model: Strict, kind, *, operator):
    payload = model.model_dump(mode="json")
    organization = payload.get("organization_id")
    with operator_session() as session:
        if organization:
            _cross_tenant(session, True)
            if session.get(Organization, UUID(organization)) is None:
                raise OperatorError("Organization not found")
        return {"id": append(session, kind, payload, operator=operator,
                             organization_id=UUID(organization) if organization else None),
                "kind": kind, "recorded": True, "visible_to_customer": False}


def classifications(session):
    """Latest operator classification per organization, in one read."""
    latest = {}
    for row in rows(session, "org_classification"):  # oldest first; later entries win
        latest[row["organization_id"]] = row["payload"]["classification"]
    return latest


def classification_of(organization, owner_subject, operator_classes):
    if organization.id in operator_classes:
        return operator_classes[organization.id], "OPERATOR"
    if str(owner_subject or "").startswith("local:"):
        return "INTERNAL", "LOCAL_IDENTITY"
    return "UNREVIEWED", "DEFAULT"


def _add_rate(total, part):
    total["numerator"] += part["numerator"]
    total["denominator"] += part["denominator"]


def _finish(item):
    item["value"] = round(item["numerator"] / item["denominator"], 4) if item["denominator"] else None
    return item


def founder_report(*, operator, weeks=12):
    """The founder's business dashboard. Internal only; no vanity metrics."""
    from .business_measurement import PROVENANCES, business_summary

    with operator_session() as session:
        _cross_tenant(session, True)
        listing = session.execute(select(Organization, User.subject).join(
            User, User.id == Organization.owner_user_id).order_by(Organization.created_at)).all()
        staff = rows(session, "staff_time")
        proofs = rows(session, "commercial_proof")
        prospects = rows(session, "prospect")
        known = classifications(session)
        classes = {o.id: classification_of(o, subject, known) for o, subject in listing}
        _cross_tenant(session, False)
        by_class = dict.fromkeys(("CUSTOMER", "DESIGN_PARTNER", "UNREVIEWED", "INTERNAL", "TEST"), 0)
        weekly, organizations, provenance = None, [], dict.fromkeys(PROVENANCES, 0)
        precision_keys = ("confirmed_rate", "dispute_rate", "false_invalidation_rate",
                          "no_impact_confirmation_rate", "mapped_change_ratio")
        precision = {key: {"numerator": 0, "denominator": 0} for key in precision_keys}
        value = {"confirmed_invalidations": 0, "disputed_invalidations": 0, "confirmed_no_impact": 0,
                 "disputed_no_impact": 0}
        paid, synthetic_systems, excluded_systems = 0, 0, 0
        for organization, _ in listing:
            classification, basis = classes[organization.id]
            by_class[classification] += 1
            _tenant(session, organization.id)
            if classification not in EXTERNAL:
                excluded_systems += session.scalar(text(
                    "SELECT count(*) FROM records WHERE organization_id = :o AND kind = 'system'"),
                    {"o": organization.id}) or 0
                continue
            summary = business_summary(session, organization.id)
            members = session.scalar(select(Membership.user_id).where(
                Membership.organization_id == organization.id).limit(1))
            account = session.get(Account, organization.id)
            paid += bool(account and account.paid)
            synthetic_systems += summary["systems"]["synthetic"]
            for key in precision_keys:
                _add_rate(precision[key], summary["precision"][key])
            for key in value:
                value[key] += summary["precision"]["value"][key]
            for key, count in summary["consequences"]["by_provenance"].items():
                provenance[key] += count
            series = summary["north_star"]["weekly"][-weeks:]
            weekly = [dict(item) for item in series] if weekly is None else [
                {**w, "watched": w["watched"] + s["watched"], "maintained": w["maintained"] + s["maintained"],
                 "relied_upon": w["relied_upon"] + s["relied_upon"]} for w, s in zip(weekly, series, strict=True)]
            minutes = sum(r["payload"]["minutes"] for r in staff if r["organization_id"] == organization.id)
            organizations.append({
                "organization_id": str(organization.id), "classification": classification,
                "classification_basis": basis, "created_at": organization.created_at.isoformat(),
                "has_members": members is not None, "paid_plan": bool(account and account.paid),
                "customer_systems": summary["systems"]["customer"], "rps": summary["north_star"]["current"],
                "activated": summary["activation"]["reached"], "activation_basis": summary["activation"]["basis"],
                "seconds_to_first_confirmed_consequence": summary["activation"]["seconds_from_signup"],
                "seconds_to_first_proposed_consequence": summary["time_to_wow"]["seconds_to_first_proposed_consequence"],
                "staff_hours": round(minutes / 60, 2)})
        _cross_tenant(session, True)
        external_ids = {o["organization_id"] for o in organizations}
        activated = [o for o in organizations if o["activated"]]
        hours = lambda items: round(sum(r["payload"]["minutes"] for r in items) / 60, 2)  # noqa: E731
        external_staff = [r for r in staff if str(r["organization_id"]) in external_ids]
        report = {
            "schema_version": PROFILE, "as_of": now().isoformat(), "internal_only": True,
            "vanity_metrics_excluded": list(VANITY_EXCLUDED),
            "organizations": {"by_classification": by_class, "external": len(organizations),
                              "note": "UNREVIEWED organizations are real self-service signups the operator has not "
                                      "classified; INTERNAL and TEST organizations are excluded from every metric."},
            "north_star": {"metric": "RPS", "current": weekly[-1]["relied_upon"] if weekly else 0,
                           "weekly": weekly or []},
            "activation": {"event": "FIRST_CONFIRMED_CONSEQUENCE", "activated_organizations": len(activated),
                           "external_organizations": len(organizations),
                           "median_seconds_to_activation": _median(
                               [o["seconds_to_first_confirmed_consequence"] for o in activated]),
                           "median_seconds_to_first_proposed_consequence": _median(
                               [o["seconds_to_first_proposed_consequence"] for o in organizations])},
            "precision": {**{key: _finish(item) for key, item in precision.items()}, "value": value},
            "consequences_by_provenance": provenance,
            "staff_time": {
                "hours_total": hours(external_staff),
                "hours_by_category": {c: hours([r for r in external_staff if r["payload"]["category"] == c])
                                      for c in STAFF_CATEGORIES},
                "hours_by_stage": _group(external_staff, "stage"),
                "hours_per_activated_organization": round(sum(o["staff_hours"] for o in activated) / len(activated), 2)
                if activated else None,
                "internal_or_test_hours_excluded": hours([r for r in staff if str(r["organization_id"]) not in external_ids])},
            "commercial": commercial_summary(prospects, proofs, organizations),
            "revenue": {"paid_plan_organizations": paid,
                        "contracted_value_usd": sum(r["payload"].get("contract_value_usd") or 0 for r in proofs
                                                    if r["payload"]["event"] == "CONTRACT_SIGNED"),
                        "basis": "Operator-entered signed contract values and provider-confirmed paid plans only. "
                                 "ThreatVeil does not recognize revenue."},
            "excluded": {"synthetic_systems_in_external_organizations": synthetic_systems,
                         "systems_in_internal_or_test_organizations": excluded_systems},
            "organizations_detail": organizations,
        }
        append(session, "operator_access", {"action": "founder_report", "organizations": len(listing)},
               operator=operator)
        return report


def _median(values):
    values = sorted(v for v in values if v is not None)
    if not values:
        return None
    middle = len(values) // 2
    return values[middle] if len(values) % 2 else round((values[middle - 1] + values[middle]) / 2)


def _group(items, key):
    result = {}
    for item in items:
        name = item["payload"].get(key) or "UNSPECIFIED"
        result[name] = round(result.get(name, 0) + item["payload"]["minutes"] / 60, 2)
    return result


def commercial_summary(prospects, proofs, organizations):
    """Commercial proof fields, per prospect and in aggregate. Only recorded facts; no inference of intent."""
    handles = sorted({r["payload"]["prospect"] for r in prospects} | {r["payload"]["prospect"] for r in proofs})
    by_org = {o["organization_id"]: o for o in organizations}
    funnel, experiments = [], {}
    for handle in handles:
        events = [r["payload"] for r in proofs if r["payload"]["prospect"] == handle]
        first = lambda name, events=events: next((e for e in events if e["event"] == name), None)  # noqa: E731
        org = next((e["organization_id"] for e in events if e.get("organization_id")), None)
        linked = by_org.get(org) if org else None
        offer = next((e for e in reversed(events) if e["event"] in {"OFFER_ACCEPTED", "OFFER_REJECTED", "OFFER_MADE"}), None)
        funnel.append({
            "prospect": handle, "qualified": bool(first("QUALIFIED")), "disqualified": bool(first("DISQUALIFIED")),
            "pain_confirmed": bool(first("PAIN_CONFIRMED")),
            "offer": offer["offer"] if offer else None, "price_usd": offer["price_usd"] if offer else None,
            "outcome": {"OFFER_ACCEPTED": "ACCEPTED", "OFFER_REJECTED": "REJECTED", "OFFER_MADE": "OPEN"}.get(
                offer["event"]) if offer else None,
            "reason": offer.get("reason") if offer else None,
            "contract_value_usd": (first("CONTRACT_SIGNED") or {}).get("contract_value_usd"),
            "kickoff": (first("KICKOFF") or {}).get("occurred_on"),
            "first_confirmed_consequence": linked["activated"] if linked else None,
            "staff_hours": linked["staff_hours"] if linked else None,
            "gate_installed": bool(first("GATE_INSTALLED")), "passport_checked": bool(first("PASSPORT_CHECKED")),
            "converted": bool(first("CONVERTED")), "organization_id": org,
        })
        for event in events:
            if event["event"] in {"OFFER_ACCEPTED", "OFFER_REJECTED"}:
                key = f"{event['offer']}@{event['price_usd']}"
                entry = experiments.setdefault(key, {"offer": event["offer"], "price_usd": event["price_usd"],
                                                     "accepted": 0, "rejected": 0, "reasons": []})
                entry["accepted" if event["event"] == "OFFER_ACCEPTED" else "rejected"] += 1
                if event.get("reason"):
                    entry["reasons"].append(event["reason"])
    made = [f for f in funnel if f["outcome"] in {"ACCEPTED", "REJECTED"}]
    return {"prospects": len(handles), "qualified": sum(f["qualified"] for f in funnel),
            "pain_confirmed": sum(f["pain_confirmed"] for f in funnel),
            "offers_decided": len(made), "offers_accepted": sum(f["outcome"] == "ACCEPTED" for f in made),
            "acceptance_rate": _finish({"numerator": sum(f["outcome"] == "ACCEPTED" for f in made),
                                        "denominator": len(made)}),
            "kickoffs": sum(bool(f["kickoff"]) for f in funnel), "conversions": sum(f["converted"] for f in funnel),
            "pricing_experiments": sorted(experiments.values(), key=lambda e: (e["offer"], e["price_usd"])),
            "funnel": funnel}


def investor_export(report, *, fmt="csv"):
    """Founder metrics with definitions, numerators and denominators. Zero is a valid value."""
    lines = [
        ("rps_current", report["north_star"]["current"], None, None, "Relied-upon Protected Systems this week"),
        ("external_organizations", report["organizations"]["external"], None, None,
         "Customer, design-partner and unreviewed self-service organizations"),
        ("activated_organizations", report["activation"]["activated_organizations"], None,
         report["activation"]["external_organizations"], "Organizations reaching FIRST_CONFIRMED_CONSEQUENCE"),
        ("median_seconds_to_activation", report["activation"]["median_seconds_to_activation"], None, None,
         "Signup to first confirmed consequence"),
    ]
    for key, item in report["precision"].items():
        if key != "value":
            lines.append((key, item["value"], item["numerator"], item["denominator"], "Latest verdict per consequence"))
    lines += [
        ("staff_hours_total", report["staff_time"]["hours_total"], None, None, "Operator-logged hours, external organizations"),
        ("hours_per_activated_organization", report["staff_time"]["hours_per_activated_organization"], None, None,
         "Operator hours divided by activated organizations"),
        ("offers_accepted", report["commercial"]["offers_accepted"], None, report["commercial"]["offers_decided"],
         "Recorded offer outcomes"),
        ("contracted_value_usd", report["revenue"]["contracted_value_usd"], None, None, "Operator-entered signed contracts"),
        ("paid_plan_organizations", report["revenue"]["paid_plan_organizations"], None, None, "Provider-confirmed paid plans"),
    ]
    rows_out = [{"metric": m, "value": v, "numerator": n, "denominator": d, "definition": definition,
                 "as_of": report["as_of"]} for m, v, n, d, definition in lines]
    if fmt == "json":
        return {"schema_version": "founder-metrics-export/v1", "generated_at": datetime.now(timezone.utc).isoformat(),
                "metrics": rows_out, "weekly_rps": report["north_star"]["weekly"],
                "note": "Every value derives from recorded facts. Zero means zero."}
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=["metric", "value", "numerator", "denominator", "definition", "as_of"])
    writer.writeheader()
    writer.writerows(rows_out)
    return stream.getvalue()
