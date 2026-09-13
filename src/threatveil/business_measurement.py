"""Truthful business measurement.

Consequence provenance, customer feedback ("Was this right?"), business activation
(FIRST_CONFIRMED_CONSEQUENCE), consequence precision and the weekly Relied-upon
Protected Systems (RPS) North Star.

Every number derives from immutable tenant records. Synthetic systems and replayed
history never count toward activation, the North Star, precision or any customer
metric. Feedback is its own append-only record: it never edits, re-scores or
suppresses the consequence it refers to, and it has no effect on assurance.
"""

from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID, uuid5

from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field
from sqlalchemy import select

from .auth import Actor, actor, require
from .change_assurance import history
from .core.contracts import digest
from .db import Organization, Record, add_record, audit, get_record, now, transaction
from .schemas import Input

router = APIRouter(tags=["business-measurement"])
PROFILE = "business-measurement/v1"
FEEDBACK_PROFILE = "consequence-feedback/v1"
PROVENANCES = ("SYNTHETIC", "CUSTOMER", "LIVE", "IMPORTED", "PROPOSED", "REPLAYED")
# Real customer activity. SYNTHETIC and REPLAYED are reported, never counted.
COUNTED = frozenset({"CUSTOMER", "LIVE", "IMPORTED", "PROPOSED"})
VERDICTS = ("CORRECT", "PARTIALLY_CORRECT", "INCORRECT", "NOT_SURE")
CONFIRMING = frozenset({"CORRECT", "PARTIALLY_CORRECT"})
CONSEQUENCE_KINDS = {"source_change": "SOURCE_CHANGE", "change_event": "STATE_TRANSITION",
                     "permission_envelope": "AUTHORITY_DECLARATION",
                     "proposed_change_assessment": "PROPOSED_CHANGE"}
LIVE_ACQUISITION = frozenset({"API_OBSERVED", "INSTRUMENTED"})
CHANGE_CAUSES = frozenset({"SOURCE_CHANGE", "STATE_TRANSITION", "AUTHORITY_DECLARATION"})
# Activation needs a determinate claim-level answer. "No baseline yet" is not one.
DETERMINATE = ("INVALIDATION", "NO_IMPACT")
WOW_EFFECTS = ("WOULD_REQUIRE_REPROOF", "NO_CLAIM_AFFECTED", "DECLARED_CLAIMS_AFFECTED",
               "NO_DECLARED_CLAIM_AFFECTED")
ACT_WINDOW = timedelta(days=7)
WATCH_WINDOW = timedelta(days=7)
REESTABLISH_WINDOW = timedelta(days=14)
MAX_SYSTEMS = 50
MAX_ENVIRONMENTS = 5
DEFINITIONS = {
    "FIRST_CONFIRMED_CONSEQUENCE": (
        "Business activation. On a non-synthetic system, a customer member confirmed a determinate claim-level "
        "consequence of a real change (live, imported, customer-recorded or proposed) as correct or partially "
        "correct, or re-established clearance within 7 days of losing it to such a change. A claim-level answer "
        "invalidates named claims or states that none are affected; declared claims count with claim_basis "
        "DECLARED. Replayed history and synthetic systems never count."),
    "FIRST_MEANINGFUL_ASSURANCE_EVENT": (
        "System-side event. After a current clearance, ThreatVeil observed a change and established its consequence "
        "for at least one claim. It does not require anyone to have read or confirmed it."),
    "FIRST_PROPOSED_CONSEQUENCE": (
        "Time to wow. The first consequence ThreatVeil computed for a proposed change the customer submitted "
        "on a non-synthetic system, whether it invalidates a claim or touches none."),
    "RPS": (
        "Relied-upon Protected Systems, weekly. A non-synthetic system counts in a week when it was watched (a live "
        "source reported within 7 days), maintained (clearance current, or lost within the previous 14 days and being "
        "re-established) and relied upon (a machine Assurance Gate check, a CI check or an external passport status "
        "check within 7 days)."),
}


def synthetic(system):
    return bool(system.payload.get("demo") or system.payload.get("fixture_profile"))


def provenance(system, record):
    """Where a consequence came from. Synthetic dominates every other origin."""
    if synthetic(system):
        return "SYNTHETIC"
    data = record.payload
    if record.kind == "proposed_change_assessment":
        return "REPLAYED" if data.get("mode") == "REPLAYED" else "PROPOSED"
    if record.kind == "source_change":
        return "LIVE" if data.get("acquisition") in LIVE_ACQUISITION else "IMPORTED"
    if record.kind == "change_event" and data.get("transition") == "PROPOSED":
        return "PROPOSED"
    return "CUSTOMER"


def view_provenance(system, view):
    if synthetic(system):
        return "SYNTHETIC"
    if view["kind"] == "SOURCE_CHANGE":
        return "LIVE" if view["origin"].get("acquisition") in LIVE_ACQUISITION else "IMPORTED"
    if view["kind"] == "STATE_TRANSITION" and view["origin"].get("acquisition") == "PROPOSED":
        return "PROPOSED"
    return "CUSTOMER"


def category(summary):
    """A determinate claim-level answer, either way, or OTHER.

    INVALIDATION: ThreatVeil said named claims need fresh evidence. NO_IMPACT: it said
    none do. Both are the product's value. Everything else (no baseline, no claims, no
    change) is recorded but is not a claim-level answer.
    """
    if summary["claims_affected"] or summary.get("declared_claims_affected"):
        return "INVALIDATION"
    if summary["effect"] == "NO_CLAIM_AFFECTED" or summary.get("declared_effect") == "NO_DECLARED_CLAIM_AFFECTED":
        return "NO_IMPACT"
    return "OTHER"


def claim_basis(summary):
    """Whether the answer rests on evidence-backed claims or on declared, unverified ones."""
    if summary["claims_affected"] or summary["effect"] == "NO_CLAIM_AFFECTED":
        return "EVIDENCED"
    return "DECLARED" if summary.get("declared_effect") else "NONE"


def summarize(view):
    """The part of a consequence a person judges. Bound into feedback by digest."""
    authority = view.get("authority") or {}
    consequence = view["consequence"]
    return {"kind": view["kind"], "headline": view["headline"], "effect": consequence["effect"],
            "classification": authority.get("classification"), "scoped": bool(consequence["scoped"]),
            "claims_affected": [{"property_id": c["property_id"], "title": c["title"]}
                                for c in consequence["claims_affected"]],
            "declared_claims_affected": [{"definition_id": c["definition_id"], "claim": c["claim"]}
                                         for c in consequence.get("declared_claims_affected") or []],
            "declared_effect": consequence.get("declared_effect"),
            "still_holds": len(consequence["still_holds"])}


def consequence(session, org, system, consequence_id):
    """Resolve one consequence of this system, recomputed from immutable records."""
    from .assurance_intelligence import _declaration_view, _source_change_view, _transition_view, load

    record = get_record(session, org, consequence_id)
    kind = CONSEQUENCE_KINDS.get(record.kind)
    if kind is None or record.payload.get("system_id") != str(system.id):
        raise HTTPException(404, "Consequence not found")
    if record.kind == "proposed_change_assessment":
        summary = record.payload["summary"]
    else:
        ctx = load(session, org, system.id, record.payload.get("environment_id"))
        if record.kind == "source_change":
            view = _source_change_view(ctx, record)
        elif record.kind == "change_event":
            view = _transition_view(ctx, record)
        else:
            index = next((i for i, e in enumerate(ctx.envelopes) if e.id == record.id), None)
            if index is None or index + 1 >= len(ctx.envelopes):
                raise HTTPException(404, "Consequence not found")  # the first boundary is not a change
            view = _declaration_view(ctx, record, ctx.envelopes[index + 1])
        summary = summarize(view)
    return record, {"id": str(record.id), "kind": kind, "environment_id": record.payload.get("environment_id"),
                    "provenance": provenance(system, record), "category": category(summary),
                    "claim_basis": claim_basis(summary), "summary": summary, "digest": digest(summary)}


class Feedback(Input):
    verdict: Literal["CORRECT", "PARTIALLY_CORRECT", "INCORRECT", "NOT_SURE"]
    comment: str | None = Field(default=None, max_length=500)
    idempotency_key: str = Field(min_length=8, max_length=120)


def feedback_view(row):
    data = row.payload
    return {"id": str(row.id), "consequence_id": data["consequence_id"], "consequence_kind": data["consequence_kind"],
            "verdict": data["verdict"], "comment": data.get("comment"), "provenance": data["provenance"],
            "counted": data["counted"], "category": data["category"], "claim_basis": data.get("claim_basis"),
            "consequence_digest": data["consequence_digest"],
            "submitted_by": data["submitted_by"], "submitted_at": row.created_at.astimezone(timezone.utc).isoformat(),
            "effect_on_assurance": "NONE"}


def _feedback_rows(session, org, system_ids=None, limit=5000):
    query = select(Record).where(Record.organization_id == org, Record.kind == "consequence_feedback")
    if system_ids is not None:
        query = query.where(Record.payload["system_id"].astext.in_(list(system_ids) or [""]))
    return list(session.scalars(query.order_by(Record.created_at.desc(), Record.id.desc()).limit(limit)))


def latest_by_consequence(rows):
    """The newest verdict per consequence. Earlier verdicts remain in history."""
    latest = {}
    for row in rows:  # newest first
        latest.setdefault(row.payload["consequence_id"], row)
    return latest


@router.post("/v1/systems/{system_id}/consequences/{consequence_id}/feedback", status_code=201)
def give_feedback(system_id: UUID, consequence_id: UUID, body: Feedback, a: Actor = Depends(actor)):
    """Was this right? Recorded beside the consequence; the consequence itself never changes."""
    require(a)
    with transaction(a.user_id, a.org_id) as session:
        system = get_record(session, a.org_id, system_id, "system")
        identifier = uuid5(a.org_id, f"consequence-feedback:{a.user_id}:{body.idempotency_key}")
        existing = session.get(Record, identifier)
        if existing is not None:
            same = (existing.payload["consequence_id"] == str(consequence_id)
                    and existing.payload["verdict"] == body.verdict and existing.payload.get("comment") == body.comment)
            if not same:
                raise HTTPException(409, "Idempotency key already recorded different feedback")
            return {**feedback_view(existing), "duplicate": True}
        record, view = consequence(session, a.org_id, system, consequence_id)
        row = add_record(session, a.org_id, "consequence_feedback", {
            "schema_version": FEEDBACK_PROFILE, "system_id": str(system.id), "environment_id": view["environment_id"],
            "consequence_id": view["id"], "consequence_kind": view["kind"], "provenance": view["provenance"],
            "counted": view["provenance"] in COUNTED, "category": view["category"],
            "claim_basis": view["claim_basis"],
            "consequence_digest": view["digest"], "consequence_summary": view["summary"],
            "verdict": body.verdict, "comment": body.comment, "submitted_by": str(a.user_id),
            "idempotency_key": body.idempotency_key, "effect_on_assurance": "NONE",
        }, {"system": system.id, "consequence": record.id}, record_id=identifier)
        audit(session, a.org_id, a.user_id, "consequence.feedback", row.id)
        return feedback_view(row)


@router.get("/v1/systems/{system_id}/consequences/{consequence_id}/feedback")
def consequence_feedback(system_id: UUID, consequence_id: UUID, a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        system = get_record(session, a.org_id, system_id, "system")
        _, view = consequence(session, a.org_id, system, consequence_id)
        rows = [r for r in _feedback_rows(session, a.org_id, [str(system.id)], limit=500)
                if r.payload["consequence_id"] == view["id"]]
        mine = next((r for r in rows if r.payload["submitted_by"] == str(a.user_id)), None)
        return {"consequence": view, "latest": feedback_view(rows[0]) if rows else None,
                "mine": feedback_view(mine) if mine else None, "history": [feedback_view(r) for r in rows[:50]],
                "principle": "Feedback is recorded beside a consequence. It never changes a claim, a clearance or evidence."}


@router.get("/v1/systems/{system_id}/consequence-feedback")
def system_feedback(system_id: UUID, a: Actor = Depends(actor)):
    """Latest verdict per consequence of one system, for rendering 'Was this right?' state."""
    with transaction(a.user_id, a.org_id) as session:
        system = get_record(session, a.org_id, system_id, "system")
        rows = _feedback_rows(session, a.org_id, [str(system.id)], limit=2000)
        latest = latest_by_consequence(rows)
        mine = latest_by_consequence([r for r in rows if r.payload["submitted_by"] == str(a.user_id)])
        return {"system_id": str(system.id), "consequences": {
            cid: {"latest": row.payload["verdict"], "mine": mine[cid].payload["verdict"] if cid in mine else None,
                  "responses": sum(1 for r in rows if r.payload["consequence_id"] == cid)}
            for cid, row in latest.items()}}


def rate(numerator, denominator):
    return {"numerator": int(numerator), "denominator": int(denominator),
            "value": round(numerator / denominator, 4) if denominator else None}


def precision(rows, mapping=None):
    """Precision with explicit numerators and denominators. NOT_SURE is never a verdict."""
    latest = [r.payload for r in latest_by_consequence(rows).values()]
    counted = [p for p in latest if p.get("counted")]
    decided = [p for p in counted if p["verdict"] != "NOT_SURE"]
    invalidations = [p for p in decided if p["category"] == "INVALIDATION"]
    no_impact = [p for p in decided if p["category"] == "NO_IMPACT"]
    confirm = lambda items: sum(1 for p in items if p["verdict"] in CONFIRMING)  # noqa: E731
    dispute = lambda items: sum(1 for p in items if p["verdict"] == "INCORRECT")  # noqa: E731
    mapping = mapping or {"mapped": 0, "total": 0}
    return {
        "consequences_with_feedback": len(counted), "not_sure": len(counted) - len(decided),
        "excluded_synthetic_or_replayed": len(latest) - len(counted),
        "confirmed_rate": rate(confirm(decided), len(decided)),
        "fully_correct_rate": rate(sum(1 for p in decided if p["verdict"] == "CORRECT"), len(decided)),
        "dispute_rate": rate(dispute(decided), len(decided)),
        "false_invalidation_rate": rate(dispute(invalidations), len(invalidations)),
        "no_impact_confirmation_rate": rate(confirm(no_impact), len(no_impact)),
        "mapped_change_ratio": rate(mapping["mapped"], mapping["total"]),
        "value": {"confirmed_invalidations": confirm(invalidations), "disputed_invalidations": dispute(invalidations),
                  "confirmed_no_impact": confirm(no_impact), "disputed_no_impact": dispute(no_impact)},
    }


def contexts(session, org, systems, *, decided_only=False):
    """One intelligence context per (system, environment), bounded."""
    from .assurance_intelligence import load

    for system in systems[:MAX_SYSTEMS]:
        environments = history(session, org, "environment", system.id)[:MAX_ENVIRONMENTS]
        if decided_only:
            decided = {d.payload["environment_id"] for d in history(session, org, "authorization_decision", system.id)}
            environments = [e for e in environments if str(e.id) in decided]
        for environment in environments:
            yield system, load(session, org, system.id, environment.id)


def _cause_provenance(ctx, cycle):
    if cycle.get("cause") not in CHANGE_CAUSES:
        return None
    if cycle["cause"] != "SOURCE_CHANGE":
        return "CUSTOMER"
    change = next((c for c in ctx.source_changes if str(c.id) == cycle.get("cause_id")), None)
    return provenance(ctx.system, change) if change else None


def _stamp(value):
    return value if isinstance(value, datetime) else datetime.fromisoformat(str(value))


def first_confirmed(session, org, systems, loaded=None):
    """FIRST_CONFIRMED_CONSEQUENCE over real systems, or None. Never synthetic, never replayed."""
    from .assurance_intelligence import cycles

    customer = [s for s in systems if not synthetic(s)]
    if not customer:
        return None
    candidates = []
    row = session.scalars(select(Record).where(
        Record.organization_id == org, Record.kind == "consequence_feedback",
        Record.payload["system_id"].astext.in_([str(s.id) for s in customer]),
        Record.payload["counted"].astext == "true",
        Record.payload["category"].astext.in_(DETERMINATE),
        Record.payload["verdict"].astext.in_(sorted(CONFIRMING))).order_by(Record.created_at).limit(1)).first()
    if row is not None:
        candidates.append({"at": row.created_at, "basis": "CONFIRMED", "system_id": row.payload["system_id"],
                           "consequence_id": row.payload["consequence_id"], "provenance": row.payload["provenance"],
                           "verdict": row.payload["verdict"],
                           "claim_basis": row.payload.get("claim_basis", "EVIDENCED")})
    for system, ctx in (loaded if loaded is not None else contexts(session, org, customer, decided_only=True)):
        if synthetic(system):
            continue
        completed, _ = cycles(ctx)
        for cycle in completed:
            origin = _cause_provenance(ctx, cycle)
            if origin in COUNTED and cycle.get("restore_seconds") is not None \
                    and cycle["restore_seconds"] <= ACT_WINDOW.total_seconds():
                candidates.append({"at": _stamp(cycle["restored_at"]), "basis": "ACTED_REPROOF",
                                   "system_id": str(system.id), "consequence_id": cycle["cause_id"],
                                   "provenance": origin, "verdict": None, "claim_basis": "EVIDENCED"})
    return min(candidates, key=lambda c: c["at"], default=None)


def first_proposed(session, org, systems, *, include_synthetic=False):
    ids = [str(s.id) for s in systems if include_synthetic or not synthetic(s)]
    if not ids:
        return None
    return session.scalars(select(Record).where(
        Record.organization_id == org, Record.kind == "proposed_change_assessment",
        Record.payload["system_id"].astext.in_(ids), Record.payload["mode"].astext == "PROPOSED",
        Record.payload["summary"]["effect"].astext.in_(WOW_EFFECTS)).order_by(Record.created_at).limit(1)).first()


def _times(session, org, kind, system_id, *conditions):
    return sorted(t.astimezone(timezone.utc) for t in session.scalars(select(Record.created_at).where(
        Record.organization_id == org, Record.kind == kind, *conditions,
        Record.payload["system_id"].astext == str(system_id))))


def _reliance(session, org, system):
    sid = str(system.id)
    gate = sorted(t.astimezone(timezone.utc) for t in session.scalars(select(Record.created_at).where(
        Record.organization_id == org, Record.kind == "service_metric",
        Record.payload["name"].astext == "assurance_gate.checked", Record.payload["system"].astext == sid,
        Record.payload["consumer"].astext.like("machine:%"))))
    passports = [str(p.id) for p in history(session, org, "assurance_passport", system.id)]
    external = sorted(t.astimezone(timezone.utc) for t in session.scalars(select(Record.created_at).where(
        Record.organization_id == org, Record.kind == "service_metric",
        Record.payload["name"].astext == "passport.status_checked",
        Record.payload["passport"].astext.in_(passports or [""]))))
    ci = _times(session, org, "github_check_publication", sid)
    ci += _times(session, org, "proposed_change_assessment", sid, Record.payload["consumer"].astext.like("machine:%"))
    return {"MACHINE_GATE_CHECK": gate, "EXTERNAL_PASSPORT_CHECK": external, "CI_CHECK": sorted(ci)}


def _within(times, end, window):
    return any(end - window < t <= end for t in times)


def _maintained(ctx_cycles, end):
    """Clearance current at `end`, or lost within the previous 14 days (being re-established)."""
    for first_allow, losses in ctx_cycles:
        if first_allow is None or first_allow > end:
            continue
        active = [lost for lost, restored in losses if lost <= end and (restored is None or restored > end)]
        if not active or any(end - lost <= REESTABLISH_WINDOW for lost in active):
            return True
    return False


def north_star(session, org, systems, *, weeks=12, at=None, loaded=None):
    """Weekly RPS with its WATCHED and MAINTAINED precursors, for non-synthetic systems only."""
    from .assurance_intelligence import clearance, cycles

    at = at or now()
    ends = [at - timedelta(days=7 * i) for i in range(weeks)][::-1]
    customer = [s for s in systems if not synthetic(s)][:MAX_SYSTEMS]
    by_system = {}
    for system, ctx in (loaded if loaded is not None else contexts(session, org, customer)):
        if synthetic(system):
            continue
        completed, open_cycle = cycles(ctx)
        allows = [d.created_at.astimezone(timezone.utc) for d in ctx.decisions if d.payload["action"] == "ALLOW"]
        losses = [(_stamp(c["lost_at"]), _stamp(c["restored_at"])) for c in completed]
        if open_cycle and open_cycle.get("lost_at"):
            losses.append((_stamp(open_cycle["lost_at"]), None))
        entry = by_system.setdefault(str(system.id), {"cycles": [], "current": []})
        entry["cycles"].append((min(allows) if allows else None, losses))
        entry["current"].append(clearance(ctx)["state"])
    systems_view, weekly = [], [{"week_ending": end.isoformat(), "watched": 0, "maintained": 0, "relied_upon": 0}
                                for end in ends]
    for system in customer:
        sid = str(system.id)
        live = _times(session, org, "source_batch", sid, Record.payload["acquisition"].astext.in_(sorted(LIVE_ACQUISITION)))
        reliance = _reliance(session, org, system)
        relied_times = sorted(t for values in reliance.values() for t in values)
        entry = by_system.get(sid, {"cycles": [], "current": []})
        level = "NONE"
        for index, end in enumerate(ends):
            watched = _within(live, end, WATCH_WINDOW)
            maintained = watched and _maintained(entry["cycles"], end)
            if index == len(ends) - 1 and maintained:
                # The current week also honours present clearance expiry, which the cycle history omits.
                maintained = any(state == "CLEARED" for state in entry["current"]) or _maintained(
                    [(first, [loss for loss in losses if loss[1] is None]) for first, losses in entry["cycles"]], end)
            relied = maintained and _within(relied_times, end, WATCH_WINDOW)
            weekly[index]["watched"] += watched
            weekly[index]["maintained"] += maintained
            weekly[index]["relied_upon"] += relied
            if index == len(ends) - 1:
                level = "RELIED_UPON" if relied else "MAINTAINED" if maintained else "WATCHED" if watched else "NONE"
        systems_view.append({"system_id": sid, "name": system.payload.get("name"), "level": level,
                             "live_source": bool(live), "reliance_events_last_7_days": {
                                 kind: sum(1 for t in values if at - WATCH_WINDOW < t <= at)
                                 for kind, values in reliance.items()}})
    return {"metric": "RPS", "definition": DEFINITIONS["RPS"], "current": weekly[-1]["relied_upon"] if weekly else 0,
            "weekly": weekly, "systems": systems_view,
            "limitations": ["Earlier weeks derive maintenance from the recorded clearance lifecycle; the current week "
                            "also applies present clearance expiry.",
                            "Gate checks are counted at most once per consumer per hour."]}


def mapping_ratio(views_by_system):
    mapped = total = 0
    for system, views in views_by_system:
        if synthetic(system):
            continue
        for view in views:
            if view["kind"] == "SOURCE_CHANGE" and not view.get("initial"):
                total += 1
                mapped += bool(view["mapping"]["fully_mapped"])
    return {"mapped": mapped, "total": total}


def business_summary(session, org):
    """This tenant's truthful business measurement."""
    from .assurance_intelligence import changes

    organization = session.get(Organization, org)
    signup = organization.created_at if organization else None
    systems = list(session.scalars(select(Record).where(Record.organization_id == org, Record.kind == "system")
                                   .order_by(Record.created_at).limit(500)))
    loaded = list(contexts(session, org, systems))
    by_provenance = dict.fromkeys(PROVENANCES, 0)
    views_by_system = []
    for system, ctx in loaded:
        views = [v for v in changes(ctx, limit=200) if not v.get("initial")]
        views_by_system.append((system, views))
        for view in views:
            by_provenance[view_provenance(system, view)] += 1
    for row in session.scalars(select(Record).where(Record.organization_id == org,
                                                    Record.kind == "proposed_change_assessment").limit(5000)):
        system = next((s for s in systems if str(s.id) == row.payload["system_id"]), None)
        if system is not None:
            by_provenance[provenance(system, row)] += 1
    confirmed = first_confirmed(session, org, systems, loaded=loaded)
    proposed = first_proposed(session, org, systems)

    def seconds(stamp):
        return max(0, round((stamp - signup).total_seconds())) if stamp and signup else None

    rows = _feedback_rows(session, org)
    return {
        "schema_version": PROFILE, "as_of": now().isoformat(), "definitions": DEFINITIONS,
        "activation": {
            "event": "FIRST_CONFIRMED_CONSEQUENCE", "reached": confirmed is not None,
            "at": confirmed["at"].isoformat() if confirmed else None,
            "seconds_from_signup": seconds(confirmed["at"]) if confirmed else None,
            "basis": confirmed["basis"] if confirmed else None,
            "provenance": confirmed["provenance"] if confirmed else None,
            "consequence_id": confirmed["consequence_id"] if confirmed else None,
            "system_id": confirmed["system_id"] if confirmed else None,
            "claim_basis": confirmed["claim_basis"] if confirmed else None,
            # The strict reading: an evidence-backed answer about a live or proposed change.
            "qualified": bool(confirmed and confirmed["claim_basis"] == "EVIDENCED"
                              and confirmed["provenance"] in {"LIVE", "PROPOSED"})},
        "time_to_wow": {
            "first_proposed_consequence_at": proposed.created_at.isoformat() if proposed else None,
            "seconds_to_first_proposed_consequence": seconds(proposed.created_at) if proposed else None,
            "seconds_to_first_confirmed_consequence": seconds(confirmed["at"]) if confirmed else None},
        "consequences": {"by_provenance": by_provenance,
                         "counted": sum(by_provenance[p] for p in COUNTED),
                         "never_counted": ["SYNTHETIC", "REPLAYED"]},
        "precision": precision(rows, mapping_ratio(views_by_system)),
        "north_star": north_star(session, org, systems, loaded=loaded),
        "systems": {"customer": sum(1 for s in systems if not synthetic(s)),
                    "synthetic": sum(1 for s in systems if synthetic(s))},
        "limitations": ["Derived from this tenant's records only; no cross-customer aggregation.",
                        "Feedback is a customer judgement recorded beside a consequence; it never alters assurance.",
                        "Synthetic systems and replayed history are shown for transparency and never counted."],
    }


@router.get("/v1/measurements/business")
def get_business(a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        return business_summary(session, a.org_id)
