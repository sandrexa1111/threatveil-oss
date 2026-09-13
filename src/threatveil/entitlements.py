"""Plan allowances count approved property families, never draft or history rows."""

from fastapi import HTTPException
from sqlalchemy import select

from .db import Account, Record

def property_limit(plan):
    from .config import settings

    configured = settings().commercial_plans.get(plan)
    if configured:
        return configured.properties
    # Unrecognized/custom plans need an explicit product configuration, not unlimited access.
    from .commercial import plan_version

    # Compatibility helper for old callers. Tenant-aware checks below always use
    # the frozen subscription version and overrides through the central service.
    legacy = {"unassigned": 20, "pilot": 20, "starter": 20, "growth": 100, "pro": 500}
    if plan in legacy:
        return legacy[plan]
    try:
        return plan_version(plan)["entitlements"]["approved_property_limit"]
    except HTTPException:
        return 0


def property_records(session, org_id):
    return list(session.scalars(select(Record).where(
        Record.organization_id == org_id, Record.kind == "property"
    )))


def family_id(record, by_id):
    seen = set()
    while record.payload.get("supersedes_id") in by_id:
        parent = by_id[record.payload["supersedes_id"]]
        if (parent.payload.get("system_id") != record.payload.get("system_id")
                or parent.payload.get("propagated_from") != record.payload.get("propagated_from")):
            break
        if record.id in seen:
            raise HTTPException(409, "Property lineage cannot contain a cycle")
        seen.add(record.id)
        record = parent
    return str(record.id)


def property_usage(session, org_id, account=None, allowance=None):
    account = account or session.get(Account, org_id)
    rows = property_records(session, org_id)
    by_id = {str(row.id): row for row in rows}
    active = {family_id(row, by_id) for row in rows if row.payload.get("approved")}
    from .commercial import entitlements

    limit = allowance if allowance is not None else entitlements(session, org_id)["approved_property_limit"]
    return {"active_properties": len(active), "property_limit": limit,
            "remaining_properties": max(0, limit - len(active)),
            "property_allowance_basis": "Approved property families; drafts and retained versions do not consume additional slots."}


def require_property_capacity(session, org_id, draft=None):
    """Serialize approvals and billing changes on one tenant account row.

    Return an existing approved version for a repeated draft approval. This both
    avoids duplicate immutable approvals and prevents a concurrent cap bypass.
    """
    from .commercial import entitlements

    limit = entitlements(session, org_id)["approved_property_limit"]
    rows = property_records(session, org_id)
    by_id = {str(row.id): row for row in rows}
    approved = [row for row in rows if row.payload.get("approved")]
    if draft:
        family = family_id(draft, by_id)
        existing = [row for row in approved if family_id(row, by_id) == family]
        repeated = [row for row in existing if row.payload.get("supersedes_id") == str(draft.id)]
        if repeated:
            return max(repeated, key=lambda row: row.created_at)
        if existing:
            return None
    active = {family_id(row, by_id) for row in approved}
    if len(active) >= limit:
        from .commercial import _limit_error

        _limit_error("approved_properties", len(active), limit, org_id, session.get(Account, org_id).plan)
    return None
