"""Bounded, tenant-filtered keyset pages over immutable workspace records."""

import base64
import json
from datetime import datetime
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import and_, func, or_, select

from .db import Record

COLLECTIONS = {
    "systems": "system",
    "properties": "property",
    "findings": "finding",
    "targets": "target",
    "runs": "run",
    "fixes": "fix",
    "baselines": "baseline",
    "gauntlet": "gauntlet",
    "gauntlets": "gauntlet",
}


def cursor_for(row):
    return base64.urlsafe_b64encode(
        json.dumps([row.created_at.isoformat(), str(row.id)]).encode()
    ).decode()


def page(
    session,
    org_id,
    kind,
    limit=200,
    cursor=None,
    query=None,
    system_id=None,
    approved=None,
    extra_conditions=(),
):
    if not 1 <= limit <= 200:
        raise HTTPException(422, "Page size must be between 1 and 200")
    conditions = [Record.organization_id == org_id, Record.kind == kind, *extra_conditions]
    if system_id:
        conditions.append(Record.payload["system_id"].astext == str(system_id))
    if approved is not None:
        conditions.append(Record.payload["approved"].astext == str(approved).lower())
    if query:
        if len(query) > 160:
            raise HTTPException(422, "Search text is too long")
        conditions.append(
            or_(
                *[
                    Record.payload[key].astext.icontains(query, autoescape=True)
                    for key in ("name", "title", "description", "version")
                ]
            )
        )
    total = session.scalar(select(func.count()).select_from(Record).where(*conditions))
    if cursor:
        try:
            if len(cursor) > 512:
                raise ValueError()
            stamp, identifier = json.loads(base64.urlsafe_b64decode(cursor))
            stamp, identifier = datetime.fromisoformat(stamp), UUID(identifier)
            if stamp.tzinfo is None:
                raise ValueError()
        except (ValueError, TypeError, json.JSONDecodeError):
            raise HTTPException(422, "Invalid page cursor") from None
        conditions.append(
            or_(Record.created_at < stamp, and_(Record.created_at == stamp, Record.id < identifier))
        )
    rows = list(
        session.scalars(
            select(Record)
            .where(*conditions)
            .order_by(Record.created_at.desc(), Record.id.desc())
            .limit(limit + 1)
        )
    )
    more = len(rows) > limit
    rows = rows[:limit]
    return rows, {
        "total": total,
        "limit": limit,
        "returned": len(rows),
        "next_cursor": cursor_for(rows[-1]) if more else None,
        "ordering": "created_at DESC, id DESC",
    }
