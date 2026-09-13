"""Tenant-owned connector installations and append-only source continuity.

The database is the serialization boundary. Source data cannot choose tenant,
issuer, qualification, positive evidence, deployment authority or policy action.
"""

import re
from datetime import datetime, timedelta
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import select

from ..core.contracts import digest
from ..db import Record, add_record, get_record, now, serialize
from .contracts import PROFILE, BatchInput, Role, Snapshot, manifests


def _query(session, org_id, kind, installation_id=None):
    statement = select(Record).where(Record.organization_id == org_id, Record.kind == kind)
    if installation_id is not None:
        statement = statement.where(Record.payload["installation_id"].astext == str(installation_id))
    return statement.order_by(Record.created_at.desc(), Record.id.desc())


def _latest(session, org_id, kind, installation_id):
    return session.scalar(_query(session, org_id, kind, installation_id).limit(1))


def _lock(session, org_id, installation_id):
    installation = get_record(session, org_id, installation_id, "connector_installation")
    session.scalar(select(Record).where(
        Record.organization_id == org_id, Record.id == installation.id,
    ).with_for_update())
    return installation


def configuration(session, org_id, installation):
    return _latest(session, org_id, "connector_configuration", installation.id)


def scope(session, org_id, system_id, environment_id):
    get_record(session, org_id, system_id, "system")
    environment = get_record(session, org_id, environment_id, "environment")
    if environment.payload.get("system_id") != str(system_id):
        raise HTTPException(422, "Connector environment belongs to another system")


def _entitled(session, org_id, connector_id, roles):
    from ..commercial import _limit_error, can_use_connector_role
    from ..db import Account

    for role in roles:
        if not can_use_connector_role(session, org_id, connector_id, str(role)):
            _limit_error(f"connector.{connector_id}.{str(role).lower()}", 0, 0,
                         org_id, session.get(Account, org_id).plan)


def validate_configuration(kind, mode, values, credential_id):
    allowed = {
        "github": {"repository", "repository_id", "ref"},
        "mcp": {"target_id", "path"},
        "gcp_cloud_run": {"service"},
    }.get(kind, set())
    if set(values) - allowed:
        raise HTTPException(422, "Unsupported connector configuration field")
    if kind == "github":
        if set(values) != allowed or not re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", str(values.get("repository", ""))
        ) or any(part in {".", ".."} for part in values["repository"].split("/")):
            raise HTTPException(422, "Exact GitHub repository and ref configuration required")
        if not re.fullmatch(r"[1-9][0-9]{0,19}", str(values["repository_id"])):
            raise HTTPException(422, "Exact GitHub numeric repository ID required")
        ref = values["ref"]
        if not isinstance(ref, str) or not re.fullmatch(r"refs/heads/[A-Za-z0-9_./-]{1,200}", ref):
            raise HTTPException(422, "GitHub connector supports one explicit branch ref")
        if ".." in ref or "//" in ref or ref.endswith(("/", ".")):
            raise HTTPException(422, "Invalid GitHub branch ref")
        values = {**values, "repository_id": str(values["repository_id"])}
    if kind == "gcp_cloud_run":
        if set(values) != allowed or not re.fullmatch(
            r"projects/[a-zA-Z0-9-]+/locations/[a-z0-9-]+/services/[a-z][a-z0-9-]{0,62}",
            str(values.get("service", "")),
        ):
            raise HTTPException(422, "Exact GCP Cloud Run service resource name required")
    if kind == "mcp" and mode == "POLL":
        if set(values) != allowed:
            raise HTTPException(422, "MCP collection requires a verified target and exact path")
        if credential_id:
            raise HTTPException(422, "MCP credentials come only from the verified target binding")
    if mode == "POLL" and kind in {"github", "gcp_cloud_run"} and not credential_id:
        raise HTTPException(422, "A tenant-owned read credential reference is required")
    if mode != "POLL" and credential_id:
        raise HTTPException(422, "Import/push installations do not use external credentials")
    return values


def create_installation(session, org_id, user_id, *, system_id, environment_id,
                        connector_id, mode, roles, values, credential_id, expires_at, name):
    scope(session, org_id, system_id, environment_id)
    manifest = manifests().get(connector_id)
    if not manifest or mode not in manifest.modes:
        raise HTTPException(422, "Unsupported connector or acquisition mode")
    selected = tuple(Role(value) for value in roles)
    if not selected or len(set(selected)) != len(selected) or set(selected) - set(manifest.installation_roles):
        raise HTTPException(422, "Requested role is not implemented by this installation path")
    _entitled(session, org_id, connector_id, selected)
    if expires_at.tzinfo is None or not now() < expires_at <= now() + timedelta(days=90):
        raise HTTPException(422, "Connector authorization must expire within 90 days")
    values = validate_configuration(connector_id, mode, values, credential_id)
    references = {"system": system_id, "environment": environment_id}
    if credential_id:
        get_record(session, org_id, credential_id, "credential")
        references["credential"] = credential_id
    if connector_id == "mcp" and mode == "POLL":
        target = get_record(session, org_id, values["target_id"], "target")
        if target.payload["system_id"] != str(system_id) or target.payload["adapter"] != "mcp":
            raise HTTPException(422, "MCP target must belong to this system")
        if values["path"] not in target.payload["paths"] or "POST" not in target.payload["methods"]:
            raise HTTPException(422, "MCP discovery path is outside the target authorization")
        references["target"] = target.id
    installation_id = uuid4()
    installation = add_record(session, org_id, "connector_installation", {
        "schema_version": PROFILE, "installation_id": str(installation_id),
        "system_id": str(system_id), "environment_id": str(environment_id),
        "name": name, "connector_id": connector_id, "connector_version": manifest.version,
        "mode": mode, "roles": [role.value for role in selected],
        "source_identity": "source:" + str(installation_id),
        "manifest": manifest.model_dump(mode="json"), "created_by": str(user_id),
        "data_class": "PRIVATE_CUSTOMER_DATA", "cross_customer_use": False,
    }, references, record_id=installation_id)
    add_record(session, org_id, "connector_configuration", {
        "schema_version": PROFILE, "installation_id": str(installation_id),
        "system_id": str(system_id), "environment_id": str(environment_id),
        "configuration": values, "credential_id": str(credential_id) if credential_id else None,
        "expires_at": expires_at.isoformat(), "active": True, "configured_by": str(user_id),
        "configuration_digest": digest({"values": values, "credential_id": str(credential_id),
                                        "expires_at": expires_at.isoformat()}),
    }, {"installation": installation_id, **references})
    return installation


def authorize(session, org_id, installation_id, *, role=None, mode=None):
    installation = _lock(session, org_id, installation_id)
    current = configuration(session, org_id, installation)
    if not current or not current.payload["active"]:
        raise HTTPException(403, "Connector authorization is revoked")
    if datetime.fromisoformat(current.payload["expires_at"]) <= now():
        raise HTTPException(403, "Connector authorization expired")
    if role and role not in installation.payload["roles"]:
        raise HTTPException(403, "Connector installation lacks the requested role")
    if mode and installation.payload["mode"] != mode:
        raise HTTPException(422, "Connector acquisition mode does not support this operation")
    _entitled(session, org_id, installation.payload["connector_id"], installation.payload["roles"])
    return installation, current


def reconfigure(session, org_id, user_id, installation_id, *, values, credential_id,
                expires_at, active, reason):
    installation = _lock(session, org_id, installation_id)
    old = configuration(session, org_id, installation)
    if expires_at.tzinfo is None or not now() < expires_at <= now() + timedelta(days=90):
        raise HTTPException(422, "Connector authorization must expire within 90 days")
    values = validate_configuration(
        installation.payload["connector_id"], installation.payload["mode"], values, credential_id,
    )
    refs = {"installation": installation_id, "previous_configuration": old.id}
    if credential_id:
        get_record(session, org_id, credential_id, "credential")
        refs["credential"] = credential_id
    if installation.payload["connector_id"] == "mcp" and installation.payload["mode"] == "POLL":
        target = get_record(session, org_id, values["target_id"], "target")
        if target.payload["system_id"] != installation.payload["system_id"] or target.payload["adapter"] != "mcp":
            raise HTTPException(422, "MCP target must belong to this system")
        if values["path"] not in target.payload["paths"] or "POST" not in target.payload["methods"]:
            raise HTTPException(422, "MCP path outside target scope")
        refs["target"] = target.id
    current = add_record(session, org_id, "connector_configuration", {
        **old.payload, "configuration": values,
        "credential_id": str(credential_id) if credential_id else None,
        "expires_at": expires_at.isoformat(), "active": active,
        "configured_by": str(user_id), "reason": reason,
        "configuration_digest": digest({"values": values, "credential_id": str(credential_id),
                                        "expires_at": expires_at.isoformat(), "active": active}),
    }, refs)
    prior = _latest(session, org_id, "source_batch", installation_id)
    changed = sorted((prior.payload.get("components") or {}).keys()) if prior else []
    add_record(session, org_id, "source_change", {
        "schema_version": PROFILE, "installation_id": str(installation_id),
        "system_id": installation.payload["system_id"],
        "environment_id": installation.payload["environment_id"],
        "source_identity": installation.payload["source_identity"],
        "change_kind": "CONNECTOR_CONFIGURATION", "transition": "OBSERVED",
        "acquisition": "DECLARED", "qualification": "UNREVIEWED",
        "before_digest": old.payload["configuration_digest"],
        "after_digest": current.payload["configuration_digest"],
        "changed_components": changed + ["connector_configuration:" + str(installation_id)],
        "valid_at": now().isoformat(), "recorded_at": now().isoformat(),
        "continuity": "UNKNOWN", "requires_reassessment": True,
        "limitations": ["Connector credential/scope changes require fresh reconciliation."],
    }, {"installation": installation_id, "configuration": current.id})
    record_failure(session, org_id, installation, current, "CONFIGURATION_CHANGED")
    return current


def record_failure(session, org_id, installation, current, code):
    return add_record(session, org_id, "source_health", {
        "schema_version": PROFILE, "installation_id": str(installation.id),
        "system_id": installation.payload["system_id"],
        "environment_id": installation.payload["environment_id"],
        "configuration_id": str(current.id), "status": code,
        "valid_at": now().isoformat(), "recorded_at": now().isoformat(),
        "continuity": "UNKNOWN", "connected": False,
        "limitations": ["No empty successful snapshot was inferred from source failure."],
    }, {"installation": installation.id, "configuration": current.id})


def previous_batch(session, org_id, installation_id):
    return session.scalar(_query(session, org_id, "source_batch", installation_id).where(
        Record.payload["projects_current"].astext == "true",
    ).limit(1))


def replay(session, org_id, installation_id, event_id, request_digest):
    previous = session.scalar(_query(session, org_id, "source_batch", installation_id).where(
        Record.payload["event_id"].astext == event_id,
    ).limit(1))
    if previous and previous.payload["request_digest"] != request_digest:
        raise HTTPException(409, "Source event ID reused with different content")
    return previous


def persist_batch(session, org_id, installation, current, *, event_id, request_digest,
                  snapshot: Snapshot, valid_at, acquisition, sequence=None,
                  cursor=None, previous_cursor=None, reconciled=False, actor_id=None):
    """Only trusted call sites select acquisition/reconciled; no public snapshot endpoint."""
    installation = _lock(session, org_id, installation.id)
    if configuration(session, org_id, installation).id != current.id:
        raise HTTPException(409, "Connector configuration changed during acquisition")
    if not current.payload["active"] or datetime.fromisoformat(current.payload["expires_at"]) <= now():
        raise HTTPException(403, "Connector authorization expired or was revoked")
    old = replay(session, org_id, installation.id, event_id, request_digest)
    if old:
        return old
    if valid_at.tzinfo is None or valid_at > now() + timedelta(seconds=30):
        raise HTTPException(422, "Source event time is in the future or lacks timezone")
    expected_acquisition = {"IMPORT": "IMPORTED", "POLL": "API_OBSERVED", "PUSH": "INSTRUMENTED"}
    if acquisition != expected_acquisition[installation.payload["mode"]]:
        raise HTTPException(422, "Source acquisition does not match installation")
    if reconciled and acquisition != "API_OBSERVED":
        raise HTTPException(422, "Only server collection can reconcile source snapshots")
    prior = previous_batch(session, org_id, installation.id)
    same_config = prior and prior.payload["configuration_id"] == str(current.id)
    old_payload = prior.payload if same_config else {}
    reordered = bool(old_payload and (
        valid_at < datetime.fromisoformat(old_payload["valid_at"])
        or sequence is not None and old_payload.get("sequence") is not None
        and sequence <= old_payload["sequence"]
    ))
    gap = bool(old_payload and (
        sequence is not None and old_payload.get("sequence") is not None
        and sequence > old_payload["sequence"] + 1
        or previous_cursor is not None and previous_cursor != old_payload.get("cursor")
        or old_payload.get("cursor") is not None and previous_cursor is None
        or old_payload.get("sequence") is not None and sequence is None
    ))
    if reconciled and snapshot.complete and not reordered:
        continuity = "SNAPSHOT_RECONCILED"
    elif reordered:
        continuity = old_payload.get("continuity", "UNKNOWN")
    elif gap or old_payload.get("continuity") == "CURSOR_GAP":
        continuity = "CURSOR_GAP"
    elif not snapshot.complete:
        continuity = "PARTIAL"
    else:
        continuity = "IMPORTED_SNAPSHOT" if acquisition == "IMPORTED" else "UNKNOWN"
    # Partial observations never remove assets. They can still introduce facts/changes.
    old_components = old_payload.get("components", {})
    components = snapshot.components if snapshot.complete else {**old_components, **snapshot.components}
    changed = sorted(key for key in old_components.keys() | components.keys()
                     if digest(old_components.get(key)) != digest(components.get(key)))
    base = {
        "schema_version": PROFILE, "installation_id": str(installation.id),
        "system_id": installation.payload["system_id"],
        "environment_id": installation.payload["environment_id"],
        "configuration_id": str(current.id),
        "source_identity": installation.payload["source_identity"],
        "source_version": snapshot.source_version,
        "mapping_version": snapshot.mapping_version,
        "acquisition": acquisition, "qualification": "UNREVIEWED",
        "valid_at": valid_at.isoformat(), "recorded_at": now().isoformat(),
        "sequence": sequence, "cursor": cursor, "previous_cursor": previous_cursor,
        "continuity": continuity, "complete": snapshot.complete,
        "limitations": list(snapshot.limitations), "data_class": "PRIVATE_CUSTOMER_DATA",
        "cross_customer_use": False, "running_state_proven": False,
    }
    batch = add_record(session, org_id, "source_batch", {
        **base, "event_id": event_id, "request_digest": request_digest,
        "components": components, "facts": snapshot.facts,
        "snapshot_digest": digest(snapshot), "projects_current": not reordered,
        "delivery": "REORDERED" if reordered else "ACCEPTED", "actor_id": str(actor_id),
    }, {"installation": installation.id, "configuration": current.id})
    add_record(session, org_id, "source_assertion", {
        **base, "subject": installation.payload["system_id"],
        "predicate": "connector_snapshot", "batch_id": str(batch.id),
        "component_keys": sorted(snapshot.components), "snapshot_digest": digest(snapshot),
        "authority_basis": "Unreviewed source assertion; qualification is fact-specific",
    }, {"installation": installation.id, "batch": batch.id})
    if changed or gap:
        add_record(session, org_id, "source_change", {
            **base, "batch_id": str(batch.id), "transition": "OBSERVED",
            "change_kind": "SOURCE_GAP" if gap else "COMPONENT_CHANGE",
            "before_digest": old_payload.get("snapshot_digest"),
            "after_digest": digest(snapshot), "changed_components": changed,
            "before_batch_id": str(prior.id) if same_config else None,
            "requires_reassessment": True, "projects_current": not reordered,
            "prevented": False,
        }, {"installation": installation.id, "batch": batch.id})
    # Reordered data is retained without replacing the last reconciled watermarks.
    if not reordered:
        add_record(session, org_id, "source_health", {
            **base, "batch_id": str(batch.id),
            "status": "CURRENT" if continuity == "SNAPSHOT_RECONCILED" else continuity,
            "connected": acquisition != "IMPORTED",
        }, {"installation": installation.id, "batch": batch.id})
    return batch


def ingest(session, org_id, user_id, installation_id, body: BatchInput, *, telemetry=False):
    from .collectors import imported_snapshot

    installation, current = authorize(
        session, org_id, installation_id, role="OBSERVE" if telemetry else None,
        mode="PUSH" if telemetry else "IMPORT",
    )
    identity = digest(body.model_dump(mode="json"))
    existing = replay(session, org_id, installation.id, body.event_id, identity)
    if existing:
        return existing
    snapshot = imported_snapshot(
        installation.payload["connector_id"], body.payload,
        installation.payload["source_identity"], body.valid_at,
    )
    if installation.payload["connector_id"] == "gcp_cloud_run":
        if snapshot.facts["service"] != current.payload["configuration"]["service"]:
            raise HTTPException(422, "Imported Cloud Run service is outside the configured boundary")
    return persist_batch(
        session, org_id, installation, current, event_id=body.event_id,
        request_digest=identity, snapshot=snapshot, valid_at=body.valid_at,
        acquisition="INSTRUMENTED" if telemetry else "IMPORTED", sequence=body.sequence,
        cursor=body.cursor, previous_cursor=body.previous_cursor, actor_id=user_id,
    )


def installation_health(session, org_id, installation, *, at=None):
    at = at or now()
    current = configuration(session, org_id, installation)
    health = _latest(session, org_id, "source_health", installation.id)
    batch = previous_batch(session, org_id, installation.id)
    payload = health.payload if health else {}
    lifetime = min(item["freshness_seconds"] for item in installation.payload["manifest"]["roles"]
                   if item["role"] in installation.payload["roles"])
    status = payload.get("status", "DECLARED")
    freshness = "UNKNOWN"
    same_config = batch and batch.payload["configuration_id"] == str(current.id)
    if not current.payload["active"]:
        status = "REVOKED"
    elif datetime.fromisoformat(current.payload["expires_at"]) <= at:
        status = "EXPIRED"
    elif same_config:
        expires = datetime.fromisoformat(batch.payload["valid_at"]) + timedelta(seconds=lifetime)
        freshness = "CURRENT" if at < expires else "STALE"
        if freshness == "STALE":
            status = "STALE"
    if status in {"REVOKED", "EXPIRED", "CONFIGURATION_CHANGED", "UNAUTHORIZED", "UNAVAILABLE",
                  "PARTIAL", "INVALID_RESPONSE", "RATE_LIMITED", "CURSOR_GAP"}:
        freshness = "UNKNOWN"
    imported = installation.payload["mode"] == "IMPORT"
    return {
        "schema_version": PROFILE, "installation_id": str(installation.id),
        "system_id": installation.payload["system_id"],
        "environment_id": installation.payload["environment_id"],
        "connector_id": installation.payload["connector_id"], "name": installation.payload["name"],
        "source_identity": installation.payload["source_identity"],
        "status": "IMPORTED" if imported and status not in {"EXPIRED", "REVOKED"} else status,
        "freshness": freshness, "connected": bool(
            not imported and payload.get("connected")
            and status in {"CURRENT", "PARTIAL", "UNKNOWN", "CURSOR_GAP"}
            and datetime.fromisoformat(payload["recorded_at"]) + timedelta(seconds=lifetime) > at
        ), "continuity": payload.get("continuity", "UNKNOWN"),
        "qualification": "UNREVIEWED", "running_state_proven": False,
        "last_valid_at": batch.payload["valid_at"] if same_config else None,
        "last_recorded_at": batch.payload["recorded_at"] if same_config else None,
        "watermark": {key: batch.payload.get(key) for key in ("sequence", "cursor")} if same_config else None,
        "component_keys": sorted(batch.payload["components"]) if same_config else [],
        "max_age_seconds": lifetime, "configuration_id": str(current.id),
        "failure": status if status in {"UNAVAILABLE", "UNAUTHORIZED", "INVALID_RESPONSE", "RATE_LIMITED"} else None,
        "limitations": installation.payload["manifest"]["limitations"] + payload.get("limitations", []),
    }


def source_health(session, org_id, system_id, environment_id):
    scope(session, org_id, system_id, environment_id)
    rows = session.scalars(_query(session, org_id, "connector_installation").where(
        Record.payload["system_id"].astext == str(system_id),
        Record.payload["environment_id"].astext == str(environment_id),
    ))
    return [installation_health(session, org_id, row) for row in rows]


def source_changes(session, org_id, system_id, environment_id, *, limit=200):
    scope(session, org_id, system_id, environment_id)
    rows = session.scalars(_query(session, org_id, "source_change").where(
        Record.payload["system_id"].astext == str(system_id),
        Record.payload["environment_id"].astext == str(environment_id),
    ).limit(min(max(limit, 1), 1000)))
    return [serialize(row) for row in rows]
