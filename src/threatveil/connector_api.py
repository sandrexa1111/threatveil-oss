"""Connector control plane: read-source installation, collection, import and health."""

import asyncio
from datetime import datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field
from sqlalchemy import select

from .auth import SECURITY, Actor, actor, require
from .connectors import (
    authorize, configuration, create_installation, ingest, installation_health, persist_batch,
    previous_batch, reconfigure, record_failure, replay,
)
from .connectors.collectors import (
    SourceFailure, collect_cloud_run, collect_mcp, github_snapshot,
)
from .connectors.contracts import BatchInput, Role, manifests
from .core.contracts import digest
from .credentials import read_reference
from .db import Record, get_record, now, serialize, transaction
from .schemas import Input
from .workspace_reads import page


router = APIRouter(prefix="/v1/connectors", tags=["connectors"])


class InstallationInput(Input):
    system_id: UUID
    environment_id: UUID
    connector_id: str = Field(min_length=1, max_length=40)
    mode: Literal["IMPORT", "POLL", "PUSH"]
    roles: list[Role] = Field(min_length=1, max_length=8)
    name: str = Field(min_length=1, max_length=120)
    configuration: dict[str, Any] = Field(default_factory=dict)
    credential_id: UUID | None = None
    expires_at: datetime


class ConfigurationInput(Input):
    configuration: dict[str, Any] = Field(default_factory=dict)
    credential_id: UUID | None = None
    expires_at: datetime
    active: bool = True
    reason: str = Field(min_length=10, max_length=2000)


class CollectInput(Input):
    event_id: str = Field(min_length=8, max_length=120)


@router.get("/catalog")
def catalog(a: Actor = Depends(actor)):
    return {"items": [item.model_dump(mode="json") for item in manifests().values()]}


class DefinitionPreviewInput(Input):
    # A supported format, or "auto" for deterministic detection.
    format: str = Field(min_length=1, max_length=40)
    document: Any
    # Only ever used to settle a tie between formats the structure already fits.
    filename: str | None = Field(default=None, max_length=200)


# Which ecosystem a format itself establishes. A model string, a host or a tool name
# never establishes a vendor, so nothing here is derived from content values.
FORMAT_ECOSYSTEM = {"claude_settings": ["claude_code"], "claude_subagent": ["claude_code"], "mcp_json": ["mcp"],
                    "langgraph": ["langgraph"], "crewai": ["crewai"], "manifest": [], "mcp_tools": ["mcp"]}


@router.post("/definition-preview")
def definition_preview(body: DefinitionPreviewInput, a: Actor = Depends(actor)):
    """What ThreatVeil can deterministically establish from a declared definition.

    Read-only and non-persisting: it parses with the same adapter the import path uses
    and returns the bounded facts, so onboarding can show what was detected before any
    system, environment or source exists. It writes nothing, records nothing, and
    establishes nothing — a definition file is declared configuration, never proof of
    what is running, and this endpoint cannot change that.

    With format "auto" the format is detected deterministically first. An ambiguous or
    unsupported document returns only the detection result, so the caller asks rather
    than guesses.
    """
    require(a)
    from .agent_definitions import ADAPTERS, MCP_CATALOG, DefinitionError, detect_format, parse_text, snapshot

    fmt, document, detection = body.format, body.document, None
    try:
        if fmt == "auto":
            detection = detect_format(document, body.filename)
            if detection["status"] != "DETECTED":
                return {"detection": detection}
            fmt, document = detection["format"], parse_text(document)
        if fmt == MCP_CATALOG:
            from .connectors.collectors import imported_snapshot

            document = parse_text(document)
            if not isinstance(document, dict):
                raise DefinitionError("An MCP tool catalog must be a JSON object")
            found = imported_snapshot("mcp", document, "preview", now())
            return {
                "format": MCP_CATALOG, "detection": detection, "agents": [], "models": [], "mcp_servers": [],
                "tools": found.facts.get("tool_names") or [], "protocol_version": found.facts.get("protocol_version"),
                "components": sorted(found.components), "complete": found.complete, "unknown": [],
                "ignored_fields": [], "limitations": list(found.limitations), "ecosystem": ["mcp"],
            }
        found = snapshot({"format": fmt, "document": document}, "preview")
        declared = ADAPTERS[fmt](document)
    except DefinitionError as error:
        raise HTTPException(422, str(error)) from None  # content-free by construction
    except (ValueError, TypeError, KeyError, RecursionError, HTTPException):
        # Never echo customer configuration back in an error.
        raise HTTPException(422, "That definition could not be read in the selected format") from None
    facts = found.facts
    parts = facts.get("definition_parts") or {}
    authorization = declared.get("authorization") or {}
    agents = authorization.get("agents") or {}
    permissions = authorization.get("permissions")
    servers = facts.get("mcp_servers") or []
    return {
        "format": facts.get("definition_format"),
        "detection": detection,
        "agents": parts.get("agents") or [],
        "tools": facts.get("tool_names") or [],
        "mcp_servers": servers,
        # Advertised in the file; never proof of the model that runs.
        "models": sorted({c["version"] for key, c in found.components.items()
                          if key.startswith("model:") and c.get("version")}),
        "permissions": {key: (permissions.get(key) or [])[:100] for key in ("allow", "deny", "ask")}
        | {"default_mode": permissions.get("default_mode")} if isinstance(permissions, dict) else None,
        "inherits_all_tools": sorted(name for name, spec in agents.items() if spec.get("tools") == "INHERITED_ALL"),
        "delegation": sorted(name for name, spec in agents.items() if spec.get("allow_delegation") is True),
        "code_execution": sorted(name for name, spec in agents.items() if spec.get("allow_code_execution") is True),
        "approval_required": sorted(tool for tool, conditions in (authorization.get("tools") or {}).items()
                                    if isinstance(conditions, dict) and conditions.get("approval_required") is True),
        "ecosystem": FORMAT_ECOSYSTEM.get(fmt, []) + (["mcp"] if servers and "mcp" not in FORMAT_ECOSYSTEM.get(fmt, []) else []),
        "components": sorted(found.components),
        "complete": found.complete,
        "unknown": facts.get("unknown") or [],
        "ignored_fields": parts.get("ignored_fields") or [],
        "limitations": list(found.limitations),
    }


@router.post("", status_code=201)
def install(body: InstallationInput, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        result = create_installation(
            session, a.org_id, a.user_id, system_id=body.system_id,
            environment_id=body.environment_id, connector_id=body.connector_id,
            mode=body.mode, roles=body.roles, values=body.configuration,
            credential_id=body.credential_id, expires_at=body.expires_at, name=body.name,
        )
        return {**serialize(result), "health": installation_health(session, a.org_id, result)}


@router.get("")
def installations(system_id: UUID | None = None, limit: int = Query(default=25, ge=1, le=200),
                  cursor: str | None = Query(default=None, max_length=512),
                  a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        if system_id:
            get_record(session, a.org_id, system_id, "system")
        rows, pagination = page(
            session, a.org_id, "connector_installation", limit, cursor, system_id=system_id,
        )
        return {"items": [
            {**serialize(item), "health": installation_health(session, a.org_id, item)}
            for item in rows
        ], "pagination": pagination}


@router.get("/{installation_id}")
def read_installation(installation_id: UUID, a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        item = get_record(session, a.org_id, installation_id, "connector_installation")
        current = configuration(session, a.org_id, item)
        return {**serialize(item), "configuration": serialize(current),
                "health": installation_health(session, a.org_id, item)}


@router.post("/{installation_id}/configuration", status_code=201)
def update_configuration(installation_id: UUID, body: ConfigurationInput,
                         a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        return serialize(reconfigure(
            session, a.org_id, a.user_id, installation_id, values=body.configuration,
            credential_id=body.credential_id, expires_at=body.expires_at,
            active=body.active, reason=body.reason,
        ))


@router.get("/{installation_id}/history")
def history(installation_id: UUID, kind: Literal[
    "source_batch", "source_change", "source_health", "source_assertion", "connector_configuration"
] = "source_change", limit: int = Query(default=25, ge=1, le=200),
            a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        get_record(session, a.org_id, installation_id, "connector_installation")
        rows = session.scalars(select(Record).where(
            Record.organization_id == a.org_id, Record.kind == kind,
            Record.payload["installation_id"].astext == str(installation_id),
        ).order_by(Record.created_at.desc(), Record.id.desc()).limit(limit))
        return {"items": [serialize(item) for item in rows], "limit": limit}


def _ingest(installation_id, body, a, telemetry):
    require(a)
    with transaction(a.user_id, a.org_id) as session:
        try:
            return serialize(ingest(session, a.org_id, a.user_id, installation_id, body,
                                    telemetry=telemetry))
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            raise HTTPException(422, "Malformed or unsupported source batch; no records created") from None


@router.post("/{installation_id}/import", status_code=201)
def import_source(installation_id: UUID, body: BatchInput, a: Actor = Depends(actor)):
    return _ingest(installation_id, body, a, False)


@router.post("/{installation_id}/telemetry", status_code=201)
def telemetry_source(installation_id: UUID, body: BatchInput, a: Actor = Depends(actor)):
    return _ingest(installation_id, body, a, True)


@router.post("/{installation_id}/collect")
def collect_source(installation_id: UUID, body: CollectInput, a: Actor = Depends(actor)):
    require(a, SECURITY)
    # One transaction holds the installation lock for a bounded read. Configuration
    # cannot change beneath a collected snapshot, and other installations remain independent.
    with transaction(a.user_id, a.org_id) as session:
        installation, current = authorize(session, a.org_id, installation_id, mode="POLL")
        identity = digest({"event_id": body.event_id, "configuration_id": str(current.id)})
        existing = replay(session, a.org_id, installation_id, body.event_id, identity)
        if existing:
            return {"status": "RECORDED", "batch": serialize(existing),
                    "health": installation_health(session, a.org_id, installation)}
        previous = previous_batch(session, a.org_id, installation_id)
        latest_health = session.scalar(select(Record).where(
            Record.organization_id == a.org_id, Record.kind == "source_health",
            Record.payload["installation_id"].astext == str(installation_id),
        ).order_by(Record.created_at.desc()).limit(1))
        if latest_health and latest_health.created_at > now() - timedelta(seconds=10):
            raise HTTPException(429, "Connector collection interval is ten seconds")
        values = current.payload["configuration"]
        kind = installation.payload["connector_id"]
        try:
            if kind == "mcp":
                from .api import authorized_target
                target = authorized_target(session, a.org_id, values["target_id"])
                target_payload = {**target.payload, "discovery_path": values["path"]}
                headers = {}
                refs = target.payload.get("credential_reference_ids", [])
                if refs:
                    headers["Authorization"] = "Bearer " + read_reference(
                        get_record(session, a.org_id, refs[0], "credential")
                    )

                def recheck():
                    with transaction(a.user_id, a.org_id) as check:
                        authorized_target(check, a.org_id, values["target_id"])

                snapshot = asyncio.run(collect_mcp(
                    target_payload, source_identity=installation.payload["source_identity"],
                    headers=headers, recheck=recheck,
                ))
                authorized_target(session, a.org_id, values["target_id"])
            else:
                token = read_reference(get_record(
                    session, a.org_id, current.payload["credential_id"], "credential",
                ))
                snapshot = (github_snapshot(values, token) if kind == "github"
                            else collect_cloud_run(values, token))
            batch = persist_batch(
                session, a.org_id, installation, current, event_id=body.event_id,
                request_digest=identity, snapshot=snapshot, valid_at=now(),
                acquisition="API_OBSERVED", reconciled=True, actor_id=a.user_id,
            )
        except SourceFailure as exc:
            record_failure(session, a.org_id, installation, current, exc.code)
            return {"status": exc.code, "batch": None,
                    "health": installation_health(session, a.org_id, installation)}
        except (ValueError, RuntimeError, TimeoutError, OSError, HTTPException):
            # No upstream payload, endpoint credentials, headers or exception details are exposed.
            record_failure(session, a.org_id, installation, current, "UNAVAILABLE")
            return {"status": "UNAVAILABLE", "batch": None,
                    "health": installation_health(session, a.org_id, installation)}
        return {"status": "RECORDED", "batch": serialize(batch),
                "health": installation_health(session, a.org_id, installation),
                "previous_batch_id": str(previous.id) if previous else None}
