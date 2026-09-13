"""Read-only MCP tools/list capture and conservative contract comparison.

Uses the existing authorized transport and version-aware negotiation. Listing a
tool grants no execution authority, and server annotations remain untrusted.
Cache hints describe freshness only; they never extend evidence validity.
"""

import json
from typing import Any

from pydantic import Field

from threatveil.core.contracts import Contract, FingerprintComponent, SystemFingerprint, digest

from .intake import (
    MAX_BYTES,
    IntakeContext,
    NormalizedIntake,
    array_value,
    bounded_document,
    component_id,
    object_value,
    text_value,
)
from .mcp_protocol import SUPPORTED_PROTOCOLS, ERAS, ProtocolError, cache_hint

MCP_LIMITATIONS = (
    "Tool descriptions, schemas and annotations are server declarations, not security evidence.",
    "Catalog comparison detects contract changes; compatibility requires reviewed policy.",
    "Authorization metadata does not prove effective permissions or a granted authority.",
)
# Protocol envelope fields. They describe transport freshness and result framing,
# never the tool contract, so they must stay outside the catalog identity digest.
CACHE_FIELDS = ("ttlMs", "cacheScope")
RESULT_ENVELOPE_FIELDS = {"tools", "nextCursor", "resultType", "_meta", *CACHE_FIELDS}


class MCPToolSnapshot(Contract):
    server_id: str = Field(min_length=1, max_length=200)
    protocol_version: str = Field(min_length=1, max_length=50)
    server_info: dict[str, Any] = Field(default_factory=dict)
    capabilities: dict[str, Any] = Field(default_factory=dict)
    catalog_metadata: dict[str, Any] = Field(default_factory=dict)
    tools: tuple[dict[str, Any], ...] = ()
    authorization: dict[str, Any] | None = None
    complete: bool = False
    supported_versions: tuple[str, ...] = ()
    cache_ttl_ms: int | None = Field(default=None, ge=0)
    cache_scope: str | None = None
    fingerprint: SystemFingerprint
    catalog_digest: str
    limitations: tuple[str, ...] = MCP_LIMITATIONS

    @property
    def era(self) -> str:
        return ERAS.get(self.protocol_version, "UNKNOWN")


def capture_mcp_tools(payload: dict, ctx: IntakeContext | None = None) -> MCPToolSnapshot:
    """Capture a tools/list result or an explicitly complete joined catalog.

    Accepted wrapper: server_id, protocol_version, server_info, capabilities,
    tools, authorization, complete. A raw JSON-RPC result may be supplied as
    result, but pagination completeness must still be declared by the caller.
    """
    bounded_document(payload)
    ctx = ctx or IntakeContext()
    server_id = text_value(payload.get("server_id", ctx.source_id), "MCP server_id", limit=200)
    protocol = text_value(
        payload.get("protocol_version", "UNKNOWN"), "MCP protocol_version", limit=50
    )
    if "error" in payload:
        raise ValueError("MCP error responses cannot be catalog snapshots")
    body = object_value(payload.get("result", payload), "MCP tools/list result")
    tools, seen = [], set()
    for raw in array_value(body.get("tools"), "MCP tools", limit=1000):
        tool = object_value(raw, "MCP tool")
        name = text_value(tool.get("name"), "MCP tool name", limit=128)
        if name in seen:
            raise ValueError("Duplicate MCP tool name")
        seen.add(name)
        schema = object_value(tool.get("inputSchema"), "MCP inputSchema")
        if schema.get("type") not in (None, "object"):
            raise ValueError("MCP inputSchema must describe an object")
        for field in ("outputSchema", "annotations", "execution", "_meta"):
            if field in tool:
                object_value(tool[field], f"MCP {field}")
        for field in ("description", "title"):
            if field in tool and not isinstance(tool[field], str):
                raise ValueError(f"MCP {field} must be a string")
        # Preserve ALL fields, including extension metadata and prompt-affecting
        # descriptions. Omitting fields from identity can hide a relevant change.
        tools.append(json.loads(json.dumps(tool, allow_nan=False)))
    tools.sort(key=lambda t: t["name"])
    declared_complete = payload.get("complete", False)
    if not isinstance(declared_complete, bool):
        raise ValueError("MCP catalog completeness must be an explicit boolean")
    cursor = body.get("nextCursor")
    if cursor is not None:
        text_value(cursor, "MCP nextCursor", limit=2048)
    complete = declared_complete and cursor is None
    if declared_complete and cursor is not None:
        raise ValueError("A paginated MCP result cannot claim a complete catalog")
    info = object_value(payload.get("server_info", {}), "MCP server_info")
    capabilities = object_value(payload.get("capabilities", {}), "MCP capabilities")
    # Cache hints may arrive on the raw result or on an explicit wrapper. They are
    # freshness metadata: recorded beside the catalog, never inside its identity.
    hint_source = {k: v for k, v in body.items() if k in CACHE_FIELDS}
    hint_source.update({k: v for k, v in payload.items() if k in CACHE_FIELDS})
    ttl_ms, cache_scope = cache_hint(hint_source) if hint_source else (None, None)
    supported = payload.get("supported_versions", [])
    if not isinstance(supported, list) or not all(isinstance(v, str) for v in supported):
        raise ValueError("MCP supported_versions must be a list of strings")
    supported = tuple(text_value(v, "MCP supported version", limit=50) for v in supported[:50])
    reserved = {
        "server_id",
        "protocol_version",
        "server_info",
        "capabilities",
        "authorization",
        "complete",
        "catalog_metadata",
        "supported_versions",
        "cache_ttl_ms",
        "cache_scope",
        "era",
        "result",
        "jsonrpc",
        "id",
        "tools",
        "nextCursor",
        *CACHE_FIELDS,
    }
    metadata = dict(object_value(payload.get("catalog_metadata", {}), "MCP catalog_metadata"))
    for label, extras in (
        (
            "result",
            {
                k: v
                for k, v in body.items()
                if k not in (reserved if body is payload else RESULT_ENVELOPE_FIELDS)
            },
        ),
        (
            "envelope",
            {k: v for k, v in payload.items() if k not in reserved} if body is not payload else {},
        ),
    ):
        if extras:
            if label in metadata and digest(metadata[label]) != digest(extras):
                raise ValueError("Conflicting MCP catalog metadata")
            metadata[label] = extras
    authorization = payload.get("authorization")
    if authorization is not None:
        object_value(authorization, "MCP authorization")
    material = {
        "protocol_version": protocol,
        "server_info": info,
        "capabilities": capabilities,
        "catalog_metadata": metadata,
        "tools": tools,
        "authorization": authorization,
    }
    catalog_digest = digest(material)
    limits = list(MCP_LIMITATIONS)
    if not complete:
        limits.append("Catalog is incomplete; absent tools cannot be interpreted as removals.")
    if protocol == "UNKNOWN":
        limits.append("MCP protocol version was not captured.")
    elif protocol not in SUPPORTED_PROTOCOLS:
        limits.append("MCP protocol revision has not been validated by this adapter.")
    if authorization is None:
        limits.append("Effective authorization configuration was not captured.")
    if ttl_ms is None:
        limits.append("The server supplied no cache hint; catalog freshness is unknown.")
    elif ttl_ms == 0:
        limits.append("The server declared this catalog immediately stale.")
    if cache_scope == "public":
        limits.append(
            "A public cache scope means this catalog is not specific to the presented authorization."
        )
    components = [
        FingerprintComponent(
            type="mcp",
            id=server_id,
            version=None if protocol == "UNKNOWN" else protocol,
            digest=catalog_digest,
            provenance="OBSERVED" if complete and protocol in SUPPORTED_PROTOCOLS else "UNKNOWN",
        )
    ]
    for tool in tools:
        components.append(
            FingerprintComponent(
                type="tool",
                id=component_id(f"{server_id}:{tool['name']}"),
                digest=digest(tool),
                provenance="OBSERVED",
                dependencies=(f"mcp:{server_id}", f"permissions:{server_id}"),
            )
        )
    components.append(
        FingerprintComponent(
            type="permissions",
            id=server_id,
            digest=digest(authorization) if authorization is not None else None,
            provenance="DECLARED" if authorization is not None else "UNKNOWN",
        )
    )
    return MCPToolSnapshot(
        server_id=server_id,
        protocol_version=protocol,
        server_info=info,
        capabilities=capabilities,
        catalog_metadata=metadata,
        tools=tuple(tools),
        authorization=authorization,
        complete=complete,
        supported_versions=supported,
        cache_ttl_ms=ttl_ms,
        cache_scope=cache_scope,
        fingerprint=SystemFingerprint(components=tuple(components)),
        catalog_digest=catalog_digest,
        limitations=tuple(limits),
    )


def normalize_mcp_tools(payload: dict, ctx: IntakeContext) -> NormalizedIntake:
    snapshot = capture_mcp_tools(payload, ctx)
    return NormalizedIntake(
        format="mcp_tools",
        source_digest=digest(payload),
        fingerprint=snapshot.fingerprint,
        details={"snapshot": snapshot.model_dump(mode="json")},
        limitations=snapshot.limitations,
    )


def _changed_paths(before: Any, after: Any, path: str = "") -> list[str]:
    if digest(before) == digest(after):
        return []
    if isinstance(before, dict) and isinstance(after, dict):
        result = []
        for key in sorted(before.keys() | after.keys()):
            pointer = path + "/" + key.replace("~", "~0").replace("/", "~1")
            if key not in before or key not in after:
                result.append(pointer)
            else:
                result.extend(_changed_paths(before[key], after[key], pointer))
        return result
    # Array order is preserved conservatively, including unfamiliar schema keywords.
    return [path or "/"]


def diff_mcp_tools(previous: MCPToolSnapshot | dict, candidate: MCPToolSnapshot | dict) -> dict:
    before, after = (
        MCPToolSnapshot.model_validate(previous),
        MCPToolSnapshot.model_validate(candidate),
    )
    if before.server_id != after.server_id:
        raise ValueError("MCP catalog comparison requires the same server identity")
    # Serialized snapshots are not trusted: rebuild and verify their derived fields.
    for snapshot in (before, after):
        rebuilt = capture_mcp_tools(
            snapshot.model_dump(
                mode="json",
                exclude={"schema_version", "fingerprint", "catalog_digest", "limitations"},
            )
        )
        if (
            rebuilt.catalog_digest != snapshot.catalog_digest
            or rebuilt.fingerprint != snapshot.fingerprint
        ):
            raise ValueError("MCP snapshot derived fingerprint does not match its catalog")
    old, new = ({t["name"]: t for t in s.tools} for s in (before, after))
    changes = []
    for name in sorted(old.keys() | new.keys()):
        if name not in old:
            changes.append(
                {
                    "tool": name,
                    "kind": "ADDED" if before.complete else "PREVIOUSLY_UNOBSERVED",
                    "paths": ["/"],
                }
            )
        elif name not in new:
            changes.append(
                {
                    "tool": name,
                    "kind": "REMOVED" if after.complete else "NOT_OBSERVED",
                    "paths": ["/"],
                }
            )
        elif digest(old[name]) != digest(new[name]):
            changes.append(
                {"tool": name, "kind": "CHANGED", "paths": _changed_paths(old[name], new[name])}
            )
    metadata = _changed_paths(
        {
            "protocol": before.protocol_version,
            "supported_versions": list(before.supported_versions),
            "info": before.server_info,
            "capabilities": before.capabilities,
            "catalog_metadata": before.catalog_metadata,
            "authorization": before.authorization,
        },
        {
            "protocol": after.protocol_version,
            "supported_versions": list(after.supported_versions),
            "info": after.server_info,
            "capabilities": after.capabilities,
            "catalog_metadata": after.catalog_metadata,
            "authorization": after.authorization,
        },
    )
    unknown = (
        not before.complete
        or not after.complete
        or any(
            version not in SUPPORTED_PROTOCOLS
            for version in (before.protocol_version, after.protocol_version)
        )
    )
    return {
        "algorithm_version": "mcp-contract-diff-v2",
        "server_id": before.server_id,
        "previous_digest": before.catalog_digest,
        "candidate_digest": after.catalog_digest,
        "previous_era": before.era,
        "candidate_era": after.era,
        "status": "UNKNOWN" if unknown else "CHANGED" if changes or metadata else "UNCHANGED",
        "changes": changes,
        "metadata_paths": metadata,
        # Freshness is reported beside the comparison; a cache hint is never a verdict.
        "candidate_cache_ttl_ms": after.cache_ttl_ms,
        "candidate_cache_scope": after.cache_scope,
        "requires_review": bool(changes or metadata or unknown),
        "limitations": list(dict.fromkeys(before.limitations + after.limitations)),
    }


def _json_response(body: bytes) -> dict:
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON-RPC response member")
            result[key] = value
        return result

    return bounded_document(json.loads(body, object_pairs_hook=no_duplicates))


async def discover_mcp_tools(adapter, *, server_id: str, max_pages: int = 20) -> MCPToolSnapshot:
    """Discover through a prepared MCPAdapter and its already-authorized transport.

    Does not expand target origins, credential scopes, allowed tool calls, or
    accepted protocol revisions. The adapter establishes the era; this function
    never chooses a protocol. Pagination is bounded and aborts on ambiguity.
    """
    if adapter.context is None:
        raise ValueError("MCP discovery requires a prepared, authorized adapter")
    if not isinstance(max_pages, int) or isinstance(max_pages, bool) or not 1 <= max_pages <= 20:
        raise ValueError("MCP discovery page limit must be between 1 and 20")
    tools, cursors, cursor, size = [], set(), None, 0
    ttl_values: list[int] = []
    scopes: set[str] = set()
    for page in range(max_pages):
        request_id = f"{adapter.context.correlation_id}:tools-list:{page}"
        try:
            result = await adapter.request_json(
                "tools/list", {"cursor": cursor} if cursor else {}, request_id
            )
        except ProtocolError as error:
            raise ValueError(f"MCP discovery response protocol/identity mismatch: {error}") from None
        size += len(json.dumps(result, allow_nan=False).encode())
        if size > MAX_BYTES:
            raise ValueError("MCP discovery failed or exceeded the bounded catalog size")
        page_ttl, page_scope = cache_hint(result)
        ttl_values.append(page_ttl)
        if page_scope is not None:
            scopes.add(page_scope)
        # The specification requires one scope for every page of a list request.
        if len(scopes) > 1:
            raise ValueError("MCP catalog pages declared conflicting cache scopes")
        tools.extend(array_value(result.get("tools"), "MCP tools", limit=1000))
        if len(tools) > 1000:
            raise ValueError("MCP discovery exceeds 1000 tools")
        cursor = result.get("nextCursor")
        if cursor is None:
            return capture_mcp_tools(
                {
                    "server_id": server_id,
                    "protocol_version": adapter.protocol_version,
                    "server_info": getattr(adapter, "server_info", {}),
                    "capabilities": getattr(adapter, "server_capabilities", {}),
                    "supported_versions": list(getattr(adapter, "supported_versions", ())),
                    "tools": tools,
                    "complete": True,
                    # The least fresh page bounds the freshness of the joined catalog.
                    "ttlMs": min(ttl_values),
                    **({"cacheScope": next(iter(scopes))} if scopes else {}),
                }
            )
        text_value(cursor, "MCP nextCursor", limit=2048)
        if cursor in cursors:
            raise ValueError("MCP discovery repeated a pagination cursor")
        cursors.add(cursor)
    raise ValueError("MCP discovery exceeded the page limit; catalog is incomplete")
