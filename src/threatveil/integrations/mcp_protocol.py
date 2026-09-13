"""Version-aware Model Context Protocol framing shared by the client, discovery and server.

Two eras exist. `2026-07-28` ("modern") is stateless: every request carries its
protocol version, client identity and capabilities in `_meta`, mirrored into HTTP
headers. `2025-11-25` and earlier ("legacy") establish a session with an
`initialize` handshake. ThreatVeil speaks both during the specification's
twelve-month deprecation window and never falls back silently: an era is
determined by an observed server response, recorded, and reported.

Nothing here grants execution authority. A declared capability, annotation or
cache hint is a server statement, never ThreatVeil evidence.
"""

import base64
import json
from typing import Any

MODERN = "2026-07-28"
LEGACY = "2025-11-25"
SUPPORTED_PROTOCOLS = (MODERN, LEGACY)
ERAS = {MODERN: "MODERN", LEGACY: "LEGACY"}

# Reserved specification sub-range. Only these codes identify a modern server.
HEADER_MISMATCH = -32020
MISSING_CLIENT_CAPABILITY = -32021
UNSUPPORTED_PROTOCOL_VERSION = -32022
MODERN_ERROR_CODES = frozenset({HEADER_MISMATCH, MISSING_CLIENT_CAPABILITY, UNSUPPORTED_PROTOCOL_VERSION})

META_PREFIX = "io.modelcontextprotocol/"
META_PROTOCOL_VERSION = META_PREFIX + "protocolVersion"
META_CLIENT_INFO = META_PREFIX + "clientInfo"
META_CLIENT_CAPABILITIES = META_PREFIX + "clientCapabilities"
META_SERVER_INFO = META_PREFIX + "serverInfo"

CLIENT_INFO = {"name": "threatveil", "version": "0.1.0"}
# Values mirrored into headers so an intermediary can route without parsing a body.
NAMED_METHODS = {"tools/call": "name", "resources/read": "uri", "prompts/get": "name"}
SENTINEL_PREFIX = "=?base64?"
SENTINEL_SUFFIX = "?="
MAX_SSE_EVENTS = 512

# Declared coverage. A parsed field is not a supported feature, and an extension
# ThreatVeil does not implement must never be advertised as negotiated.
FEATURE_SUPPORT = {
    "stateless_per_request_metadata": "SUPPORTED",
    "protocol_version_header": "SUPPORTED",
    "header_body_mirroring": "SUPPORTED",
    "server_discover": "SUPPORTED",
    "tools_list_pagination": "SUPPORTED",
    "cache_hints_ttl_scope": "SUPPORTED",
    "unsupported_version_renegotiation": "SUPPORTED",
    "legacy_initialize_handshake": "SUPPORTED",
    "streamable_http_json_response": "SUPPORTED",
    "streamable_http_sse_response": "PARTIAL",
    "result_type_complete": "SUPPORTED",
    "result_type_input_required": "UNSUPPORTED",
    "multi_round_trip_requests": "UNSUPPORTED",
    "subscriptions_listen": "UNSUPPORTED",
    "tool_x_mcp_header": "PARTIAL",
    "extensions_tasks": "IGNORED",
    "extensions_apps_ui": "IGNORED",
    "enterprise_managed_authorization": "UNKNOWN",
    "client_id_metadata_documents": "UNKNOWN",
    "stdio_transport": "UNSUPPORTED",
    "elicitation_sampling_roots": "UNSUPPORTED",
}


class ProtocolError(ValueError):
    """Raised when a peer response cannot be interpreted under a supported revision."""


def era(version: str) -> str:
    if version not in ERAS:
        raise ProtocolError("Unsupported MCP protocol revision")
    return ERAS[version]


def is_modern(version: str) -> bool:
    return era(version) == "MODERN"


def header_value(value: str) -> str:
    """Encode per the specification's Base64 sentinel rules for header mirroring."""
    plain = (
        value == value.strip()
        and all(0x20 <= ord(character) <= 0x7E for character in value)
        and not (value.startswith(SENTINEL_PREFIX) and value.endswith(SENTINEL_SUFFIX))
    )
    if plain:
        return value
    return SENTINEL_PREFIX + base64.b64encode(value.encode()).decode() + SENTINEL_SUFFIX


def decode_header_value(value: str) -> str:
    if value.startswith(SENTINEL_PREFIX) and value.endswith(SENTINEL_SUFFIX):
        inner = value[len(SENTINEL_PREFIX) : -len(SENTINEL_SUFFIX)]
        try:
            return base64.b64decode(inner, validate=True).decode()
        except (ValueError, UnicodeDecodeError):
            raise ProtocolError("Invalid Base64 header sentinel") from None
    return value


def request_meta(version: str, capabilities: dict | None = None) -> dict:
    """Required per-request protocol metadata. clientCapabilities is mandatory."""
    return {
        META_PROTOCOL_VERSION: version,
        META_CLIENT_INFO: dict(CLIENT_INFO),
        META_CLIENT_CAPABILITIES: dict(capabilities or {}),
    }


def request_body(version: str, method: str, params: dict, request_id: str) -> dict:
    params = dict(params)
    if is_modern(version):
        params["_meta"] = {**request_meta(version), **params.get("_meta", {})}
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def request_headers(version: str, method: str, params: dict, session_id: str | None = None) -> dict:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": version,
    }
    if is_modern(version):
        # Mirrored fields must match the body exactly or the server returns -32020.
        headers["Mcp-Method"] = method
        field = NAMED_METHODS.get(method)
        if field is not None:
            value = params.get(field)
            if not isinstance(value, str):
                raise ProtocolError("Named MCP method requires a string name or uri")
            headers["Mcp-Name"] = header_value(value)
    elif session_id:
        headers["Mcp-Session-Id"] = session_id
    return headers


def _strict_json(raw: bytes | str) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ProtocolError("Duplicate JSON-RPC member")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise ProtocolError("Malformed MCP response") from None


def decode_response(body: bytes, headers: Any, request_id: str) -> dict:
    """Accept a single JSON object or a request-scoped SSE stream, as required."""
    content_type = ""
    if headers:
        items = headers.items() if hasattr(headers, "items") else headers
        content_type = next(
            (str(v) for k, v in items if str(k).lower() == "content-type"), ""
        ).lower()
    if not content_type.startswith("text/event-stream"):
        envelope = _strict_json(body)
        if not isinstance(envelope, dict):
            raise ProtocolError("MCP response must be a JSON object")
        return envelope
    try:
        text = body.decode()
    except UnicodeDecodeError:
        raise ProtocolError("MCP event stream is not UTF-8") from None
    final, events = None, 0
    for block in text.replace("\r\n", "\n").split("\n\n"):
        events += 1
        if events > MAX_SSE_EVENTS:
            raise ProtocolError("MCP event stream exceeded its bounded event count")
        data = "\n".join(
            line[5:].lstrip(" ") for line in block.split("\n") if line.startswith("data:")
        )
        if not data.strip():
            continue
        message = _strict_json(data)
        # Progress and logging notifications precede the final response; ignore them.
        if isinstance(message, dict) and message.get("id") == request_id and (
            "result" in message or "error" in message
        ):
            final = message
    if final is None:
        raise ProtocolError("MCP event stream carried no response for this request")
    return final


def modern_error(envelope: Any) -> dict | None:
    """Return a recognized specification error, which identifies a modern server."""
    if not isinstance(envelope, dict):
        return None
    error = envelope.get("error")
    if isinstance(error, dict) and error.get("code") in MODERN_ERROR_CODES:
        return error
    return None


def negotiable_version(error: dict) -> str | None:
    """Choose a mutually supported revision from an UnsupportedProtocolVersionError."""
    if error.get("code") != UNSUPPORTED_PROTOCOL_VERSION:
        return None
    data = error.get("data")
    offered = data.get("supported") if isinstance(data, dict) else None
    if not isinstance(offered, list):
        return None
    for candidate in SUPPORTED_PROTOCOLS:
        if candidate in offered:
            return candidate
    return None


def result_of(envelope: dict, request_id: str) -> dict:
    """Validate identity and completeness. An interim result is not a catalog."""
    if envelope.get("jsonrpc") != "2.0" or envelope.get("id") != request_id:
        raise ProtocolError("MCP response protocol or identity mismatch")
    if "error" in envelope:
        raise ProtocolError("MCP server returned an error response")
    result = envelope.get("result")
    if not isinstance(result, dict):
        raise ProtocolError("MCP result must be an object")
    # Absent resultType means "complete" on servers implementing earlier revisions.
    kind = result.get("resultType", "complete")
    if kind == "input_required":
        raise ProtocolError("Multi round-trip input is not supported by this read-only client")
    if kind != "complete":
        raise ProtocolError("Unrecognized MCP resultType")
    return result


def cache_hint(result: dict) -> tuple[int, str | None]:
    """Freshness hint only. It never extends the validity of security evidence."""
    ttl = result.get("ttlMs")
    if isinstance(ttl, bool) or not isinstance(ttl, int):
        ttl = 0
    ttl = max(0, min(ttl, 2**53 - 1))
    scope = result.get("cacheScope")
    return ttl, scope if scope in {"public", "private"} else None
