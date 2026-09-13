"""Bounded remote MCP JSON-RPC adapter. No stdio/process execution.

Speaks the stateless `2026-07-28` revision by default and falls back to the
`2025-11-25` handshake only when a server demonstrably requires it. The era is
established by an observed response, never assumed, and an unrecognized revision
fails closed rather than degrading to a weaker protocol.
"""

import json

from threatveil.core.contracts import Observation
from threatveil.integrations.mcp_protocol import (
    LEGACY,
    MODERN,
    SUPPORTED_PROTOCOLS,
    ProtocolError,
    cache_hint,
    decode_response,
    era,
    is_modern,
    modern_error,
    negotiable_version,
    request_body,
    request_headers,
    result_of,
)

from .base import AdapterCapabilities, Stimulus
from .http import HTTPAgentAdapter


class MCPAdapter(HTTPAgentAdapter):
    capabilities = AdapterCapabilities(
        id="mcp-remote",
        version="2.0",
        input_modalities=("tool_call",),
        action_types=("DIGITAL_TOOL_ACTION",),
        state_sources=("structured_tool_result",),
        reset_capability="CUSTOMER_RESET",
        side_effect_class="DIGITAL_ONLY",
        observation_coverage=("tool_result_only",),
        execution_mode="DIGITAL_STAGING",
        authority_model="Approved tools only; customer account authority",
    )

    def __init__(self, transport, allowed_tools: tuple[str, ...], *, preferred: str = MODERN):
        super().__init__(transport)
        if not allowed_tools:
            raise ValueError("MCP requires an explicit tool allowlist")
        if preferred not in SUPPORTED_PROTOCOLS:
            raise ValueError("Preferred MCP revision is not implemented by this adapter")
        self.allowed_tools = frozenset(allowed_tools)
        self.preferred = preferred
        self.protocol_version = preferred
        self.era: str | None = None
        self._session_id: str | None = None
        self._initialized = False
        self.server_info: dict = {}
        self.server_capabilities: dict = {}
        self.supported_versions: tuple[str, ...] = ()
        self.cache_ttl_ms: int | None = None
        self.cache_scope: str | None = None

    def _headers(self, method: str = "tools/call", params: dict | None = None) -> dict[str, str]:
        return request_headers(self.protocol_version, method, params or {}, self._session_id)

    async def _post(self, method: str, params: dict, request_id: str):
        body = json.dumps(
            request_body(self.protocol_version, method, params, request_id), allow_nan=False
        ).encode()
        if len(body) > 262144:
            raise ValueError("MCP request exceeds 256 KiB")
        return await self.transport.request(
            "POST",
            self.context.endpoint_url,
            body=body,
            headers=self._headers(method, params),
        )

    async def request_json(self, method: str, params: dict, request_id: str) -> dict:
        """Send one bounded request under the negotiated era and return its result."""
        if not self._initialized:
            await self._negotiate()
        response = await self._post(method, params, request_id)
        if response.status_code != 200 or len(response.body) > 1048576:
            raise RuntimeError(f"MCP request failed with HTTP {response.status_code}")
        return result_of(decode_response(response.body, response.headers, request_id), request_id)

    async def _negotiate(self) -> None:
        """Probe modern first; fall back only on a response that is not modern."""
        if self.context is None:
            raise ValueError("MCP negotiation requires a prepared, authorized adapter")
        if is_modern(self.preferred):
            await self._discover(f"{self.context.correlation_id}:server-discover", retry=True)
        else:
            self.protocol_version = self.preferred
        # A server that answered discovery with only a legacy revision, or that is
        # not modern at all, still needs the handshake before any other request.
        if not self._initialized:
            await self._initialize()

    async def _discover(self, request_id: str, *, retry: bool) -> None:
        response = await self._post("server/discover", {}, request_id)
        if response.status_code not in (200, 400, 404, 405):
            raise RuntimeError(f"MCP discovery failed with HTTP {response.status_code}")
        try:
            envelope = decode_response(response.body, response.headers, request_id)
        except ProtocolError:
            envelope = None
        # A handshake-era server answers an unknown method with a JSON-RPC error,
        # commonly under HTTP 200. Only a recognized specification code is modern.
        if response.status_code == 200 and isinstance(envelope, dict) and "error" not in envelope:
            self._accept_discovery(result_of(envelope, request_id))
            return
        error = modern_error(envelope)
        if error is None:
            # Not a recognized modern error: this is a legacy server. Fall back.
            self.protocol_version = LEGACY
            return
        chosen = negotiable_version(error)
        if chosen is None:
            raise ProtocolError("MCP server supports no revision implemented by this adapter")
        self.protocol_version = chosen
        if is_modern(chosen) and retry:
            await self._discover(request_id + ":retry", retry=False)

    def _accept_discovery(self, result: dict) -> None:
        offered = result.get("supportedVersions")
        if not isinstance(offered, list) or not all(isinstance(v, str) for v in offered):
            raise ProtocolError("MCP discovery must list the server's supported versions")
        chosen = next((v for v in SUPPORTED_PROTOCOLS if v in offered), None)
        if chosen is None:
            raise ProtocolError("MCP server supports no revision implemented by this adapter")
        if not is_modern(chosen):
            # The server answered a modern probe but only serves a legacy revision.
            self.protocol_version = chosen
            return
        capabilities = result.get("capabilities")
        if not isinstance(capabilities, dict):
            raise ProtocolError("MCP discovery must report structured capabilities")
        if "tools" not in capabilities:
            raise ValueError("MCP server does not declare tool support")
        meta = result.get("_meta") if isinstance(result.get("_meta"), dict) else {}
        info = meta.get("io.modelcontextprotocol/serverInfo", {})
        self.server_info = info if isinstance(info, dict) else {}
        self.server_capabilities = capabilities
        self.supported_versions = tuple(v for v in offered if isinstance(v, str))[:50]
        self.protocol_version = chosen
        self.cache_ttl_ms, self.cache_scope = cache_hint(result)
        self.era = era(chosen)
        self._initialized = True

    async def _initialize(self) -> None:
        """Legacy handshake, retained for the specification's deprecation window."""
        if self._initialized:
            return
        if is_modern(self.protocol_version):
            self.protocol_version = LEGACY
        request_id = f"{self.context.correlation_id}:initialize"
        response = await self.transport.request(
            "POST",
            self.context.endpoint_url,
            body=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": self.protocol_version,
                        "capabilities": {},
                        "clientInfo": {"name": "threatveil", "version": "0.1.0"},
                    },
                }
            ).encode(),
            headers=self._headers("initialize"),
        )
        if response.status_code != 200 or len(response.body) > 1048576:
            raise RuntimeError("MCP initialization failed or exceeded bounds")
        result = json.loads(response.body)
        if result.get("id") != request_id or result.get("error"):
            raise ValueError("MCP initialization protocol/identity mismatch")
        negotiated = result.get("result", {}).get("protocolVersion")
        if negotiated not in SUPPORTED_PROTOCOLS or is_modern(negotiated):
            raise ValueError("MCP initialization protocol/identity mismatch")
        self.protocol_version = negotiated
        if "tools" not in result.get("result", {}).get("capabilities", {}):
            raise ValueError("MCP server does not declare tool support")
        info = result["result"].get("serverInfo", {})
        capabilities = result["result"].get("capabilities", {})
        if not isinstance(info, dict) or not isinstance(capabilities, dict):
            raise ValueError("MCP server metadata must be structured objects")
        self.server_info, self.server_capabilities = info, capabilities
        self.supported_versions = (negotiated,)
        session = next(
            (v for k, v in response.headers.items() if k.lower() == "mcp-session-id"), None
        )
        if session and (len(session) > 512 or not all(33 <= ord(c) <= 126 for c in session)):
            raise ValueError("Invalid MCP session header")
        self._session_id = session
        response = await self.transport.request(
            "POST",
            self.context.endpoint_url,
            body=json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode(),
            headers=self._headers("notifications/initialized"),
        )
        if response.status_code not in (200, 202, 204):
            raise RuntimeError("MCP initialized notification rejected")
        self.era = era(self.protocol_version)
        self._initialized = True

    async def stimulate(self, stimulus: Stimulus) -> None:
        if self.context is None or stimulus.correlation_id != self.context.correlation_id:
            raise ValueError("Unprepared or unrelated MCP stimulus")
        if stimulus.type != "tool_call" or stimulus.payload.get("name") not in self.allowed_tools:
            raise ValueError("MCP tool is not explicitly authorized")
        if set(stimulus.payload) - {"name", "arguments"}:
            raise ValueError("Unsupported MCP stimulus fields")
        if not isinstance(stimulus.payload.get("arguments", {}), dict):
            raise ValueError("MCP tool arguments must be an object")
        result = await self.request_json(
            "tools/call", dict(stimulus.payload), stimulus.correlation_id
        )
        if result.get("isError"):
            raise ValueError("MCP error or response identity mismatch")
        content = result.get("structuredContent", {})
        if isinstance(content, dict) and "observation" in content:
            self._observation = Observation.model_validate(content["observation"])
            if self._observation.correlation_id != stimulus.correlation_id:
                raise ValueError("MCP observation correlation mismatch")
        else:
            self._observation = Observation(
                correlation_id=stimulus.correlation_id,
                limitations=("MCP tool output alone does not prove a committed side effect.",),
            )

    async def cleanup(self) -> None:
        await super().cleanup()
        self._session_id, self._initialized, self.era = None, False, None
        self.protocol_version = self.preferred
        self.server_info, self.server_capabilities = {}, {}
        self.supported_versions = ()
        self.cache_ttl_ms, self.cache_scope = None, None
