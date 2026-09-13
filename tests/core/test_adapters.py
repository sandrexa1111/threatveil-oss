import asyncio
import json

import pytest

from threatveil.adapters import (
    AdapterContext,
    HTTPAgentAdapter,
    MCPAdapter,
    OpenAICompatibleAdapter,
    Stimulus,
    StructuredTraceAdapter,
    TransportResponse,
)
from threatveil.core import canonical_property, evaluate_trace
from threatveil.core.procurement import _trial
from threatveil.core.variants import bounded_variants
from threatveil.sdk import Trace


class FakeTransport:
    def __init__(self, body, status=200):
        self.body, self.status, self.requests = body, status, []

    async def request(self, method, url, *, body=None, headers=None):
        self.requests.append((method, url, body, headers))
        return TransportResponse(self.status, json.dumps(self.body).encode(), {})


def test_http_adapter_injects_transport_and_validates_correlation():
    observation = _trial("fixed", bounded_variants()[0])
    transport = FakeTransport(observation.model_dump(mode="json"))
    adapter = HTTPAgentAdapter(transport)

    async def scenario():
        context = AdapterContext(
            "https://registered.example/test", "DIGITAL_STAGING", observation.correlation_id
        )
        await adapter.prepare(context)
        await adapter.stimulate(
            Stimulus(
                type="structured_input",
                payload={"invoice": "synthetic"},
                correlation_id=observation.correlation_id,
            )
        )
        result = await adapter.observe()
        assert result.correlation_id == observation.correlation_id
        assert evaluate_trace(canonical_property(), result)["security_verdict"] == "INCONCLUSIVE"
        assert transport.requests[0][:2] == ("POST", context.endpoint_url)
        await adapter.cleanup()
        with pytest.raises(ValueError):
            await adapter.observe()

    asyncio.run(scenario())


def test_recorded_trace_does_not_verify_current_boundary():
    observation = _trial("fixed", bounded_variants()[0])

    async def scenario():
        adapter = StructuredTraceAdapter()
        await adapter.prepare(
            AdapterContext("recorded", "RECORDED_REPLAY", observation.correlation_id)
        )
        await adapter.stimulate(
            Stimulus(
                type="structured_input",
                payload=observation.model_dump(mode="json"),
                correlation_id=observation.correlation_id,
            )
        )
        assert (await adapter.observe()).boundary_mocked

    asyncio.run(scenario())


def test_mcp_rejects_unapproved_tools_without_network():
    transport = FakeTransport({})

    async def scenario():
        adapter = MCPAdapter(transport, ("approved_tool",))
        await adapter.prepare(
            AdapterContext("https://registered.example/mcp", "DIGITAL_STAGING", "run-1")
        )
        with pytest.raises(ValueError):
            await adapter.stimulate(
                Stimulus(
                    type="tool_call", payload={"name": "execute_shell"}, correlation_id="run-1"
                )
            )
        assert not transport.requests

    asyncio.run(scenario())


def test_mcp_falls_back_to_the_handshake_and_keeps_tool_output_non_authoritative():
    class MCPTransport:
        def __init__(self):
            self.methods = []

        async def request(self, method, url, *, body=None, headers=None):
            payload = json.loads(body)
            self.methods.append(payload["method"])
            if payload["method"] == "server/discover":
                # A handshake-era server does not implement discovery.
                error = {
                    "jsonrpc": "2.0",
                    "id": payload["id"],
                    "error": {"code": -32601, "message": "Method not found"},
                }
                return TransportResponse(200, json.dumps(error).encode(), {})
            if payload["method"] == "initialize":
                result = {
                    "jsonrpc": "2.0",
                    "id": payload["id"],
                    "result": {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}},
                }
                return TransportResponse(
                    200, json.dumps(result).encode(), {"Mcp-Session-Id": "session-1"}
                )
            assert headers["Mcp-Session-Id"] == "session-1"
            if payload["method"] == "notifications/initialized":
                return TransportResponse(202, b"", {})
            result = {
                "jsonrpc": "2.0",
                "id": payload["id"],
                "result": {"content": [{"type": "text", "text": "Done"}]},
            }
            return TransportResponse(200, json.dumps(result).encode(), {})

    transport = MCPTransport()

    async def scenario():
        adapter = MCPAdapter(transport, ("approved_tool",))
        await adapter.prepare(
            AdapterContext("https://registered.example/mcp", "DIGITAL_STAGING", "run-1")
        )
        await adapter.stimulate(
            Stimulus(
                type="tool_call",
                payload={"name": "approved_tool", "arguments": {}},
                correlation_id="run-1",
            )
        )
        assert transport.methods == [
            "server/discover",
            "initialize",
            "notifications/initialized",
            "tools/call",
        ]
        assert adapter.era == "LEGACY" and adapter.protocol_version == "2025-11-25"
        assert not (await adapter.observe()).witnesses
        await adapter.cleanup()
        assert adapter._initialized is False and adapter.protocol_version == "2026-07-28"

    asyncio.run(scenario())


def test_mcp_uses_the_stateless_revision_with_mirrored_headers_and_no_session():
    class ModernTransport:
        def __init__(self):
            self.methods, self.headers = [], []

        async def request(self, method, url, *, body=None, headers=None):
            payload = json.loads(body)
            self.methods.append(payload["method"])
            self.headers.append(dict(headers or {}))
            if payload["method"] == "server/discover":
                result = {
                    "resultType": "complete",
                    "supportedVersions": ["2026-07-28"],
                    "capabilities": {"tools": {}},
                    "_meta": {
                        "io.modelcontextprotocol/serverInfo": {"name": "erp", "version": "3"}
                    },
                    "ttlMs": 3600000,
                    "cacheScope": "public",
                }
            else:
                assert payload["method"] == "tools/call"
                result = {
                    "resultType": "complete",
                    "content": [{"type": "text", "text": "Done"}],
                    "isError": False,
                }
            envelope = {"jsonrpc": "2.0", "id": payload["id"], "result": result}
            return TransportResponse(
                200, json.dumps(envelope).encode(), {"Content-Type": "application/json"}
            )

    transport = ModernTransport()

    async def scenario():
        adapter = MCPAdapter(transport, ("approved_tool",))
        await adapter.prepare(
            AdapterContext("https://registered.example/mcp", "DIGITAL_STAGING", "run-1")
        )
        await adapter.stimulate(
            Stimulus(
                type="tool_call",
                payload={"name": "approved_tool", "arguments": {}},
                correlation_id="run-1",
            )
        )
        assert transport.methods == ["server/discover", "tools/call"]
        assert adapter.era == "MODERN" and adapter.protocol_version == "2026-07-28"
        call = transport.headers[-1]
        assert call["MCP-Protocol-Version"] == "2026-07-28"
        assert call["Mcp-Method"] == "tools/call" and call["Mcp-Name"] == "approved_tool"
        assert "Mcp-Session-Id" not in call
        assert "text/event-stream" in call["Accept"]
        assert not (await adapter.observe()).witnesses

    asyncio.run(scenario())


def test_mcp_refuses_an_interim_multi_round_trip_result():
    class InputRequiredTransport:
        async def request(self, method, url, *, body=None, headers=None):
            payload = json.loads(body)
            if payload["method"] == "server/discover":
                result = {
                    "resultType": "complete",
                    "supportedVersions": ["2026-07-28"],
                    "capabilities": {"tools": {}},
                }
            else:
                result = {"resultType": "input_required", "inputRequests": {}}
            envelope = {"jsonrpc": "2.0", "id": payload["id"], "result": result}
            return TransportResponse(
                200, json.dumps(envelope).encode(), {"Content-Type": "application/json"}
            )

    async def scenario():
        adapter = MCPAdapter(InputRequiredTransport(), ("approved_tool",))
        await adapter.prepare(
            AdapterContext("https://registered.example/mcp", "DIGITAL_STAGING", "run-1")
        )
        with pytest.raises(ValueError):
            await adapter.stimulate(
                Stimulus(
                    type="tool_call",
                    payload={"name": "approved_tool", "arguments": {}},
                    correlation_id="run-1",
                )
            )

    asyncio.run(scenario())


def test_mcp_reads_a_request_scoped_event_stream_response():
    class StreamTransport:
        async def request(self, method, url, *, body=None, headers=None):
            payload = json.loads(body)
            if payload["method"] == "server/discover":
                result = {
                    "resultType": "complete",
                    "supportedVersions": ["2026-07-28"],
                    "capabilities": {"tools": {}},
                }
                return TransportResponse(
                    200,
                    json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": result}).encode(),
                    {"Content-Type": "application/json"},
                )
            progress = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}
            final = {
                "jsonrpc": "2.0",
                "id": payload["id"],
                "result": {"resultType": "complete", "content": [], "isError": False},
            }
            stream = f"data: {json.dumps(progress)}\n\ndata: {json.dumps(final)}\n\n"
            return TransportResponse(
                200, stream.encode(), {"Content-Type": "text/event-stream; charset=utf-8"}
            )

    async def scenario():
        adapter = MCPAdapter(StreamTransport(), ("approved_tool",))
        await adapter.prepare(
            AdapterContext("https://registered.example/mcp", "DIGITAL_STAGING", "run-1")
        )
        await adapter.stimulate(
            Stimulus(
                type="tool_call",
                payload={"name": "approved_tool", "arguments": {}},
                correlation_id="run-1",
            )
        )
        observation = await adapter.observe()
        assert not observation.witnesses and observation.limitations

    asyncio.run(scenario())


def test_model_adapter_does_not_execute_generated_calls():
    transport = FakeTransport({"choices": [{"message": {"tool_calls": [{"name": "wire_money"}]}}]})

    async def scenario():
        adapter = OpenAICompatibleAdapter(transport, "customer-approved-model")
        await adapter.prepare(
            AdapterContext("https://registered.example/chat", "DIGITAL_STAGING", "run-1")
        )
        await adapter.stimulate(
            Stimulus(
                type="chat_messages",
                payload={"messages": [{"role": "user", "content": "Test"}]},
                correlation_id="run-1",
            )
        )
        assert len(transport.requests) == 1
        assert not (await adapter.observe()).receipts

    asyncio.run(scenario())


def test_sdk_is_instrumentation_not_self_qualification():
    source = _trial("fixed", bounded_variants()[0])
    trace = Trace("customer-wrapper", "1", "beneficiary-write-authorization")
    trace.tool_call(source.receipts[0].action)
    result = trace.observation(complete=True)
    assert result.witnesses[0].authority == "INSTRUMENTED"
    assert result.receipts[0].sequence == 0
