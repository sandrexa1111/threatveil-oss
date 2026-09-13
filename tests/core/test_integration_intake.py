import asyncio
import copy
import json

import pytest

from threatveil.adapters import AdapterContext, MCPAdapter, TransportResponse
from threatveil.core.contracts import (
    ActionPhase,
    ObservationContract,
    Predicate,
    PropertyDefinition,
)
from threatveil.core.evaluation import evaluate_trace
from threatveil.integrations.intake import IntakeContext, normalize_integration
from threatveil.integrations.mcp_protocol import (
    LEGACY,
    META_CLIENT_CAPABILITIES,
    META_PROTOCOL_VERSION,
    META_SERVER_INFO,
    MODERN,
)
from threatveil.integrations.mcp_discovery import (
    capture_mcp_tools,
    diff_mcp_tools,
    discover_mcp_tools,
)


def attr(key, value, kind="stringValue"):
    return {"key": key, "value": {kind: value}}


def otlp():
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        attr("service.name", "checkout"),
                        attr("service.version", "build-a"),
                    ]
                },
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "traceId": "a" * 32,
                                "spanId": "b" * 16,
                                "parentSpanId": "c" * 16,
                                "startTimeUnixNano": "1789000000000000000",
                                "endTimeUnixNano": "1789000000001000000",
                                "attributes": [
                                    attr("gen_ai.operation.name", "execute_tool"),
                                    attr("gen_ai.tool.name", "payment.update"),
                                    attr("gen_ai.provider.name", "openai"),
                                    attr("gen_ai.request.model", "model-a"),
                                    attr("gen_ai.request.temperature", 0, "doubleValue"),
                                    attr("gen_ai.agent.id", "agent-1"),
                                    attr("gen_ai.input.messages", "private prompt"),
                                    attr("threatveil.authority", "AUTHORITATIVE"),
                                    attr("threatveil.task_outcome", "SUCCESS"),
                                ],
                                "status": {"code": 1},
                            }
                        ]
                    }
                ],
            }
        ]
    }


def test_otel_preserves_invocation_but_cannot_self_qualify_or_reveal_content():
    imported = normalize_integration(
        "otel_genai", otlp(), context={"source_id": "collector", "boundary": "test"}
    )
    obs = imported.observations[0]
    assert obs.task_outcome == "UNKNOWN"
    assert obs.receipts[0].action.phase == ActionPhase.DISPATCHED
    assert obs.receipts[0].action.authorized is None
    assert obs.receipts[0].action.after is None
    assert obs.witnesses[0].authority == "INSTRUMENTED"
    assert not obs.witnesses[0].complete
    assert imported.trace_edges[0].parent_span_id == "c" * 16
    assert imported.trace_edges[0].agent_id == "agent-1"
    assert "private prompt" not in imported.model_dump_json()
    prop = PropertyDefinition(
        id="property",
        title="No payment update",
        predicates=(
            Predicate(
                kind="forbidden_action",
                operations=("payment.update",),
                phases=(ActionPhase.DISPATCHED,),
            ),
        ),
        observation_contract=ObservationContract(
            boundary="test",
            required_witnesses=("collector",),
            required_operations=("payment.update",),
        ),
    )
    # Even an accidental source allowlist cannot promote imported INSTRUMENTED data.
    verdict = evaluate_trace(
        prop, obs, qualified_witnesses={"collector": "1"}, now=obs.witnesses[0].observed_at
    )
    assert verdict["security_verdict"] == "INCONCLUSIVE"


def test_otel_rejects_duplicate_attributes_and_spans():
    payload = otlp()
    span = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    span["attributes"].append(attr("gen_ai.tool.name", "different"))
    with pytest.raises(ValueError, match="Duplicate OTLP attribute"):
        normalize_integration("otel_genai", payload)
    payload = otlp()
    spans = payload["resourceSpans"][0]["scopeSpans"][0]["spans"]
    spans.append(copy.deepcopy(spans[0]))
    with pytest.raises(ValueError, match="Duplicate OTLP span"):
        normalize_integration("otel_genai", payload)


@pytest.mark.parametrize(
    "field,value", [("traceId", "0" * 32), ("spanId", "not-hex"), ("endTimeUnixNano", "1")]
)
def test_otel_rejects_invalid_identity_and_time(field, value):
    payload = otlp()
    payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0][field] = value
    with pytest.raises(ValueError):
        normalize_integration("otel_genai", payload)


def test_otel_dropped_data_and_conflicting_config_remain_unknown():
    payload = otlp()
    spans = payload["resourceSpans"][0]["scopeSpans"][0]["spans"]
    spans.append(copy.deepcopy(spans[0]))
    spans[1]["spanId"] = "d" * 16
    spans[1]["attributes"][4] = attr("gen_ai.request.temperature", 1, "doubleValue")
    spans[1]["droppedAttributesCount"] = 1
    imported = normalize_integration("otel_genai", payload)
    assert (
        next(c for c in imported.fingerprint.components if c.type == "model_config").provenance
        == "UNKNOWN"
    )
    assert any("dropped" in limitation for limitation in imported.limitations)


def test_otel_anyvalue_array_and_nested_kvlist_are_not_discarded():
    payload = otlp()
    span = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    span["attributes"].append(
        attr(
            "gen_ai.tool.definitions",
            {"values": [{"kvlistValue": {"values": [attr("name", "payment.update")]}}]},
            "arrayValue",
        )
    )
    assert any(
        c.type == "toolset"
        for c in normalize_integration("otel_genai", payload).fingerprint.components
    )


def test_correlation_binding_is_checked():
    with pytest.raises(ValueError, match="correlation"):
        normalize_integration(
            "otel_genai", otlp(), context={"expected_correlation_id": "another-run"}
        )


def test_unknown_mcp_catalog_extensions_and_protocols_cannot_disappear():
    payload = catalog()
    before = capture_mcp_tools(payload)
    payload["_meta"] = {"custom.auth": {"scopes": ["admin"]}}
    after = capture_mcp_tools(payload)
    assert before.catalog_digest != after.catalog_digest
    assert diff_mcp_tools(before, after)["status"] == "CHANGED"
    payload["protocol_version"] = "2099-01-01"
    assert capture_mcp_tools(payload).fingerprint.components[0].provenance == "UNKNOWN"


def test_unknown_composition_extensions_preserve_array_order():
    payload = bom()
    payload["vendorExtension"] = {"dependencies": ["first-policy", "second-policy"]}
    before = normalize_integration("cyclonedx", payload).fingerprint
    payload["vendorExtension"]["dependencies"].reverse()
    assert before != normalize_integration("cyclonedx", payload).fingerprint


def test_partial_composition_does_not_become_known_because_another_is_complete():
    payload = bom()
    payload["compositions"].append({"aggregate": "incomplete"})
    assert any(
        c.type == "composition_coverage" and c.provenance == "UNKNOWN"
        for c in normalize_integration("cyclonedx", payload).fingerprint.components
    )


def test_openai_current_response_export_missing_model_and_mcp_names_remain_unknown():
    payload = {
        "spans": [
            {
                "id": "response-1",
                "trace_id": "trace-1",
                "span_data": {"type": "response", "response_id": "resp-1", "usage": {}},
            },
            {
                "id": "mcp-1",
                "trace_id": "trace-1",
                "span_data": {"type": "mcp_tools", "server": "payments", "result": ["update"]},
            },
        ]
    }
    imported = normalize_integration("openai_agents", payload)
    assert len(imported.observations[0].receipts) == 2
    assert {c.type for c in imported.fingerprint.components if c.provenance == "UNKNOWN"} == {
        "model",
        "mcp",
    }


def openai_spans():
    return {
        "spans": [
            {
                "id": "span-1",
                "trace_id": "trace-1",
                "parent_id": "span-agent",
                "started_at": "2026-09-10T00:00:00Z",
                "ended_at": "2026-09-10T00:00:01Z",
                "span_data": {
                    "type": "function",
                    "name": "payment.update",
                    "output": "Committed successfully",
                    "input": "private secret",
                },
            },
            {
                "id": "span-2",
                "trace_id": "trace-1",
                "span_data": {"type": "handoff", "from_agent": "triage", "to_agent": "payments"},
            },
            {
                "id": "span-3",
                "trace_id": "trace-1",
                "span_data": {
                    "type": "generation",
                    "model": "model-a",
                    "model_config": {"temperature": 0},
                },
            },
        ]
    }


def test_openai_function_handoff_and_model_are_normalized_without_authority():
    imported = normalize_integration("openai_agents", openai_spans())
    assert imported.observations[0].receipts[0].action.phase == "DISPATCHED"
    assert imported.observations[0].task_outcome == "UNKNOWN"
    assert imported.trace_edges[1].delegated_to == "payments"
    assert imported.trace_edges[1].authority == "UNVERIFIED"
    assert any(c.type == "model_config" for c in imported.fingerprint.components)
    assert "private secret" not in imported.model_dump_json()


def test_openai_partial_or_failed_execution_does_not_claim_denial():
    payload = openai_spans()
    payload["spans"][0].pop("ended_at")
    payload["spans"][0]["error"] = {"message": "access denied"}
    obs = normalize_integration("openai_agents", payload).observations[0]
    assert obs.execution_status == "ERROR"
    assert obs.receipts[0].action.phase == "ATTEMPTED"
    assert obs.receipts[0].action.authorized is None


def test_openai_rejects_duplicate_ids_and_naive_time():
    payload = openai_spans()
    payload["spans"].append(payload["spans"][0])
    with pytest.raises(ValueError, match="Duplicate imported"):
        normalize_integration("openai_agents", payload)
    payload = openai_spans()
    payload["spans"][0]["ended_at"] = "2026-09-10T00:00:01"
    with pytest.raises(ValueError, match="timezone"):
        normalize_integration("openai_agents", payload)


def test_claude_hook_pair_preserves_phase_and_post_failure_cannot_erase_attempt():
    common = {
        "session_id": "session-1",
        "tool_use_id": "toolu-1",
        "tool_name": "Write",
        "agent_id": "child",
        "tool_input": {"contents": "private secret"},
    }
    imported = normalize_integration(
        "anthropic_hooks",
        {
            "events": [
                {**common, "hook_event_name": "PreToolUse"},
                {**common, "hook_event_name": "PostToolUseFailure", "error": "access denied"},
            ]
        },
    )
    obs = imported.observations[0]
    assert [r.action.phase for r in obs.receipts] == ["ATTEMPTED", "DISPATCHED"]
    assert obs.task_outcome == "UNKNOWN"
    assert obs.execution_status == "ERROR"
    assert "private secret" not in imported.model_dump_json()
    assert all(r.action.authorized is None for r in obs.receipts)


def catalog():
    return {
        "server_id": "payments",
        "protocol_version": "2025-11-25",
        "complete": True,
        "authorization": {"required_scopes": ["payments:write"]},
        "tools": [
            {
                "name": "update",
                "description": "Update approved payment",
                "inputSchema": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                    "required": ["id"],
                },
                "annotations": {"readOnlyHint": False},
            },
            {"name": "read", "inputSchema": {"type": "object"}},
        ],
    }


def test_mcp_catalog_order_is_stable_but_descriptions_extensions_and_schema_change():
    before = capture_mcp_tools(catalog())
    candidate = catalog()
    candidate["tools"].reverse()
    assert diff_mcp_tools(before, capture_mcp_tools(candidate))["status"] == "UNCHANGED"
    candidate["tools"][1]["description"] = "Update any payment"
    candidate["tools"][1]["inputSchema"]["additionalProperties"] = True
    candidate["tools"][1]["_meta"] = {"custom:auth": "changed"}
    result = diff_mcp_tools(before, capture_mcp_tools(candidate))
    assert result["status"] == "CHANGED"
    assert set(result["changes"][0]["paths"]) == {
        "/description",
        "/inputSchema/additionalProperties",
        "/_meta",
    }


def test_mcp_incomplete_catalog_cannot_prove_tool_removal():
    candidate = catalog()
    candidate["tools"] = [candidate["tools"][0]]
    candidate["complete"] = False
    result = diff_mcp_tools(capture_mcp_tools(catalog()), capture_mcp_tools(candidate))
    assert result["status"] == "UNKNOWN"
    assert result["changes"][0]["kind"] == "NOT_OBSERVED"
    assert capture_mcp_tools(candidate).fingerprint.components[0].provenance == "UNKNOWN"


def test_mcp_metadata_and_permission_changes_are_in_fingerprint():
    old = capture_mcp_tools(catalog())
    candidate = catalog()
    candidate["authorization"]["required_scopes"].append("admin")
    new = capture_mcp_tools(candidate)
    assert old.catalog_digest != new.catalog_digest
    assert "/authorization/required_scopes" in diff_mcp_tools(old, new)["metadata_paths"]
    candidate.pop("authorization")
    assert (
        next(
            c
            for c in capture_mcp_tools(candidate).fingerprint.components
            if c.type == "permissions"
        ).provenance
        == "UNKNOWN"
    )


@pytest.mark.parametrize("mutation", ["duplicate", "schema", "cursor", "complete-string"])
def test_mcp_rejects_ambiguous_or_malformed_catalog(mutation):
    payload = catalog()
    if mutation == "duplicate":
        payload["tools"].append(payload["tools"][0])
    elif mutation == "schema":
        payload["tools"][0]["inputSchema"] = None
    elif mutation == "cursor":
        payload["nextCursor"] = "next"
    else:
        payload["complete"] = "true"
    with pytest.raises(ValueError):
        capture_mcp_tools(payload)


def test_mcp_diff_rejects_forged_snapshot_fingerprint():
    snapshot = capture_mcp_tools(catalog()).model_dump(mode="json")
    snapshot["tools"][0]["inputSchema"]["additionalProperties"] = True
    with pytest.raises(ValueError, match="derived fingerprint"):
        diff_mcp_tools(snapshot, capture_mcp_tools(catalog()))


class DiscoveryTransport:
    """Configurable MCP server fixture covering both protocol eras.

    A legacy server answers the modern `server/discover` probe with an ordinary
    JSON-RPC error, which is how a handshake-era server actually behaves.
    """

    def __init__(self, failure=None, era="LEGACY", supported=None, ttl=300000, scope="public"):
        self.requests, self.failure, self.era = [], failure, era
        self.headers: list[dict] = []
        self.supported = supported or (
            [MODERN, LEGACY] if era == "MODERN" else [LEGACY]
        )
        self.ttl, self.scope = ttl, scope

    def _reject(self, request, code, message, data=None):
        error = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        envelope = {"jsonrpc": "2.0", "id": request.get("id"), "error": error}
        status = 400 if code in (-32020, -32021, -32022) else 200
        return TransportResponse(status, json.dumps(envelope).encode(), {})

    async def request(self, method, url, *, body=None, headers=None):
        assert url == "https://registered.example/mcp"
        request = json.loads(body)
        self.requests.append(request)
        self.headers.append(dict(headers or {}))
        name = request["method"]
        if name == "server/discover":
            if self.era != "MODERN":
                # Handshake-era servers do not implement discovery.
                return self._reject(request, -32601, "Method not found")
            if self.failure == "version":
                self.era, self.failure = "MODERN", None
                return self._reject(
                    request,
                    -32022,
                    "Unsupported protocol version",
                    {"supported": self.supported, "requested": MODERN},
                )
            if self.failure == "no_versions":
                result = {"resultType": "complete", "capabilities": {"tools": {}}}
            else:
                result = {
                    "resultType": "complete",
                    "supportedVersions": self.supported,
                    "capabilities": {"tools": {}},
                    "_meta": {META_SERVER_INFO: {"name": "payments", "version": "2"}},
                    "ttlMs": 3600000,
                    "cacheScope": "public",
                }
            return TransportResponse(
                200,
                json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode(),
                {"Content-Type": "application/json"},
            )
        if name == "initialize":
            result = {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "payments", "version": "2"},
            }
        elif name == "notifications/initialized":
            return TransportResponse(202, b"", {})
        else:
            assert name == "tools/list"
            if self.era == "MODERN":
                # Required per-request metadata and header mirroring.
                meta = request["params"]["_meta"]
                assert meta[META_PROTOCOL_VERSION] == MODERN
                assert isinstance(meta[META_CLIENT_CAPABILITIES], dict)
                assert self.headers[-1]["MCP-Protocol-Version"] == MODERN
                assert self.headers[-1]["Mcp-Method"] == "tools/list"
                assert "Mcp-Session-Id" not in self.headers[-1]
            if request["params"].get("cursor"):
                result = {"tools": [catalog()["tools"][1]]}
                if self.failure == "cycle":
                    result["nextCursor"] = "second"
            else:
                result = {"tools": [catalog()["tools"][0]], "nextCursor": "second"}
            if self.era == "MODERN":
                result = {
                    "resultType": "complete",
                    **result,
                    "ttlMs": self.ttl,
                    **({"cacheScope": self.scope} if self.scope else {}),
                }
                if self.failure == "scope_conflict" and request["params"].get("cursor"):
                    result["cacheScope"] = "private"
        envelope = {
            "jsonrpc": "2.0",
            "id": "wrong" if self.failure == "id" and name == "tools/list" else request["id"],
            "result": result,
        }
        return TransportResponse(200, json.dumps(envelope).encode(), {"Mcp-Session-Id": "session"})


def test_mcp_discovery_falls_back_to_the_legacy_handshake_without_silent_downgrade():
    transport = DiscoveryTransport()
    adapter = MCPAdapter(transport, ("update",))

    async def scenario():
        await adapter.prepare(
            AdapterContext("https://registered.example/mcp", "DIGITAL_STAGING", "capture-1")
        )
        snapshot = await discover_mcp_tools(adapter, server_id="payments")
        assert snapshot.complete
        assert len(snapshot.tools) == 2
        assert snapshot.server_info["version"] == "2"
        assert snapshot.protocol_version == LEGACY and snapshot.era == "LEGACY"
        # The modern probe is always attempted first and its failure is observed.
        assert [r["method"] for r in transport.requests] == [
            "server/discover",
            "initialize",
            "notifications/initialized",
            "tools/list",
            "tools/list",
        ]
        await adapter.cleanup()
        assert adapter.server_info == {} and adapter.era is None

    asyncio.run(scenario())


def test_mcp_discovery_uses_the_stateless_revision_and_records_freshness():
    transport = DiscoveryTransport(era="MODERN")
    adapter = MCPAdapter(transport, ("update",))

    async def scenario():
        await adapter.prepare(
            AdapterContext("https://registered.example/mcp", "DIGITAL_STAGING", "capture-1")
        )
        snapshot = await discover_mcp_tools(adapter, server_id="payments")
        assert snapshot.complete and len(snapshot.tools) == 2
        assert snapshot.protocol_version == MODERN and snapshot.era == "MODERN"
        assert snapshot.supported_versions == (MODERN, LEGACY)
        assert snapshot.server_info["version"] == "2"
        assert snapshot.cache_ttl_ms == 300000 and snapshot.cache_scope == "public"
        # No handshake, and no session identifier is minted or echoed.
        assert [r["method"] for r in transport.requests] == [
            "server/discover",
            "tools/list",
            "tools/list",
        ]

    asyncio.run(scenario())


def test_mcp_discovery_retries_with_a_mutually_supported_revision():
    transport = DiscoveryTransport(failure="version", era="MODERN", supported=[MODERN])
    adapter = MCPAdapter(transport, ("update",))

    async def scenario():
        await adapter.prepare(
            AdapterContext("https://registered.example/mcp", "DIGITAL_STAGING", "capture-1")
        )
        snapshot = await discover_mcp_tools(adapter, server_id="payments")
        assert snapshot.protocol_version == MODERN
        assert [r["method"] for r in transport.requests][:2] == [
            "server/discover",
            "server/discover",
        ]

    asyncio.run(scenario())


def test_mcp_discovery_refuses_a_server_offering_no_implemented_revision():
    transport = DiscoveryTransport(failure="version", era="MODERN", supported=["1900-01-01"])
    adapter = MCPAdapter(transport, ("update",))

    async def scenario():
        await adapter.prepare(
            AdapterContext("https://registered.example/mcp", "DIGITAL_STAGING", "capture-1")
        )
        with pytest.raises(ValueError):
            await discover_mcp_tools(adapter, server_id="payments")

    asyncio.run(scenario())


def test_mcp_discovery_records_an_immediately_stale_catalog():
    transport = DiscoveryTransport(era="MODERN", ttl=0)
    adapter = MCPAdapter(transport, ("update",))

    async def scenario():
        await adapter.prepare(
            AdapterContext("https://registered.example/mcp", "DIGITAL_STAGING", "capture-1")
        )
        snapshot = await discover_mcp_tools(adapter, server_id="payments")
        assert snapshot.cache_ttl_ms == 0
        assert any("immediately stale" in item for item in snapshot.limitations)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "failure,era",
    [
        ("id", "LEGACY"),
        ("cycle", "LEGACY"),
        ("limit", "LEGACY"),
        ("id", "MODERN"),
        ("cycle", "MODERN"),
        ("no_versions", "MODERN"),
        ("scope_conflict", "MODERN"),
    ],
)
def test_mcp_discovery_aborts_partial_or_mismatched_response(failure, era):
    adapter = MCPAdapter(DiscoveryTransport(failure, era=era), ("update",))

    async def scenario():
        await adapter.prepare(
            AdapterContext("https://registered.example/mcp", "DIGITAL_STAGING", "capture-1")
        )
        with pytest.raises(ValueError):
            await discover_mcp_tools(
                adapter, server_id="payments", max_pages=1 if failure == "limit" else 20
            )

    asyncio.run(scenario())


def bom():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "components": [
            {"type": "application", "name": "agent", "bom-ref": "agent", "version": "1"},
            {
                "type": "machine-learning-model",
                "name": "model-a",
                "bom-ref": "model",
                "version": "1",
                "modelCard": {"modelParameters": {"task": "text-generation"}},
            },
        ],
        "dependencies": [
            {"ref": "agent", "dependsOn": ["model"]},
            {"ref": "model", "dependsOn": []},
        ],
        "compositions": [{"aggregate": "complete"}],
    }


def test_cyclonedx_model_and_dependency_graph_are_typed_and_order_stable():
    before = normalize_integration("cyclonedx", bom())
    candidate = bom()
    candidate["components"].reverse()
    candidate["dependencies"].reverse()
    after = normalize_integration("cyclonedx", candidate)
    assert before.fingerprint == after.fingerprint
    assert next(
        c for c in before.fingerprint.components if c.type == "application"
    ).dependencies == ("model:model",)
    candidate["components"][0]["modelCard"]["modelParameters"]["task"] = "tool-use"
    assert normalize_integration("cyclonedx", candidate).fingerprint != before.fingerprint


def test_cyclonedx_missing_graph_and_unresolved_refs_are_explicit_unknown():
    payload = bom()
    payload["dependencies"] = [{"ref": "agent", "dependsOn": ["external"]}]
    result = normalize_integration("cyclonedx", payload)
    assert result.details["unresolved_references"] == ["external"]
    assert result.details["missing_dependency_graph"] == ["model"]
    assert any(
        c.provenance == "UNKNOWN" and c.id == "external" for c in result.fingerprint.components
    )
    assert (
        "dependency_graph:model"
        in next(c for c in result.fingerprint.components if c.type == "model").dependencies
    )


def test_cyclonedx_duplicate_identity_rejected_and_unknown_extension_is_hashed():
    payload = bom()
    payload["components"].append(payload["components"][0])
    with pytest.raises(ValueError, match="Duplicate"):
        normalize_integration("cyclonedx", payload)
    payload = bom()
    before = normalize_integration("cyclonedx", payload)
    payload["vendor-extension"] = {"policy": "changed"}
    assert before.fingerprint != normalize_integration("cyclonedx", payload).fingerprint


def sarif():
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "scanner",
                        "version": "1",
                        "rules": [
                            {
                                "id": "AUTH-1",
                                "name": "Missing authorization",
                                "messageStrings": {"finding": {"text": "Missing check at {0}"}},
                                "defaultConfiguration": {"level": "error"},
                            }
                        ],
                    }
                },
                "artifacts": [{"location": {"uri": "src/payment.py", "uriBaseId": "%SRCROOT%"}}],
                "results": [
                    {
                        "ruleId": "AUTH-1",
                        "ruleIndex": 0,
                        "message": {"id": "finding", "arguments": ["payment.update"]},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"index": 0},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                        "partialFingerprints": {"primaryLocationLineHash": "abc"},
                        "baselineState": "unchanged",
                        "suppressions": [{"kind": "inSource", "status": "accepted"}],
                    }
                ],
            }
        ],
    }


def test_sarif_resolves_rules_messages_artifacts_and_retains_suppressed_finding():
    imported = normalize_integration("sarif", sarif())
    finding = imported.findings[0]
    assert finding.description == "Missing check at payment.update"
    assert finding.level == "error"
    assert finding.locations[0]["physicalLocation"]["artifactLocation"]["uri"] == "src/payment.py"
    assert finding.status == "DRAFT"
    assert finding.suppressions[0]["status"] == "accepted"
    assert finding.partial_fingerprints["primaryLocationLineHash"] == "abc"
    assert finding.source_digest == imported.source_digest
    assert not imported.observations


@pytest.mark.parametrize("mutation", ["rule", "artifact", "message"])
def test_sarif_rejects_conflicting_references_and_unresolved_messages(mutation):
    payload = sarif()
    result = payload["runs"][0]["results"][0]
    if mutation == "rule":
        result["ruleId"] = "another"
    elif mutation == "artifact":
        result["locations"][0]["physicalLocation"]["artifactLocation"]["index"] = 20
    else:
        result["message"]["arguments"] = []
    with pytest.raises(ValueError):
        normalize_integration("sarif", payload)


def test_sarif_tool_extension_rule_identity_is_resolved():
    payload = sarif()
    run = payload["runs"][0]
    run["tool"]["extensions"] = [run["tool"]["driver"]]
    run["tool"]["driver"] = {"name": "main"}
    run["results"][0]["rule"] = {"toolComponent": {"index": 0, "name": "scanner"}}
    assert normalize_integration("sarif", payload).findings[0].scanner == "scanner"


@pytest.mark.parametrize(
    "kind,payload",
    [
        ("sarif", {"version": "99", "runs": []}),
        ("cyclonedx", {"bomFormat": "CycloneDX", "specVersion": "2.0"}),
        ("unknown", {}),
    ],
)
def test_unsupported_formats_rejected(kind, payload):
    with pytest.raises(ValueError):
        normalize_integration(kind, payload)


def test_bounds_nonfinite_numbers_and_naive_received_time_are_rejected():
    with pytest.raises(ValueError, match="finite"):
        normalize_integration("mcp_tools", {**catalog(), "extension": float("nan")})
    with pytest.raises(ValueError, match="4 MiB"):
        normalize_integration("mcp_tools", {**catalog(), "extension": "x" * (4 * 1024 * 1024)})
    payload = {"child": {}}
    child = payload["child"]
    for _ in range(35):
        child["child"] = {}
        child = child["child"]
    with pytest.raises(ValueError, match="structural"):
        normalize_integration("mcp_tools", payload)
    with pytest.raises(ValueError, match="timezone"):
        IntakeContext(received_at="2026-09-10T00:00:00")
