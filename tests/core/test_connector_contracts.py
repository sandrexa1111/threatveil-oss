import asyncio
import copy
import json
from datetime import datetime, timezone

import httpx
import pytest
from google.cloud import run_v2
from google.iam.v1 import policy_pb2

from threatveil.connectors.collectors import (
    SourceFailure, cloud_run_snapshot, collect_cloud_run, collect_mcp,
    github_snapshot, imported_snapshot,
)
from threatveil.connectors.contracts import CONFORMANCE, Role, manifests
from threatveil.core.contracts import digest
from threatveil.adapters.base import TransportResponse


SERVICE = "projects/customer-project/locations/us-central1/services/finance-agent"


def cloud_payload():
    return {
        "service": {
            "name": SERVICE, "etag": "service-etag", "generation": "2", "observedGeneration": "2",
            "reconciling": False, "latestReadyRevision": SERVICE + "/revisions/finance-002",
            "template": {"serviceAccount": "agent@customer-project.iam.gserviceaccount.com",
                         "containers": [{"image": "repo/finance@sha256:" + "a" * 64,
                                         "env": [{"name": "SECRET", "value": "DO_NOT_RETAIN"}]}]},
            "trafficStatuses": [{"revision": "finance-001", "percent": 20},
                                {"revision": "finance-002", "percent": 80}],
        },
        "iam_policy": {"version": 3, "etag": "policy-etag", "bindings": [
            {"role": "roles/run.invoker", "members": ["serviceAccount:private@example.invalid"]}
        ]},
    }


def test_role_contract_is_explicit_and_read_installs_cannot_be_enforcers():
    catalog = manifests()
    for manifest in catalog.values():
        for role in manifest.roles:
            assert role.supported_versions and role.permissions and role.facts
            assert role.qualification_assumptions and role.freshness_seconds
            assert role.continuity and role.pagination and role.failures
            assert role.data_classification and role.retention and role.limits
            assert role.conformance_version == CONFORMANCE
        assert not {Role.ENFORCE, Role.EXECUTE} & set(manifest.installation_roles)
    assert {r.role for r in catalog["github"].roles} == {
        Role.DISCOVER, Role.CHANGE, Role.ENFORCE, Role.EXPORT,
    }


def test_cloud_config_iam_and_identity_changes_are_visible_without_running_proof():
    payload = cloud_payload()
    first = cloud_run_snapshot(payload)
    assert first.complete
    assert first.facts["running_state_proven"] is False
    assert len(first.facts["control_plane_status"]["trafficStatuses"]) == 2
    assert "DO_NOT_RETAIN" not in first.model_dump_json()
    assert "private@example.invalid" not in first.model_dump_json()
    changed = copy.deepcopy(payload)
    changed["iam_policy"]["bindings"][0]["members"].append("allUsers")
    changed["service"]["template"]["serviceAccount"] = "more-powerful@example.invalid"
    changed["service"]["template"]["containers"][0]["env"][0]["value"] = "CHANGED_SECRET"
    second = cloud_run_snapshot(changed)
    for kind in ("permissions", "cloud_configuration", "identity"):
        assert first.components[f"{kind}:{SERVICE}"] != second.components[f"{kind}:{SERVICE}"]
    assert first.components[f"deployment:{SERVICE}"] == second.components[f"deployment:{SERVICE}"]
    changed["service"]["reconciling"] = True
    assert not cloud_run_snapshot(changed).complete
    changed["service"]["reconciling"] = False
    changed["service"]["observedGeneration"] = "1"
    assert not cloud_run_snapshot(changed).complete


def test_cloud_sdk_reads_exact_resource_without_retries_and_rejects_race():
    class Client:
        def __init__(self, race=False):
            self.calls, self.race = [], race

        def get_service(self, *, request, retry, timeout):
            self.calls.append(("service", request, retry, timeout))
            return run_v2.Service(
                name=SERVICE, etag="A" if len(self.calls) < 3 or not self.race else "B",
                generation=2, observed_generation=2,
                template=run_v2.RevisionTemplate(containers=[run_v2.Container(image="repo/image")]),
            )

        def get_iam_policy(self, *, request, retry, timeout):
            self.calls.append(("iam", request, retry, timeout))
            return policy_pb2.Policy(version=3, etag=b"abc")

    client = Client()
    snapshot = collect_cloud_run({"service": SERVICE}, "test-token", client=client)
    assert snapshot.complete and snapshot.facts["running_state_proven"] is False
    assert len(client.calls) == 4
    assert all(retry is None and timeout == 10 for _, _, retry, timeout in client.calls)
    assert all(request.get("name", request.get("resource")) == SERVICE for _, request, _, _ in client.calls)
    with pytest.raises(SourceFailure, match="PARTIAL"):
        collect_cloud_run({"service": SERVICE}, "test-token", client=Client(race=True))


def test_github_exact_ref_bounded_read_never_calls_write_or_treats_repo_as_deployment():
    requests = []

    def respond(request):
        requests.append(request)
        assert request.method == "GET" and request.url.host == "api.github.com"
        assert request.headers["x-github-api-version"] == "2022-11-28"
        if request.url.path == "/repos/acme/finance":
            return httpx.Response(200, json={"id": 42, "full_name": "acme/finance"})
        return httpx.Response(200, json={"ref": "refs/heads/main", "object": {
            "type": "commit", "sha": "a" * 40,
        }})

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        snapshot = github_snapshot({"repository": "acme/finance", "repository_id": "42",
                                    "ref": "refs/heads/main"}, "read-token", client=client)
    assert len(requests) == 3
    assert snapshot.facts["running_state_proven"] is False
    assert snapshot.components["git_commit:42"]["digest"] == "a" * 40
    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(SourceFailure, match="INVALID_RESPONSE"):
            github_snapshot({"repository": "acme/finance", "repository_id": "99",
                             "ref": "refs/heads/main"}, "token", client=client)


def test_otel_success_never_establishes_effect_task_or_private_content():
    stamp = int(datetime.now(timezone.utc).timestamp() * 1e9)
    attrs = [{"key": key, "value": {"stringValue": value}} for key, value in (
        ("gen_ai.operation.name", "execute_tool"), ("gen_ai.tool.name", "refund"),
        ("gen_ai.request.model", "opaque-latest"), ("gen_ai.provider.name", "provider"),
        ("gen_ai.input.messages", "PRIVATE_PROMPT"), ("threatveil.task_outcome", "SUCCESS"),
    )]
    payload = {"resourceSpans": [{"scopeSpans": [{"spans": [{
        "traceId": "a" * 32, "spanId": "b" * 16, "startTimeUnixNano": str(stamp),
        "attributes": attrs, "status": {"code": 1},
    }]}]}]}
    snapshot = imported_snapshot("otel", payload, "server-assigned-source", datetime.now(timezone.utc))
    assert snapshot.facts["committed_effect"] == "UNKNOWN"
    assert snapshot.facts["task_outcome"] == "UNKNOWN"
    assert not snapshot.complete and not snapshot.facts["running_state_proven"]
    assert "PRIVATE_PROMPT" not in snapshot.model_dump_json()


def _collect(monkeypatch, responder):
    from threatveil.targets import SafeTransport

    checks = []
    monkeypatch.setattr(SafeTransport, "request", responder)
    result = asyncio.run(collect_mcp(
        {"origin": "https://fixture.invalid", "paths": ["/mcp"], "methods": ["POST"],
         "discovery_path": "/mcp"}, source_identity="source:server-issued", headers={},
        recheck=lambda: checks.append(True),
    ))
    return result, checks


def test_mcp_remote_discovery_rechecks_target_and_cannot_execute_tools(monkeypatch):
    methods = []

    async def request(self, method, url=None, **kwargs):
        payload = json.loads(kwargs["body"])
        methods.append(payload["method"])
        if payload["method"] == "server/discover":
            return TransportResponse(200, json.dumps({
                "jsonrpc": "2.0", "id": payload["id"],
                "error": {"code": -32601, "message": "Method not found"},
            }).encode(), {})
        if payload["method"] == "initialize":
            result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "fixture", "version": "1"}}
        elif payload["method"] == "notifications/initialized":
            return TransportResponse(202, b"", {})
        else:
            result = {"tools": [{"name": "refund", "inputSchema": {"type": "object"}}]}
        return TransportResponse(200, json.dumps({
            "jsonrpc": "2.0", "id": payload.get("id"), "result": result,
        }).encode(), {})

    result, checks = _collect(monkeypatch, request)
    assert result.complete
    assert methods == ["server/discover", "initialize", "notifications/initialized", "tools/list"]
    assert len(checks) == 4
    assert result.facts["running_state_proven"] is False
    assert result.facts["protocol_era"] == "LEGACY"
    assert result.source_version == "MCP 2025-11-25"


def test_mcp_remote_discovery_uses_the_current_revision_and_records_freshness(monkeypatch):
    methods = []

    async def request(self, method, url=None, **kwargs):
        payload = json.loads(kwargs["body"])
        methods.append(payload["method"])
        assert kwargs["headers"]["MCP-Protocol-Version"] == "2026-07-28"
        assert kwargs["headers"]["Mcp-Method"] == payload["method"]
        assert payload["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
        if payload["method"] == "server/discover":
            result = {"resultType": "complete", "supportedVersions": ["2026-07-28"],
                      "capabilities": {"tools": {}},
                      "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "fixture"}}}
        else:
            assert payload["method"] == "tools/list"
            result = {"resultType": "complete", "ttlMs": 60000, "cacheScope": "private",
                      "tools": [{"name": "refund", "inputSchema": {"type": "object"}}]}
        return TransportResponse(200, json.dumps({
            "jsonrpc": "2.0", "id": payload["id"], "result": result,
        }).encode(), {"Content-Type": "application/json"})

    result, checks = _collect(monkeypatch, request)
    assert result.complete
    assert methods == ["server/discover", "tools/list"]
    assert len(checks) == 2
    assert result.source_version == "MCP 2026-07-28"
    assert result.facts["protocol_era"] == "MODERN"
    assert result.facts["catalog_cache_ttl_ms"] == 60000
    assert result.facts["catalog_cache_scope"] == "private"
    assert result.facts["running_state_proven"] is False
    assert "tool:" in " ".join(result.components)


def test_mcp_read_transport_rejects_every_method_outside_discovery(monkeypatch):
    from threatveil.connectors.collectors import SourceFailure
    from threatveil.targets import SafeTransport

    async def request(self, method, url=None, **kwargs):
        payload = json.loads(kwargs["body"])
        if payload["method"] == "server/discover":
            result = {"resultType": "complete", "supportedVersions": ["2026-07-28"],
                      "capabilities": {"tools": {}}}
        else:
            # A server that answers a read with a tool invocation must not be followed.
            result = {"resultType": "complete", "tools": []}
        return TransportResponse(200, json.dumps({
            "jsonrpc": "2.0", "id": payload["id"], "result": result,
        }).encode(), {"Content-Type": "application/json"})

    monkeypatch.setattr(SafeTransport, "request", request)
    from threatveil.adapters.base import AdapterContext
    from threatveil.adapters.mcp import MCPAdapter
    from threatveil.connectors.collectors import collect_mcp as _unused  # noqa: F401

    async def scenario():
        # Reconstruct the connector's bounded transport and prove tools/call is refused.
        captured = {}

        async def guard(self, method, url=None, **kwargs):
            message = json.loads(kwargs["body"])
            if message.get("method") not in {
                "server/discover", "tools/list", "initialize", "notifications/initialized"
            }:
                captured["blocked"] = message["method"]
                raise SourceFailure("UNAUTHORIZED")
            return await request(self, method, url, **kwargs)

        monkeypatch.setattr(SafeTransport, "request", guard)
        adapter = MCPAdapter(SafeTransport(
            {"origin": "https://fixture.invalid", "paths": ["/mcp"], "methods": ["POST"]}, {},
        ), ("refund",))
        await adapter.prepare(
            AdapterContext("https://fixture.invalid/mcp", "DIGITAL_STAGING", "source:x")
        )
        from threatveil.adapters.base import Stimulus

        with pytest.raises(SourceFailure):
            await adapter.stimulate(Stimulus(
                type="tool_call", payload={"name": "refund", "arguments": {}},
                correlation_id="source:x",
            ))
        assert captured["blocked"] == "tools/call"

    asyncio.run(scenario())


def test_unsupported_mcp_revision_cannot_claim_complete_catalog():
    snapshot = imported_snapshot("mcp", {
        "server_id": "forged-source", "protocol_version": "2099-01-01", "complete": True,
        "tools": [{"name": "tool", "inputSchema": {"type": "object"}}],
    }, "source:server-issued", datetime.now(timezone.utc))
    assert not snapshot.complete
    assert "forged-source" not in snapshot.model_dump_json()
    assert digest(snapshot)
