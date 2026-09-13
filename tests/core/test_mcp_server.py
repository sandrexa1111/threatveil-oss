import io
import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from threatveil.cli import app
from threatveil.sdk.client import ThreatVeilClient
from threatveil.integrations.mcp_protocol import MODERN as MODERN_PROTOCOL
from threatveil.sdk.mcp_server import (
    MAX_REQUEST_BYTES,
    PROTOCOL_VERSION,
    ThreatVeilMCPServer,
    public_schemas,
    serve,
)
from threatveil.sdk.receipts import sign_release_receipt


def request(method, params=None, identifier=1):
    return {"jsonrpc": "2.0", "id": identifier, "method": method, "params": params or {}}


def initialize(server):
    result = server.handle(
        request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "acceptance", "version": "1"},
            },
        )
    )
    assert result["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_public_mcp_catalog_and_schemas_work_without_credentials():
    server = ThreatVeilMCPServer()
    assert server.handle(request("tools/list"))["error"]["code"] == -32600
    initialize(server)
    tools = server.handle(request("tools/list"))["result"]["tools"]
    assert all(t["annotations"]["readOnlyHint"] for t in tools)
    assert all("execute" not in t["name"] and "approve" not in t["name"] for t in tools)
    templates = server.handle(
        request("tools/call", {"name": "threatveil_templates", "arguments": {}})
    )["result"]
    assert not templates["isError"] and len(templates["structuredContent"]["items"]) >= 20
    resources = server.handle(request("resources/list"))["result"]["resources"]
    assert len(resources) == 4
    for resource in resources:
        result = server.handle(request("resources/read", {"uri": resource["uri"]}))["result"]
        assert isinstance(json.loads(result["contents"][0]["text"]), dict)
    assert public_schemas()["threatveil://schemas/assurance-receipt-v1"] == json.loads(
        Path("schemas/assurance-receipt-v1.schema.json").read_text()
    )


def test_mcp_never_reads_tenant_history_without_authentication():
    server = ThreatVeilMCPServer()
    initialize(server)
    result = server.handle(
        request("tools/call", {"name": "threatveil_get_release", "arguments": {"id": str(uuid4())}})
    )
    assert result["result"]["isError"]
    assert "TV_API_TOKEN" in result["result"]["content"][0]["text"]
    with ThreatVeilClient("https://host.example") as client:
        with pytest.raises(ValueError, match="authenticated"):
            ThreatVeilMCPServer(client)


def test_mcp_read_uses_fixed_authenticated_api_and_rejects_origin_or_path_override():
    calls = []
    identifier = str(uuid4())

    def transport(request):
        calls.append(request)
        return httpx.Response(200, json={"id": identifier, "release_action": "BLOCK"})

    with httpx.Client(transport=httpx.MockTransport(transport)) as http_client:
        with ThreatVeilClient(
            "https://control.example", "SYNTHETIC_TOKEN", http_client=http_client
        ) as client:
            server = ThreatVeilMCPServer(client)
            initialize(server)
            result = server.handle(
                request(
                    "tools/call",
                    {"name": "threatveil_get_release", "arguments": {"id": identifier}},
                )
            )
            assert result["result"]["structuredContent"]["release_action"] == "BLOCK"
            for arguments in (
                {"id": identifier, "base_url": "https://attacker.invalid"},
                {"id": "../billing"},
            ):
                invalid = server.handle(
                    request(
                        "tools/call", {"name": "threatveil_get_release", "arguments": arguments}
                    )
                )
                assert invalid["error"]["code"] == -32602
    assert len(calls) == 1
    assert str(calls[0].url) == f"https://control.example/v1/releases/{identifier}"
    assert calls[0].method == "GET"
    assert calls[0].headers["Authorization"] == "Bearer SYNTHETIC_TOKEN"


def test_mcp_http_failures_never_reveal_response_payload_or_token():
    def transport(request):
        return httpx.Response(403, json={"detail": "PRIVATE_SECRET"})

    with httpx.Client(transport=httpx.MockTransport(transport)) as http_client:
        with ThreatVeilClient(
            "https://control.example", "SYNTHETIC_TOKEN", http_client=http_client
        ) as client:
            server = ThreatVeilMCPServer(client)
            initialize(server)
            result = server.handle(request("tools/call", {"name": "threatveil_properties"}))
    assert result["result"]["isError"]
    assert "403" in json.dumps(result)
    assert "PRIVATE_SECRET" not in json.dumps(result)
    assert "SYNTHETIC_TOKEN" not in json.dumps(result)


def test_mcp_stdio_framing_notifications_duplicate_json_and_size_bounds():
    messages = [
        request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "acceptance", "version": "1"},
            },
        ),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        request("resources/list", identifier=2),
    ]
    incoming = io.BytesIO(("\n".join(json.dumps(m) for m in messages) + "\n").encode())
    outgoing = io.StringIO()
    serve(ThreatVeilMCPServer(), incoming, outgoing)
    responses = [json.loads(line) for line in outgoing.getvalue().splitlines()]
    assert len(responses) == 2 and responses[-1]["id"] == 2
    outgoing = io.StringIO()
    serve(
        ThreatVeilMCPServer(),
        io.BytesIO(b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}\n'),
        outgoing,
    )
    assert json.loads(outgoing.getvalue())["error"]["code"] == -32700
    outgoing = io.StringIO()
    serve(ThreatVeilMCPServer(), io.BytesIO(b"x" * (MAX_REQUEST_BYTES + 2)), outgoing)
    assert json.loads(outgoing.getvalue())["error"]["code"] == -32600


@pytest.mark.parametrize(
    "message",
    [
        request("initialize", {"protocolVersion": "2099-01-01"}),
        request("ping", [], True),
        {"method": "ping", "id": 1},
    ],
)
def test_mcp_rejects_unsupported_protocol_or_invalid_rpc(message):
    assert "error" in ThreatVeilMCPServer().handle(message)


def test_mcp_resource_uri_cannot_read_files_or_network():
    server = ThreatVeilMCPServer()
    initialize(server)
    for uri in ("file:///etc/passwd", "https://example.com", "threatveil://schemas/../../secrets"):
        assert server.handle(request("resources/read", {"uri": uri}))["error"]["code"] == -32002


def test_cli_normalize_stays_local_and_never_overwrites_output(tmp_path, monkeypatch):
    monkeypatch.delenv("TV_API_TOKEN", raising=False)
    output = tmp_path / "normalized.json"
    runner = CliRunner()
    args = [
        "normalize",
        "mcp_tools",
        "integrations/intake-examples/mcp-tools.json",
        "--output",
        str(output),
    ]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert json.loads(output.read_text())["review_required"] is True
    before = output.read_bytes()
    assert runner.invoke(app, args).exit_code != 0
    assert output.read_bytes() == before
    assert (
        runner.invoke(
            app, ["normalize", "unsupported", "integrations/intake-examples/mcp-tools.json"]
        ).exit_code
        != 0
    )


def test_sdk_release_and_intake_are_bounded_and_keep_idempotency():
    calls = []

    def transport(request):
        calls.append(request)
        return httpx.Response(200, json={"id": str(uuid4()), "items": []})

    identifier = str(uuid4())
    with httpx.Client(transport=httpx.MockTransport(transport)) as http_client:
        with ThreatVeilClient(
            "https://control.example", "SYNTHETIC_TOKEN", http_client=http_client
        ) as client:
            client.list_releases(system_id=identifier, cursor="a+b/=", limit=2)
            client.import_integration(
                "sarif",
                system_id=identifier,
                payload={"version": "2.1.0", "runs": []},
                idempotency_key="stable-key",
            )
            client.create_release(identifier)
            with pytest.raises(ValueError):
                client.list_properties(limit=201)
            with pytest.raises(ValueError):
                client.get_proof_plan("../billing")
            with pytest.raises(ValueError):
                client.import_integration("../billing", system_id=identifier, payload={})
    assert calls[0].url.params["cursor"] == "a+b/="
    assert json.loads(calls[1].content)["idempotency_key"] == "stable-key"
    assert json.loads(calls[2].content)["policy"] == {"mode": "WARN"}
    assert len(calls) == 3


def test_real_stdio_process_only_emits_json_rpc_and_public_data():
    messages = [
        request("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                               "clientInfo": {"name": "process-test", "version": "1"}}),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        request("tools/call", {"name": "threatveil_templates"}, identifier=2),
        request("tools/call", {"name": "threatveil_properties"}, identifier=3),
    ]
    environment = {key: value for key, value in os.environ.items() if key != "TV_API_TOKEN"}
    process = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "threatveil.sdk.mcp_server"],
        input="".join(json.dumps(message) + "\n" for message in messages),
        text=True, capture_output=True, timeout=20, check=True, env=environment,
    )
    responses = [json.loads(line) for line in process.stdout.splitlines()]
    assert [response["id"] for response in responses] == [1, 2, 3]
    assert responses[1]["result"]["structuredContent"]["items"]
    assert responses[2]["result"]["isError"] is True
    assert process.stderr == ""


def test_cli_receipt_verifies_external_key_and_scope_without_claiming_freshness(tmp_path):
    organization, system = str(uuid4()), str(uuid4())
    decision = {
        "id": str(uuid4()), "organization_id": organization, "system_id": system,
        "evaluated_at": "2026-09-10T10:00:00+00:00", "candidate_fingerprint_digest": "a" * 64,
        "candidate": {"type": "git_commit", "id": "repository", "version": "b" * 40,
                      "digest": "b" * 40},
        "release_action": "BLOCK", "underlying_action": "BLOCK",
        "policy": {"mode": "BLOCK", "property_modes": {}},
        "properties": [], "exceptions": [], "limitations": ["No qualified proof"],
    }
    key = Ed25519PrivateKey.generate()
    receipt_path, key_path = tmp_path / "receipt.json", tmp_path / "trusted.pem"
    receipt_path.write_text(json.dumps({"envelope": sign_release_receipt(decision, key)}))
    key_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    args = ["verify-receipt", str(receipt_path), "--public-key", str(key_path),
            "--candidate-fingerprint", "a" * 64, "--organization", organization,
            "--system", system]
    runner = CliRunner()
    verified = runner.invoke(app, args)
    assert verified.exit_code == 0, verified.output
    assert json.loads(verified.output)["historical_only"] is True
    assert runner.invoke(app, [*args, "--require-action", "ALLOW"]).exit_code == 1
    assert runner.invoke(app, [*args[:-1], str(uuid4())]).exit_code == 1
    key_path.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    assert runner.invoke(app, args).exit_code == 1


def modern(method, params=None, identifier=1, version=None):
    """Stateless request: version, identity and capabilities travel per request."""
    body = dict(params or {})
    body["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": version or MODERN_PROTOCOL,
        "io.modelcontextprotocol/clientInfo": {"name": "acceptance", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    return {"jsonrpc": "2.0", "id": identifier, "method": method, "params": body}


def test_modern_requests_are_served_statelessly_without_a_handshake():
    server = ThreatVeilMCPServer()
    discover = server.handle(modern("server/discover"))["result"]
    assert discover["resultType"] == "complete"
    assert discover["supportedVersions"] == [MODERN_PROTOCOL, PROTOCOL_VERSION]
    assert discover["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "threatveil"
    assert discover["ttlMs"] > 0 and discover["cacheScope"] == "public"
    # No initialize, no notifications/initialized: the catalog is immediately readable.
    tools = server.handle(modern("tools/list"))["result"]
    assert tools["resultType"] == "complete" and tools["cacheScope"] == "public"
    assert all(t["annotations"]["readOnlyHint"] for t in tools["tools"])
    assert server.initialized is False and server.ready is False


def test_modern_unsupported_version_returns_the_specification_error():
    server = ThreatVeilMCPServer()
    error = server.handle(modern("tools/list", version="1900-01-01"))["error"]
    assert error["code"] == -32022
    assert error["data"]["supported"] == [MODERN_PROTOCOL, PROTOCOL_VERSION]
    assert error["data"]["requested"] == "1900-01-01"


def test_modern_requests_require_client_capabilities_and_reject_the_handshake():
    server = ThreatVeilMCPServer()
    request = modern("tools/list")
    del request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]
    assert server.handle(request)["error"]["code"] == -32602
    assert server.handle(modern("initialize"))["error"]["code"] == -32600
    # A legacy revision may not be declared through per-request metadata.
    assert server.handle(modern("tools/list", version=PROTOCOL_VERSION))["error"]["code"] == -32602


def test_modern_unknown_resource_uses_the_replacement_error_code():
    server = ThreatVeilMCPServer()
    assert server.handle(
        modern("resources/read", {"uri": "threatveil://schemas/missing"})
    )["error"]["code"] == -32602
    initialize(server)
    # The retired code remains correct for a client on the handshake revision.
    assert server.handle(
        request("resources/read", {"uri": "threatveil://schemas/missing"})
    )["error"]["code"] == -32002


def test_legacy_discovery_is_refused_and_the_handshake_still_works():
    server = ThreatVeilMCPServer()
    assert server.handle(request("server/discover"))["error"]["code"] == -32601
    initialize(server)
    tools = server.handle(request("tools/list"))["result"]
    # Earlier revisions carry neither resultType nor cache hints.
    assert "resultType" not in tools and "ttlMs" not in tools


def test_modern_tool_results_are_typed_but_never_cacheable():
    server = ThreatVeilMCPServer()
    result = server.handle(
        modern("tools/call", {"name": "threatveil_templates", "arguments": {}})
    )["result"]
    assert result["resultType"] == "complete" and not result["isError"]
    assert "ttlMs" not in result and "cacheScope" not in result
