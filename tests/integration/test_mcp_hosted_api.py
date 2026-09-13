"""MCP history reads use actual tenant API authentication and PostgreSQL scope."""

from uuid import uuid4

from fastapi.testclient import TestClient

from threatveil.api import app
from threatveil.sdk.client import ThreatVeilClient
from threatveil.sdk.mcp_server import PROTOCOL_VERSION, ThreatVeilMCPServer

from test_product import customer as customer, run, setup, with_enforcement


def call(server, name, **arguments):
    return server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                          "params": {"name": name, "arguments": arguments}})["result"]


def server_for(http_client, token):
    client = ThreatVeilClient("http://127.0.0.1:8000", token, http_client=http_client)
    server = ThreatVeilMCPServer(client)
    server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
        "clientInfo": {"name": "hosted-acceptance", "version": "1"}}})
    server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return server


def token_for(owner):
    response = owner.post("/v1/api-tokens", json={
        "name": "Read-only MCP acceptance", "permission": "read", "expires_in_days": 1})
    assert response.status_code == 201, response.text
    return response.json()


def test_mcp_read_token_sees_own_release_and_immediately_honors_revocation(customer):
    demo = setup(customer)
    result = run(customer, demo, "fixed")
    plan = customer.post("/v1/proof-plans", json={
        "system_id": demo["system"]["id"], "candidate": result["candidate"],
        "fingerprint": result["fingerprint"], "trials_per_variant": 2})
    assert plan.status_code == 201, plan.text
    with_enforcement(customer)
    release = customer.post("/v1/releases", json={
        "plan_id": plan.json()["id"], "policy": {"mode": "BLOCK"}})
    assert release.status_code == 201, release.text
    release_id = release.json()["id"]
    token = token_for(customer)
    with TestClient(app) as hosted, TestClient(app) as other:
        server = server_for(hosted, token["token"])
        own = call(server, "threatveil_get_release", id=release_id)
        assert not own["isError"]
        assert own["structuredContent"]["release_action"] == "ALLOW"
        properties = call(server, "threatveil_properties", system_id=demo["system"]["id"])
        assert {item["id"] for item in properties["structuredContent"]["items"]} == {
            demo["property"]["id"]}
        login = other.post("/v1/auth/local", json={"email": f"{uuid4()}@local.invalid"},
                           headers={"origin": "http://127.0.0.1:3000"})
        assert login.status_code == 200, login.text
        other.headers.update({"origin": "http://127.0.0.1:3000",
                              "x-csrf-token": login.json()["csrf_token"]})
        other_token = token_for(other)
        with TestClient(app) as other_hosted:
            other_server = server_for(other_hosted, other_token["token"])
            denied = call(other_server, "threatveil_get_release", id=release_id)
            assert denied["isError"] and "404" in denied["content"][0]["text"]
            assert call(other_server, "threatveil_properties")["structuredContent"]["items"] == []
        assert customer.delete(f"/v1/api-tokens/{token['id']}").status_code == 200
        revoked = call(server, "threatveil_get_release", id=release_id)
        assert revoked["isError"] and "401" in revoked["content"][0]["text"]
