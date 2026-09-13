"""Definition preview: onboarding reads what it can establish, and writes nothing."""

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from threatveil import api
from threatveil.config import settings


ORIGIN = "http://127.0.0.1:3000"
DEFINITION = {
    "permissions": {"allow": ["Bash(git:*)", "Read"], "deny": ["WebFetch"]},
    "mcpServers": {"github": {"command": "gh-mcp"}, "filesystem": {"command": "fs-mcp"}},
    "model": "claude-opus-5",
}


def login(client):
    client.cookies.set("tv_session", str(uuid4()))
    result = client.post("/v1/auth/local", json={"email": f"{uuid4()}@local.invalid"}, headers={"origin": ORIGIN})
    assert result.status_code == 200, result.text
    client.headers.update({"origin": ORIGIN, "x-csrf-token": result.json()["csrf_token"]})


@pytest.fixture
def member(monkeypatch):
    monkeypatch.setenv("TV_ENV", "test")
    monkeypatch.setenv("TV_LOCAL_AUTH", "true")
    settings.cache_clear()
    with TestClient(api.app) as client:
        login(client)
        yield client
    settings.cache_clear()


def test_preview_reports_declared_facts_without_persisting(member):
    systems_before = member.get("/v1/systems").json()
    connectors_before = member.get("/v1/connectors").json()

    result = member.post("/v1/connectors/definition-preview",
                         json={"format": "claude_settings", "document": DEFINITION})

    assert result.status_code == 200, result.text
    body = result.json()
    assert body["format"] == "claude_settings"
    assert body["tools"] == ["Bash(git:*)", "Read"]
    assert body["mcp_servers"] == ["filesystem", "github"]
    # A definition is declared configuration; the preview must say so, not imply proof.
    assert any("declared configuration" in line for line in body["limitations"])
    # Nothing was created: no system, no source, no observation.
    assert member.get("/v1/systems").json() == systems_before
    assert member.get("/v1/connectors").json() == connectors_before


def test_preview_error_never_echoes_customer_configuration(member):
    secret = f"customer-secret-{uuid4()}"
    result = member.post("/v1/connectors/definition-preview",
                         json={"format": "claude_settings", "document": {"permissions": secret}})
    assert result.status_code == 422
    assert secret not in result.text


def test_preview_rejects_unknown_format(member):
    result = member.post("/v1/connectors/definition-preview", json={"format": "not-a-format", "document": {}})
    assert result.status_code == 422


def test_preview_requires_a_session(monkeypatch):
    monkeypatch.setenv("TV_ENV", "test")
    monkeypatch.setenv("TV_LOCAL_AUTH", "true")
    settings.cache_clear()
    with TestClient(api.app) as client:
        result = client.post("/v1/connectors/definition-preview", headers={"origin": ORIGIN},
                             json={"format": "claude_settings", "document": DEFINITION})
    settings.cache_clear()
    assert result.status_code == 401
