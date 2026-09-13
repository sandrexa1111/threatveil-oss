"""Actual PostgreSQL tenancy, immutable intake, review and idempotency checks."""

import copy
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from threatveil import api
from threatveil.config import settings
from threatveil.db import Membership, Record, transaction

ORIGIN = "http://127.0.0.1:3000"


def login(client):
    client.cookies.set("tv_session", str(uuid4()))
    response = client.post(
        "/v1/auth/local", json={"email": f"{uuid4()}@local.invalid"}, headers={"origin": ORIGIN}
    )
    assert response.status_code == 200, response.text
    client.headers.update({"origin": ORIGIN, "x-csrf-token": response.json()["csrf_token"]})


@pytest.fixture
def owner(monkeypatch):
    monkeypatch.setenv("TV_ENV", "test")
    monkeypatch.setenv("TV_LOCAL_AUTH", "true")
    settings.cache_clear()
    with TestClient(api.app) as client:
        login(client)
        yield client
    settings.cache_clear()


def body(system_id, key=None):
    return {
        "system_id": system_id,
        "idempotency_key": key or str(uuid4()),
        "payload": {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "scanner", "version": "1"}},
                    "results": [
                        {
                            "ruleId": "AUTH-1",
                            "message": {"text": "Missing authorization"},
                            "level": "error",
                            "suppressions": [{"kind": "inSource", "status": "accepted"}],
                        }
                    ],
                }
            ],
        },
    }


def test_intake_persists_source_and_draft_findings_without_qualification(owner):
    system = owner.post("/v1/systems", json={"name": "Intake system"}).json()
    request = body(system["id"])
    created = owner.post("/v1/integrations/intake/sarif", json=request)
    assert created.status_code == 201, created.text
    intake = created.json()
    assert intake["status"] == "DRAFT"
    assert intake["cross_customer_use"] is False
    assert "payload" not in intake
    finding = owner.get("/v1/findings").json()["items"][0]
    assert finding["source_type"] == "sarif"
    assert finding["status"] == "DRAFT"
    assert finding["suppressions"][0]["status"] == "accepted"
    assert finding["provenance"]["source_digest"] == intake["source_digest"]
    assert finding["id"] in intake["finding_ids"]
    assert owner.get("/v1/properties").json()["items"] == []
    assert owner.get("/v1/runs").json()["items"] == []
    replay = owner.post("/v1/integrations/intake/sarif", json=request)
    assert replay.status_code == 201 and replay.json()["id"] == intake["id"]
    assert len(owner.get("/v1/findings").json()["items"]) == 1
    request["payload"]["runs"][0]["results"][0]["message"]["text"] = "Different finding"
    assert owner.post("/v1/integrations/intake/sarif", json=request).status_code == 409


def test_intake_is_tenant_scoped_in_api_and_forced_rls(owner):
    system = owner.post("/v1/systems", json={"name": "Owned system"}).json()
    intake = owner.post("/v1/integrations/intake/sarif", json=body(system["id"])).json()
    with TestClient(api.app) as other:
        login(other)
        assert (
            other.post("/v1/integrations/intake/sarif", json=body(system["id"])).status_code == 404
        )
        assert other.get(f"/v1/integrations/intake/{intake['id']}").status_code == 404
        assert (
            other.get("/v1/integrations/intake", params={"system_id": system["id"]}).status_code
            == 404
        )
        assert other.get("/v1/integrations/intake").json()["items"] == []
        identity = other.get("/v1/auth/me").json()
    with transaction(org_id=UUID(identity["organization"]["id"])) as session:
        assert session.scalar(select(Record).where(Record.id == UUID(intake["id"]))) is None


def test_malformed_intake_rolls_back_all_findings_and_does_not_echo_secrets(owner, capsys):
    system = owner.post("/v1/systems", json={"name": "Invalid source"}).json()
    payload = body(system["id"])
    payload["payload"]["runs"][0]["results"].append({"message": {"id": "PRIVATE_SECRET"}})
    response = owner.post("/v1/integrations/intake/sarif", json=payload)
    assert response.status_code == 422
    assert "PRIVATE_SECRET" not in response.text
    assert "PRIVATE_SECRET" not in capsys.readouterr().out
    assert owner.get("/v1/findings").json()["items"] == []
    assert owner.get("/v1/integrations/intake").json()["items"] == []


def test_intake_requires_mutator_csrf_and_supports_bounded_pagination(owner):
    system = owner.post("/v1/systems", json={"name": "Review roles"}).json()
    identity = owner.get("/v1/auth/me").json()
    org, user = UUID(identity["organization"]["id"]), UUID(identity["user"]["id"])
    for _ in range(2):
        assert (
            owner.post("/v1/integrations/intake/sarif", json=body(system["id"])).status_code == 201
        )
    first = owner.get("/v1/integrations/intake", params={"limit": 1}).json()
    second = owner.get(
        "/v1/integrations/intake", params={"limit": 1, "cursor": first["pagination"]["next_cursor"]}
    ).json()
    assert first["items"][0]["id"] != second["items"][0]["id"]
    assert "normalized" not in first["items"][0]
    with transaction(user, org) as session:
        session.get(Membership, (org, user)).role = "viewer"
    assert owner.post("/v1/integrations/intake/sarif", json=body(system["id"])).status_code == 403
    assert owner.get("/v1/integrations/intake").status_code == 200
    with transaction(user, org) as session:
        session.get(Membership, (org, user)).role = "developer"
    del owner.headers["x-csrf-token"]
    assert owner.post("/v1/integrations/intake/sarif", json=body(system["id"])).status_code == 403


def mcp_body(system_id):
    return {
        "system_id": system_id,
        "idempotency_key": str(uuid4()),
        "payload": {
            "server_id": "payments",
            "protocol_version": "2025-11-25",
            "complete": True,
            "tools": [{"name": "update", "inputSchema": {"type": "object"}}],
        },
    }


def review_body(intake):
    fingerprint = copy.deepcopy(intake["normalized"]["fingerprint"])
    fingerprint["components"].append(
        {
            "type": "application",
            "id": "checkout",
            "version": "v2",
            "digest": "a" * 64,
            "provenance": "DECLARED",
        }
    )
    return {
        "source_digest": intake["source_digest"],
        "candidate": {
            "type": "application_version",
            "id": "checkout",
            "version": "v2",
            "digest": "a" * 64,
        },
        "fingerprint": fingerprint,
        "previous_fingerprint": {"components": []},
        "review_reason": "Review the discovered payments contract for candidate v2",
        "idempotency_key": str(uuid4()),
    }


def test_fingerprint_review_is_security_only_exact_and_preserves_unknown(owner):
    system = owner.post("/v1/systems", json={"name": "MCP discovery"}).json()
    response = owner.post("/v1/integrations/intake/mcp_tools", json=mcp_body(system["id"]))
    assert response.status_code == 201, response.text
    intake = response.json()
    review = review_body(intake)
    uri = f"/v1/integrations/intake/{intake['id']}/approve-fingerprint"
    identity = owner.get("/v1/auth/me").json()
    org, user = UUID(identity["organization"]["id"]), UUID(identity["user"]["id"])
    with transaction(user, org) as session:
        session.get(Membership, (org, user)).role = "developer"
    assert owner.post(uri, json=review).status_code == 403
    with transaction(user, org) as session:
        session.get(Membership, (org, user)).role = "security"
    invalid = copy.deepcopy(review)
    for component in invalid["fingerprint"]["components"]:
        if component["type"] == "permissions":
            component["provenance"] = "OBSERVED"
    assert owner.post(uri, json=invalid).status_code == 422
    invalid = copy.deepcopy(review)
    invalid["source_digest"] = "b" * 64
    assert owner.post(uri, json=invalid).status_code == 409
    invalid = copy.deepcopy(review)
    invalid["fingerprint"]["components"] = invalid["fingerprint"]["components"][1:]
    assert owner.post(uri, json=invalid).status_code == 422
    approved = owner.post(uri, json=review)
    assert approved.status_code == 201, approved.text
    saved = approved.json()
    assert saved["status"] == "REVIEWED_DECLARATION"
    assert all(c["provenance"] != "OBSERVED" for c in saved["fingerprint"]["components"])
    assert any(
        c["type"] == "permissions" and c["provenance"] == "UNKNOWN"
        for c in saved["fingerprint"]["components"]
    )
    assert owner.post(uri, json=review).json()["id"] == saved["id"]
    assert owner.get(f"/v1/integrations/intake/{intake['id']}").json()["status"] == "DRAFT"
    assert owner.get("/v1/runs").json()["items"] == []
    with transaction(user, org) as session:
        delta = session.get(Record, UUID(saved["change_set_id"]))
        assert delta.payload["source"] == "reviewed_integration_intake"
        assert delta.payload["unknowns"]


def test_telemetry_private_text_is_not_persisted(owner):
    system = owner.post("/v1/systems", json={"name": "Agent trace"}).json()
    payload = {
        "system_id": system["id"],
        "idempotency_key": str(uuid4()),
        "payload": {
            "spans": [
                {
                    "trace_id": "trace-1",
                    "id": "span-1",
                    "span_data": {
                        "type": "function",
                        "name": "update",
                        "input": "PRIVATE_SECRET",
                        "output": "Success",
                    },
                }
            ]
        },
    }
    response = owner.post("/v1/integrations/intake/openai_agents", json=payload)
    assert response.status_code == 201, response.text
    assert "PRIVATE_SECRET" not in response.text
    obs = response.json()["normalized"]["observations"][0]
    assert obs["task_outcome"] == "UNKNOWN" and not obs["witnesses"][0]["complete"]
