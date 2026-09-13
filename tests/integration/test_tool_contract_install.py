"""Tool contract drafts preserve real PostgreSQL tenancy, review and execution gates."""

import json
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


def payload(system_id):
    return {
        "system_id": system_id,
        "reviewed": True,
        "binding": {
            "tool": "erp.beneficiary",
            "tool_version": "v1",
            "operation": "beneficiary.update",
            "boundary": "beneficiary-approval",
            "witness_id": "erp-ledger",
            "principal": {"id": "agent", "tenant_id": "fixture-tenant"},
            "resource": {"type": "beneficiary", "id": "vendor-1", "tenant_id": "fixture-tenant"},
            "approver_id": "finance-reviewer",
            "initial_state": {"account": "SYNTHETIC-OLD"},
            "allowed_state": {"account": "SYNTHETIC-APPROVED"},
        },
    }


def test_install_creates_six_drafts_without_runs_then_uses_existing_approval(owner):
    demo = owner.post("/v1/demo/setup", json={}).json()
    catalogue = owner.get("/v1/tool-contracts")
    assert catalogue.status_code == 200
    assert len(catalogue.json()["items"][0]["axes"]) == 6
    result = owner.post("/v1/tool-contracts/install", json=payload(demo["system"]["id"]))
    assert result.status_code == 201, result.text
    bundle = result.json()
    assert bundle["status"] == "DRAFT" and len(bundle["items"]) == 6
    assert all(
        not prop["approved"] and prop["binding_digest"] == bundle["binding_digest"]
        for prop in bundle["items"]
    )
    assert owner.get("/v1/runs").json()["items"] == []
    prop = bundle["items"][0]
    rejected = owner.post(
        "/v1/runs",
        json={
            "system_id": demo["system"]["id"],
            "target_id": demo["target"]["id"],
            "property_id": prop["id"],
            "version": "fixed",
            "idempotency_key": str(uuid4()),
        },
    )
    assert rejected.status_code == 409
    assert "approv" in rejected.json()["detail"].lower()
    approved = owner.post(f"/v1/properties/{prop['id']}/approve", json={})
    assert approved.status_code == 200, approved.text
    assert approved.json()["approved"] and approved.json()["id"] != prop["id"]
    assert approved.json()["tool_contract_id"] == bundle["bundle_id"]
    assert owner.get("/v1/runs").json()["items"] == []
    exported = [json.loads(line) for line in owner.get("/v1/memory/export").text.splitlines()]
    assert any(
        row.get("kind") == "tool_contract" and row["id"] == bundle["bundle_id"] for row in exported
    )


def test_installer_cannot_reference_or_read_other_tenant_contracts(owner):
    system = owner.post("/v1/systems", json={"name": "Owner system"}).json()
    with TestClient(api.app) as other:
        login(other)
        denied = other.post("/v1/tool-contracts/install", json=payload(system["id"]))
        assert denied.status_code == 404
        assert other.get("/v1/properties").json()["items"] == []
        identity = other.get("/v1/auth/me").json()
    installed = owner.post("/v1/tool-contracts/install", json=payload(system["id"])).json()
    with transaction(org_id=UUID(identity["organization"]["id"])) as session:
        assert (
            session.scalar(select(Record).where(Record.id == UUID(installed["bundle_id"]))) is None
        )


def test_review_required_and_invalid_bindings_fail_before_any_draft_write(owner):
    system = owner.post("/v1/systems", json={"name": "Reviewed system"}).json()
    invalid = payload(system["id"])
    invalid["reviewed"] = False
    assert owner.post("/v1/tool-contracts/install", json=invalid).status_code == 422
    invalid["reviewed"] = True
    invalid["binding"]["resource"]["tenant_id"] = "different-tenant"
    assert owner.post("/v1/tool-contracts/install", json=invalid).status_code == 422
    assert owner.get("/v1/properties").json()["items"] == []


def test_viewer_cannot_install_and_developer_cannot_approve(owner):
    system = owner.post("/v1/systems", json={"name": "Role boundary"}).json()
    identity = owner.get("/v1/auth/me").json()
    org_id, user_id = UUID(identity["organization"]["id"]), UUID(identity["user"]["id"])
    with transaction(user_id, org_id) as session:
        session.get(Membership, (org_id, user_id)).role = "viewer"
    assert owner.get("/v1/tool-contracts").status_code == 200
    assert owner.post("/v1/tool-contracts/install", json=payload(system["id"])).status_code == 403
    with transaction(user_id, org_id) as session:
        session.get(Membership, (org_id, user_id)).role = "developer"
    created = owner.post("/v1/tool-contracts/install", json=payload(system["id"]))
    assert created.status_code == 201
    prop = created.json()["items"][0]
    assert owner.post(f"/v1/properties/{prop['id']}/approve", json={}).status_code == 403


def test_missing_csrf_cannot_install(owner):
    system = owner.post("/v1/systems", json={"name": "CSRF boundary"}).json()
    del owner.headers["x-csrf-token"]
    assert owner.post("/v1/tool-contracts/install", json=payload(system["id"])).status_code == 403
