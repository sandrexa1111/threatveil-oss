"""Retained qualified relationships outlive raw observations without leaking other tenants."""

from datetime import timedelta
from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from threatveil import api, evidence_storage
from threatveil.db import now
from threatveil.security_memory import entity_reference
from test_observers import observer_customer as observer_customer, qualify, execute


def test_qualified_failure_relationships_survive_raw_expiry(observer_customer, monkeypatch):
    h = observer_customer
    observer = qualify(h)
    failed = execute(h, observer, "vulnerable", candidate="failing-build")
    query = {
        "tool": "erp.beneficiary",
        "principal_id": "procurement-agent",
        "resource_id": "vendor-1",
    }
    response = h[0].post("/v1/memory/query", json=query)
    assert response.status_code == 200, response.text
    rows = response.json()["items"]
    assert len(rows) == 1 and rows[0]["run_id"] == failed["id"]
    facts = rows[0]["facts"]
    assert len(facts) == 1 and facts[0]["phase"] == "COMMITTED" and facts[0]["violation"]
    assert facts[0]["principal_ref"] == entity_reference(
        UUID(h[1]["system"]["organization_id"]), "principal", "procurement-agent"
    )
    assert "vendor-1" not in response.text and "SYNTHETIC-ATTACKER-ACCOUNT" not in response.text
    # Qualification's deliberately prohibited control did not masquerade as a customer failure.
    assert h[0].post("/v1/memory/query", json={}).json()["pagination"]["total"] == 1
    monkeypatch.setattr(evidence_storage, "now", lambda: now() + timedelta(days=31))
    raw = h[0].get(f"/v1/runs/{failed['id']}/captures/{rows[0]['capture_id']}")
    assert raw.status_code == 410
    assert h[0].post("/v1/memory/query", json=query).json()["items"][0]["facts"] == facts
    assert (
        h[0].post("/v1/memory/query", json={"principal_id": "unrelated-principal"}).json()["items"]
        == []
    )


def test_security_memory_query_is_tenant_bound(observer_customer):
    h = observer_customer
    failed = execute(h, qualify(h), "vulnerable", candidate="failing-build")
    with TestClient(api.app) as other:
        login = other.post(
            "/v1/auth/local",
            json={"email": f"{uuid4()}@local.invalid"},
            headers={"origin": "http://127.0.0.1:3000"},
        )
        other.headers.update(
            {"origin": "http://127.0.0.1:3000", "x-csrf-token": login.json()["csrf_token"]}
        )
        query = other.post("/v1/memory/query", json={"tool": "erp.beneficiary"})
        assert query.status_code == 200 and query.json()["items"] == []
        assert failed["id"] not in query.text
