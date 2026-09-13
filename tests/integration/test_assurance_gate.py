"""The Assurance Gate: every status a consumer must distinguish, and none authorizes."""

from datetime import timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select

from threatveil.db import Record, now, transaction
from test_assurance_intelligence import change, cleared, finance, other_tenant
from test_product import customer as customer  # noqa: F401


def gate(client, setup, **params):
    response = client.get(f"/v1/systems/{setup['system_id']}/assurance/current", params=params)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["authorizes"] is False and body["schema_version"] == "threatveil-assurance-gate/v1"
    return body


def test_current_clearance_is_cleared_and_bounded_in_time(customer):
    setup, baseline = cleared(customer)
    body = gate(customer, setup)
    assert (body["status"], body["action"], body["cleared"]) == ("CURRENT", "ALLOW", True)
    assert body["decision"]["id"] == baseline["authorization_id"]
    assert body["state"]["digest"] and body["authority"]["envelope_digest"]
    assert body["freshness"]["max_age_seconds"] == 60 and body["freshness"]["valid_until"] > body["evaluated_at"]
    assert "UNKNOWN" in body["consumer_contract"] and body["claims"] == {"total": 3, "supported": 3, "affected": []}


def test_an_observed_change_supersedes_and_scoped_authority_is_reported_separately(customer):
    setup, _ = cleared(customer)
    change(customer, setup, "beneficiary_approval_relaxed")
    body = gate(customer, setup)
    assert (body["status"], body["cleared"]) == ("SUPERSEDED", False)
    assert [c["title"] for c in body["claims"]["affected"]] == ["Beneficiary changes require finance approval"]
    invoice = gate(customer, setup, action="invoice.update")
    assert invoice["scope"]["status"] == "SUPPORTED" and invoice["scope"]["cleared"] is False
    beneficiary = gate(customer, setup, action="beneficiary.update")
    assert beneficiary["scope"]["status"] == "NEEDS_FRESH_EVIDENCE"
    outside = gate(customer, setup, action="payment.execute")
    assert outside["scope"]["status"] == "UNDECLARED" and not outside["scope"]["cleared"]


def test_expired_authority_is_expired_never_current(customer, monkeypatch):
    setup, _ = cleared(customer)
    later = now() + timedelta(days=31)
    for module in ("threatveil.change_assurance", "threatveil.change_assurance_api", "threatveil.assurance_intelligence"):
        monkeypatch.setattr(f"{module}.now", lambda: later)
    body = gate(customer, setup)
    assert (body["status"], body["cleared"]) == ("EXPIRED", False)
    assert body["decision"]["signed_statement_live"] is False


def test_moved_support_without_an_observed_change_requires_reassessment(customer, monkeypatch):
    setup, _ = cleared(customer)
    from threatveil import commercial
    from threatveil.connectors import configuration, record_failure
    from threatveil.db import get_record

    monkeypatch.setattr(commercial, "can_use_connector_role", lambda *args: True)
    installed = customer.post("/v1/connectors", json={
        "system_id": setup["system_id"], "environment_id": setup["environment_id"], "connector_id": "otel",
        "mode": "PUSH", "roles": ["OBSERVE"], "name": "Runtime telemetry", "configuration": {},
        "expires_at": (now() + timedelta(days=1)).isoformat()})
    assert installed.status_code == 201, installed.text
    org = UUID(customer.get("/v1/auth/me").json()["organization"]["id"])
    with transaction(org_id=org) as session:
        source = get_record(session, org, installed.json()["id"], "connector_installation")
        record_failure(session, org, source, configuration(session, org, source), "UNAVAILABLE")
    body = gate(customer, setup)
    assert (body["status"], body["cleared"]) == ("REASSESS", False)
    assert any(o["kind"] == "RECONNECT_SOURCE" for o in body["obligations"])


def test_revoked_clearance_is_revoked(customer):
    setup, baseline = cleared(customer)
    revoked = customer.post(f"/v1/change-assurance/decisions/{baseline['authorization_id']}/revoke",
                            json={"reason": "Security owner withdrew this clearance"})
    assert revoked.status_code == 201, revoked.text
    assert (gate(customer, setup)["status"], gate(customer, setup)["cleared"]) == ("REVOKED", False)


def test_unknown_never_means_authorization(customer):
    system = customer.post("/v1/systems", json={"name": "Claims agent", "description": "Adjusts claims",
                                                "actions": [], "access": []})
    assert system.status_code == 201, system.text
    body = gate(customer, {"system_id": system.json()["id"]})
    assert (body["status"], body["cleared"], body["decision"]) == ("UNKNOWN", False, None)
    assert body["reasons"] == ["No environment is defined for this system."]


def test_a_stale_state_the_consumer_holds_is_superseded(customer):
    setup, _ = cleared(customer)
    body = gate(customer, setup, expected_state_digest="0" * 64)
    assert (body["status"], body["cleared"]) == ("SUPERSEDED", False)
    current = gate(customer, setup)
    assert gate(customer, setup, expected_state_digest=current["state"]["digest"])["cleared"] is True
    assert customer.get(f"/v1/systems/{setup['system_id']}/assurance/current",
                        params={"expected_state_digest": "not-a-digest"}).status_code == 422


def test_the_gate_refuses_another_tenant(customer):
    setup, _ = cleared(customer)
    assert other_tenant().get(f"/v1/systems/{setup['system_id']}/assurance/current").status_code == 404


def test_gate_consumption_is_recorded_once_per_consumer_and_hour(customer):
    setup = finance(customer)
    for _ in range(3):
        customer.get(f"/v1/systems/{setup['system_id']}/assurance/current", headers={"x-threatveil-consumer": "ci-gate"})
    customer.get(f"/v1/systems/{setup['system_id']}/assurance/current", headers={"x-threatveil-consumer": "Bad Label!"})
    org = UUID(customer.get("/v1/auth/me").json()["organization"]["id"])
    with transaction(org_id=org) as session:
        consumers = session.scalars(select(Record.payload["consumer"].astext).where(
            Record.organization_id == org, Record.kind == "service_metric",
            Record.payload["name"].astext == "assurance_gate.checked")).all()
        assert sorted(consumers) == ["person:ci-gate", "person:unspecified"]
        assert session.scalar(select(func.count()).select_from(Record).where(
            Record.organization_id == org, Record.kind == "service_metric")) >= 2


def test_a_machine_read_token_can_consume_the_gate(customer):
    setup, _ = cleared(customer)
    token = customer.post("/v1/api-tokens", json={"name": "CI gate", "permission": "read",
                                                  "expires_at": (now() + timedelta(days=7)).isoformat()})
    if token.status_code != 201:
        token = customer.post("/v1/api-tokens", json={"name": "CI gate", "permission": "read"})
    assert token.status_code == 201, token.text
    secret = token.json().get("token") or token.json().get("secret")
    from fastapi.testclient import TestClient
    from threatveil.api import app

    machine = TestClient(app, client=("127.202.1.1", 50000))
    body = machine.get(f"/v1/systems/{setup['system_id']}/assurance/current",
                       headers={"authorization": f"Bearer {secret}", "x-threatveil-consumer": str(uuid4())[:8]})
    assert body.status_code == 200, body.text
    assert body.json()["cleared"] is True
    assert machine.post(f"/v1/systems/{setup['system_id']}/passports", json={},
                        headers={"authorization": f"Bearer {secret}"}).status_code == 403
