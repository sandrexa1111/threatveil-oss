"""Connector conformance against PostgreSQL: continuity, tenancy, authority and expiry."""

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from threatveil import api, commercial
from threatveil.config import settings
from threatveil.connectors import (
    configuration, installation_health, persist_batch, record_failure, source_changes,
)
from threatveil.connectors.collectors import SourceFailure
from threatveil.connectors.contracts import Snapshot
from threatveil.core.contracts import digest
from threatveil.db import Record, get_record, now, serialize, transaction


ORIGIN = "http://127.0.0.1:3000"
SERVICE = "projects/customer-project/locations/us-central1/services/finance-agent"
ACTUAL_CONNECTOR_CAPABILITY = commercial.can_use_connector_role


def login(client):
    client.cookies.set("tv_session", str(uuid4()))
    result = client.post("/v1/auth/local", json={"email": f"{uuid4()}@local.invalid"},
                         headers={"origin": ORIGIN})
    assert result.status_code == 200, result.text
    client.headers.update({"origin": ORIGIN, "x-csrf-token": result.json()["csrf_token"]})


@pytest.fixture
def owner(monkeypatch):
    monkeypatch.setenv("TV_ENV", "test")
    monkeypatch.setenv("TV_LOCAL_AUTH", "true")
    settings.cache_clear()
    # Connector semantics are tested independently of catalog commercial quotas;
    # a dedicated denial case below exercises the real call-site boundary.
    monkeypatch.setattr(commercial, "can_use_connector_role", lambda *args: True)
    with TestClient(api.app) as client:
        login(client)
        yield client
    settings.cache_clear()


def setup(owner, *, kind="mcp", mode="IMPORT", roles=None, values=None, credential=None):
    system = owner.post("/v1/systems", json={"name": "Finance connector conformance"})
    assert system.status_code == 201, system.text
    environment = owner.post("/v1/change-assurance/environments", json={
        "system_id": system.json()["id"], "name": "Staging", "purpose": "STAGING",
        "boundary": "Synthetic-safe finance records only", "owner": "Finance engineering",
    })
    assert environment.status_code == 201, environment.text
    body = {
        "system_id": system.json()["id"], "environment_id": environment.json()["id"],
        "connector_id": kind, "mode": mode,
        "roles": roles or (["OBSERVE"] if kind == "otel" else ["DISCOVER", "CHANGE"]),
        "name": "Bounded source", "configuration": values or {}, "credential_id": credential,
        "expires_at": (now() + timedelta(days=1)).isoformat(),
    }
    result = owner.post("/v1/connectors", json=body)
    assert result.status_code == 201, result.text
    return result.json(), body


def mcp_payload(tool_names=("invoice.update", "beneficiary.change"), *, complete=True, permission="read"):
    return {"server_id": "forged-external-issuer", "protocol_version": "2025-11-25",
            "complete": complete, "tools": [
                {"name": name, "inputSchema": {"type": "object"}} for name in tool_names
            ], "authorization": {"scope": permission}}


def submit(owner, installation, *, payload=None, sequence=1, valid_at=None,
           cursor=None, previous_cursor=None, event_id=None, telemetry=False):
    return owner.post(f"/v1/connectors/{installation['id']}/{'telemetry' if telemetry else 'import'}", json={
        "event_id": event_id or str(uuid4()), "payload": payload or mcp_payload(),
        "valid_at": (valid_at or now()).isoformat(), "sequence": sequence,
        "cursor": cursor, "previous_cursor": previous_cursor,
    })


def identity(owner):
    value = owner.get("/v1/auth/me").json()
    return UUID(value["user"]["id"]), UUID(value["organization"]["id"])


def test_source_identity_import_status_and_history_remain_unqualified(owner):
    installation, _ = setup(owner)
    result = submit(owner, installation)
    assert result.status_code == 201, result.text
    batch = result.json()
    assert batch["acquisition"] == "IMPORTED" and batch["qualification"] == "UNREVIEWED"
    assert batch["source_identity"] == "source:" + installation["id"]
    assert "forged-external-issuer" not in result.text
    assert batch["running_state_proven"] is False
    state = owner.get(f"/v1/connectors/{installation['id']}").json()["health"]
    assert state["status"] == "IMPORTED" and state["connected"] is False
    assert state["freshness"] == "CURRENT"
    assert owner.get("/v1/properties").json()["items"] == []
    assert owner.get("/v1/runs").json()["items"] == []


def test_duplicate_reorder_cursor_gap_and_partial_snapshot_preserve_truth(owner):
    installation, _ = setup(owner)
    first_at = now() - timedelta(seconds=10)
    event_id = str(uuid4())
    first = submit(owner, installation, sequence=1, cursor="first", event_id=event_id,
                   valid_at=first_at).json()
    duplicate = submit(owner, installation, sequence=1, cursor="first", event_id=event_id,
                       valid_at=first_at)
    assert duplicate.json()["id"] == first["id"]
    conflict = submit(owner, installation, sequence=1, cursor="first", event_id=event_id,
                      valid_at=first_at, payload=mcp_payload(permission="admin"))
    assert conflict.status_code == 409
    partial = submit(owner, installation, sequence=3, cursor="third", previous_cursor="lost",
                     payload=mcp_payload(("invoice.update",), complete=False)).json()
    assert partial["continuity"] == "CURSOR_GAP"
    assert any("beneficiary.change" in key for key in partial["components"])
    late = submit(owner, installation, sequence=2, cursor="second", previous_cursor="first",
                  valid_at=first_at + timedelta(seconds=1)).json()
    assert late["delivery"] == "REORDERED" and not late["projects_current"]
    state = owner.get(f"/v1/connectors/{installation['id']}").json()["health"]
    assert state["watermark"] == {"sequence": 3, "cursor": "third"}
    assert state["continuity"] == "CURSOR_GAP" and state["freshness"] == "UNKNOWN"
    next_batch = submit(owner, installation, sequence=4, cursor="fourth", previous_cursor="third").json()
    assert next_batch["continuity"] == "CURSOR_GAP"
    rows = owner.get(f"/v1/connectors/{installation['id']}/history", params={"kind": "source_batch"}).json()["items"]
    assert len(rows) == 4  # duplicate and conflicting replay never append another event


def test_changed_permissions_have_before_after_and_no_github_dependency(owner):
    installation, _ = setup(owner)
    first = submit(owner, installation).json()
    second = submit(owner, installation, sequence=2, payload=mcp_payload(permission="write")).json()
    user, org = identity(owner)
    with transaction(user, org) as session:
        changes = source_changes(session, org, installation["system_id"], installation["environment_id"])
    last = changes[0]
    assert last["before_digest"] == first["snapshot_digest"]
    assert last["after_digest"] == second["snapshot_digest"]
    assert any(key.startswith("permissions:") for key in last["changed_components"])
    assert last["requires_reassessment"] and last["transition"] == "OBSERVED"
    assert last["prevented"] is False


def test_outage_expiry_and_reconfiguration_cannot_reuse_old_source_freshness(owner):
    installation, body = setup(owner)
    first = submit(owner, installation).json()
    user, org = identity(owner)
    with transaction(user, org) as session:
        row = get_record(session, org, installation["id"], "connector_installation")
        current = configuration(session, org, row)
        record_failure(session, org, row, current, "UNAVAILABLE")
        state = installation_health(session, org, row)
        assert state["freshness"] == "UNKNOWN" and state["failure"] == "UNAVAILABLE"
        stale = installation_health(session, org, row, at=now() + timedelta(minutes=10))
        assert stale["freshness"] == "STALE"
        expired = installation_health(session, org, row, at=now() + timedelta(days=2))
        assert expired["status"] == "EXPIRED" and expired["freshness"] == "UNKNOWN"
    reconfigured = owner.post(f"/v1/connectors/{installation['id']}/configuration", json={
        "configuration": {}, "expires_at": body["expires_at"], "reason": "Reapprove source scope after review",
    })
    assert reconfigured.status_code == 201, reconfigured.text
    state = owner.get(f"/v1/connectors/{installation['id']}").json()["health"]
    assert state["freshness"] == "UNKNOWN" and state["last_valid_at"] is None
    with transaction(user, org) as session:
        assert serialize(get_record(session, org, first["id"], "source_batch"))["snapshot_digest"] == first["snapshot_digest"]


def test_cross_tenant_wrong_environment_and_credential_references_are_rejected(owner):
    installation, body = setup(owner)
    with TestClient(api.app) as other:
        login(other)
        assert other.get(f"/v1/connectors/{installation['id']}").status_code == 404
        assert submit(other, installation).status_code == 404
        assert other.post("/v1/connectors", json=body).status_code == 404
        assert other.get("/v1/connectors").json()["items"] == []
        _, other_org = identity(other)
    with transaction(org_id=other_org) as session:
        assert session.scalar(select(Record).where(Record.id == UUID(installation["id"]))) is None
    changed = {**body, "system_id": str(uuid4())}
    assert owner.post("/v1/connectors", json=changed).status_code == 404
    changed = {**body, "connector_id": "gcp_cloud_run", "mode": "POLL",
               "configuration": {"service": SERVICE}, "credential_id": str(uuid4())}
    assert owner.post("/v1/connectors", json=changed).status_code == 404


def test_read_role_no_enforcement_forged_authority_future_time_and_entitlement(owner, monkeypatch):
    installation, body = setup(owner)
    assert owner.post("/v1/connectors", json={**body, "roles": ["ENFORCE"]}).status_code == 422
    assert owner.post("/v1/connectors", json={**body, "source_identity": "forged"}).status_code == 422
    assert submit(owner, installation, valid_at=now() + timedelta(hours=1)).status_code == 422
    wrong = owner.post(f"/v1/connectors/{installation['id']}/import", json={
        "event_id": str(uuid4()), "payload": mcp_payload(), "valid_at": now().isoformat(),
        "acquisition": "API_OBSERVED", "qualification": "SOURCE_QUALIFIED",
    })
    assert wrong.status_code == 422
    assert owner.post(f"/v1/connectors/{installation['id']}/collect", json={"event_id": str(uuid4())}).status_code == 422
    first = submit(owner, installation).json()
    monkeypatch.setattr(commercial, "can_use_connector_role", lambda *args: False)
    assert submit(owner, installation, sequence=2).status_code == 402
    rows = owner.get(f"/v1/connectors/{installation['id']}/history", params={"kind": "source_batch"}).json()["items"]
    assert [row["id"] for row in rows] == [first["id"]]
    assert owner.get(f"/v1/connectors/{installation['id']}").status_code == 200


def test_cloud_collection_success_duplicate_and_outage_are_distinct(owner, monkeypatch):
    from threatveil import connector_api
    credential = owner.post("/v1/credentials", json={
        "name": "Read only cloud token", "secret_version": "local:test:cloud-read",
    })
    assert credential.status_code == 201, credential.text
    installation, _ = setup(owner, kind="gcp_cloud_run", mode="POLL",
                            values={"service": SERVICE}, credential=credential.json()["id"])
    snapshot = Snapshot(source_version="Cloud Run Admin API v2", complete=True,
                        components={f"permissions:{SERVICE}": {"digest": digest("policy")}},
                        facts={"running_state_proven": False})
    monkeypatch.setattr(connector_api, "read_reference", lambda _: "test-read-token")
    calls = []

    def read(values, token):
        calls.append((values, token))
        return snapshot

    monkeypatch.setattr(connector_api, "collect_cloud_run", read)
    event_id = str(uuid4())
    result = owner.post(f"/v1/connectors/{installation['id']}/collect", json={"event_id": event_id})
    assert result.status_code == 200, result.text
    data = result.json()
    assert data["status"] == "RECORDED" and data["health"]["connected"]
    assert data["health"]["continuity"] == "SNAPSHOT_RECONCILED"
    assert data["batch"]["qualification"] == "UNREVIEWED"
    assert not data["batch"]["running_state_proven"]
    duplicate = owner.post(f"/v1/connectors/{installation['id']}/collect", json={"event_id": event_id})
    assert duplicate.json()["batch"]["id"] == data["batch"]["id"] and len(calls) == 1
    assert owner.post(f"/v1/connectors/{installation['id']}/collect", json={"event_id": str(uuid4())}).status_code == 429
    # Advance the clock, preserving immutable source records.
    clock = now() + timedelta(seconds=20)
    monkeypatch.setattr(connector_api, "now", lambda: clock)

    def unavailable(*_):
        raise SourceFailure("UNAVAILABLE")

    monkeypatch.setattr(connector_api, "collect_cloud_run", unavailable)
    outage = owner.post(f"/v1/connectors/{installation['id']}/collect", json={"event_id": str(uuid4())})
    assert outage.json()["status"] == "UNAVAILABLE" and outage.json()["batch"] is None
    assert outage.json()["health"]["freshness"] == "UNKNOWN"
    assert not outage.json()["health"]["connected"]


def test_push_telemetry_is_connected_instrumentation_with_unknown_coverage(owner):
    installation, _ = setup(owner, kind="otel", mode="PUSH")
    timestamp = str(int(datetime.now(timezone.utc).timestamp() * 1e9))
    payload = {"resourceSpans": [{"scopeSpans": [{"spans": [{
        "traceId": "a" * 32, "spanId": "b" * 16, "startTimeUnixNano": timestamp,
        "attributes": [{"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}},
                       {"key": "gen_ai.tool.name", "value": {"stringValue": "refund"}}],
        "status": {"code": 1},
    }]}]}]}
    result = submit(owner, installation, payload=payload, telemetry=True)
    assert result.status_code == 201, result.text
    assert result.json()["acquisition"] == "INSTRUMENTED"
    assert result.json()["facts"]["committed_effect"] == "UNKNOWN"
    state = owner.get(f"/v1/connectors/{installation['id']}").json()["health"]
    assert state["connected"] and state["freshness"] == "UNKNOWN" and state["continuity"] == "PARTIAL"
    assert submit(owner, installation, payload=payload, telemetry=False).status_code == 422


def test_import_cannot_forge_live_reconciliation_even_internal_contract(owner):
    installation, _ = setup(owner)
    user, org = identity(owner)
    with transaction(user, org) as session:
        row = get_record(session, org, installation["id"], "connector_installation")
        current = configuration(session, org, row)
        with pytest.raises(Exception, match="Only server collection"):
            persist_batch(session, org, row, current, event_id=str(uuid4()), request_digest="a" * 64,
                          snapshot=Snapshot(source_version="test", complete=True), valid_at=now(),
                          acquisition="IMPORTED", reconciled=True)


def test_wrong_cloud_resource_and_expired_or_revoked_source_cannot_ingest(owner):
    installation, body = setup(owner, kind="gcp_cloud_run", values={"service": SERVICE})
    payload = {"service": {"name": SERVICE.replace("finance-agent", "other-agent")}, "iam_policy": {}}
    assert submit(owner, installation, payload=payload).status_code == 422
    revoked = owner.post(f"/v1/connectors/{installation['id']}/configuration", json={
        "configuration": body["configuration"], "expires_at": body["expires_at"],
        "active": False, "reason": "Customer explicitly revoked this source",
    })
    assert revoked.status_code == 201
    assert submit(owner, installation, payload=payload).status_code == 403
    assert owner.get(f"/v1/connectors/{installation['id']}").json()["health"]["status"] == "REVOKED"


def test_finance_assurance_reassesses_after_imported_permission_change_and_fresh_proof(owner, monkeypatch):
    """Full synthetic re-proof may discharge an imported hint, never qualify its source."""
    monkeypatch.setattr(commercial, "can_use_connector_role", ACTUAL_CONNECTOR_CAPABILITY)
    setup_response = owner.post("/v1/change-assurance/finance/setup", json={
        "owner": "Finance test owner", "confirm_synthetic_scope": True,
    })
    assert setup_response.status_code == 201, setup_response.text
    setup_data = setup_response.json()

    def assess():
        result = owner.post("/v1/change-assurance/finance/assess", json={
            "system_id": setup_data["system_id"], "version": "fixed", "idempotency_key": str(uuid4()),
        })
        assert result.status_code == 201, result.text
        return result.json()

    baseline = assess()
    assert baseline["action"] == "ALLOW"
    decision_url = f"/v1/change-assurance/decisions/{baseline['authorization_id']}"
    historical = owner.get(decision_url).json()
    assert historical["current_status"] == "CURRENT"
    upgraded = owner.post("/v1/commercial/subscription", json={
        "action": "upgrade", "plan": "pro", "idempotency_key": str(uuid4()),
    })
    assert upgraded.status_code == 200, upgraded.text
    assert owner.get(decision_url).json()["current_status"] == "CURRENT"
    created = owner.post("/v1/connectors", json={
        "system_id": setup_data["system_id"], "environment_id": setup_data["environment_id"],
        "connector_id": "mcp", "mode": "IMPORT", "roles": ["DISCOVER", "CHANGE"],
        "name": "Declared finance tool catalog", "expires_at": (now() + timedelta(days=1)).isoformat(),
    })
    assert created.status_code == 201, created.text
    installation = created.json()
    assert submit(owner, installation, payload=mcp_payload(permission="read")).status_code == 201
    assert submit(owner, installation, sequence=2, payload=mcp_payload(permission="write")).status_code == 201
    current = owner.get(f"/v1/change-assurance/states/{baseline['state_id']}/current").json()
    assert not current["all_supported"] and current["policy_action"] != "ALLOW"
    assert any("Source change" in reason for row in current["properties"] for reason in row["reasons"])
    old_decision = owner.get(decision_url).json()
    # The system was observed to change after issuance, so the clearance describes an
    # earlier state: SUPERSEDED. REASSESS remains for support that moved without an
    # observed change (see the source-outage test). Both are non-current.
    assert old_decision["current_status"] == "SUPERSEDED"
    assert old_decision["action"] == historical["action"] == "ALLOW"  # historical signed meaning retained
    renewed = assess()
    assert renewed["action"] == "ALLOW"
    assert owner.get(f"/v1/change-assurance/decisions/{renewed['authorization_id']}").json()["current_status"] == "CURRENT"
    source = owner.get(f"/v1/connectors/{installation['id']}").json()["health"]
    assert source["status"] == "IMPORTED" and not source["connected"]
    assert source["qualification"] == "UNREVIEWED" and not source["running_state_proven"]
