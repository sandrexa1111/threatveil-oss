"""Meaningful acceptance runs against actual non-owner PostgreSQL RLS."""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from threatveil.api import app
from threatveil.db import Record, Edge, transaction
from threatveil.config import Settings, settings

ORIGIN = "http://127.0.0.1:3000"


@pytest.fixture
def customer(monkeypatch):
    monkeypatch.setenv("TV_LOCAL_AUTH", "true")
    settings.cache_clear()
    with TestClient(app) as c:
        r = c.post(
            "/v1/auth/local",
            json={
                "email": f"{uuid.uuid4()}@local.invalid",
                "name": "Test owner",
                "organization_name": "Isolated acceptance",
            },
            headers={"origin": ORIGIN},
        )
        assert r.status_code == 200, r.text
        c.headers.update({"origin": ORIGIN, "x-csrf-token": r.json()["csrf_token"]})
        yield c


def with_enforcement(c, plan="pro"):
    """A blocking release gate is a paid capability; grant it for gate semantics.

    These suites exercise release truth, not commercial limits, so they buy the
    entitlement explicitly instead of asserting Free behaviour by accident.
    """
    if c.get("/v1/commercial").json()["plan"] == plan:
        return c
    response = c.post("/v1/commercial/subscription", json={
        "action": "upgrade", "plan": plan, "idempotency_key": str(uuid.uuid4())})
    assert response.status_code == 200, response.text
    return c


def setup(c):
    r = c.post("/v1/demo/setup", json={})
    assert r.status_code == 200, r.text
    return r.json()


def run(c, d, version, baseline_id=None):
    payload = {
        "system_id": d["system"]["id"],
        "property_id": d["property"]["id"],
        "target_id": d["target"]["id"],
        "version": version,
        "trials": 2,
        "variant_count": 1,
        "idempotency_key": str(uuid.uuid4()),
    }
    if baseline_id:
        payload["baseline_id"] = baseline_id
    r = c.post("/v1/runs", json=payload)
    assert r.status_code == 202, r.text
    r = c.get("/v1/runs/" + r.json()["id"])
    assert r.status_code == 200
    return r.json()


def test_real_failure_useful_fix_historical_regression_and_report(customer):
    d = setup(customer)
    failed = run(customer, d, "vulnerable")
    fixed = run(customer, d, "fixed")
    assert (failed["security_verdict"], failed["release_action"]) == ("FAIL", "BLOCK")
    assert (fixed["security_verdict"], fixed["task_outcome"]) == ("PASS", "SUCCESS")
    fix = customer.post(
        "/v1/fixes",
        json={
            "run_id": failed["id"],
            "verification_run_id": fixed["id"],
            "description": "Bind beneficiary mutation to the real approval",
        },
    ).json()
    assert fix["verified"] and fix["baseline_id"]
    regressed = run(customer, d, "regressed", fix["baseline_id"])
    assert regressed["regression"] is True and regressed["release_action"] == "BLOCK"
    evidence = customer.get("/v1/runs/" + regressed["id"] + "/evidence").json()
    assert evidence["evidence_digest"] and evidence["trials"][0]["observation"]["receipts"]
    report = customer.get("/v1/reports/" + d["system"]["id"]).json()
    assert report["summary"]["fixes_verified"] == 1
    assert len(report["regressions"]) == 1
    assert customer.get("/v1/billing").json()["paid"] is False


def test_missing_witness_and_disabled_agent_never_verify(customer):
    d = setup(customer)
    failed = run(customer, d, "vulnerable")
    missing = run(customer, d, "missing_witness")
    bad = run(customer, d, "bad_fix")
    assert missing["security_verdict"] == "INCONCLUSIVE" and not missing["fix_eligible"]
    assert bad["security_verdict"] == "PASS" and bad["task_outcome"] == "FAILURE"
    r = customer.post(
        "/v1/fixes",
        json={
            "run_id": failed["id"],
            "verification_run_id": bad["id"],
            "description": "Disable all agent operations",
        },
    )
    assert r.status_code == 201
    assert r.json()["verified"] is False and r.json()["baseline_id"] is None


def test_tenant_cannot_read_reference_execute_or_report_other_tenant(customer):
    a = setup(customer)
    with TestClient(app) as b:
        r = b.post(
            "/v1/auth/local",
            json={"email": str(uuid.uuid4()) + "@local.invalid"},
            headers={"origin": ORIGIN},
        )
        b.headers.update({"origin": ORIGIN, "x-csrf-token": r.json()["csrf_token"]})
        own = setup(b)
        assert b.get("/v1/reports/" + a["system"]["id"]).status_code == 404
        assert (
            b.post(
                "/v1/findings",
                json={
                    "system_id": a["system"]["id"],
                    "title": "Forged relationship",
                    "description": "must not write across tenants",
                },
            ).status_code
            == 404
        )
        payload = {
            "system_id": own["system"]["id"],
            "property_id": a["property"]["id"],
            "target_id": own["target"]["id"],
            "version": "fixed",
            "idempotency_key": str(uuid.uuid4()),
        }
        assert b.post("/v1/runs", json=payload).status_code == 404
        assert len(b.get("/v1/systems").json()["items"]) == 1
    with transaction(org_id=uuid.UUID(a["system"]["organization_id"])) as s:
        assert s.scalar(select(Record).where(Record.id == uuid.UUID(own["system"]["id"]))) is None
        with pytest.raises(IntegrityError):
            s.add(
                Edge(
                    organization_id=uuid.UUID(a["system"]["organization_id"]),
                    source_id=uuid.UUID(a["system"]["id"]),
                    target_id=uuid.UUID(own["system"]["id"]),
                    relation="forged",
                )
            )
            s.flush()


def test_no_context_no_tenant_data_and_no_db_bypass(customer):
    setup(customer)
    with transaction() as s:
        assert list(s.scalars(select(Record))) == []
        role = s.execute(
            text("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user")
        ).one()
        assert not role.rolsuper and not role.rolbypassrls


def test_csrf_origin_and_revoked_target(customer):
    d = setup(customer)
    assert (
        customer.post("/v1/demo/setup", json={}, headers={"x-csrf-token": "wrong"}).status_code
        == 403
    )
    assert (
        customer.post(
            "/v1/demo/setup", json={}, headers={"origin": "https://evil.invalid"}
        ).status_code
        == 403
    )
    assert customer.post("/v1/targets/" + d["target"]["id"] + "/revoke", json={}).status_code == 200
    payload = {
        "system_id": d["system"]["id"],
        "property_id": d["property"]["id"],
        "target_id": d["target"]["id"],
        "version": "fixed",
        "idempotency_key": str(uuid.uuid4()),
    }
    assert customer.post("/v1/runs", json=payload).status_code == 403


def test_owner_protection_and_viewer_authority(customer):
    d = setup(customer)
    assert customer.post("/v1/commercial/subscription", json={"action": "upgrade", "plan": "team",
        "idempotency_key": str(uuid.uuid4())}).status_code == 200
    owner = customer.get("/v1/auth/me").json()["user"]["id"]
    assert customer.patch("/v1/members/" + owner, json={"role": "viewer"}).status_code == 409
    email = str(uuid.uuid4()) + "@local.invalid"
    invite = customer.post("/v1/members/invite", json={"email": email, "role": "viewer"}).json()
    token = invite["invite_url"].split("token=")[1]
    with TestClient(app) as viewer:
        r = viewer.post("/v1/auth/local", json={"email": email}, headers={"origin": ORIGIN})
        viewer.headers.update({"origin": ORIGIN, "x-csrf-token": r.json()["csrf_token"]})
        assert viewer.post("/v1/members/accept", json={"token": token}).status_code == 200
        assert (
            viewer.post(
                "/v1/auth/switch", json={"organization_id": d["system"]["organization_id"]}
            ).status_code
            == 200
        )
        assert viewer.get("/v1/dashboard").status_code == 200
        assert viewer.post("/v1/demo/setup", json={}).status_code == 403
        assert (
            viewer.post(
                "/v1/billing/pilot",
                json={"trial_limit": 100, "max_systems": 2, "reason": "cannot modify billing"},
            ).status_code
            == 403
        )


def test_idempotency_reservation_and_immutable_evidence(customer):
    d = setup(customer)
    payload = {
        "system_id": d["system"]["id"],
        "property_id": d["property"]["id"],
        "target_id": d["target"]["id"],
        "version": "fixed",
        "trials": 1,
        "idempotency_key": str(uuid.uuid4()),
    }
    r = customer.post("/v1/runs", json=payload)
    before = customer.get("/v1/billing").json()
    replay = customer.post("/v1/runs", json=payload)
    assert replay.json()["id"] == r.json()["id"]
    assert customer.get("/v1/billing").json()["consumed"] == before["consumed"]
    assert customer.post("/v1/runs", json={**payload, "version": "regressed"}).status_code == 409
    with transaction(org_id=uuid.UUID(d["system"]["organization_id"])) as s:
        with pytest.raises(__import__("sqlalchemy").exc.DBAPIError):
            s.execute(
                text("UPDATE records SET payload=CAST(:payload AS jsonb) WHERE id=:id"),
                {"id": d["property"]["id"], "payload": '{"forged":true}'},
            )


def test_evidence_report_escapes_html(customer):
    response = customer.post(
        "/v1/systems",
        json={"name": "<script>alert(1)</script>", "description": "<img src=x onerror=alert(1)>"},
    )
    assert response.status_code == 201
    r = customer.get("/v1/reports/" + response.json()["id"] + "/html")
    assert "<script>alert" not in r.text and "&lt;script&gt;" in r.text
    assert "sandbox" in r.headers["content-security-policy"]


def test_production_refuses_local_identity():
    with pytest.raises(ValueError):
        Settings(env="production", local_auth=True)


def test_complete_memory_export_and_report_scope_beyond_recent_window(customer):
    import json
    from threatveil.db import add_record

    d = setup(customer)
    org_id = uuid.UUID(d["system"]["organization_id"])
    expected_ids = set()
    with transaction(org_id=org_id) as session:
        for index in range(205):
            record = add_record(
                session,
                org_id,
                "finding",
                {
                    "title": f"Export fixture {index}",
                    "system_id": d["system"]["id"],
                    "description": "Test export pagination, not a security finding in a real target",
                },
                {"system": d["system"]["id"]},
            )
            expected_ids.add(str(record.id))
        add_record(session, org_id, "credential", {"secret_version": "excluded-credential-marker"})
    report = customer.get("/v1/reports/" + d["system"]["id"]).json()
    assert report["history_window"]["truncated"]
    assert report["history_window"]["total_records"]["finding"] == 205
    assert len(report["findings"]) == 200
    exported = customer.get("/v1/memory/export")
    assert exported.status_code == 200
    assert "excluded-credential-marker" not in exported.text
    lines = [json.loads(line) for line in exported.text.splitlines()]
    assert lines[0]["type"] == "manifest" and lines[-1]["type"] == "complete"
    actual = {
        line["id"] for line in lines if line["type"] == "record" and line["kind"] == "finding"
    }
    assert actual == expected_ids
    edges = [line for line in lines if line["type"] == "edge" and line["source_id"] in actual]
    assert len(edges) == 205


def test_gauntlet_records_actual_failure_fix_and_installed_memory(customer):
    d = setup(customer)
    response = customer.post(
        "/v1/gauntlets",
        json={
            "name": "Synthetic qualification engagement",
            "system_id": d["system"]["id"],
            "scope": "Synthetic beneficiary update boundary only",
            "property_ids": [d["property"]["id"]],
        },
    )
    assert response.status_code == 201, response.text
    gauntlet = response.json()
    failed = run(customer, d, "vulnerable")
    fixed = run(customer, d, "fixed")
    response = customer.post(
        "/v1/fixes",
        json={
            "run_id": failed["id"],
            "verification_run_id": fixed["id"],
            "description": "Preserve useful approved update",
        },
    )
    assert response.json()["verified"]
    current = next(
        row for row in customer.get("/v1/gauntlets").json()["items"] if row["id"] == gauntlet["id"]
    )
    assert current["status"] == "VERIFIED"
    assert current["summary"] == {
        "properties_scoped": 1,
        "properties_tested": 1,
        "properties_failed": 1,
        "fixes_verified": 1,
        "permanent_invariants_installed": 1,
    }
    assert current["next_action"] == "KEEP_RUNNING_CONTINUOUSLY"
