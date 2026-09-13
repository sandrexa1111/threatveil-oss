"""Minimized tenant measurements cannot create evidence or bypass data consent."""

import json
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy import select

from threatveil.api import app
from threatveil.db import Record, add_record, transaction

from test_commercial_platform import customer as customer, create_system, ORIGIN


def report(client, **fields):
    return client.post("/v1/measurements/events", json={"name": "upgrade.requested",
        "feature": "protected_systems", "idempotency_key": str(uuid4()), **fields})


def test_default_consent_and_real_quota_measurements(customer):
    client, org = customer
    consent = client.get("/v1/measurements/consent").json()
    assert consent["service_operation"] is True
    assert not consent["product_analytics"] and not consent["research"] and not consent["cross_customer_learning"]
    assert report(client).status_code == 409
    assert create_system(client, "Sensitive customer workflow title").status_code == 201
    assert create_system(client, "Sensitive rejected title").status_code == 402
    response = client.get("/v1/measurements")
    assert response.status_code == 200, response.text
    summary = response.json()
    assert summary["systems"]["registered"] == 1
    assert summary["commercial"]["limit_events"] == [{"plan": "free", "resource": "protected_systems", "count": 1}]
    assert "Sensitive" not in response.text
    assert summary["systems"]["currently_supported_customer_systems"] == 0
    with transaction(org_id=org) as session:
        metric = session.scalar(select(Record).where(Record.kind == "service_metric"))
        assert metric and metric.payload["source"] == "SERVER_ENFORCED"
        assert "Sensitive" not in json.dumps(metric.payload)


def test_optin_idempotency_revocation_and_no_security_authority(customer):
    client, org = customer
    assert client.post("/v1/measurements/consent", json={"product_analytics": True}).status_code == 201
    key = str(uuid4())
    first = report(client, idempotency_key=key)
    assert first.status_code == 201 and first.json()["assurance_authority"] is False
    repeated = report(client, idempotency_key=key)
    assert repeated.json()["duplicate"] and repeated.json()["id"] == first.json()["id"]
    assert report(client, idempotency_key=key, feature="observers").status_code == 409
    assert report(client, name="security.pass").status_code == 422
    assert report(client, prompt="Do not collect customer prompts").status_code == 422
    assert report(client, name="decision.used", action="ALLOW").status_code == 201
    metrics = client.get("/v1/measurements").json()
    assert metrics["systems"]["currently_supported_customer_systems"] == 0
    assert metrics["decisions"]["authorization_actions"] == {}
    assert metrics["commercial"]["reported_upgrade_features"] == {"protected_systems": 1}
    assert client.post("/v1/measurements/consent", json={"product_analytics": False}).status_code == 201
    assert report(client).status_code == 409
    with transaction(org_id=org) as session:
        assert len(list(session.scalars(select(Record).where(Record.kind == "product_metric")))) == 2
        assert len(list(session.scalars(select(Record).where(Record.kind == "measurement_consent")))) == 2


def test_consent_axes_are_independent_and_processing_stays_disabled(customer):
    client, _ = customer
    assert client.post("/v1/measurements/consent", json={"research": True}).status_code == 422
    response = client.post("/v1/measurements/consent", json={"research": True,
        "contract_reference": "CONSENT-LOCAL-TEST", "cross_customer_learning": False})
    assert response.status_code == 201
    consent = response.json()
    assert consent["research"] and not consent["cross_customer_learning"] and not consent["product_analytics"]
    assert not consent["research_pipeline_enabled"] and not consent["training_pipeline_enabled"]
    assert report(client).status_code == 409


def test_raw_evidence_never_enters_metric_response_and_tenants_are_isolated(customer):
    client, org = customer
    system = create_system(client).json()
    with transaction(org_id=org) as session:
        add_record(session, org, "result", {"security_verdict": "FAIL", "task_outcome": "SUCCESS",
            "usage": {"units": 4}, "duration_ms": 120, "prompt": "PRIVATE_EVIDENCE_CANARY",
            "business_resource": "PRIVATE_RESOURCE_CANARY"})
    metrics = client.get("/v1/measurements")
    assert "PRIVATE_" not in metrics.text
    assert metrics.json()["verification"]["security"] == {"FAIL": 1}
    assert metrics.json()["verification"]["consumed_execution_units"] == 4
    with TestClient(app) as other:
        login = other.post("/v1/auth/local", json={"email": f"{uuid4()}@local.invalid"}, headers={"origin": ORIGIN})
        other.headers.update({"origin": ORIGIN, "x-csrf-token": login.json()["csrf_token"]})
        other.post("/v1/measurements/consent", json={"product_analytics": True})
        assert report(other, system_id=system["id"]).status_code == 404
        assert other.get("/v1/measurements").json()["verification"]["result_records"] == 0
        assert other.get("/v1/measurements").json()["commercial"]["limit_events"] == []
    assert UUID(system["organization_id"]) == org


def test_supported_counts_come_from_current_case_and_keep_synthetic_separate(customer):
    from test_change_assurance import prepare, assess

    client, _ = customer
    prepared = prepare(client)
    assessment = assess(client, prepared)
    current = client.get("/v1/measurements")
    assert current.status_code == 200, current.text
    assert current.json()["systems"]["currently_supported_synthetic_systems"] == 1
    assert current.json()["systems"]["currently_supported_customer_systems"] == 0
    assert current.json()["onboarding"]["systems_with_a_first_supported_case"] == 1
    assert current.json()["systems"]["currently_protected_synthetic_systems"] == 0
    decision = client.get(f"/v1/change-assurance/decisions/{assessment['authorization_id']}").json()
    assert client.post("/v1/change-assurance/enforcement", json={
        "authorization_id": decision["id"], "mechanism": "synthetic_compare_and_set",
        **{key: decision[key] for key in ("environment_id", "state_digest", "audience", "expected_prior_epoch", "request_nonce")}
    }).status_code == 201
    assert client.get("/v1/measurements").json()["systems"]["currently_protected_synthetic_systems"] == 1
    assess(client, prepared, "bad_fix")
    broken = client.get("/v1/measurements").json()
    assert broken["systems"]["currently_supported_synthetic_systems"] == 0
    assert broken["systems"]["currently_protected_synthetic_systems"] == 0
    assert broken["current_assurance"]["boundary_support"] == {"requires_review": 1}
    assert broken["onboarding"]["systems_with_a_first_supported_case"] == 1
