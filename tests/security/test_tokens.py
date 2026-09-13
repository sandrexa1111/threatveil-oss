"""Scoped API keys retain tenant and current membership limits in real PostgreSQL."""

from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from threatveil import api
from threatveil.config import settings
from threatveil.db import ApiToken, Membership, now, transaction

ORIGIN = "http://127.0.0.1:3000"


@pytest.fixture
def account(monkeypatch):
    monkeypatch.setenv("TV_ENV", "test")
    monkeypatch.setenv("TV_LOCAL_AUTH", "true")
    settings.cache_clear()
    with TestClient(api.app) as owner:
        owner.cookies.set("tv_session", str(uuid4()))
        response = owner.post(
            "/v1/auth/local", json={"email": f"{uuid4()}@local.invalid"}, headers={"origin": ORIGIN}
        )
        assert response.status_code == 200, response.text
        owner.headers.update({"origin": ORIGIN, "x-csrf-token": response.json()["csrf_token"]})
        demo = owner.post("/v1/demo/setup", json={}).json()
        identity = owner.get("/v1/auth/me").json()
        yield owner, demo, identity
    settings.cache_clear()


def issue(owner, permission="execute"):
    response = owner.post(
        "/v1/api-tokens",
        json={"name": "Security test", "permission": permission, "expires_in_days": 1},
    )
    assert response.status_code == 201, response.text
    return response.json()


def payload(demo):
    return {
        "system_id": demo["system"]["id"],
        "property_id": demo["property"]["id"],
        "target_id": demo["target"]["id"],
        "version": "fixed",
        "trials": 1,
        "variant_count": 1,
        "idempotency_key": str(uuid4()),
    }


def test_read_token_cannot_execute_and_execute_token_cannot_administer(account):
    owner, demo, _ = account
    read, execute = issue(owner, "read"), issue(owner)
    with TestClient(api.app) as client:
        client.headers["authorization"] = f"Bearer {read['token']}"
        assert client.get("/v1/dashboard").status_code == 200
        assert client.post("/v1/runs", json=payload(demo)).status_code == 403
        client.headers["authorization"] = f"Bearer {execute['token']}"
        assert client.post("/v1/runs", json=payload(demo)).status_code == 202
        assert client.post("/v1/api-tokens", json={"name": "escalation"}).status_code == 403
        assert (
            client.post(
                "/v1/billing/pilot",
                json={"trial_limit": 99999, "max_systems": 50, "reason": "must not change billing"},
            ).status_code
            == 403
        )
        assert (
            client.post(f"/v1/properties/{demo['property']['id']}/approve", json={}).status_code
            == 403
        )


def test_token_revocation_and_expiry_take_effect_immediately(account):
    owner, demo, _ = account
    token = issue(owner)
    with TestClient(api.app) as client:
        client.headers["authorization"] = f"Bearer {token['token']}"
        assert client.get("/v1/dashboard").status_code == 200
        assert owner.delete(f"/v1/api-tokens/{token['id']}").status_code == 200
        assert client.get("/v1/dashboard").status_code == 401
        token = issue(owner)
        with transaction(org_id=UUID(demo["system"]["organization_id"])) as session:
            row = session.scalar(select(ApiToken).where(ApiToken.id == UUID(token["id"])))
            row.expires_at = now() - timedelta(seconds=1)
        client.headers["authorization"] = f"Bearer {token['token']}"
        assert client.get("/v1/dashboard").status_code == 401


def test_token_rechecks_membership_and_demotions(account):
    owner, demo, identity = account
    token = issue(owner)
    org_id, user_id = UUID(demo["system"]["organization_id"]), UUID(identity["user"]["id"])
    with TestClient(api.app) as client:
        client.headers["authorization"] = f"Bearer {token['token']}"
        with transaction(user_id=user_id, org_id=org_id) as session:
            session.get(Membership, (org_id, user_id)).role = "viewer"
        assert client.get("/v1/dashboard").status_code == 200
        assert client.post("/v1/runs", json=payload(demo)).status_code == 403
        with transaction(user_id=user_id, org_id=org_id) as session:
            session.delete(session.get(Membership, (org_id, user_id)))
        assert client.get("/v1/dashboard").status_code == 401


def test_api_token_never_selects_another_organization(account):
    owner, demo, _ = account
    token = issue(owner)
    with TestClient(api.app) as other, TestClient(api.app) as token_client:
        other.cookies.set("tv_session", str(uuid4()))
        login = other.post(
            "/v1/auth/local", json={"email": f"{uuid4()}@local.invalid"}, headers={"origin": ORIGIN}
        )
        other.headers.update({"origin": ORIGIN, "x-csrf-token": login.json()["csrf_token"]})
        target = other.post("/v1/demo/setup", json={}).json()
        token_client.headers["authorization"] = f"Bearer {token['token']}"
        assert token_client.get(f"/v1/reports/{target['system']['id']}").status_code == 404
        assert token_client.post("/v1/runs", json=payload(target)).status_code == 404
        assert token_client.post(
            "/v1/auth/switch", json={"organization_id": target["system"]["organization_id"]}
        ).status_code in (403, 401)
        systems = token_client.get("/v1/systems").json()["items"]
        assert {s["id"] for s in systems} == {demo["system"]["id"]}


def test_api_token_proxy_header_does_not_grant_admin(account):
    owner, _, _ = account
    token = issue(owner, "read")
    with TestClient(api.app) as client:
        client.headers.update(
            {
                "authorization": "Bearer cloud-run-identity-placeholder",
                "x-threatveil-token": token["token"],
            }
        )
        assert client.get("/v1/dashboard").status_code == 200
        assert client.post("/v1/demo/setup", json={}).status_code == 403
        assert client.get("/v1/api-tokens").status_code == 403


def test_cookie_authentication_still_requires_csrf_with_a_valid_token(account):
    owner, demo, _ = account
    token = issue(owner)
    owner.headers["authorization"] = f"Bearer {token['token']}"
    response = owner.post("/v1/runs", json=payload(demo), headers={"x-csrf-token": "wrong"})
    assert response.status_code == 403
