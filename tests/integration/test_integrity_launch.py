"""Real PostgreSQL launch lineage: human notes cannot create a gate or paid state."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.exc import DBAPIError

from test_github_release import github_customer as github_customer
from test_product import customer as customer

from threatveil import api
from threatveil.config import settings
from threatveil.db import Membership, Record, now, transaction

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


def launch(client):
    demo = client.post("/v1/demo/setup", json={}).json()
    response = client.post(
        "/v1/gauntlets",
        json={
            "system_id": demo["system"]["id"],
            "name": "Procurement Integrity Launch",
            "scope": "One staging system, approved property and authoritative ledger observation.",
            "property_ids": [demo["property"]["id"]],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def time_payload():
    return {
        "work_date": now().date().isoformat(),
        "minutes": 45,
        "category": "observation",
        "note": "Configured the customer ledger observer.",
        "idempotency_key": str(uuid4()),
    }


def test_launch_reuses_existing_scope_but_never_equates_it_to_installation_or_payment(owner):
    saved = launch(owner)
    response = owner.get("/v1/integrity-launches")
    assert response.status_code == 200, response.text
    detail = response.json()["items"][0]
    assert detail["id"] == saved["id"] and detail["kind"] == "gauntlet"
    assert detail["execution_status"] == "SCOPED"
    assert detail["installation_status"] == "NOT_CONFIGURED"
    assert detail["conversion"]["paid"] is False
    assert detail["effort"]["minutes"] == 0
    assert detail["milestones"]["properties_approved"]
    event = owner.post(
        f"/v1/integrity-launches/{saved['id']}/events",
        json={
            "event": "scope_reviewed",
            "note": "Engineering reviewed staging scope and allowed effects.",
            "reviewed": True,
            "idempotency_key": str(uuid4()),
        },
    )
    assert event.status_code == 201, event.text
    detail = owner.get(f"/v1/integrity-launches/{saved['id']}").json()
    assert detail["milestones"]["scope_reviewed"]
    assert not detail["milestones"]["live_gate_delivery_verified"]
    assert not detail["conversion"]["paid"]
    assert detail["execution_status"] == "SCOPED"


def test_effort_is_measured_idempotent_and_cannot_be_rewritten(owner):
    saved = launch(owner)
    endpoint = f"/v1/integrity-launches/{saved['id']}/time"
    payload = time_payload()
    first = owner.post(endpoint, json=payload)
    assert first.status_code == 201, first.text
    second = owner.post(endpoint, json=payload)
    assert second.json()["id"] == first.json()["id"]
    assert owner.post(endpoint, json={**payload, "minutes": 90}).status_code == 409
    detail = owner.get(f"/v1/integrity-launches/{saved['id']}").json()
    assert detail["effort"] == {
        "minutes": 45,
        "hours": 0.75,
        "by_category_minutes": {"observation": 45},
    }
    identity = owner.get("/v1/auth/me").json()
    with (
        pytest.raises(DBAPIError),
        transaction(UUID(identity["user"]["id"]), UUID(identity["organization"]["id"])) as session,
    ):
        session.execute(
            update(Record)
            .where(Record.id == UUID(first.json()["id"]))
            .values(payload={**first.json(), "minutes": 0})
        )
    assert owner.get(endpoint).json()["items"][0]["minutes"] == 45


def test_concurrent_retry_records_effort_once(owner):
    saved = launch(owner)
    payload = time_payload()
    endpoint = f"/v1/integrity-launches/{saved['id']}/time"
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: owner.post(endpoint, json=payload), range(2)))
    assert all(r.status_code == 201 for r in responses)
    assert responses[0].json()["id"] == responses[1].json()["id"]
    assert owner.get(f"/v1/integrity-launches/{saved['id']}").json()["effort"]["minutes"] == 45


def test_claimed_installation_payment_and_future_effort_are_rejected(owner):
    saved = launch(owner)
    base = f"/v1/integrity-launches/{saved['id']}"
    for forged in ("installed_warn", "paid", "security_pass"):
        assert (
            owner.post(
                base + "/events",
                json={
                    "event": forged,
                    "note": "Claimed manually only.",
                    "reviewed": True,
                    "idempotency_key": str(uuid4()),
                },
            ).status_code
            == 422
        )
    assert (
        owner.post(
            base + "/time",
            json={**time_payload(), "work_date": (now().date() + timedelta(days=1)).isoformat()},
        ).status_code
        == 422
    )
    assert owner.post(base + "/time", json={**time_payload(), "paid": True}).status_code == 422
    assert owner.get(base).json()["effort"]["minutes"] == 0


def test_tenant_cannot_read_or_append_to_another_launch(owner):
    saved = launch(owner)
    posted = owner.post(f"/v1/integrity-launches/{saved['id']}/time", json=time_payload()).json()
    with TestClient(api.app) as other:
        login(other)
        base = f"/v1/integrity-launches/{saved['id']}"
        assert other.get("/v1/integrity-launches").json()["items"] == []
        for route in (base, base + "/time", base + "/events"):
            assert other.get(route).status_code == 404
        assert other.post(base + "/time", json=time_payload()).status_code == 404
        assert (
            other.get(
                "/v1/integrity-launches", params={"system_id": saved["system_id"]}
            ).status_code
            == 404
        )
        identity = other.get("/v1/auth/me").json()
    with transaction(org_id=UUID(identity["organization"]["id"])) as session:
        assert session.scalar(select(Record).where(Record.id == UUID(posted["id"]))) is None


def test_roles_and_csrf_restrict_review_and_effort(owner):
    saved = launch(owner)
    identity = owner.get("/v1/auth/me").json()
    user, org = UUID(identity["user"]["id"]), UUID(identity["organization"]["id"])
    base = f"/v1/integrity-launches/{saved['id']}"
    with transaction(user, org) as session:
        session.get(Membership, (org, user)).role = "developer"
    assert (
        owner.post(
            base + "/events",
            json={
                "event": "scope_reviewed",
                "note": "Reviewed engineering scope.",
                "reviewed": True,
                "idempotency_key": str(uuid4()),
            },
        ).status_code
        == 403
    )
    assert owner.post(base + "/time", json=time_payload()).status_code == 201
    with transaction(user, org) as session:
        session.get(Membership, (org, user)).role = "viewer"
    assert owner.get(base).status_code == 200
    assert owner.post(base + "/time", json=time_payload()).status_code == 403
    del owner.headers["x-csrf-token"]
    assert owner.post(base + "/time", json=time_payload()).status_code == 403


def test_launch_history_is_paginated_and_keeps_total_effort(owner):
    saved = launch(owner)
    base = f"/v1/integrity-launches/{saved['id']}"
    for _ in range(3):
        assert owner.post(base + "/time", json=time_payload()).status_code == 201
    first = owner.get(base + "/time", params={"limit": 2}).json()
    assert len(first["items"]) == 2 and first["pagination"]["total"] == 3
    second = owner.get(
        base + "/time", params={"limit": 2, "cursor": first["pagination"]["next_cursor"]}
    ).json()
    assert len(second["items"]) == 1
    assert second["items"][0]["id"] not in {r["id"] for r in first["items"]}
    assert owner.get(base).json()["effort"]["minutes"] == 135
    assert owner.get(base + "/time", params={"cursor": "forged"}).status_code == 422


def test_installed_milestone_requires_confirmed_publication_and_active_binding(github_customer):
    # Shared real-PostgreSQL integration fixture substitutes only GitHub HTTP.
    from test_github_release import make_release
    from threatveil.db import GitHubBinding
    from threatveil.integrations.github_release import reconcile_github_checks

    h = github_customer
    saved = launch(h["client"])
    base = f"/v1/integrity-launches/{saved['id']}"
    make_release(h)
    before = h["client"].get(base)
    assert before.status_code == 200, before.text
    assert before.json()["installation_status"] == "DELIVERY_NOT_VERIFIED"
    assert before.json()["milestones"]["signed_receipt_recorded"]
    assert not before.json()["milestones"]["live_gate_delivery_verified"]
    assert reconcile_github_checks(organization_id=h["org"])["delivered"] >= 1
    after = h["client"].get(base).json()
    assert after["installation_status"] == "LIVE_WARN_DELIVERY_VERIFIED"
    assert after["milestones"]["live_gate_delivery_verified"]
    assert after["live_publication"]["check_id"]
    assert not after["conversion"]["paid"]
    with transaction(h["user"], h["org"]) as session:
        session.get(GitHubBinding, h["repository_id"]).enabled = False
    revoked = h["client"].get(base).json()
    assert not revoked["milestones"]["live_gate_delivery_verified"]
    assert revoked["installation_status"] == "NOT_CONFIGURED"
