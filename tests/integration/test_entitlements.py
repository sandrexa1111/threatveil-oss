"""Tenant-persisted approval limits and live OIDC configuration visibility."""

from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from threatveil.api import app
from threatveil.config import settings
from threatveil.db import Account, GitHubBinding, add_record, transaction

ORIGIN = "http://127.0.0.1:3000"


@pytest.fixture
def owner(monkeypatch):
    monkeypatch.setenv("TV_ENV", "test")
    monkeypatch.setenv("TV_LOCAL_AUTH", "true")
    settings.cache_clear()
    with TestClient(app) as client:
        login = client.post("/v1/auth/local", json={"email": f"{uuid4()}@local.invalid"},
                            headers={"origin": ORIGIN})
        assert login.status_code == 200
        client.headers.update({"origin": ORIGIN, "x-csrf-token": login.json()["csrf_token"]})
        demo = client.post("/v1/demo/setup", json={}).json()
        # This suite preserves the historical pilot contract. Fresh organization
        # FREE behavior is exercised separately in test_commercial_platform.py.
        configured = client.post("/v1/billing/pilot", json={"trial_limit": 500,
            "max_systems": 3, "reason": "Explicit legacy pilot compatibility fixture"})
        assert configured.status_code == 200, configured.text
        yield client, demo
    settings.cache_clear()


def draft(client, demo):
    result = client.post("/v1/properties", json={"system_id": demo["system"]["id"],
        "title": "Reviewed authorization property", "description": "Bound a real security property.",
        "definition": demo["property"]["definition"]})
    assert result.status_code == 201, result.text
    return result.json()["id"]


def test_configured_commercial_scope_is_published_and_enforced(owner, monkeypatch):
    from threatveil.config import CommercialPlan
    from threatveil.integrations.billing import system_limit

    client, demo = owner
    cfg = settings()
    monkeypatch.setattr(cfg, 'commercial_plans', {'integrity': CommercialPlan(label='Protected system', systems=2, properties=1)})
    with transaction(org_id=UUID(demo['system']['organization_id'])) as session:
        session.get(Account, UUID(demo['system']['organization_id'])).plan = 'integrity'
    offer = client.get('/v1/billing').json()['offers'][0]
    assert offer['id'] == 'integrity' and 'monthly_usd' not in offer
    assert offer['checkout_configured'] is False and system_limit('integrity') == 2
    assert client.post(f'/v1/properties/{draft(client, demo)}/approve').status_code == 402


def test_concurrent_approval_cannot_exceed_advertised_cap_and_upgrade_preserves_history(owner):
    client, demo = owner
    org_id = UUID(demo["system"]["organization_id"])
    with transaction(org_id=org_id) as session:
        session.get(Account, org_id).plan = "starter"
    # The demo is already one active family. Drafts consume no active slots.
    for _ in range(18):
        assert client.post(f"/v1/properties/{draft(client, demo)}/approve").status_code == 200
    pending = [draft(client, demo), draft(client, demo)]
    assert client.get("/v1/billing").json()["active_properties"] == 19

    def approve(identifier):
        with TestClient(app) as concurrent:
            concurrent.cookies.update(client.cookies)
            concurrent.headers.update(client.headers)
            return concurrent.post(f"/v1/properties/{identifier}/approve")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(approve, pending))
    assert sorted(r.status_code for r in results) == [200, 402]
    approved = next(r.json() for r in results if r.status_code == 200)
    successful_draft = approved["supersedes_id"]
    # A repeated approval must refer to the same version, including at the limit.
    assert client.post(f"/v1/properties/{successful_draft}/approve").json()["id"] == approved["id"]
    state = client.get("/v1/billing").json()
    assert (state["active_properties"], state["property_limit"], state["remaining_properties"]) == (20, 20, 0)
    assert state["offers"] == []  # Public prices require explicitly configured commercial scope.
    blocked_draft = next(p for p in pending if p != successful_draft)
    with transaction(org_id=org_id) as session:
        session.get(Account, org_id).plan = "growth"
    assert client.post(f"/v1/properties/{blocked_draft}/approve").status_code == 200
    with transaction(org_id=org_id) as session:
        session.get(Account, org_id).plan = "starter"
    state = client.get("/v1/billing").json()
    assert state["active_properties"] == 21 and state["remaining_properties"] == 0
    assert client.post(f"/v1/properties/{draft(client, demo)}/approve").status_code == 402
    assert client.get(f"/v1/reports/{demo['system']['id']}").status_code == 200


def test_concurrent_repeat_approval_creates_one_billable_version(owner):
    client, demo = owner
    identifier = draft(client, demo)
    def approve(_):
        with TestClient(app) as concurrent:
            concurrent.cookies.update(client.cookies)
            concurrent.headers.update(client.headers)
            return concurrent.post(f"/v1/properties/{identifier}/approve")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(approve, range(2)))
    assert all(r.status_code == 200 for r in results)
    assert results[0].json()["id"] == results[1].json()["id"]
    assert client.get("/v1/billing").json()["active_properties"] == 2


def test_github_status_uses_current_organization_oidc_bindings(owner):
    client, demo = owner
    org_id = UUID(demo["system"]["organization_id"])
    user_id = UUID(client.get("/v1/auth/me").json()["user"]["id"])
    repository_id = str(uuid4().int)
    def github():
        return next(i for i in client.get("/v1/integrations").json()["items"] if i["id"] == "github")
    assert github()["status"] == "no_active_binding"
    with transaction(org_id=org_id) as session:
        session.add(GitHubBinding(repository_id=repository_id, repository="fixture/authorized",
            organization_id=org_id, user_id=user_id, owner_id="1234", enabled=True,
            workflow_ref="fixture/authorized/.github/workflows/verify.yml@refs/heads/main",
            allowed_ref="refs/heads/main", run_template={}))
    state = github()
    assert state["configured"] and state["mode"] == "oidc" and state["status"] == "bound_unverified"
    assert state["active_bindings"] == 1 and state["bindings"][0]["repository_id"] == repository_id
    with transaction(org_id=org_id) as session:
        session.get(GitHubBinding, repository_id).enabled = False
    assert github()["status"] == "no_active_binding" and github()["active_bindings"] == 0


def test_propagated_property_has_separate_approval_lineage_and_allowance(owner):
    client, demo = owner
    source = client.post(f"/v1/properties/{draft(client, demo)}/approve").json()
    destination = client.post("/v1/systems", json={"name": "Second payment agent", "description": "Separate system binding", "access": ["payments"], "actions": ["write"]}).json()
    copied = client.post("/v1/propagation/adopt", json={"source_property_id": source["id"], "destination_system_id": destination["id"]}).json()
    assert not copied["approved"] and "supersedes_id" not in copied and "approved_by" not in copied
    approved = client.post(f"/v1/properties/{copied['id']}/approve").json()
    assert approved["id"] != source["id"] and approved["system_id"] == destination["id"]
    assert approved["supersedes_id"] == copied["id"]
    assert client.get("/v1/billing").json()["active_properties"] == 3


def test_workspace_pages_preserve_totals_and_find_older_properties(owner):
    client, demo = owner
    org_id = UUID(demo["system"]["organization_id"])
    with transaction(org_id=org_id) as session:
        for index in range(205):
            add_record(session, org_id, "property", {"system_id": demo["system"]["id"],
                "title": f"Pagination draft {index:03}", "approved": False,
                "definition": demo["property"]["definition"]})
    dashboard = client.get("/v1/dashboard").json()
    assert dashboard["pagination"]["properties"]["total"] == 206
    assert len(dashboard["properties"]) == 200 and dashboard["summary"]["properties"] == 1
    cursor = dashboard["pagination"]["properties"]["next_cursor"]
    remaining = client.get("/v1/workspace/properties", params={"cursor": cursor}).json()
    assert len(remaining["items"]) == 6 and remaining["pagination"]["next_cursor"] is None
    assert not set(r["id"] for r in remaining["items"]) & set(r["id"] for r in dashboard["properties"])
    assert demo["property"]["id"] in [r["id"] for r in remaining["items"]]
    approved = client.get("/v1/workspace/properties", params={"approved": "true", "query": "Untrusted", "system_id": demo["system"]["id"]}).json()
    assert approved["pagination"]["total"] == 1 and approved["items"][0]["id"] == demo["property"]["id"]
    assert client.get("/v1/workspace/properties", params={"cursor": "malformed"}).status_code == 422
    assert client.get("/v1/workspace/properties", params={"limit": 201}).status_code == 422
