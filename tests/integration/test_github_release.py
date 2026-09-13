"""GitHub lifecycle in real PostgreSQL; only the GitHub provider is substituted."""

import hashlib
import hmac
import json
from datetime import timedelta
from uuid import UUID, uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from fastapi.testclient import TestClient
from sqlalchemy import select

from threatveil.api import app
from threatveil.config import settings
from threatveil.db import GitHubBinding, Membership, Outbox, Record, now, transaction
from threatveil.integrations.github_app import GitHubAppClient, GitHubAppError
from threatveil.integrations import github_release as service

from test_product import customer as customer, setup, with_enforcement


@pytest.fixture
def github_customer(customer, monkeypatch):
    c, d = customer, setup(customer)
    org = UUID(d["system"]["organization_id"])
    user = UUID(c.get("/v1/auth/me").json()["user"]["id"])
    repo_id = str(uuid4().int % 10**15 + 1)
    repository = "company/agent-" + repo_id
    cfg = settings()
    monkeypatch.setattr(cfg, "github_app_id", "12")
    monkeypatch.setattr(cfg, "github_private_key", "configured-in-test-provider")
    monkeypatch.setattr(cfg, "github_webhook_secret", "test-webhook-shared-secret")
    monkeypatch.setattr(cfg, "web_origin", "https://threatveil.local.invalid")
    c.headers["origin"] = cfg.web_origin
    key = generate_private_key(public_exponent=65537, key_size=2048)
    state = {"checks": [], "writes": [], "lost_response": False, "read_failure": False}

    def handler(request):
        if request.url.path.endswith("/installation"):
            return httpx.Response(
                200,
                json={
                    "id": 123,
                    "app_id": 12,
                    "account": {"id": 789},
                    "suspended_at": None,
                    "permissions": {"checks": "write"},
                },
            )
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(
                201,
                json={
                    "token": "fake-test-installation-token-value",
                    "expires_at": (now() + timedelta(minutes=59)).isoformat(),
                    "permissions": {"checks": "write"},
                },
            )
        if request.url.path == f"/repos/{repository}":
            return httpx.Response(
                200, json={"id": int(repo_id), "full_name": repository, "owner": {"id": 789}}
            )
        if request.method == "GET":
            if state["read_failure"]:
                raise httpx.ConnectError("injected provider read failure")
            return httpx.Response(200, json={"check_runs": state["checks"]})
        payload = json.loads(request.content)
        if request.method == "POST":
            check = {**payload, "id": 111, "app": {"id": 12}}
            state["checks"].append(check)
        else:
            check = {**state["checks"][0], **payload}
            state["checks"][0] = check
        state["writes"].append(request.method)
        if state["lost_response"]:
            state["lost_response"] = False
            raise httpx.ReadTimeout("provider accepted check but response was lost")
        return httpx.Response(201 if request.method == "POST" else 200, json=check)

    monkeypatch.setattr(
        service,
        "app_client",
        lambda: GitHubAppClient(
            "12", key, http_client=httpx.Client(transport=httpx.MockTransport(handler))
        ),
    )
    with transaction(user, org) as session:
        session.add(
            GitHubBinding(
                repository_id=repo_id,
                repository=repository,
                owner_id="789",
                organization_id=org,
                user_id=user,
                allowed_ref="refs/heads/main",
                workflow_ref=repository + "/.github/workflows/release.yml@refs/heads/main",
                run_template={"system_id": d["system"]["id"]},
                enabled=True,
            )
        )
    registered = c.post(
        "/v1/github/app/installations", json={"repository_id": repo_id, "installation_id": "123"}
    )
    assert registered.status_code == 201, registered.text
    return {
        "client": c,
        "demo": d,
        "org": org,
        "user": user,
        "repository_id": repo_id,
        "repository": repository,
        "installation": registered.json(),
        "state": state,
    }


def make_release(h, mode="WARN"):
    c = h["client"]
    candidate = {
        "type": "git_commit",
        "id": h["repository_id"],
        "version": "a" * 40,
        "digest": "a" * 40,
    }
    plan = c.post(
        "/v1/proof-plans",
        json={
            "system_id": h["demo"]["system"]["id"],
            "candidate": candidate,
            "fingerprint": {
                "components": [
                    {
                        "type": "application",
                        "id": h["repository_id"],
                        "version": "a" * 40,
                        "provenance": "DECLARED",
                    }
                ]
            },
        },
    )
    assert plan.status_code == 201, plan.text
    if mode == "BLOCK":
        with_enforcement(c)
    result = c.post("/v1/releases", json={"plan_id": plan.json()["id"], "policy": {"mode": mode}})
    assert result.status_code == 201, result.text
    return result.json()


def delivery_for(h, release):
    with transaction(org_id=h["org"]) as session:
        row = session.scalar(
            select(Outbox).where(
                Outbox.organization_id == h["org"],
                Outbox.topic == service.TOPIC,
                Outbox.payload["release_id"].astext == release["id"],
            )
        )
        return row.id, row.status, dict(row.payload)


def expire_retry(identifier):
    with transaction() as session:
        row = session.get(Outbox, identifier)
        row.payload = {**row.payload, "next_at": (now() - timedelta(seconds=1)).isoformat()}


def webhook(h, payload, event="push", **headers):
    body = json.dumps(payload, separators=(",", ":")).encode()
    sig = (
        "sha256="
        + hmac.new(settings().github_webhook_secret.encode(), body, hashlib.sha256).hexdigest()
    )
    return h["client"].post(
        "/v1/webhooks/github",
        content=body,
        headers={
            "x-github-event": event,
            "x-hub-signature-256": sig,
            "x-github-delivery": str(uuid4()),
            **headers,
        },
    )


def push(h):
    return {
        "repository": {
            "id": int(h["repository_id"]),
            "full_name": h["repository"],
            "owner": {"id": 789},
        },
        "installation": {"id": 123},
        "ref": "refs/heads/main",
        "after": "a" * 40,
        "before": "b" * 40,
        "deleted": False,
    }


def test_registered_app_warn_receipt_queue_and_confirmed_publication(github_customer):
    h = github_customer
    release = make_release(h)
    assert release["release_action"] == "WARN" and release["underlying_action"] == "BLOCK"
    assert delivery_for(h, release)[1] == "pending"
    assert service.reconcile_github_checks(organization_id=h["org"])["delivered"] >= 1
    identifier, status, payload = delivery_for(h, release)
    assert status == "delivered"
    with transaction(org_id=h["org"]) as session:
        publication = session.get(Record, UUID(payload["publication_id"]))
        assert publication.payload["sha"] == "a" * 40
        assert publication.payload["conclusion"] == "neutral"
        assert publication.payload["current_applicable"] is True
        assert publication.payload["receipt_id"] == release["receipt_id"]
    assert h["state"]["writes"] == ["POST"]
    assert h["state"]["checks"][0]["details_url"].endswith('/app/releases?release=' + release['id'])
    assert service.reconcile_github_checks(organization_id=h["org"])["delivered"] == 0
    again = h["client"].post(f"/v1/github/releases/{release['id']}/publish")
    assert again.status_code == 202 and again.json()["delivery_id"] == str(identifier)


def test_lost_check_response_is_recovered_by_lookup_and_patch(github_customer):
    h = github_customer
    release = make_release(h, "BLOCK")
    h["state"]["lost_response"] = True
    service.reconcile_github_checks(organization_id=h["org"])
    identifier, status, _ = delivery_for(h, release)
    assert status == "ambiguous" and h["state"]["writes"] == ["POST"]
    expire_retry(identifier)
    service.reconcile_github_checks(organization_id=h["org"])
    assert delivery_for(h, release)[1] == "delivered"
    assert h["state"]["writes"] == ["POST", "PATCH"]
    assert len(h["state"]["checks"]) == 1


def test_read_failure_before_creation_can_retry_without_losing_authority(github_customer):
    h = github_customer
    release = make_release(h)
    h["state"]["read_failure"] = True
    service.reconcile_github_checks(organization_id=h["org"])
    identifier, status, payload = delivery_for(h, release)
    assert status == "retry" and not payload.get("write_started")
    h["state"]["read_failure"] = False
    expire_retry(identifier)
    service.reconcile_github_checks(organization_id=h["org"])
    assert delivery_for(h, release)[1] == "delivered" and h["state"]["writes"] == ["POST"]


def test_webhook_deduplication_uses_signed_body_and_preserves_change(github_customer):
    h = github_customer
    first = webhook(h, push(h))
    second = webhook(h, push(h), **{"x-github-delivery": "attacker-changed-header"})
    assert first.status_code == second.status_code == 202
    assert not first.json()["duplicate"] and second.json()["duplicate"]
    assert first.json()["event_id"] == second.json()["event_id"]
    with transaction(org_id=h["org"]) as session:
        row = session.get(Record, UUID(first.json()["event_id"]))
        assert row.kind == "github_change_event" and row.payload["status"] == "REPROOF_REQUIRED"
    wrong = push(h)
    wrong["ref"] = "refs/heads/attacker"
    assert webhook(h, wrong).status_code == 403
    assert webhook(h, push(h), **{"x-hub-signature-256": "sha256=" + "0" * 64}).status_code == 401


def test_app_revocation_blocks_pending_publication_and_cannot_be_replayed_to_reenable(
    github_customer,
):
    h = github_customer
    release = make_release(h)
    event = {
        "action": "suspend",
        "installation": {"id": 123, "account": {"id": 789}},
        "test_delivery": h["repository_id"],
    }
    response = webhook(h, event, "installation")
    assert response.status_code == 202 and response.json()["revoked"] >= 1
    service.reconcile_github_checks(organization_id=h["org"])
    assert delivery_for(h, release)[1] == "retry" and not h["state"]["writes"]
    event["action"] = "unsuspend"
    assert webhook(h, event, "installation").json()["accepted"] is False
    with transaction(org_id=h["org"]) as session:
        assert service.active_installation(session, h["org"], h["repository_id"]) is None


def test_tenant_crossing_and_removed_security_authority_cannot_publish(github_customer):
    h = github_customer
    release = make_release(h)
    with TestClient(app) as other:
        login = other.post(
            "/v1/auth/local",
            json={"email": f"{uuid4()}@local.invalid"},
            headers={"origin": settings().web_origin},
        )
        assert login.status_code == 200, login.text
        other.headers.update(
            {"origin": settings().web_origin, "x-csrf-token": login.json()["csrf_token"]}
        )
        assert other.post(f"/v1/github/releases/{release['id']}/publish").status_code == 404
        assert (
            other.post(
                "/v1/github/app/installations",
                json={"repository_id": h["repository_id"], "installation_id": "123"},
            ).status_code
            == 404
        )
        assert other.get("/v1/github/app/installations").json()["items"] == []
    with transaction(h["user"], h["org"]) as session:
        session.get(Membership, (h["org"], h["user"])).role = "viewer"
    service.reconcile_github_checks(organization_id=h["org"])
    assert delivery_for(h, release)[1] == "retry" and not h["state"]["writes"]
    assert h["client"].post(f"/v1/github/releases/{release['id']}/publish").status_code == 403


def test_claim_fence_rejects_stale_worker_before_side_effect(github_customer):
    h = github_customer
    release = make_release(h)
    identifier, _, _ = delivery_for(h, release)
    claim = service._claim_delivery(identifier)
    assert claim and service._claim_delivery(identifier) is None
    expire_retry(identifier)
    replacement = service._claim_delivery(identifier)
    assert replacement and replacement[3] != claim[3]
    assert replacement[2] is True  # A crash before the durable write marker is retryable.
    with pytest.raises(GitHubAppError, match="claim"):
        service._begin_write(identifier, claim[3])
    service._begin_write(identifier, replacement[3])


def test_replayed_lifecycle_event_cannot_revoke_fresh_reverified_installation(github_customer):
    h = github_customer
    event = {
        "action": "suspend",
        "installation": {"id": 123, "account": {"id": 789}},
        "test_delivery": h["repository_id"],
    }
    assert webhook(h, event, "installation").status_code == 202
    restored = h["client"].post(
        "/v1/github/app/installations",
        json={
            "repository_id": h["repository_id"],
            "installation_id": "123",
        },
    )
    assert restored.status_code == 201, restored.text
    replay = webhook(h, event, "installation")
    assert replay.status_code == 202 and replay.json()["duplicate"] is True
    with transaction(org_id=h["org"]) as session:
        active = service.active_installation(session, h["org"], h["repository_id"])
        assert str(active.id) == restored.json()["id"]


def test_current_check_is_refreshed_without_duplicate_creation_and_old_release_is_superseded(
    github_customer,
):
    h = github_customer
    first = make_release(h)
    service.reconcile_github_checks(organization_id=h["org"])
    identifier, status, _ = delivery_for(h, first)
    assert status == "delivered"
    expire_retry(identifier)
    service.reconcile_github_checks(organization_id=h["org"])
    assert h["state"]["writes"] == ["POST", "PATCH"]
    assert len(h["state"]["checks"]) == 1
    second = make_release(h, "BLOCK")
    assert delivery_for(h, first)[1] == "superseded"
    assert delivery_for(h, second)[1] == "pending"
    stale = h["client"].post(f"/v1/github/releases/{first['id']}/publish")
    assert stale.status_code == 409


def test_authorization_is_rechecked_immediately_before_external_write(github_customer, monkeypatch):
    h = github_customer
    release = make_release(h)
    from threatveil import release_integrity

    real_assess = release_integrity.current_release_assessment
    calls = []

    def expires_before_write(*args):
        value = real_assess(*args)
        calls.append(True)
        if len(calls) >= 2:
            return {
                **value,
                "release_action": "BLOCK",
                "underlying_action": "BLOCK",
                "current": False,
            }
        return value

    monkeypatch.setattr(release_integrity, "current_release_assessment", expires_before_write)
    service.reconcile_github_checks(organization_id=h["org"])
    _, status, payload = delivery_for(h, release)
    assert status == "retry" and not payload.get("write_started")
    assert not h["state"]["writes"]
