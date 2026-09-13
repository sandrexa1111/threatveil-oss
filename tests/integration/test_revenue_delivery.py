"""Real outbox persistence; provider requests are intercepted and never sent."""

import copy
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from threatveil import api
from threatveil.config import settings
from threatveil.db import Invite, Membership, Outbox, now, transaction
from threatveil.integrations import revenue_delivery as delivery

ORIGIN = "http://127.0.0.1:3000"


@pytest.fixture
def revenue(monkeypatch):
    for key, value in {"TV_ENV": "test", "TV_LOCAL_AUTH": "true", "TV_RESEND_API_KEY": "test_resend_never_sent",
        "TV_EMAIL_FROM": "ThreatVeil <invites@example.invalid>", "TV_RESEND_DELIVERY_ENABLED": "true",
        "TV_HUBSPOT_TOKEN": "test_hubspot_never_sent", "TV_HUBSPOT_DELIVERY_ENABLED": "true",
        "TV_HUBSPOT_OWNER_ID": "1234"}.items():
        monkeypatch.setenv(key, value)
    settings.cache_clear()
    calls = []
    def provider(method, url, token, body=None, *, headers=None):
        calls.append({"method": method, "url": url, "body": copy.deepcopy(body), "headers": dict(headers or {})})
        if "resend.com" in url:
            return 200, {"id": "email-accepted-once"}
        if method == "GET":
            return 404, {}
        return 201, {"id": "contact-1234"}
    monkeypatch.setattr(delivery, "_request", provider)
    with TestClient(api.app) as owner:
        owner.cookies.set("tv_session", str(uuid4()))
        response = owner.post("/v1/auth/local", json={"email": f"{uuid4()}@local.invalid"}, headers={"origin": ORIGIN})
        assert response.status_code == 200
        owner.headers.update({"origin": ORIGIN, "x-csrf-token": response.json()["csrf_token"]})
        provisioned = owner.post("/v1/commercial/subscription", json={"action": "upgrade",
            "plan": "team", "idempotency_key": str(uuid4())})
        assert provisioned.status_code == 200, provisioned.text
        org = UUID(owner.get("/v1/auth/me").json()["organization"]["id"])
        yield owner, org, calls
    settings.cache_clear()


def invitation(h):
    response = h[0].post("/v1/members/invite", json={"email": f"{uuid4()}@customer.invalid", "role": "developer"})
    assert response.status_code == 200, response.text
    return response.json()["delivery_id"]


def lead(h, message="Sensitive private finding which must not leave the intake store"):
    response = h[0].post("/v1/leads", json={"email": f"{uuid4()}@customer.invalid", "name": "Customer Contact",
        "company": "Customer Company", "message": message, "consent": True})
    assert response.status_code == 202
    return response.json()["id"]


def row(identifier):
    with transaction() as session:
        value = session.get(Outbox, UUID(identifier))
        return {"status": value.status, "attempts": value.attempts, "payload": copy.deepcopy(value.payload)}


def due(identifier):
    with transaction() as session:
        value = session.get(Outbox, UUID(identifier))
        value.payload = {**value.payload, "delivery": {**value.payload.get("delivery", {}),
            "next_attempt_at": (now() - timedelta(seconds=1)).isoformat(),
            "lease_until": (now() - timedelta(seconds=1)).isoformat()}}


def test_invitation_is_durably_accepted_once_and_status_never_exposes_bearer_link(revenue):
    h = revenue
    identifier = invitation(h)
    result = delivery.process_one(identifier)
    assert result["status"] == "accepted" and result["provider_id"] == "email-accepted-once"
    assert delivery.process_one(identifier)["status"] == "accepted"
    assert len(h[2]) == 1 and h[2][0]["headers"]["Idempotency-Key"].endswith(identifier)
    assert h[2][0]["body"]["to"] == [row(identifier)["payload"]["email"]]
    status = delivery.delivery_status(h[1])
    assert status["items"][0]["status"] == "accepted"
    assert "token=" not in str(status) and "text" not in str(status)


def test_invitation_remains_recoverable_when_email_configuration_is_missing(revenue, monkeypatch):
    monkeypatch.setenv("TV_RESEND_DELIVERY_ENABLED", "false")
    settings.cache_clear()
    identifier = invitation(revenue)
    assert row(identifier)["status"] == "pending"
    assert delivery.process_one(identifier)["status"] == "awaiting_config"
    assert revenue[2] == []
    monkeypatch.setenv("TV_RESEND_DELIVERY_ENABLED", "true")
    settings.cache_clear()
    assert delivery.process_one(identifier)["status"] == "accepted"


def test_uncertain_email_retry_uses_identical_payload_and_provider_key(revenue, monkeypatch):
    h = revenue
    identifier, calls = invitation(h), []
    def provider(method, url, token, body=None, *, headers=None):
        calls.append((copy.deepcopy(body), dict(headers)))
        if len(calls) == 1:
            raise delivery.DeliveryError("provider_transport_uncertain", retryable=True)
        return 200, {"id": "same-provider-operation"}
    monkeypatch.setattr(delivery, "_request", provider)
    assert delivery.process_one(identifier)["status"] == "retry"
    assert delivery.process_one(identifier)["status"] == "retry" and len(calls) == 1
    due(identifier)
    monkeypatch.setenv("TV_EMAIL_FROM", "Changed sender <new@example.invalid>")
    settings.cache_clear()
    assert delivery.process_one(identifier)["status"] == "accepted"
    assert calls[0] == calls[1]


def test_concurrent_delivery_claims_do_not_send_two_invitations(revenue):
    identifier = invitation(revenue)
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: delivery.process_one(identifier), range(2)))
    assert any(r["status"] == "accepted" for r in outcomes)
    assert len(revenue[2]) == 1 and row(identifier)["attempts"] == 1


def test_expired_idempotency_window_requires_reconciliation_without_resending(revenue):
    identifier = invitation(revenue)
    with transaction() as session:
        value = session.get(Outbox, UUID(identifier))
        value.attempts, value.status = 1, "retry"
        value.payload = {**value.payload, "delivery": {"first_attempt_at": (now() - timedelta(hours=24)).isoformat()}}
    result = delivery.process_one(identifier)
    assert result["status"] == "needs_review" and result["last_error"] == "delivery_requires_reconciliation"
    assert revenue[2] == []


@pytest.mark.parametrize("reason", ["used", "expired", "wrong_recipient", "wrong_origin", "wrong_hash"])
def test_inactive_or_misbound_invitation_is_never_sent(revenue, reason):
    h = revenue
    identifier = invitation(h)
    with transaction(org_id=h[1]) as session:
        outbox = session.get(Outbox, UUID(identifier))
        invite = session.get(Invite, outbox.payload["invitation_token_hash"])
        if reason == "used":
            invite.used_at = now()
        elif reason == "expired":
            invite.expires_at = now() - timedelta(seconds=1)
        else:
            payload = dict(outbox.payload)
            if reason == "wrong_recipient":
                payload["email"] = "other@customer.invalid"
            elif reason == "wrong_origin":
                payload["url"] = payload["url"].replace(ORIGIN, "https://attacker.invalid")
            else:
                payload["invitation_token_hash"] = "0" * 64
            outbox.payload = payload
    assert delivery.process_one(identifier)["status"] == "blocked"
    assert h[2] == []


def test_crm_exports_only_consented_contact_and_request_fields(revenue):
    h = revenue
    identifier = lead(h)
    result = delivery.process_one(identifier)
    assert result["status"] == "accepted"
    assert [c["method"] for c in h[2]] == ["GET", "POST"]
    properties = h[2][1]["body"]["properties"]
    assert set(properties) == {"email", "firstname", "company", "hubspot_owner_id", *delivery.CRM_FIELDS}
    assert properties["threatveil_demo_request_id"] == identifier
    assert "Sensitive private finding" not in str(h[2])
    assert delivery.process_one(identifier)["status"] == "accepted" and len(h[2]) == 2


def test_missing_or_non_boolean_contact_consent_cannot_route(revenue):
    h = revenue
    identifier = lead(h)
    with transaction() as session:
        outbox = session.get(Outbox, UUID(identifier))
        outbox.payload = {**outbox.payload, "consent": "true"}
    assert delivery.process_one(identifier)["status"] == "blocked"
    assert h[2] == []


def test_existing_customer_identity_lifecycle_and_owner_are_preserved(revenue, monkeypatch):
    h = revenue
    identifier, calls = lead(h), []
    def provider(method, url, token, body=None, *, headers=None):
        calls.append((method, copy.deepcopy(body)))
        if method == "GET":
            return 200, {"id": "existing-contact", "properties": {"hubspot_owner_id": "existing-owner",
                "firstname": "Verified Customer", "company": "Known Company", "lifecyclestage": "customer"}}
        return 200, {"id": "existing-contact"}
    monkeypatch.setattr(delivery, "_request", provider)
    assert delivery.process_one(identifier)["status"] == "accepted"
    assert calls[1][0] == "PATCH" and set(calls[1][1]["properties"]) == set(delivery.CRM_FIELDS)


def test_older_retry_does_not_replace_a_newer_crm_request(revenue, monkeypatch):
    identifier = lead(revenue)
    calls = []
    def provider(method, url, token, body=None, *, headers=None):
        calls.append(method)
        return 200, {"id": "existing-contact", "properties": {
            "threatveil_demo_requested_at": str(int((now() + timedelta(minutes=1)).timestamp() * 1000))}}
    monkeypatch.setattr(delivery, "_request", provider)
    assert delivery.process_one(identifier)["status"] == "accepted"
    assert calls == ["GET"]


def test_provider_failures_retry_boundedly_without_storing_response_or_secret(revenue, monkeypatch):
    identifier = invitation(revenue)
    monkeypatch.setattr(delivery, "_request", lambda *_args, **_kwargs: (503, {"message": "provider detail with secret=DO_NOT_STORE"}))
    for attempt in range(delivery.MAX_ATTEMPTS):
        due(identifier)
        result = delivery.process_one(identifier)
        assert result["attempts"] == attempt + 1
    assert result["status"] == "needs_review"
    assert "DO_NOT_STORE" not in str(row(identifier))
    assert "test_resend_never_sent" not in str(row(identifier))


def test_expired_processing_lease_recovers_the_original_email_operation(revenue):
    identifier = invitation(revenue)
    with transaction() as session:
        value = session.get(Outbox, UUID(identifier))
        value.attempts, value.status = 1, "processing"
        value.payload = {**value.payload, "delivery": {"first_attempt_at": now().isoformat(),
            "lease_until": (now() - timedelta(seconds=1)).isoformat(), "attempt_token": "crashed-worker"}}
    assert delivery.process_one(identifier)["status"] == "accepted"
    assert revenue[2][0]["headers"]["Idempotency-Key"] == "threatveil/invite/" + identifier


def test_delayed_retry_does_not_starve_a_ready_delivery(revenue, monkeypatch):
    delayed, ready = invitation(revenue), invitation(revenue)
    with transaction() as session:
        item = session.get(Outbox, UUID(delayed))
        item.status = "retry"
        item.payload = {**item.payload, "delivery": {"next_attempt_at": (now() + timedelta(hours=1)).isoformat()}}
    @contextmanager
    def scoped_transaction(*args, **kwargs):
        with transaction(*args, **kwargs) as session:
            class Scoped:
                def __getattr__(self, key):
                    return getattr(session, key)
                def scalars(self, statement):
                    return session.scalars(statement.where(Outbox.id.in_([UUID(delayed), UUID(ready)])))
            yield Scoped()
    monkeypatch.setattr(delivery, "transaction", scoped_transaction)
    result = delivery.deliver_pending(limit=1)
    assert len(result["items"]) == 1 and result["items"][0]["id"] == ready
    assert result["items"][0]["status"] == "accepted"
    assert row(delayed)["attempts"] == 0


def test_no_provider_delivery_when_credentials_exist_but_flags_are_disabled(revenue, monkeypatch):
    for key in ("TV_RESEND_DELIVERY_ENABLED", "TV_HUBSPOT_DELIVERY_ENABLED"):
        monkeypatch.setenv(key, "false")
    settings.cache_clear()
    assert delivery.deliver_pending() == {"items": [], "status": "awaiting_configuration"}
    assert revenue[2] == []


def test_invitation_delivery_status_is_organization_scoped(revenue):
    identifier = invitation(revenue)
    assert delivery.delivery_status(revenue[1])["items"][0]["id"] == identifier
    assert delivery.delivery_status(uuid4())["items"] == []


def test_actual_vendor_transport_bounds_responses_and_never_follows_redirects(monkeypatch):
    import httpx
    factory, requests, options = httpx.Client, [], []
    def handler(request):
        requests.append(request)
        return httpx.Response(302, json={"error": "redirect"}, headers={"location": "https://attacker.invalid"})
    def client(**kwargs):
        options.append(kwargs)
        return factory(transport=httpx.MockTransport(handler), **kwargs)
    monkeypatch.setattr(httpx, "Client", client)
    status, _ = delivery._request("POST", "https://api.resend.com/emails", "test-only-key", {"to": ["safe@local.invalid"]})
    assert status == 302 and len(requests) == 1
    assert options[0]["trust_env"] is False and options[0]["follow_redirects"] is False
    def oversized(_):
        return httpx.Response(200, content=b"x" * 100_001)
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: factory(transport=httpx.MockTransport(oversized), **kwargs))
    with pytest.raises(delivery.DeliveryError, match="provider_response_too_large"):
        delivery._request("GET", "https://api.resend.com/emails", "test-only-key")


def test_concurrent_api_invites_reuse_one_active_invitation_and_delivery(revenue):
    owner, org, calls = revenue
    email = f"{uuid4()}@customer.invalid"
    def submit(_):
        with TestClient(api.app) as client:
            client.cookies.update(owner.cookies)
            return client.post("/v1/members/invite", json={"email": email, "role": "developer"},
                headers={"origin": ORIGIN, "x-csrf-token": owner.headers["x-csrf-token"]})
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(submit, range(2)))
    assert all(r.status_code == 200 for r in responses)
    assert responses[0].json()["delivery_id"] == responses[1].json()["delivery_id"]
    assert responses[0].json()["invite_url"] == responses[1].json()["invite_url"]
    with transaction(org_id=org) as session:
        active = list(session.scalars(select(Invite).where(Invite.organization_id == org,
            Invite.email == email, Invite.used_at.is_(None), Invite.expires_at > now())))
        outbox = list(session.scalars(select(Outbox).where(Outbox.organization_id == org,
            Outbox.topic == "invitation.email", Outbox.payload["email"].astext == email)))
        assert len(active) == len(outbox) == 1
    assert delivery.process_one(responses[0].json()["delivery_id"])["status"] == "accepted"
    assert len(calls) == 1


def test_changed_invite_role_expires_prior_authority_and_only_new_role_can_join(revenue):
    owner, org, calls = revenue
    email = f"{uuid4()}@customer.invalid"
    old = owner.post("/v1/members/invite", json={"email": email, "role": "admin"}).json()
    new = owner.post("/v1/members/invite", json={"email": email, "role": "viewer"}).json()
    assert old["delivery_id"] != new["delivery_id"]
    assert delivery.process_one(old["delivery_id"])["status"] == "blocked"
    assert delivery.process_one(new["delivery_id"])["status"] == "accepted"
    assert len(calls) == 1
    with TestClient(api.app) as invited:
        invited.cookies.set("tv_session", str(uuid4()))
        login = invited.post("/v1/auth/local", json={"email": email}, headers={"origin": ORIGIN})
        assert login.status_code == 200
        invited.headers.update({"origin": ORIGIN, "x-csrf-token": login.json()["csrf_token"]})
        old_token = parse_qs(urlsplit(old["invite_url"]).query)["token"][0]
        new_token = parse_qs(urlsplit(new["invite_url"]).query)["token"][0]
        assert invited.post("/v1/members/accept", json={"token": old_token}).status_code == 403
        assert invited.post("/v1/members/accept", json={"token": new_token}).status_code == 200
        user = UUID(invited.get("/v1/auth/me").json()["user"]["id"])
        with transaction(org_id=org) as session:
            assert session.get(Membership, (org, user)).role == "viewer"


def test_delivery_status_api_has_flat_scoped_shape_and_requires_owner(revenue):
    owner, org, _ = revenue
    identifier = invitation(revenue)
    response = owner.get("/v1/deliveries")
    assert response.status_code == 200 and isinstance(response.json()["items"], list)
    assert response.json()["items"][0]["id"] == identifier
    assert "token=" not in response.text
    user = UUID(owner.get("/v1/auth/me").json()["user"]["id"])
    with transaction(user_id=user, org_id=org) as session:
        session.get(Membership, (org, user)).role = "developer"
    assert owner.get("/v1/deliveries").status_code == 403


def test_maintenance_revenue_hook_requires_launcher_identity(revenue, monkeypatch):
    from threatveil import broker, evidence_storage, maintenance
    identifier = invitation(revenue)
    @contextmanager
    def scoped_transaction(*args, **kwargs):
        with transaction(*args, **kwargs) as session:
            class Scoped:
                def __getattr__(self, key):
                    return getattr(session, key)
                def scalars(self, statement):
                    return session.scalars(statement.where(Outbox.id == UUID(identifier)))
            yield Scoped()
    monkeypatch.setattr(delivery, "transaction", scoped_transaction)
    monkeypatch.setattr(maintenance, "reconcile_runs", lambda: {"recovered": [], "timed_out": [], "retried_unclaimed": []})
    monkeypatch.setattr(maintenance, "tick_schedules", lambda: [])
    monkeypatch.setattr(evidence_storage, "purge_local_expired", lambda: 0)
    with TestClient(broker.app) as client:
        response = client.post("/internal/reconcile", headers={"authorization": "Bearer " + broker.local_identity_token()})
        assert response.status_code in (401, 403) and revenue[2] == []
        response = client.post("/internal/reconcile", headers={"authorization": "Bearer " + broker.local_identity_token("local-launcher")})
        assert response.status_code == 200, response.text
        assert response.json()["deliveries"]["items"][0]["status"] == "accepted"
        assert len(revenue[2]) == 1


def test_existing_member_does_not_receive_an_unusable_invitation(revenue):
    owner, org, calls = revenue
    email = owner.get("/v1/auth/me").json()["user"]["email"]
    response = owner.post("/v1/members/invite", json={"email": email, "role": "developer"})
    assert response.status_code == 409 or (
        response.status_code == 200 and response.json().get("status") == "already_member"
    )
    with transaction() as session:
        rows = list(session.scalars(select(Outbox).where(Outbox.organization_id == org,
            Outbox.topic == "invitation.email", Outbox.payload["email"].astext == email)))
        assert rows == []
    assert calls == []
