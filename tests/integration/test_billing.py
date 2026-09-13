"""Stripe signature verification plus real PostgreSQL entitlement reconciliation.

All payments are synthetic fixtures; no provider requests or actual money movement.
"""

import copy
import hashlib
import hmac
import json
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from threatveil import api
from threatveil.config import settings
from threatveil.db import Account, CustomerRoute, Record, WebhookEvent, now, transaction
from threatveil.integrations import billing

ORIGIN = "http://127.0.0.1:3000"
SIGNING_SECRET = "unit-test-webhook-secret"  # noqa: S105 - synthetic HMAC fixture, never a provider secret


def sign(event, *, timestamp=None, secret=SIGNING_SECRET):
    raw = json.dumps(event, separators=(",", ":")).encode()
    stamp = int(time.time()) if timestamp is None else timestamp
    signature = hmac.new(secret.encode(), str(stamp).encode()+b"."+raw, hashlib.sha256).hexdigest()
    return raw, f"t={stamp},v1={signature}"


def event_for(fixture, kind="invoice.paid", created=None, live=True):
    obj = {"id": fixture["invoice_id"], "customer": fixture["customer_id"],
           "subscription": fixture["subscription_id"]}
    if kind.startswith("customer.subscription."):
        obj["id"] = fixture["subscription_id"]
    return {"id": f"evt_{uuid4().hex}", "object": "event", "type": kind,
            "created": created or int(time.time()), "livemode": live,
            "data": {"object": obj}}


def deliver(client, event):
    raw, signature = sign(event)
    return client.post("/v1/webhooks/stripe", content=raw,
                       headers={"stripe-signature": signature, "content-type": "application/json"})


@pytest.fixture
def billing_account(monkeypatch):
    monkeypatch.setenv("TV_ENV", "test")
    monkeypatch.setenv("TV_LOCAL_AUTH", "true")
    monkeypatch.setenv("TV_STRIPE_WEBHOOK_SECRET", SIGNING_SECRET)
    monkeypatch.setenv("TV_STRIPE_PRICES", '{"growth":"price_synthetic_growth"}')
    monkeypatch.setenv("TV_STRIPE_TRIAL_ALLOWANCES", '{"growth":100}')
    settings.cache_clear()
    with TestClient(api.app) as owner:
        owner.cookies.set("tv_session", str(uuid4()))
        login = owner.post("/v1/auth/local", json={"email": f"{uuid4()}@local.invalid"}, headers={"origin": ORIGIN})
        assert login.status_code == 200, login.text
        owner.headers.update({"origin": ORIGIN, "x-csrf-token": login.json()["csrf_token"]})
        demo = owner.post("/v1/demo/setup", json={}).json()
        org_id = UUID(demo["system"]["organization_id"])
        customer_id, subscription_id, invoice_id = (f"{prefix}_{uuid4().hex}" for prefix in ("cus", "sub", "in"))
        with transaction(org_id=org_id) as session:
            account = session.get(Account, org_id)
            account.stripe_customer, account.stripe_subscription = customer_id, subscription_id
            account.status, account.plan, account.paid = "awaiting_payment", "unassigned", False
            account.trial_limit, account.consumed, account.reserved = 20, 3, 2
            account.period_end = None  # Explicit historical pre-subscription fixture.
            session.add(CustomerRoute(customer_id=customer_id, organization_id=org_id))
        snapshot = {"subscription": {"id": subscription_id, "customer": customer_id,
            "livemode": True, "status": "active", "latest_invoice": invoice_id,
            "items": {"data": [{"price": {"id": "price_synthetic_growth"},
                                  "current_period_end": int(now().timestamp())+86400}]}},
            "invoice": {"id": invoice_id, "customer": customer_id, "status": "paid", "amount_paid": 49900},
            "confirmed_payments": [{"payment_intent_id": "pi_synthetic", "amount": 49900, "live": True}]}
        monkeypatch.setattr(billing, "current_state", lambda sub: copy.deepcopy(snapshot))
        yield {"owner": owner, "org_id": org_id, "customer_id": customer_id,
               "subscription_id": subscription_id, "invoice_id": invoice_id, "snapshot": snapshot}
    settings.cache_clear()


def account_state(fixture):
    with transaction(org_id=fixture["org_id"]) as session:
        account = session.get(Account, fixture["org_id"])
        return {k: getattr(account, k) for k in ("status", "plan", "paid", "trial_limit", "consumed",
                                                "reserved", "period_end", "event_created")}


def test_actual_stripe_signatures_and_recency_are_required(billing_account):
    fixture = billing_account
    event = event_for(fixture)
    for stamp, secret in ((int(time.time()), "wrong-secret"), (int(time.time())-1000, SIGNING_SECRET)):
        raw, signature = sign(event, timestamp=stamp, secret=secret)
        response = fixture["owner"].post("/v1/webhooks/stripe", content=raw,
                                          headers={"stripe-signature": signature})
        assert response.status_code == 400
    assert account_state(fixture)["paid"] is False
    assert deliver(fixture["owner"], event).status_code == 200
    state = account_state(fixture)
    assert state["status"] == "active" and state["paid"] is True
    assert state["plan"] == "growth" and state["trial_limit"] == 100
    assert state["consumed"] == 0 and state["reserved"] == 2


def test_duplicate_event_does_not_reset_current_period_usage(billing_account):
    fixture = billing_account
    event = event_for(fixture)
    assert deliver(fixture["owner"], event).status_code == 200
    with transaction(org_id=fixture["org_id"]) as session:
        session.get(Account, fixture["org_id"]).consumed = 17
    repeated = deliver(fixture["owner"], event)
    assert repeated.status_code == 200 and repeated.json()["duplicate"]
    assert account_state(fixture)["consumed"] == 17
    with transaction(org_id=fixture["org_id"]) as session:
        assert len(list(session.scalars(select(Record).where(Record.kind == "billing_receipt")))) == 1


def test_concurrent_duplicate_events_are_idempotently_acknowledged(billing_account, monkeypatch):
    fixture = billing_account
    snapshot = copy.deepcopy(fixture["snapshot"])

    def delayed_snapshot(_):
        time.sleep(0.1)
        return copy.deepcopy(snapshot)
    monkeypatch.setattr(billing, "current_state", delayed_snapshot)
    event = event_for(fixture)

    def request(_):
        with TestClient(api.app) as client:
            return deliver(client, event).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(request, range(2)))
    assert statuses == [200, 200]


def test_old_delivery_uses_current_provider_snapshot_and_revokes_failed_payment(billing_account):
    fixture = billing_account
    newer = event_for(fixture, created=int(time.time())+10)
    assert deliver(fixture["owner"], newer).status_code == 200
    fixture["snapshot"]["subscription"]["status"] = "past_due"
    fixture["snapshot"]["invoice"].update(status="open", amount_paid=0)
    fixture["snapshot"]["confirmed_payments"] = []
    older = event_for(fixture, created=int(time.time())-10)
    assert deliver(fixture["owner"], older).status_code == 200
    state = account_state(fixture)
    assert state["status"] == "past_due" and state["paid"] is False
    assert state["event_created"] == newer["created"]


@pytest.mark.parametrize("case", ["testmode", "no_payment", "zero_invoice", "cancelled", "wrong_price"])
def test_unpaid_or_unrecognized_subscription_cannot_activate_entitlements(billing_account, case):
    fixture = billing_account
    if case == "no_payment":
        fixture["snapshot"]["confirmed_payments"] = []
    elif case == "zero_invoice":
        fixture["snapshot"]["invoice"]["amount_paid"] = 0
    elif case == "cancelled":
        fixture["snapshot"]["subscription"]["status"] = "canceled"
    elif case == "wrong_price":
        fixture["snapshot"]["subscription"]["items"]["data"][0]["price"]["id"] = "unconfigured_price"
    assert deliver(fixture["owner"], event_for(fixture, live=case != "testmode")).status_code == 200
    state = account_state(fixture)
    assert state["status"] != "active"
    if case in ("testmode", "no_payment", "zero_invoice"):
        assert state["paid"] is False
    assert state["trial_limit"] == 20


def test_provider_failure_leaves_event_retryable_and_entitlements_unchanged(billing_account, monkeypatch):
    fixture = billing_account
    event = event_for(fixture)

    def unavailable(_):
        raise RuntimeError("Synthetic provider outage")
    monkeypatch.setattr(billing, "current_state", unavailable)
    assert deliver(fixture["owner"], event).status_code == 502
    assert account_state(fixture)["status"] == "awaiting_payment"
    with transaction() as session:
        assert session.get(WebhookEvent, "stripe:"+event["id"]) is None


def test_modern_provider_reconciliation_freezes_canonical_plan(billing_account, monkeypatch):
    fixture = billing_account
    cfg = settings()
    monkeypatch.setattr(cfg, "stripe_prices", {"pro": "price_new_pro"})
    monkeypatch.setattr(cfg, "stripe_trial_allowances", {"pro": 2000})
    fixture["snapshot"]["subscription"]["items"]["data"][0]["price"]["id"] = "price_new_pro"
    event = event_for(fixture)
    assert deliver(fixture["owner"], event).status_code == 200
    state = fixture["owner"].get("/v1/commercial").json()
    assert state["plan"] == "pro" and state["provider"] == "stripe"
    assert state["entitlements"]["protected_system_limit"] == 3
    assert state["entitlements"]["monthly_verification_budget"] == 2000
    assert state["paid"] is True
    assert deliver(fixture["owner"], event).json()["duplicate"]
    assert fixture["owner"].get("/v1/commercial").json()["revision"] == state["revision"]


def test_explicit_test_entitlements_never_assert_collected_money(billing_account, monkeypatch):
    fixture = billing_account
    cfg = settings()
    monkeypatch.setattr(cfg, "stripe_test_entitlements_enabled", True)
    monkeypatch.setattr(cfg, "stripe_secret_key", "sk_test_synthetic_no_request")
    monkeypatch.setattr(cfg, "stripe_prices", {"pro": "price_new_pro"})
    monkeypatch.setattr(cfg, "stripe_trial_allowances", {"pro": 2000})
    fixture["snapshot"]["subscription"]["livemode"] = False
    fixture["snapshot"]["subscription"]["items"]["data"][0]["price"]["id"] = "price_new_pro"
    fixture["snapshot"]["confirmed_payments"][0]["live"] = False
    assert deliver(fixture["owner"], event_for(fixture, live=False)).status_code == 200
    state = fixture["owner"].get("/v1/commercial").json()
    assert state["plan"] == "pro" and state["status"] == "active"
    assert state["provider"] == "stripe_test" and state["paid"] is False
    with transaction(org_id=fixture["org_id"]) as session:
        receipts = list(session.scalars(select(Record).where(Record.kind == "billing_receipt")))
        assert receipts[0].payload["test_entitlement_activated"] is True
        assert receipts[0].payload["settled_payment_observed"] is False


@pytest.mark.parametrize("defect", ["subscription", "invoice", "tenant"])
def test_provider_scope_mismatch_cannot_mutate_entitlements(billing_account, defect):
    fixture = billing_account
    if defect == "subscription":
        fixture["snapshot"]["subscription"]["id"] = "sub_other"
    elif defect == "invoice":
        fixture["snapshot"]["invoice"]["customer"] = "cus_other"
    else:
        fixture["snapshot"]["subscription"]["customer"] = "cus_other"
    before = account_state(fixture)
    assert deliver(fixture["owner"], event_for(fixture)).status_code == 400
    assert account_state(fixture) == before


@pytest.mark.parametrize("defect", [None, "refunded", "disputed", "amount_refunded", "failed_intent", "unpaid_charge"])
def test_payment_collector_checks_actual_intent_and_charge(monkeypatch, defect):
    charge = {"paid": True, "refunded": False, "disputed": False, "amount_refunded": 0}
    intent = {"id": "pi_synthetic", "status": "succeeded", "amount_received": 49900,
              "livemode": True, "latest_charge": charge}
    if defect in ("refunded", "disputed"):
        charge[defect] = True
    elif defect == "amount_refunded":
        charge["amount_refunded"] = 1
    elif defect == "failed_intent":
        intent["status"] = "requires_payment_method"
    elif defect == "unpaid_charge":
        charge["paid"] = False
    payment = {"payment": {"type": "payment_intent", "payment_intent": "pi_synthetic"},
               "status": "paid", "amount_paid": 49900, "livemode": True}
    provider = SimpleNamespace(v1=SimpleNamespace(
        subscriptions=SimpleNamespace(retrieve=lambda _: {"id": "sub_synthetic", "latest_invoice": "in_synthetic"}),
        invoices=SimpleNamespace(retrieve=lambda _: {"id": "in_synthetic", "status": "paid"}),
        invoice_payments=SimpleNamespace(list=lambda _: {"data": [payment]}),
        payment_intents=SimpleNamespace(retrieve=lambda *_: intent)))
    monkeypatch.setattr(billing, "client", lambda: provider)
    assert bool(billing.current_state("sub_synthetic")["confirmed_payments"]) is (defect is None)
