from datetime import datetime, timezone
from typing import Protocol

import stripe
from fastapi import HTTPException
from sqlalchemy.dialects.postgresql import insert
from ..config import settings
from ..db import Account, CustomerRoute, WebhookEvent, transaction, context, add_record

PLAN_SYSTEMS = {"starter": 1, "growth": 5, "pro": 15}


def _price_ids():
    from ..commercial import catalog

    prices = {**{p.id: p.stripe_price_id for p in catalog().plans if p.stripe_price_id},
              **settings().stripe_prices}
    if len(prices.values()) != len(set(prices.values())):
        raise HTTPException(503, "Stripe Price IDs must identify one unambiguous plan")
    return prices


def system_limit(plan):
    configured = settings().commercial_plans.get(plan)
    if configured:
        return configured.systems
    if plan in PLAN_SYSTEMS:
        return PLAN_SYSTEMS[plan]
    from ..commercial import plan_version

    try:
        return plan_version(plan)["entitlements"]["protected_system_limit"]
    except HTTPException:
        return 0


class BillingProvider(Protocol):
    """Provider operations return commercial state, never an assurance verdict."""

    def checkout(self, actor, plan): ...
    def portal(self, actor): ...


class MockBillingProvider:
    def checkout(self, actor, plan):
        from ..commercial import mutate, resolve

        with transaction(actor.user_id, actor.org_id) as session:
            _, state, _ = resolve(session, actor.org_id)
            revision = state["revision"] if state else 0
            result = mutate(session, actor.org_id, {"action": "upgrade", "plan": plan,
                "idempotency_key": f"checkout:{revision}:{plan}", "expected_revision": revision}, actor.user_id)
        return {"url": settings().web_origin + "/app/billing?billing=mock",
                "status": result["status"], "provider": "mock", "paid": False,
                "meaning": "Local simulated entitlement activation; no charge occurred."}

    def portal(self, actor):
        return {"url": settings().web_origin + "/app/billing", "provider": "mock", "paid": False}


class StripeBillingProvider:
    def checkout(self, actor, plan):
        return _stripe_checkout(actor, plan)

    def portal(self, actor):
        return _stripe_portal(actor)


def billing_provider():
    from ..commercial import provider_name

    provider = provider_name()
    if provider == "mock":
        return MockBillingProvider()
    if provider == "stripe":
        return StripeBillingProvider()
    raise HTTPException(503, "Billing provider is disabled")


def client():
    if not settings().stripe_secret_key:
        raise HTTPException(
            503, "Stripe is not configured; manual pilot entitlement is available to the operator"
        )
    return stripe.StripeClient(settings().stripe_secret_key)


def create_checkout(actor, plan):
    return billing_provider().checkout(actor, plan)


def _stripe_checkout(actor, plan):
    cfg = settings()
    if cfg.stripe_secret_key and not cfg.stripe_secret_key.startswith("sk_test_") and not getattr(cfg, "stripe_live_charges_enabled", False):
        raise HTTPException(403, "Live checkout requires explicit live-charge configuration")
    if not system_limit(plan):
        raise HTTPException(422, "Unknown subscription plan")
    prices = _price_ids()
    if not prices.get(plan) or not cfg.stripe_trial_allowances.get(plan):
        raise HTTPException(
            503,
            "Price and measured execution allowance must be configured before selling this plan",
        )
    api = client()
    with transaction(actor.user_id, actor.org_id) as s:
        account = s.get(Account, actor.org_id, with_for_update=True)
        if not account.stripe_customer:
            customer = api.v1.customers.create(
                {"email": actor.email, "metadata": {"organization_id": str(actor.org_id)}},
                options={"idempotency_key": "tv-customer-" + str(actor.org_id)},
            )
            account.stripe_customer = customer.id
            s.add(CustomerRoute(customer_id=customer.id, organization_id=actor.org_id))
        session = api.v1.checkout.sessions.create(
            {
                "mode": "subscription",
                "customer": account.stripe_customer,
                "line_items": [{"price": prices[plan], "quantity": 1}],
                "success_url": cfg.web_origin + "/app/settings?billing=returned",
                "cancel_url": cfg.web_origin + "/app/settings?billing=cancelled",
                "subscription_data": {
                    "metadata": {"organization_id": str(actor.org_id), "plan": plan}
                },
                "metadata": {"organization_id": str(actor.org_id), "plan": plan},
            }
        )
        return {"url": session.url, "status": "awaiting_webhook", "paid": False}


def create_portal(actor):
    return billing_provider().portal(actor)


def _stripe_portal(actor):
    api = client()
    with transaction(actor.user_id, actor.org_id) as s:
        account = s.get(Account, actor.org_id)
        if not account.stripe_customer:
            raise HTTPException(409, "No Stripe customer exists yet")
        portal = api.v1.billing_portal.sessions.create(
            {
                "customer": account.stripe_customer,
                "return_url": settings().web_origin + "/app/settings",
            }
        )
        return {"url": portal.url}


def process_webhook(raw, signature):
    cfg = settings()
    if not cfg.stripe_webhook_secret:
        raise HTTPException(503, "Stripe webhook is not configured")
    try:
        event = stripe.Webhook.construct_event(
            raw, signature, cfg.stripe_webhook_secret, tolerance=300
        )
    except Exception:
        raise HTTPException(400, "Stripe signature rejected") from None
    data = event.to_dict_recursive() if hasattr(event, "to_dict_recursive") else dict(event)
    return apply_event(data)


def plain(value):
    return value.to_dict_recursive() if hasattr(value, "to_dict_recursive") else dict(value)


def current_state(subscription_id):
    """Re-read current provider state; webhook delivery order is not a billing clock."""
    api = client()
    subscription = plain(api.v1.subscriptions.retrieve(subscription_id))
    latest = subscription.get("latest_invoice")
    if isinstance(latest, dict):
        latest = latest["id"]
    invoice = plain(api.v1.invoices.retrieve(latest)) if latest else {}
    payments = (
        plain(
            api.v1.invoice_payments.list({"invoice": latest, "status": "paid", "limit": 100})
        ).get("data", [])
        if latest
        else []
    )
    confirmed = []
    for payment in payments:
        detail = payment.get("payment", {})
        if (
            detail.get("type") != "payment_intent"
            or payment.get("status") != "paid"
            or payment.get("amount_paid", 0) <= 0
        ):
            continue
        intent_id = detail.get("payment_intent")
        if isinstance(intent_id, dict):
            intent_id = intent_id["id"]
        intent = plain(api.v1.payment_intents.retrieve(intent_id, {"expand": ["latest_charge"]}))
        charge = intent.get("latest_charge") or {}
        if (
            intent.get("status") == "succeeded"
            and intent.get("amount_received", 0) > 0
            and isinstance(charge, dict)
            and charge.get("paid") is True
            and not charge.get("refunded")
            and not charge.get("disputed")
            and charge.get("amount_refunded", 0) == 0
        ):
            confirmed.append(
                {
                    "payment_intent_id": intent["id"],
                    "amount": payment["amount_paid"],
                    "live": bool(intent.get("livemode") and payment.get("livemode")),
                }
            )
    return {"subscription": subscription, "invoice": invoice, "confirmed_payments": confirmed}


def apply_event(event):
    """Only signed events enter here; successful live payment is independently confirmed."""
    cfg = settings()
    obj, kind = event["data"]["object"], event["type"]
    event_id = "stripe:" + event["id"]
    with transaction() as s:
        # Claim delivery atomically inside the same transaction as entitlement
        # changes. A concurrent duplicate waits for this transaction to commit;
        # a provider failure rolls back the claim so Stripe can safely retry.
        claimed = s.execute(
            insert(WebhookEvent)
            .values(id=event_id, provider="stripe")
            .on_conflict_do_nothing(index_elements=["id"])
            .returning(WebhookEvent.id)
        ).scalar_one_or_none()
        if claimed is None:
            return {"received": True, "duplicate": True}
        route = s.get(CustomerRoute, obj.get("customer", ""), with_for_update=True)
        if not route:
            return {"received": True, "applied": False}
        context(s, org_id=route.organization_id)
        account = s.get(Account, route.organization_id, with_for_update=True)
        incoming = (
            obj.get("id")
            if kind.startswith("customer.subscription.")
            else obj.get("subscription")
            or obj.get("parent", {}).get("subscription_details", {}).get("subscription")
        )
        subscription_id = account.stripe_subscription or incoming
        if incoming and incoming != subscription_id:
            if (
                kind == "customer.subscription.created"
                and account.status == "cancelled"
                and event.get("created", 0) > account.event_created
            ):
                subscription_id = incoming
            else:
                return {"received": True, "applied": False}
        if not subscription_id or not (
            kind.startswith("customer.subscription.")
            or kind.startswith("invoice.")
            or kind in {"charge.refunded", "charge.dispute.created"}
        ):
            return {"received": True, "applied": False}
        try:
            snapshot = current_state(subscription_id)
        except Exception:
            raise HTTPException(
                502, "Billing reconciliation unavailable; webhook will be retried"
            ) from None
        subscription, invoice = snapshot["subscription"], snapshot["invoice"]
        if (subscription.get("customer") != account.stripe_customer
                or subscription.get("id") != subscription_id
                or (invoice.get("customer") and invoice["customer"] != account.stripe_customer)):
            raise HTTPException(400, "Billing customer mismatch")
        lines = subscription.get("items", {}).get("data", [])
        price = lines[0].get("price", {}).get("id") if len(lines) == 1 else None
        plan = next((p for p, value in _price_ids().items() if value == price), None)
        if plan and not system_limit(plan):
            plan = None
        confirmed = snapshot["confirmed_payments"]
        paid = (
            invoice.get("status") == "paid"
            and invoice.get("amount_paid", 0) > 0
            and bool(event.get("livemode"))
            and bool(subscription.get("livemode"))
            and any(p["live"] and p["amount"] > 0 for p in confirmed)
        )
        test_activation = bool(
            getattr(cfg, "stripe_test_entitlements_enabled", False)
            and cfg.stripe_secret_key.startswith("sk_test_")
            and not event.get("livemode") and not subscription.get("livemode")
            and not invoice.get("livemode")
            and invoice.get("status") == "paid" and invoice.get("amount_paid", 0) > 0
            and any(not p["live"] and p["amount"] > 0 for p in confirmed)
        )
        account.stripe_subscription = subscription_id
        account.event_created = max(account.event_created, event.get("created", 0))
        account.paid = paid
        status = subscription.get("status")
        account.status = (
            "cancelled"
            if status in {"canceled", "unpaid", "incomplete_expired", "paused"}
            else "past_due"
            if status == "past_due"
            else "awaiting_payment"
        )
        if plan:
            account.plan, account.max_systems = plan, system_limit(plan)
        if (paid or test_activation) and status == "active" and plan and cfg.stripe_trial_allowances.get(plan, 0) > 0:
            account.status = "active"
            period_end = lines[0].get("current_period_end") or subscription.get(
                "current_period_end"
            )
            if period_end and (
                not account.period_end or period_end > account.period_end.timestamp()
            ):
                # Existing reservations remain charged against the new budget until they settle.
                account.consumed = 0
                account.period_end = datetime.fromtimestamp(period_end, tz=timezone.utc)
            account.trial_limit = cfg.stripe_trial_allowances[plan]
        add_record(
            s,
            route.organization_id,
            "billing_receipt",
            {
                "event_id": event["id"],
                "invoice_id": invoice.get("id"),
                "subscription_id": subscription_id,
                "live": bool(event.get("livemode")),
                "settled_payment_observed": paid,
                "test_entitlement_activated": test_activation,
                "confirmed_payments": confirmed,
                "plan": account.plan,
                "status": account.status,
                "meaning": "Successful provider payment confirmed; bank payout timing is not asserted.",
            },
        )
        from ..commercial import record_provider_subscription

        record_provider_subscription(s, account, event["id"], "stripe_test" if test_activation else "stripe",
            (lines[0].get("current_period_start") if lines else None) or subscription.get("current_period_start"),
            (lines[0].get("current_period_end") if lines else None) or subscription.get("current_period_end"))
    return {"received": True}
