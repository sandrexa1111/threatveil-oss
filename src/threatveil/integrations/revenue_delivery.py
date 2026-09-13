"""Credential-gated transactional delivery, with durable retries and no raw evidence export.

Provider acceptance is not inbox delivery. Resend retains idempotency keys for
24 hours; unresolved email attempts stop before that window expires. HubSpot
receives only contact/routing fields, never the free-text intake message.
"""

import hashlib
import json
import re
import secrets
from datetime import datetime, timedelta
from urllib.parse import parse_qs, quote, urlsplit
from uuid import UUID

import httpx
from sqlalchemy import and_, or_, select, text

from ..auth import digest
from ..config import settings
from ..db import Invite, Outbox, context, now, transaction

TOPICS = ("invitation.email", "lead.crm")
ACTIVE = ("pending", "retry", "processing", "awaiting_config")
MAX_ATTEMPTS = 8
EMAIL_RETRY_WINDOW = timedelta(hours=23)
CONTACTS = "https://api.hubapi.com/crm/objects/2026-03/contacts"
CRM_FIELDS = ("threatveil_demo_request_id", "threatveil_demo_requested_at")


class DeliveryError(Exception):
    def __init__(self, code, retryable=False, delay=60):
        super().__init__(code)
        self.code, self.retryable, self.delay = code, retryable, delay


def enabled(topic, cfg):
    if topic == "invitation.email":
        return bool(
            getattr(cfg, "resend_delivery_enabled", False) and cfg.resend_api_key and cfg.email_from
        )
    return bool(
        getattr(cfg, "hubspot_delivery_enabled", False)
        and cfg.hubspot_token
        and getattr(cfg, "hubspot_owner_id", "")
    )


def _email(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[^\s@<>\x00-\x1f]+@[^\s@<>\x00-\x1f]+\.[^\s@<>\x00-\x1f]+", value
    ):
        raise DeliveryError("invalid_recipient")
    return value.lower()


def _request(method, url, token, body=None, *, headers=None):
    """Only fixed vendor hosts reach this transport. Bound responses and redact errors."""
    try:
        with httpx.Client(timeout=10, follow_redirects=False, trust_env=False) as client:
            with client.stream(
                method,
                url,
                json=body,
                headers={
                    "Authorization": "Bearer " + token,
                    "Accept": "application/json",
                    **(headers or {}),
                },
            ) as response:
                content = bytearray()
                for chunk in response.iter_bytes():
                    if len(content) + len(chunk) > 100_000:
                        raise DeliveryError("provider_response_too_large", retryable=True)
                    content.extend(chunk)
                try:
                    data = json.loads(content) if content else {}
                except (ValueError, UnicodeError):
                    raise DeliveryError("provider_response_invalid", retryable=True) from None
                if not isinstance(data, dict):
                    raise DeliveryError("provider_response_invalid", retryable=True)
                return response.status_code, data
    except httpx.HTTPError:
        raise DeliveryError("provider_transport_uncertain", retryable=True) from None


def _failure(status, data):
    if status == 429 or status >= 500:
        raise DeliveryError(
            "provider_rate_limited" if status == 429 else "provider_unavailable", retryable=True
        )
    if status in (401, 403):
        raise DeliveryError("provider_configuration_rejected")
    if status == 409 and data.get("name") == "concurrent_idempotent_requests":
        raise DeliveryError("provider_request_in_progress", retryable=True)
    raise DeliveryError("provider_request_rejected")


def _validated_invite(session, row, cfg):
    if not row.organization_id:
        raise DeliveryError("invitation_scope_missing")
    context(session, org_id=row.organization_id)
    url = str(row.payload.get("url", ""))
    parsed, expected = urlsplit(url), urlsplit(cfg.web_origin)
    query = parse_qs(parsed.query)
    if (
        (parsed.scheme, parsed.netloc, parsed.path) != (expected.scheme, expected.netloc, "/invite")
        or parsed.fragment
        or set(query) != {"token"}
        or len(query["token"]) != 1
    ):
        raise DeliveryError("invitation_url_outside_application")
    token = query["token"][0]
    if row.payload.get("invitation_token_hash", digest(token)) != digest(token):
        raise DeliveryError("invitation_binding_invalid")
    invitation = session.get(Invite, digest(token))
    email = _email(row.payload.get("email"))
    if (
        not invitation
        or invitation.organization_id != row.organization_id
        or invitation.email != email
    ):
        raise DeliveryError("invitation_binding_invalid")
    if invitation.used_at or invitation.expires_at <= now():
        raise DeliveryError("invitation_no_longer_active")
    return {
        "from": cfg.email_from,
        "to": [email],
        "subject": "Your ThreatVeil invitation",
        "text": "You were invited to a ThreatVeil workspace. Sign in with this email address to accept:\n\n"
        + url
        + "\n\nThis invitation expires seven days after it was created. If unexpected, you can ignore it.",
    }


def _prepare(session, row, cfg):
    if row.topic == "invitation.email":
        return _validated_invite(session, row, cfg)
    if row.payload.get("consent") is not True:
        raise DeliveryError("contact_consent_missing")
    name, company = row.payload.get("name"), row.payload.get("company")
    if (
        not isinstance(name, str)
        or not 1 <= len(name) <= 120
        or not isinstance(company, str)
        or not 1 <= len(company) <= 160
    ):
        raise DeliveryError("contact_fields_invalid")
    return {
        "email": _email(row.payload.get("email")),
        "name": name,
        "company": company,
        "request_id": str(row.id),
        "requested_at": str(int(row.created_at.timestamp() * 1000)),
        "owner_id": str(cfg.hubspot_owner_id),
    }


def _send_email(request, cfg, key):
    status, data = _request(
        "POST",
        "https://api.resend.com/emails",
        cfg.resend_api_key,
        request,
        headers={"Idempotency-Key": key},
    )
    if not 200 <= status < 300:
        _failure(status, data)
    if not isinstance(data.get("id"), str) or not data["id"]:
        raise DeliveryError("provider_acceptance_uncertain", retryable=True)
    return data["id"][:150]


def _millis(value):
    try:
        return int(value)
    except (ValueError, TypeError):
        try:
            return int(datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp() * 1000)
        except (ValueError, TypeError, OverflowError):
            return 0


def _send_contact(request, cfg):
    contact_url = CONTACTS + "/" + quote(request["email"], safe="") + "?idProperty=email"
    status, existing = _request(
        "GET",
        contact_url + "&properties=hubspot_owner_id," + ",".join(CRM_FIELDS),
        cfg.hubspot_token,
    )
    routing = {CRM_FIELDS[0]: request["request_id"], CRM_FIELDS[1]: request["requested_at"]}
    if status == 200:
        properties = existing.get("properties") or {}
        if _millis(properties.get(CRM_FIELDS[1])) > int(request["requested_at"]):
            return str(existing["id"])
        # Public intake never overwrites an established customer's identity or lifecycle.
        if not properties.get("hubspot_owner_id"):
            routing["hubspot_owner_id"] = request["owner_id"]
        status, result = _request("PATCH", contact_url, cfg.hubspot_token, {"properties": routing})
    elif status == 404:
        properties = {
            "email": request["email"],
            "firstname": request["name"],
            "company": request["company"],
            "hubspot_owner_id": request["owner_id"],
            **routing,
        }
        status, result = _request("POST", CONTACTS, cfg.hubspot_token, {"properties": properties})
        if status == 409:
            # Another writer may have created this unique email; next attempt reads it.
            raise DeliveryError("contact_created_concurrently", retryable=True)
    else:
        _failure(status, existing)
    if not 200 <= status < 300:
        _failure(status, result)
    if not isinstance(result.get("id"), str) or not result["id"]:
        raise DeliveryError("provider_acceptance_uncertain", retryable=True)
    return result["id"][:150]


def _public(row):
    info = row.payload.get("delivery") or {}
    return {
        "id": str(row.id),
        "topic": row.topic,
        "status": row.status,
        "attempts": row.attempts,
        **{
            key: info.get(key)
            for key in ("last_error", "next_attempt_at", "accepted_at", "provider_id")
        },
    }


def process_one(identifier):
    """Durably claim before calling a provider; serialize retries and contact updates."""
    cfg, stamp = settings(), now()
    with transaction() as session:
        row = session.scalar(
            select(Outbox)
            .where(Outbox.id == UUID(str(identifier)), Outbox.topic.in_(TOPICS))
            .with_for_update(skip_locked=True)
        )
        if row is None:
            return {"id": str(identifier), "status": "busy_or_missing"}
        if row.status not in ACTIVE:
            return _public(row)
        info = dict(row.payload.get("delivery") or {})
        due = info.get("lease_until") if row.status == "processing" else info.get("next_attempt_at")
        if due and datetime.fromisoformat(due) > stamp:
            return _public(row)
        try:
            if row.topic == "lead.crm" and row.payload.get("consent") is not True:
                raise DeliveryError("contact_consent_missing")
            if not enabled(row.topic, cfg):
                row.status = "awaiting_config"
                return _public(row)
            prepared = _prepare(session, row, cfg)
            if row.attempts >= MAX_ATTEMPTS or (
                row.topic == "invitation.email"
                and info.get("first_attempt_at")
                and datetime.fromisoformat(info["first_attempt_at"]) + EMAIL_RETRY_WINDOW <= stamp
            ):
                raise DeliveryError("delivery_requires_reconciliation")
            info.setdefault("request", prepared)
            # Freeze request bytes across retries, including sender/template changes.
            info.setdefault("first_attempt_at", stamp.isoformat())
            info.update(
                attempt_token=secrets.token_urlsafe(24),
                lease_until=(stamp + timedelta(minutes=2)).isoformat(),
                last_error=None,
            )
            row.status, row.attempts = "processing", row.attempts + 1
            row.payload = {**row.payload, "delivery": info}
            attempt_token = info["attempt_token"]
        except DeliveryError as error:
            row.status = (
                "needs_review" if error.code == "delivery_requires_reconciliation" else "blocked"
            )
            row.payload = {**row.payload, "delivery": {**info, "last_error": error.code}}
            return _public(row)
    with transaction() as session:
        row = session.get(Outbox, UUID(str(identifier)), with_for_update=True)
        info = dict(row.payload.get("delivery") or {})
        if row.status != "processing" or info.get("attempt_token") != attempt_token:
            return _public(row)
        try:
            _prepare(session, row, cfg)  # Recheck current invitation and consent before sending.
            if row.topic == "lead.crm":
                key = int.from_bytes(
                    hashlib.sha256(info["request"]["email"].encode()).digest()[:8],
                    "big",
                    signed=True,
                )
                if not session.scalar(text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": key}):
                    raise DeliveryError("contact_delivery_busy", retryable=True, delay=5)
            provider_id = (
                _send_email(info["request"], cfg, "threatveil/invite/" + str(row.id))
                if row.topic == "invitation.email"
                else _send_contact(info["request"], cfg)
            )
            row.status = "accepted"
            info.update(provider_id=provider_id, accepted_at=now().isoformat(), last_error=None)
        except DeliveryError as error:
            row.status = (
                "retry" if error.retryable and row.attempts < MAX_ATTEMPTS else "needs_review"
            )
            info.update(
                last_error=error.code,
                next_attempt_at=(
                    now() + timedelta(seconds=min(3600, max(error.delay, 15 * 2**row.attempts)))
                ).isoformat(),
            )
        except Exception:
            # Unknown outcomes require human reconciliation; no secret-bearing exception is persisted.
            row.status = "needs_review"
            info["last_error"] = "delivery_outcome_uncertain"
        row.payload = {**row.payload, "delivery": info}
        return _public(row)


def deliver_pending(limit=10):
    if not 1 <= limit <= 20:
        raise ValueError("Delivery batch must contain between one and twenty items")
    cfg = settings()
    topics = [topic for topic in TOPICS if enabled(topic, cfg)]
    if not topics:
        return {"items": [], "status": "awaiting_configuration"}
    with transaction() as session:
        stamp = now().isoformat()
        next_at = Outbox.payload["delivery"]["next_attempt_at"].astext
        lease_until = Outbox.payload["delivery"]["lease_until"].astext
        due = or_(
            and_(Outbox.status != "processing", or_(next_at.is_(None), next_at <= stamp)),
            and_(Outbox.status == "processing", or_(lease_until.is_(None), lease_until <= stamp)),
        )
        identifiers = list(
            session.scalars(
                select(Outbox.id)
                .where(Outbox.topic.in_(topics), Outbox.status.in_(ACTIVE), due)
                .order_by(Outbox.created_at)
                .limit(limit)
            )
        )
    return {"items": [process_one(identifier) for identifier in identifiers], "status": "checked"}


def delivery_status(org_id):
    """Organization owners may inspect invitation delivery without exposing bearer links."""
    with transaction(org_id=org_id) as session:
        rows = list(
            session.scalars(
                select(Outbox)
                .where(Outbox.organization_id == org_id, Outbox.topic == "invitation.email")
                .order_by(Outbox.created_at.desc())
                .limit(100)
            )
        )
        return {"items": [_public(row) for row in rows]}
