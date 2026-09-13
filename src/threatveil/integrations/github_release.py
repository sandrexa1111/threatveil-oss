"""Tenant-routed GitHub App installation, webhook ledger and durable check delivery."""

import hashlib
from datetime import timedelta
from functools import partial
from uuid import UUID, NAMESPACE_URL, uuid4, uuid5

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field
from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert

from ..auth import Actor, SECURITY, actor, require
from ..config import settings
from ..db import (
    GitHubBinding,
    Membership,
    Outbox,
    Record,
    WebhookEvent,
    add_record,
    audit,
    context,
    get_record,
    now,
    serialize,
    transaction,
)
from ..schemas import Input
from .github_app import (
    GitHubAppClient,
    GitHubAppError,
    GitHubWriteAmbiguous,
    push_candidate,
    verify_webhook,
)

router = APIRouter(prefix="/v1", tags=["github-app"])
TOPIC = "github.check.publish"


class InstallationInput(Input):
    repository_id: str = Field(pattern=r"^[1-9][0-9]{0,19}$")
    installation_id: str = Field(pattern=r"^[1-9][0-9]{0,19}$")


def app_client():
    cfg = settings()
    return GitHubAppClient(cfg.github_app_id, cfg.github_private_key)


def _binding(session, org, repository_id, *, lock=False):
    binding = session.get(GitHubBinding, str(repository_id), with_for_update=lock)
    if not binding or binding.organization_id != org or not binding.enabled:
        raise HTTPException(404, "Repository has no active reviewed binding in this workspace")
    member = session.get(Membership, (org, binding.user_id))
    if not member or member.role not in SECURITY:
        raise HTTPException(403, "Repository binding owner no longer has security authority")
    return binding


def active_installation(session, org, repository_id):
    """Return the current locally enabled, reviewed installation, or None."""
    try:
        _binding(session, org, repository_id)
    except HTTPException:
        return None
    installs = list(
        session.scalars(
            select(Record)
            .where(
                Record.organization_id == org,
                Record.kind == "github_app_installation",
                Record.payload["repository_id"].astext == str(repository_id),
            )
            .order_by(Record.created_at.desc())
            .limit(100)
        )
    )
    for row in installs:
        revoked = session.scalar(
            select(Record.id)
            .where(
                Record.organization_id == org,
                Record.kind == "github_app_revocation",
                Record.payload["installation_record_id"].astext == str(row.id),
            )
            .limit(1)
        )
        if not revoked:
            return row
    return None


@router.post("/github/app/installations", status_code=201)
def register_installation(body: InstallationInput, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        binding = _binding(session, a.org_id, body.repository_id, lock=True)
        if active_installation(session, a.org_id, body.repository_id):
            raise HTTPException(409, "Revoke the existing App installation before replacement")
        try:
            with app_client() as github:
                verified = github.repository_installation(
                    binding.repository,
                    binding.repository_id,
                    binding.owner_id,
                    body.installation_id,
                )
        except GitHubAppError as error:
            raise HTTPException(422, str(error)) from None
        system_id = binding.run_template["system_id"]
        get_record(session, a.org_id, system_id, "system")
        row = add_record(
            session,
            a.org_id,
            "github_app_installation",
            {
                **verified,
                "system_id": system_id,
                "security_owner_id": str(binding.user_id),
                "registered_by": str(a.user_id),
                "verified_at": now().isoformat(),
                "permissions": {"checks": "write"},
                "live_check_delivered": False,
            },
            {"system": system_id},
        )
        audit(session, a.org_id, a.user_id, "github_app.registered", row.id)
        return serialize(row)


def _revoke(session, org, row, reason, user_id=None):
    existing = session.scalar(
        select(Record)
        .where(
            Record.organization_id == org,
            Record.kind == "github_app_revocation",
            Record.payload["installation_record_id"].astext == str(row.id),
        )
        .limit(1)
    )
    if existing:
        return existing
    revoked = add_record(
        session,
        org,
        "github_app_revocation",
        {
            "installation_record_id": str(row.id),
            "installation_id": row.payload["installation_id"],
            "repository_id": row.payload["repository_id"],
            "system_id": row.payload["system_id"],
            "reason": reason,
            "revoked_at": now().isoformat(),
        },
        {"installation": row.id},
    )
    audit(session, org, user_id, "github_app.revoked", row.id)
    return revoked


@router.post("/github/app/installations/{identifier}/revoke", status_code=201)
def revoke_installation(identifier: UUID, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        row = get_record(session, a.org_id, identifier, "github_app_installation")
        session.get(GitHubBinding, row.payload["repository_id"], with_for_update=True)
        return serialize(
            _revoke(session, a.org_id, row, "Revoked by workspace security owner", a.user_id)
        )


@router.get("/github/app/installations")
def list_installations(a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        rows = list(
            session.scalars(
                select(Record)
                .where(
                    Record.organization_id == a.org_id,
                    Record.kind == "github_app_installation",
                )
                .order_by(Record.created_at.desc())
                .limit(100)
            )
        )
        active = {}
        for row in rows:
            repository_id = row.payload["repository_id"]
            if repository_id not in active:
                current = active_installation(session, a.org_id, repository_id)
                active[repository_id] = current.id if current else None
        return {
            "items": [
                {**serialize(row), "enabled": active[row.payload["repository_id"]] == row.id}
                for row in rows
            ],
            "live_provider_status": "Checked during registration and delivery",
        }


def _webhook_record_id(body):
    # Delivery headers are not included in GitHub's HMAC. Claim the authenticated
    # bytes so changing X-GitHub-Delivery cannot replay the same payload.
    return uuid5(NAMESPACE_URL, "threatveil:github-webhook:" + hashlib.sha256(body).hexdigest())


@router.post("/webhooks/github", status_code=202)
async def github_webhook(request: Request):
    body = await request.body()
    try:
        payload = verify_webhook(
            body, request.headers.get("x-hub-signature-256", ""), settings().github_webhook_secret
        )
    except GitHubAppError as error:
        raise HTTPException(401, str(error)) from None
    event = request.headers.get("x-github-event", "")
    if event not in {"push", "installation", "installation_repositories"}:
        return {"accepted": False, "reason": "Event has no release-integrity operation"}
    identifier = _webhook_record_id(body)
    if event == "push":
        repository_id = str((payload.get("repository") or {}).get("id", ""))
        with transaction() as session:
            binding = session.get(GitHubBinding, repository_id, with_for_update=True)
            if not binding or not binding.enabled:
                return {"accepted": False, "reason": "Repository is not registered"}
            context(session, binding.user_id, binding.organization_id)
            install = active_installation(session, binding.organization_id, repository_id)
            if not install:
                return {"accepted": False, "reason": "No active App installation"}
            existing = session.get(Record, identifier)
            if existing:
                return {"accepted": True, "duplicate": True, "event_id": str(existing.id)}
            try:
                candidate = push_candidate(payload, binding, install.payload["installation_id"])
            except GitHubAppError as error:
                raise HTTPException(403, str(error)) from None
            row = add_record(
                session,
                binding.organization_id,
                "github_change_event",
                {
                    "system_id": install.payload["system_id"],
                    "repository_id": repository_id,
                    "installation_id": install.payload["installation_id"],
                    "candidate": candidate,
                    "before": payload.get("before"),
                    "ref": payload["ref"],
                    "body_digest": hashlib.sha256(body).hexdigest(),
                    "source": "github_app_push",
                    "status": "REPROOF_REQUIRED",
                    "received_at": now().isoformat(),
                    "limitations": [
                        "Push authenticates change, not the deployed candidate or security evidence."
                    ],
                },
                {"installation": install.id, "system": install.payload["system_id"]},
                record_id=identifier,
            )
            audit(
                session, binding.organization_id, binding.user_id, "github.change_observed", row.id
            )
            return {
                "accepted": True,
                "duplicate": False,
                "event_id": str(row.id),
                "candidate": candidate,
            }
    # Deletion/suspension/removal can only remove authorization. Unsuspend/add
    # never silently resurrects an old review; registration must verify it again.
    action = payload.get("action")
    if event == "installation" and action not in {"deleted", "suspend"}:
        return {
            "accepted": False,
            "reason": "Explicit registration is required to enable an installation",
        }
    if event == "installation_repositories" and action != "removed":
        return {
            "accepted": False,
            "reason": "Explicit registration is required for added repositories",
        }
    installation = payload.get("installation") or {}
    owner_id = str((installation.get("account") or {}).get("id", ""))
    installation_id = str(installation.get("id", ""))
    removed = {
        str(row.get("id"))
        for row in payload.get("repositories_removed", [])
        if isinstance(row, dict)
    }
    revoked = 0
    with transaction() as session:
        claimed = session.scalar(
            insert(WebhookEvent)
            .values(
                id="github:" + hashlib.sha256(body).hexdigest(),
                provider="github",
            )
            .on_conflict_do_nothing()
            .returning(WebhookEvent.id)
        )
        if not claimed:
            return {"accepted": True, "duplicate": True, "revoked": 0}
        bindings = list(
            session.scalars(
                select(GitHubBinding).where(GitHubBinding.owner_id == owner_id).with_for_update()
            )
        )
        for binding in bindings:
            if event == "installation_repositories" and binding.repository_id not in removed:
                continue
            context(session, binding.user_id, binding.organization_id)
            row = active_installation(session, binding.organization_id, binding.repository_id)
            if row and row.payload["installation_id"] == installation_id:
                _revoke(
                    session,
                    binding.organization_id,
                    row,
                    "Authenticated GitHub installation " + action,
                )
                revoked += 1
    return {"accepted": True, "revoked": revoked}


def enqueue_release_checks(session, org, release, *, refresh=False):
    """Queue only a trusted exact Git release in the same transaction as its receipt."""
    decision = release.payload
    candidate = decision.get("candidate") or {}
    if candidate.get("type") != "git_commit":
        return None
    install = active_installation(session, org, candidate.get("id"))
    if not install or install.payload["system_id"] != decision.get("system_id"):
        return None
    identifier = uuid5(release.id, "github.check.publish")
    existing = session.get(Outbox, identifier)
    if existing:
        if refresh and existing.status == "superseded":
            raise HTTPException(
                409, "A newer release superseded this check; create a fresh release decision"
            )
        if refresh and existing.status in {"delivered", "retry", "needs_attention", "ambiguous"}:
            existing.status = "retry"
            existing.attempts = 0
            existing.payload = {**existing.payload, "next_at": now().isoformat()}
        return str(existing.id)
    # One reviewed repository/ref routes one current release. Historical delivery
    # records remain immutable; only its newest decision needs ongoing polling.
    previous = session.scalars(
        select(Outbox)
        .where(
            Outbox.organization_id == org,
            Outbox.topic == TOPIC,
            Outbox.payload["repository_id"].astext == candidate["id"],
            Outbox.status.in_(["pending", "retry", "claimed", "ambiguous", "delivered"]),
        )
        .with_for_update()
    )
    for row in previous:
        row.status = "superseded"
    session.add(
        Outbox(
            id=identifier,
            organization_id=org,
            topic=TOPIC,
            payload={
                "release_id": str(release.id),
                "installation_record_id": str(install.id),
                "repository_id": candidate["id"],
            },
        )
    )
    return str(identifier)


@router.post("/github/releases/{release_id}/publish", status_code=202)
def publish_release(release_id: UUID, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        release = get_record(session, a.org_id, release_id, "release")
        candidate = release.payload.get("candidate") or {}
        _binding(session, a.org_id, candidate.get("id"), lock=True)
        queued = enqueue_release_checks(session, a.org_id, release, refresh=True)
        if not queued:
            raise HTTPException(
                422, "Exact Git release requires an active system-bound App installation"
            )
        return {"delivery_id": queued, "status": "queued"}


@router.get("/github/check-deliveries")
def check_deliveries(a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        rows = session.scalars(
            select(Outbox)
            .where(Outbox.organization_id == a.org_id, Outbox.topic == TOPIC)
            .order_by(Outbox.created_at.desc())
            .limit(100)
        )
        return {
            "items": [
                {
                    "id": str(row.id),
                    "status": row.status,
                    "attempts": row.attempts,
                    "release_id": row.payload["release_id"],
                    "last_error": row.payload.get("last_error"),
                }
                for row in rows
            ]
        }


@router.get("/github/change-events")
def change_events(a: Actor = Depends(actor)):
    with transaction(a.user_id, a.org_id) as session:
        rows = session.scalars(
            select(Record)
            .where(
                Record.organization_id == a.org_id,
                Record.kind == "github_change_event",
            )
            .order_by(Record.created_at.desc())
            .limit(100)
        )
        return {"items": [serialize(row) for row in rows]}


def _claim_delivery(identifier):
    with transaction() as session:
        row = session.scalar(
            select(Outbox)
            .where(Outbox.id == identifier, Outbox.topic == TOPIC)
            .with_for_update(skip_locked=True)
        )
        if row is None or row.status not in {
            "pending",
            "retry",
            "claimed",
            "ambiguous",
            "delivered",
        }:
            return None
        next_at = row.payload.get("next_at")
        if next_at and now().isoformat() < next_at:
            return None
        if row.status == "delivered":
            row.attempts = 0
        if row.attempts >= 10:
            row.status = "needs_attention"
            return None
        payload = dict(row.payload)
        permit_create = not payload.get("write_started")
        fence = str(uuid4())
        payload.update(claim_id=fence, next_at=(now() + timedelta(minutes=2)).isoformat())
        row.payload, row.status, row.attempts = payload, "claimed", row.attempts + 1
        return row.organization_id, payload, permit_create, fence


def _finish_delivery(identifier, fence, status, fields):
    with transaction() as session:
        row = session.get(Outbox, identifier, with_for_update=True)
        if row and row.payload.get("claim_id") == fence and row.status == "claimed":
            row.payload = {**row.payload, **fields}
            row.status = status


def _begin_write(identifier, fence):
    with transaction() as session:
        row = session.get(Outbox, identifier, with_for_update=True)
        if (
            not row
            or row.status != "claimed"
            or row.payload.get("claim_id") != fence
            or row.payload.get("next_at", "") <= now().isoformat()
        ):
            raise GitHubAppError("GitHub delivery claim is no longer current")
        row.payload = {**row.payload, "write_started": True}


def _begin_release_write(session, org, release, assessment, identifier, fence):
    from ..release_integrity import current_release_assessment

    fresh = current_release_assessment(session, org, release)
    if any(
        fresh[key] != assessment[key] for key in ("release_action", "underlying_action", "current")
    ):
        raise GitHubAppError(
            "Release authorization changed during GitHub reconciliation; retry required"
        )
    _begin_write(identifier, fence)


def reconcile_github_checks(limit=20, *, organization_id=None):
    """Retry bounded delivery; crash-ambiguous creates reconcile without re-creating."""
    if not settings().github_app_id or not settings().github_private_key:
        return {"delivered": 0, "pending_external_configuration": True}
    with transaction() as session:
        identifiers = list(
            session.scalars(
                select(Outbox.id)
                .where(
                    Outbox.topic == TOPIC,
                    *([Outbox.organization_id == organization_id] if organization_id else []),
                    Outbox.status.in_(["pending", "retry", "claimed", "ambiguous", "delivered"]),
                    or_(
                        Outbox.payload["next_at"].astext.is_(None),
                        Outbox.payload["next_at"].astext <= now().isoformat(),
                    ),
                )
                .order_by(Outbox.created_at)
                .limit(max(1, min(limit, 100)))
            )
        )
    delivered, failed = 0, 0
    for identifier in identifiers:
        claimed = _claim_delivery(identifier)
        if not claimed:
            continue
        org, route, permit_create, fence = claimed
        try:
            with transaction(org_id=org) as session:
                release = get_record(session, org, route["release_id"], "release")
                from ..release_integrity import current_release_assessment, lock_system

                # Organization deletion locks systems before installation routing.
                # Follow that same order to avoid binding -> system inversion.
                lock_system(session, org, release.payload["system_id"])
                binding = _binding(session, org, route["repository_id"], lock=True)
                context(session, binding.user_id, org)
                install = active_installation(session, org, binding.repository_id)
                if not install or str(install.id) != route["installation_record_id"]:
                    raise HTTPException(403, "App installation was revoked or replaced")
                if release.payload["system_id"] != install.payload["system_id"]:
                    raise HTTPException(403, "Release does not belong to the installed system")
                current = current_release_assessment(session, org, release)
                decision = dict(release.payload)
                decision["historical_release_action"] = decision["release_action"]
                decision["release_action"] = current["release_action"]
                decision["underlying_action"] = current["underlying_action"]
                decision["properties"] = current["properties"]
                decision_id, receipt_id = str(release.id), decision["receipt_id"]
                public_url = settings().web_origin.rstrip("/") + "/app/releases?release=" + decision_id
                repo, installation_id = binding.repository, install.payload["installation_id"]
                repository_id, system_id = binding.repository_id, decision["system_id"]
                owner_id, installation_record_id = binding.owner_id, install.id
                # Keep the same system/repository lock through the bounded write;
                # evidence cannot change between the current assessment and check.
                with app_client() as github:
                    github.repository_installation(repo, repository_id, owner_id, installation_id)
                    result = github.publish_check(
                        repo,
                        installation_id,
                        repository_id,
                        decision,
                        public_url,
                        permit_create=permit_create,
                        before_write=partial(
                            _begin_release_write, session, org, release, current, identifier, fence
                        ),
                    )
            with transaction(org_id=org) as session:
                outbox = session.get(Outbox, identifier, with_for_update=True)
                if outbox.payload.get("claim_id") != fence or outbox.status != "claimed":
                    continue
                publication = add_record(
                    session,
                    org,
                    "github_check_publication",
                    {
                        **result,
                        "release_id": decision_id,
                        "receipt_id": receipt_id,
                        "system_id": system_id,
                        "repository_id": repository_id,
                        "installation_id": installation_id,
                        "installation_record_id": route["installation_record_id"],
                        "policy_mode": decision["policy"]["mode"],
                        "delivered_at": now().isoformat(),
                        "current_applicable": current["current"],
                        "current_reasons": current["reasons"],
                        "effective_action": decision["release_action"],
                    },
                    {
                        "release": decision_id,
                        "receipt": receipt_id,
                        "installation": installation_record_id,
                    },
                )
                outbox.status = "delivered"
                outbox.payload = {
                    **outbox.payload,
                    "publication_id": str(publication.id),
                    "next_at": (now() + timedelta(minutes=5)).isoformat(),
                }
                delivered += 1
        except GitHubWriteAmbiguous:
            _finish_delivery(
                identifier,
                fence,
                "ambiguous",
                {"last_error": "GitHub write outcome requires reconciliation"},
            )
            failed += 1
        except (GitHubAppError, HTTPException, ValueError) as error:
            # No raw external response/request or credential is saved in the outbox.
            reason = error.detail if isinstance(error, HTTPException) else str(error)
            _finish_delivery(identifier, fence, "retry", {"last_error": str(reason)[:300]})
            failed += 1
    return {"delivered": delivered, "failed": failed, "pending_external_configuration": False}
