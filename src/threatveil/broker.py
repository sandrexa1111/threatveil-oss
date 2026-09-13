"""Run capabilities. Workers authenticate with identity AND a scoped possession proof."""

import base64
import json
import secrets
from datetime import timedelta
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .observability import SafeErrorBoundary

from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from .auth import digest
from .http_limits import BodyLimitMiddleware
from .config import settings
from .db import (
    Lease,
    CapabilityRoute,
    LeaseNonce,
    RunState,
    Outbox,
    transaction,
    context,
    get_record,
    now,
    add_record,
)

app = FastAPI(title="ThreatVeil execution broker", docs_url=None, redoc_url=None)
app.add_middleware(BodyLimitMiddleware)


def local_identity_token(identity=None):
    if not settings().is_local:
        raise RuntimeError("Local service identity is disabled")
    path = Path(".local/service-identities") / (
        digest(identity or settings().worker_identity) + ".token"
    )
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.exists():
        import os

        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_urlsafe(32))
        except FileExistsError:
            pass
    return path.read_text().strip()


def service_identity(request: Request, expected=None):
    cfg = settings()
    token = request.headers.get("authorization", "").removeprefix("Bearer ")
    identity = expected or cfg.worker_identity
    if len(token) < 32:
        raise HTTPException(401, "Service identity required")
    if cfg.is_local:
        if request.client.host not in {
            "127.0.0.1",
            "::1",
            "testclient",
        } or not secrets.compare_digest(token, local_identity_token(identity)):
            raise HTTPException(401, "Worker identity rejected")
        return identity
    from google.oauth2 import id_token
    from google.auth.transport.requests import Request as GoogleRequest

    try:
        claims = id_token.verify_oauth2_token(token, GoogleRequest(), audience=cfg.broker_audience)
        if claims.get("email") != identity or claims.get("email_verified") is not True:
            raise ValueError()
    except Exception:
        raise HTTPException(401, "Service identity rejected") from None
    return identity


def prepare_dispatch(org_id, run_id):
    from .api import authorized_target

    cfg = settings()
    token = secrets.token_urlsafe(32)
    with transaction(org_id=org_id) as s:
        from .release_integrity import lock_system

        run = get_record(s, org_id, run_id, "run")
        lock_system(s, org_id, run.payload["system_id"])
        state = s.get(RunState, (org_id, run_id), with_for_update=True)
        if not state or state.status not in {"QUEUED", "DISPATCHED"}:
            raise HTTPException(409, "Run is not dispatchable")
        run = get_record(s, org_id, run_id, "run")
        authorized_target(s, org_id, run.payload["target_id"])
        previous = list(
            s.scalars(select(Lease).where(Lease.organization_id == org_id, Lease.run_id == run_id))
        )
        for item in previous:
            item.revoked = True
        lease = Lease(
            organization_id=org_id,
            run_id=run_id,
            token_hash=digest(token),
            bootstrap_expires=now() + timedelta(seconds=cfg.bootstrap_ttl_seconds),
            spec_digest=state.spec_digest,
            identity=cfg.worker_identity,
            fence=max([p.fence for p in previous], default=0) + 1,
        )
        s.add(lease)
        s.flush()
        s.add(
            CapabilityRoute(token_hash=lease.token_hash, lease_id=lease.id, organization_id=org_id)
        )
        state.status = "DISPATCHED"
    return {"run_id": str(run_id), "bootstrap_token": token}


class Claim(BaseModel):
    run_id: UUID
    bootstrap_token: str = Field(min_length=32, max_length=100)
    worker_key: str = Field(min_length=40, max_length=100)
    nonce: str = Field(min_length=16, max_length=100)
    signature: str = Field(min_length=40, max_length=200)


def claim_message(body: Claim):
    return f"{body.run_id}\n{digest(body.bootstrap_token)}\n{body.nonce}".encode()


def verify_signature(public_key, signature, message):
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True))
        key.verify(base64.b64decode(signature, validate=True), message)
    except Exception:
        raise HTTPException(401, "Worker possession proof rejected") from None


@app.post("/v1/claim")
def claim(body: Claim, request: Request):
    identity = service_identity(request)
    verify_signature(body.worker_key, body.signature, claim_message(body))
    with transaction() as s:
        route = s.get(CapabilityRoute, digest(body.bootstrap_token))
        if not route:
            raise HTTPException(403, "Run capability rejected")
        context(s, org_id=route.organization_id)
        current = s.get(Lease, route.lease_id)
        if not current:
            raise HTTPException(403, "Run capability rejected")
        from .release_integrity import lock_system

        run = get_record(s, route.organization_id, current.run_id, "run")
        lock_system(s, route.organization_id, run.payload["system_id"])
        state = s.get(RunState, (route.organization_id, current.run_id), with_for_update=True)
        lease = s.get(Lease, route.lease_id, with_for_update=True, populate_existing=True)
        if not state or state.settled or state.status not in {"DISPATCHED", "RUNNING"}:
            raise HTTPException(403, "Run is no longer claimable")
        if lease.run_id != body.run_id or lease.revoked or lease.identity != identity:
            raise HTTPException(403, "Run capability rejected")
        if lease.claimed_at:
            if (
                lease.worker_key != body.worker_key
                or lease.nonce != body.nonce
                or lease.lease_expires <= now()
            ):
                raise HTTPException(409, "Bootstrap already redeemed")
        else:
            if lease.bootstrap_expires <= now():
                raise HTTPException(403, "Bootstrap expired")
            from .api import authorized_target

            run = get_record(s, route.organization_id, body.run_id, "run")
            authorized_target(s, route.organization_id, run.payload["target_id"])
            state = s.get(RunState, (route.organization_id, body.run_id), with_for_update=True)
            if state.status != "DISPATCHED" or state.spec_digest != lease.spec_digest:
                raise HTTPException(409, "Run cannot be claimed")
            lease.claimed_at = now()
            lease.worker_key = body.worker_key
            lease.nonce = body.nonce
            lease.lease_expires = now() + timedelta(seconds=settings().lease_ttl_seconds)
            state.status = "RUNNING"
        return {
            "lease_id": str(lease.id),
            "run_id": str(lease.run_id),
            "fence": lease.fence,
            "expires_at": lease.lease_expires.isoformat(),
            "spec_digest": lease.spec_digest,
        }


class LeaseRequest(BaseModel):
    lease_id: UUID
    fence: int = Field(ge=1)
    nonce: str = Field(min_length=16, max_length=100)
    timestamp: int
    payload: dict = Field(default_factory=dict)
    signature: str = Field(min_length=40, max_length=200)


def lease_message(body: LeaseRequest, action):
    return f"{body.lease_id}\n{body.fence}\n{action}\n{body.nonce}\n{body.timestamp}\n{digest(json.dumps(body.payload, sort_keys=True, separators=(',', ':')))}".encode()


def authorize(s, body, request, action):
    identity = service_identity(request)
    route = s.scalar(select(CapabilityRoute).where(CapabilityRoute.lease_id == body.lease_id))
    if not route:
        raise HTTPException(403, "Lease unavailable")
    context(s, org_id=route.organization_id)
    current = s.get(Lease, body.lease_id)
    if not current:
        raise HTTPException(403, "Lease unavailable")
    from .release_integrity import lock_system

    run = get_record(s, route.organization_id, current.run_id, "run")
    lock_system(s, route.organization_id, run.payload["system_id"])
    state = s.get(RunState, (route.organization_id, current.run_id), with_for_update=True)
    lease = s.get(Lease, body.lease_id, with_for_update=True, populate_existing=True)
    if (
        not state
        or state.status != "RUNNING"
        or state.settled
        or state.spec_digest != lease.spec_digest
    ):
        raise HTTPException(403, "Run is no longer active")
    if (
        lease.revoked
        or not lease.claimed_at
        or lease.lease_expires <= now()
        or lease.fence != body.fence
        or lease.identity != identity
        or abs(now().timestamp() - body.timestamp) > 30
    ):
        raise HTTPException(403, "Lease expired, revoked or stale")
    verify_signature(lease.worker_key, body.signature, lease_message(body, action))
    if s.get(LeaseNonce, (lease.id, body.nonce)):
        raise HTTPException(409, "Lease request was replayed")
    s.add(LeaseNonce(lease_id=lease.id, nonce=body.nonce))
    run = get_record(s, lease.organization_id, lease.run_id, "run")
    from .api import authorized_target

    authorized_target(s, lease.organization_id, run.payload["target_id"])
    if run.payload.get("observer_id"):
        from .observers import active_observer

        active_observer(s, lease.organization_id, run.payload["observer_id"])
    return lease, run


@app.post("/v1/spec")
def spec(body: LeaseRequest, request: Request):
    with transaction() as s:
        lease, run = authorize(s, body, request, "spec")
        target = get_record(s, lease.organization_id, run.payload["target_id"], "target")
        return {
            "run_id": str(run.id),
            "spec": run.payload,
            "target": target.payload,
            "fence": lease.fence,
        }


@app.post("/v1/renew")
def renew(body: LeaseRequest, request: Request):
    with transaction() as s:
        lease, _ = authorize(s, body, request, "renew")
        from .captures import require_capture_capacity

        require_capture_capacity(s, lease.organization_id, lease.run_id)
        if (now() - lease.claimed_at).total_seconds() > 900:
            raise HTTPException(403, "Maximum run duration reached")
        lease.lease_expires = now() + timedelta(seconds=settings().lease_ttl_seconds)
        return {"expires_at": lease.lease_expires.isoformat()}


@app.post("/v1/credential")
def credential(body: LeaseRequest, request: Request):
    with transaction() as s:
        lease, run = authorize(s, body, request, "credential")
        target = get_record(s, lease.organization_id, run.payload["target_id"], "target")
        reference = str(body.payload.get("credential_reference_id", ""))
        if reference not in target.payload.get("credential_reference_ids", []):
            raise HTTPException(403, "Credential not authorized for this run")
        record = get_record(s, lease.organization_id, reference, "credential")
        from .credentials import read_reference

        value = read_reference(record)
        return {
            "value": value,
            "scope": "current authorized run",
            "provider_token_ttl": "provider-dependent",
        }


@app.post("/v1/complete")
def complete(body: LeaseRequest, request: Request):
    if len(json.dumps(body.payload)) > 2_000_000:
        raise HTTPException(413, "Evidence exceeds limit")
    with transaction() as s:
        lease, run = authorize(s, body, request, "complete")
        from .api import finish_run
        from .core import run_procurement
        from .captures import evaluate_persisted
        from .execution import evaluate_acquisition

        target = get_record(s, lease.organization_id, run.payload["target_id"], "target")
        try:
            if target.payload["adapter"] == "synthetic_procurement":
                # Reconstruct all statistics, metadata and verdicts from assigned observations.
                from .core.finance import run_finance
                execute_fixture = run_finance if target.payload.get("fixture_profile") == "finance-v1" else run_procurement
                result = execute_fixture(
                    run.payload["version"],
                    run.payload["property_definition"],
                    run.payload["trials"],
                    run.payload["variant_count"],
                    execution_id=str(run.id),
                    recorded_trials=body.payload.get("result", {}).get("trials", []),
                )
            else:
                if body.payload:
                    raise ValueError(
                        "Completion only accepts references to durable server evidence"
                    )
                if target.payload["adapter"] == "structured_trace":
                    result = evaluate_acquisition(
                        run.payload,
                        [
                            {
                                "variant_id": "recorded",
                                "index": 0,
                                "observation": run.payload["observation"],
                            }
                        ],
                    )
                else:
                    result = evaluate_persisted(s, lease.organization_id, run)
        except (ValueError, KeyError, TypeError):
            raise HTTPException(
                422, "Evidence is invalid, incomplete or belongs to another run assignment"
            ) from None
        lease.revoked = True
        # Complete after committing the lease consumption; finalization is idempotent and retryable via reconciliation.
        org_id = lease.organization_id
        run_id = lease.run_id
        add_record(
            s,
            org_id,
            "worker_completion",
            {"run_id": str(run_id), "result": result},
            {"run": run_id},
        )
    finish_run(org_id, run_id, result)
    return {"status": "accepted", "run_id": str(run_id)}


@app.post("/v1/observe")
def observe(body: LeaseRequest, request: Request):
    from .captures import persist_capture

    with transaction() as session:
        lease, run = authorize(session, body, request, "observe")
        target = get_record(session, lease.organization_id, run.payload["target_id"], "target")
        if target.payload["adapter"] not in {"http", "mcp", "openai_compatible"}:
            raise HTTPException(422, "Only active external runs use streaming observations")
        record = persist_capture(session, lease.organization_id, run, body.payload)
        return {
            "capture_id": str(record.id),
            "security_verdict": record.payload["evaluation"]["security_verdict"],
        }


def launcher_identity(request):
    import os

    return service_identity(request, os.environ.get("TV_LAUNCHER_IDENTITY", "local-launcher"))


@app.post("/v1/fail")
def fail(body: LeaseRequest, request: Request):
    with transaction() as session:
        lease, run = authorize(session, body, request, "fail")
        lease.revoked = True
        org_id, run_id = lease.organization_id, run.id
        result = {
            "security_verdict": "INCONCLUSIVE",
            "task_outcome": "UNKNOWN",
            "execution_status": "ERROR",
            "limitations": ["Worker did not complete the assigned evidence capture."],
        }
        add_record(
            session,
            org_id,
            "worker_completion",
            {"run_id": str(run_id), "result": result},
            {"run": run_id},
        )
    from .api import finish_run

    finish_run(org_id, run_id, result)
    return {"status": "accepted"}


@app.post("/internal/pending")
def pending(request: Request):
    launcher_identity(request)
    with transaction() as s:
        items = list(
            s.scalars(
                select(Outbox)
                .where(Outbox.topic == "run.dispatch", Outbox.status == "pending")
                .order_by(Outbox.created_at)
                .limit(20)
            )
        )
        return {
            "items": [
                {"id": str(i.id), "organization_id": str(i.organization_id), **i.payload}
                for i in items
            ]
        }


@app.post("/internal/prepare-dispatch")
def prepare(body: dict, request: Request):
    launcher_identity(request)
    try:
        return prepare_dispatch(UUID(body["organization_id"]), UUID(body["run_id"]))
    except (ValueError, KeyError):
        raise HTTPException(422, "Valid run dispatch required") from None


@app.post("/internal/dispatched")
def dispatched(body: dict, request: Request):
    launcher_identity(request)
    with transaction() as s:
        item = s.get(Outbox, UUID(body["outbox_id"]), with_for_update=True)
        if not item:
            raise HTTPException(404, "Dispatch unavailable")
        item.status = "delivered"
        item.attempts += 1
    return {"ok": True}


@app.post("/internal/reconcile")
def reconcile(request: Request):
    launcher_identity(request)
    from .maintenance import reconcile as run_maintenance

    return run_maintenance()


app.add_middleware(SafeErrorBoundary)
