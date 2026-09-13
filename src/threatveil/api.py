"""ThreatVeil's organization-bound control plane."""

import json
import ipaddress
import secrets
import time
from contextlib import asynccontextmanager
from datetime import timedelta
from uuid import UUID, uuid4

from .observability import SafeErrorBoundary, event
from .assurance import router as assurance_router
from .security_memory import router as memory_router
from .tool_contracts import router as tool_contract_router
from .release_integrity import router as release_integrity_router
from .core.contracts import digest as contract_digest
from .integrity_launch import router as integrity_launch_router
from .integrations.github_release import router as github_app_router
from .integration_intake_api import router as integration_intake_router
from .governance import router as governance_router
from .trust import router as trust_router
from .release_machine import router as release_machine_router
from .commercial_api import router as commercial_router
from .connector_api import router as connector_router
from .change_assurance_api import router as change_assurance_router
from .measurements import router as measurements_router, QuotaExceeded, quota_exception_handler
from .assurance_api import router as assurance_intelligence_router
from .activation import router as activation_router
from .ai import router as ai_router
from .assurance_packs import router as assurance_pack_router
from .auto_reproof import router as auto_reproof_router
from .business_measurement import router as business_router
from .claim_builder import router as claim_builder_router
from .dependency_mapping import router as dependency_mapping_router
from .observer_platform import router as observer_platform_router
from .proposed_changes import router as proposed_change_router

from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, text, func, String
from sqlalchemy.exc import IntegrityError

from . import __version__
from .auth import (
    Actor,
    actor,
    require,
    check_origin,
    create_session,
    verify_firebase,
    digest,
    COOKIE,
    OWNERS,
    SECURITY,
)
from .config import settings
from .db import (
    transaction,
    context,
    now,
    engine,
    Account,
    RunState,
    TargetState,
    Membership,
    Organization,
    User,
    LoginSession,
    Invite,
    Outbox,
    Record,
    add_record,
    get_record,
    records,
    serialize,
    audit,
)
from .observers import ObserverInput, ObserverApproval

from .schemas import (
    LocalLogin,
    SystemInput,
    FindingInput,
    PropertyInput,
    TargetInput,
    RunInput,
    FixInput,
    GauntletInput,
    ImpactInput,
    InviteInput,
    PilotInput,
    CredentialInput,
    LeadInput,
)
from .targets import origin_parts, public_addresses, bounded_request


@asynccontextmanager
async def lifespan(app):
    cfg = settings()
    with engine().connect() as conn:
        role = conn.execute(
            text("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user")
        ).one()
        if role.rolsuper or role.rolbypassrls:
            raise RuntimeError("Runtime database role must not bypass RLS")
        owner = conn.execute(
            text(
                "SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tableowner=current_user) "
            )
        ).scalar()
        if owner:
            raise RuntimeError("Runtime database role must not own tables")
    if cfg.sentry_dsn:
        import sentry_sdk

        sentry_sdk.init(
            dsn=cfg.sentry_dsn,
            send_default_pii=False,
            include_local_variables=False,
            traces_sample_rate=0,
            before_send=lambda event, hint: {
                k: v
                for k, v in event.items()
                if k
                not in {
                    "request",
                    "breadcrumbs",
                    "extra",
                    "user",
                    "exception",
                    "logentry",
                    "message",
                }
            },
        )
    yield


app = FastAPI(title="ThreatVeil", version=__version__, lifespan=lifespan)
app.add_exception_handler(QuotaExceeded, quota_exception_handler)
ActorDep = Depends(actor)


@app.middleware("http")
async def boundaries(request, call_next):
    correlation = request.scope.get("tv_request_id") or str(uuid4())
    # Limits are enforced while streaming, not only through a spoofable Content-Length.
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        chunks = bytearray()
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > 2_000_000:
                return JSONResponse({"detail": "Request body exceeds limit"}, status_code=413)
            chunks.extend(chunk)
        request._body = bytes(chunks)
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        from sqlalchemy.dialects.postgresql import insert
        from .db import RateBucket

        route = request.url.path
        window = int(time.time() // 60)
        with transaction() as session:
            identity = "peer:" + (request.client.host if request.client else "unknown")
            cookie = request.cookies.get(COOKIE)
            # Caller-controlled random cookies must not reset the login limiter.
            # Only an existing unexpired session may become an authenticated key.
            if cookie and route not in {"/v1/leads", "/v1/auth/local", "/v1/auth/exchange"}:
                active_session = session.get(LoginSession, digest(cookie))
                if active_session and active_session.expires_at > now():
                    identity = "user:" + str(active_session.user_id)
            key = digest(identity + "|" + route)
            stmt = insert(RateBucket).values(key=key, window=window, count=1)
            count = session.execute(
                stmt.on_conflict_do_update(
                    index_elements=["key", "window"], set_={"count": RateBucket.count + 1}
                ).returning(RateBucket.count)
            ).scalar_one()
        limit = 20 if route in {"/v1/leads", "/v1/auth/local", "/v1/auth/exchange"} else 120
        if count > limit:
            return JSONResponse(
                {"detail": "Request rate limit reached"},
                status_code=429,
                headers={"Retry-After": "60"},
            )
    response = await call_next(request)
    response.headers["X-Request-ID"] = correlation
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Tenant data is never cacheable. The published trust root carries no tenant
    # data by construction and must be mirrorable by external verifiers.
    if not (request.url.path == "/v1/trust/keys" and response.status_code == 200):
        response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.exception_handler(IntegrityError)
async def conflict(request, error):
    return JSONResponse({"detail": "Conflicting record or tenant relationship"}, status_code=409)


@app.get("/healthz")
def health():
    return {"ok": True, "service": "threatveil-api", "version": __version__}


@app.post("/v1/auth/local")
def local_login(body: LocalLogin, request: Request, response: Response):
    try:
        loopback = ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        loopback = settings().env == "test" and request.client.host == "testclient"
    if (
        not settings().is_local
        or not settings().local_auth
        or not loopback
    ):
        raise HTTPException(404, "Local identity unavailable")
    return create_session(
        request,
        response,
        subject="local:" + body.email,
        email=body.email,
        name=body.name,
        organization_name=body.organization_name,
        mode="local",
    )


class ExchangeBody(BaseModel):
    id_token: str = Field(min_length=50, max_length=12000)
    organization_name: str = Field(default="My organization", min_length=1, max_length=120)


@app.post("/v1/auth/exchange")
def exchange(body: ExchangeBody, request: Request, response: Response):
    check_origin(request)
    if not settings().firebase_project:
        raise HTTPException(503, "Managed identity is not configured")
    claims = verify_firebase(body.id_token)
    return create_session(
        request,
        response,
        subject="firebase:" + claims["uid"],
        email=claims["email"],
        name=claims.get("name", claims["email"]),
        organization_name=body.organization_name,
        mode="managed",
    )


@app.get("/v1/auth/me")
def me(a: Actor = ActorDep):
    with transaction(a.user_id, a.org_id) as s:
        org = s.get(Organization, a.org_id)
        memberships = list(s.scalars(select(Membership).where(Membership.user_id == a.user_id)))
        return {
            "user": {"id": str(a.user_id), "name": a.name, "email": a.email, "role": a.role},
            "organization": {"id": str(a.org_id), "name": org.name, "role": a.role},
            "memberships": [
                {"organization_id": str(m.organization_id), "role": m.role} for m in memberships
            ],
            "csrf_token": a.csrf,
            "mode": a.mode,
        }


@app.post("/v1/auth/logout")
def logout(request: Request, response: Response, a: Actor = ActorDep):
    with transaction(a.user_id, a.org_id) as s:
        s.delete(s.get(LoginSession, digest(request.cookies[COOKIE])))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.post("/v1/auth/switch")
def switch(body: dict, request: Request, a: Actor = ActorDep):
    try:
        org_id = UUID(body["organization_id"])
    except (ValueError, KeyError):
        raise HTTPException(422, "Valid organization required") from None
    with transaction(a.user_id) as s:
        membership = s.get(Membership, (org_id, a.user_id))
        if not membership:
            raise HTTPException(403, "Not an organization member")
        session = s.get(LoginSession, digest(request.cookies[COOKIE]))
        session.organization_id = org_id
    return {"ok": True}


def list_kind(kind, a):
    from .workspace_reads import page

    with transaction(a.user_id, a.org_id) as session:
        rows, pagination = page(session, a.org_id, kind)
        return {"items": [serialize(row) for row in rows], "pagination": pagination}


def workspace_value(session, org_id, row):
    if row.kind == "run":
        return run_view(session, org_id, row)
    if row.kind == "gauntlet":
        return gauntlet_view(session, org_id, row)
    value = serialize(row)
    if row.kind == "target":
        state = session.get(TargetState, (org_id, row.id))
        value.update(
            verified=bool(
                state and state.verified_at and not state.revoked_at and state.expires_at > now()
            ),
            expires_at=state.expires_at.isoformat() if state else None,
            status="revoked"
            if state and state.revoked_at
            else "expired"
            if state and state.expires_at <= now()
            else "verified"
            if state and state.verified_at
            else "unverified",
        )
    return value


@app.get("/v1/workspace/{collection}")
def workspace_page(
    collection: str,
    a: Actor = ActorDep,
    limit: int = 100,
    cursor: str | None = None,
    query: str | None = None,
    system_id: UUID | None = None,
    approved: bool | None = None,
):
    from .workspace_reads import COLLECTIONS, page

    if collection not in COLLECTIONS:
        raise HTTPException(404, "Unknown workspace collection")
    with transaction(a.user_id, a.org_id) as session:
        rows, pagination = page(
            session, a.org_id, COLLECTIONS[collection], limit, cursor, query, system_id, approved
        )
        return {
            "items": [workspace_value(session, a.org_id, row) for row in rows],
            "pagination": pagination,
        }


@app.get("/v1/systems")
def list_systems(a: Actor = ActorDep):
    return list_kind("system", a)


@app.post("/v1/systems", status_code=201)
def create_system(body: SystemInput, a: Actor = ActorDep):
    require(a)
    with transaction(a.user_id, a.org_id) as s:
        from .commercial import require_system_capacity
        require_system_capacity(s, a.org_id)
        r = add_record(s, a.org_id, "system", body.model_dump(mode="json"))
        audit(s, a.org_id, a.user_id, "system.created", r.id)
        return serialize(r)


@app.get("/v1/findings")
def list_findings(a: Actor = ActorDep):
    return list_kind("finding", a)


@app.post("/v1/findings", status_code=201)
def create_finding(body: FindingInput, a: Actor = ActorDep):
    require(a)
    with transaction(a.user_id, a.org_id) as s:
        get_record(s, a.org_id, body.system_id, "system")
        r = add_record(
            s, a.org_id, "finding", body.model_dump(mode="json"), {"system": body.system_id}
        )
        return serialize(r)


@app.get("/v1/templates")
def get_templates(a: Actor = ActorDep):
    from .core import templates

    return {"items": templates()}


@app.post("/v1/threat-model")
def threat_model(body: dict, a: Actor = ActorDep):
    from .core import templates

    access = set(body.get("access", []))
    actions = set(body.get("actions", []))
    result = []
    for t in templates():
        tags = (
            set(t.get("access", t.get("resource_types", [])))
            | set(t.get("actions", []))
            | set(t.get("tags", []))
        )
        overlap = tags & (access | actions)
        if overlap:
            result.append({**t, "reason": "Relevant access/action: " + ", ".join(sorted(overlap))})
    return {
        "items": result,
        "coverage_note": "Suggested properties require local bindings and qualified observations.",
    }


@app.post("/v1/compiler/propose")
def compiler_proposal(body: dict, a: Actor = ActorDep):
    require(a)
    from .compiler import propose
    from .core import templates

    with transaction(a.user_id, a.org_id) as s:
        finding = get_record(s, a.org_id, body.get("finding_id"), "finding")
        try:
            result = propose(finding.payload, templates())
        except Exception:
            raise HTTPException(502, "Compiler unavailable; use manual property review") from None
        r = add_record(
            s,
            a.org_id,
            "proposal",
            {**result, "finding_id": str(finding.id), "system_id": finding.payload["system_id"]},
            {"finding": finding.id},
        )
        return serialize(r)


@app.get("/v1/properties")
def list_properties(a: Actor = ActorDep):
    return list_kind("property", a)


@app.post("/v1/properties", status_code=201)
def create_property(body: PropertyInput, a: Actor = ActorDep):
    require(a)
    from .core import templates

    with transaction(a.user_id, a.org_id) as s:
        get_record(s, a.org_id, body.system_id, "system")
        refs = {"system": body.system_id}
        if body.finding_id:
            finding = get_record(s, a.org_id, body.finding_id, "finding")
            if finding.payload["system_id"] != str(body.system_id):
                raise HTTPException(422, "Finding belongs to another system")
            refs["finding"] = body.finding_id
        definition = body.definition
        if not definition and body.template_id:
            template = next(
                (t for t in templates() if t.get("id", t.get("template_id")) == body.template_id),
                None,
            )
            if not template:
                raise HTTPException(422, "Unknown template")
            definition = template.get("definition", template.get("property_definition", {}))
        if not definition:
            raise HTTPException(422, "A structured property definition is required")
        data = body.model_dump(mode="json")
        data.update(definition=definition, approved=False, version=1)
        r = add_record(s, a.org_id, "property", data, refs)
        return serialize(r)


@app.post("/v1/properties/{record_id}/approve")
def approve_property(record_id: UUID, a: Actor = ActorDep):
    require(a, SECURITY)
    from .core.contracts import PropertyDefinition
    from .entitlements import require_property_capacity

    with transaction(a.user_id, a.org_id) as s:
        prop = get_record(s, a.org_id, record_id, "property")
        from .release_integrity import lock_system

        lock_system(s, a.org_id, prop.payload["system_id"])
        if prop.payload.get("approved"):
            return serialize(prop)
        approved = require_property_capacity(s, a.org_id, prop)
        if approved:
            return serialize(approved)
        try:
            definition = PropertyDefinition.model_validate(prop.payload["definition"]).model_dump(
                mode="json"
            )
        except Exception:
            raise HTTPException(
                422, "Property definition does not satisfy the observation contract"
            ) from None
        r = add_record(
            s,
            a.org_id,
            "property",
            {
                **prop.payload,
                "definition": definition,
                "approved": True,
                "version": prop.payload.get("version", 1) + 1,
                "supersedes_id": str(prop.id),
                "approved_by": str(a.user_id),
            },
            {"supersedes": prop.id, "system": prop.payload["system_id"]},
        )
        binding = add_record(
            s,
            a.org_id,
            "binding",
            {
                "property_id": str(r.id),
                "system_id": prop.payload["system_id"],
                "approved_by": str(a.user_id),
                "definition_digest": digest(json.dumps(definition, sort_keys=True)),
            },
            {"property": r.id, "system": prop.payload["system_id"]},
        )
        audit(s, a.org_id, a.user_id, "property.approved", r.id)
        return {**serialize(r), "binding_id": str(binding.id)}


@app.get("/v1/targets")
def list_targets(a: Actor = ActorDep):
    with transaction(a.user_id, a.org_id) as s:
        result = []
        for r in records(s, a.org_id, "target"):
            st = s.get(TargetState, (a.org_id, r.id))
            result.append(
                {
                    **serialize(r),
                    "verified": bool(st.verified_at),
                    "revoked": bool(st.revoked_at),
                    "status": "revoked"
                    if st.revoked_at
                    else "expired"
                    if st.expires_at <= now()
                    else "verified"
                    if st.verified_at
                    else "unverified",
                }
            )
        return {"items": result}


@app.post("/v1/targets", status_code=201)
def create_target(body: TargetInput, a: Actor = ActorDep):
    require(a, SECURITY)
    if body.expires_at.tzinfo is None or not now() < body.expires_at <= now() + timedelta(days=90):
        raise HTTPException(422, "Target expiry must be within 90 days and include timezone")
    if body.adapter != "structured_trace":
        try:
            origin_parts(body.origin or "")
            public_addresses(origin_parts(body.origin).hostname, 443)
        except (ValueError, OSError):
            raise HTTPException(422, "Target origin is invalid or prohibited") from None
    if body.adapter == "mcp" and not body.allowed_tools:
        raise HTTPException(422, "MCP requires explicitly authorized tools")
    if body.adapter == "openai_compatible" and not body.model:
        raise HTTPException(422, "Model adapter requires a pinned model identifier")
    challenge = secrets.token_urlsafe(32)
    with transaction(a.user_id, a.org_id) as s:
        get_record(s, a.org_id, body.system_id, "system")
        refs = {"system": body.system_id}
        for i, ref in enumerate(body.credential_reference_ids):
            get_record(s, a.org_id, ref, "credential")
            refs["credential_" + str(i)] = ref
        r = add_record(s, a.org_id, "target", body.model_dump(mode="json"), refs)
        s.add(
            TargetState(
                organization_id=a.org_id,
                target_id=r.id,
                challenge_hash=digest(challenge),
                expires_at=body.expires_at,
            )
        )
        audit(s, a.org_id, a.user_id, "target.registered", r.id)
        return {
            **serialize(r),
            "challenge": challenge,
            "challenge_path": "/.well-known/threatveil-authorization",
            "verified": False,
            "instructions": "Publish the challenge as plain text at the origin challenge path. Structured traces require explicit source authorization.",
        }


@app.post("/v1/targets/{record_id}/verify")
def verify_target(record_id: UUID, a: Actor = ActorDep):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as s:
        target = get_record(s, a.org_id, record_id, "target")
        st = s.get(TargetState, (a.org_id, record_id), with_for_update=True)
        if st.revoked_at or st.expires_at <= now():
            raise HTTPException(409, "Target authorization expired or revoked")
        if target.payload["adapter"] == "structured_trace":
            st.verified_at = now()
        elif target.payload["adapter"] == "synthetic_procurement":
            st.verified_at = now()
        else:
            try:
                result = bounded_request(
                    target.payload["origin"], "/.well-known/threatveil-authorization", "GET"
                )
                if (
                    result["status_code"] != 200
                    or digest(result["body"].decode().strip()) != st.challenge_hash
                ):
                    raise ValueError("Challenge mismatch")
            except Exception:
                raise HTTPException(
                    422, "Origin verification failed; check the published challenge"
                ) from None
            st.verified_at = now()
        audit(s, a.org_id, a.user_id, "target.verified", record_id)
        return {"id": str(record_id), "verified": True, "status": "verified"}


@app.post("/v1/targets/{record_id}/revoke")
def revoke_target(record_id: UUID, a: Actor = ActorDep):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as s:
        target = get_record(s, a.org_id, record_id, "target")
        from .release_integrity import lock_system

        lock_system(s, a.org_id, target.payload["system_id"])
        s.get(TargetState, (a.org_id, record_id), with_for_update=True).revoked_at = now()
        audit(s, a.org_id, a.user_id, "target.revoked", record_id)
    return {"revoked": True}


def authorized_target(s, org_id, target_id):
    from .governance import ensure_active

    ensure_active(s, org_id)
    target = get_record(s, org_id, target_id, "target")
    state = s.get(TargetState, (org_id, target.id))
    if not state or not state.verified_at or state.revoked_at or state.expires_at <= now():
        raise HTTPException(403, "Target is unverified, expired or revoked")
    if target.payload.get("execution_class", "DIGITAL_SANDBOX") not in {
        "DIGITAL_SANDBOX",
        "DIGITAL_STAGING",
    }:
        raise HTTPException(403, "Physical and simulation execution are not enabled")
    return target


@app.post("/v1/demo/setup")
def demo_setup(a: Actor = ActorDep):
    require(a, SECURITY)
    from .core import canonical_property
    from .entitlements import require_property_capacity

    with transaction(a.user_id, a.org_id) as s:
        account = s.get(Account, a.org_id, with_for_update=True)
        old = s.scalar(
            select(Record)
            .where(
                Record.organization_id == a.org_id,
                Record.kind == "system",
                Record.payload["demo"].astext == "true",
            )
            .order_by(Record.created_at)
            .limit(1)
        )
        if old:
            prop = s.scalar(
                select(Record)
                .where(
                    Record.organization_id == a.org_id,
                    Record.kind == "property",
                    Record.payload["system_id"].astext == str(old.id),
                    Record.payload["approved"].astext == "true",
                    Record.payload["definition"]["id"].astext == "procurement-payment-approval-v1",
                )
                .order_by(Record.created_at)
                .limit(1)
            )
            target = s.scalar(
                select(Record)
                .where(
                    Record.organization_id == a.org_id,
                    Record.kind == "target",
                    Record.payload["system_id"].astext == str(old.id),
                    Record.payload["adapter"].astext == "synthetic_procurement",
                )
                .order_by(Record.created_at)
                .limit(1)
            )
            if not prop or not target:
                raise HTTPException(409, "Synthetic fixture records require operator review")
            return {
                "system": serialize(old),
                "property": serialize(prop),
                "target": serialize(target),
            }
        from .commercial import require_system_capacity
        require_system_capacity(s, a.org_id)
        require_property_capacity(s, a.org_id)
        system = add_record(
            s,
            a.org_id,
            "system",
            {
                "name": "Procurement agent",
                "description": "Synthetic procurement workflow with an authoritative beneficiary ledger.",
                "demo": True,
                "access": ["payments", "files"],
                "actions": ["write", "approve"],
                "fingerprint": {"components": []},
            },
        )
        definition = canonical_property()
        prop = add_record(
            s,
            a.org_id,
            "property",
            {
                "system_id": str(system.id),
                "title": "Untrusted documents cannot change beneficiary details",
                "description": "Only approved instructions may mutate the beneficiary ledger.",
                "definition": definition,
                "approved": True,
                "version": 1,
                "demo": True,
            },
            {"system": system.id},
        )
        add_record(
            s,
            a.org_id,
            "binding",
            {
                "system_id": str(system.id),
                "property_id": str(prop.id),
                "approved_by": str(a.user_id),
                "demo": True,
            },
            {"system": system.id, "property": prop.id},
        )
        target = add_record(
            s,
            a.org_id,
            "target",
            {
                "system_id": str(system.id),
                "name": "Synthetic procurement ledger",
                "adapter": "synthetic_procurement",
                "execution_class": "DIGITAL_SANDBOX",
                "authorization_note": "Local synthetic fixture, no external network effects",
                "credential_reference_ids": [],
            },
            {"system": system.id},
        )
        s.add(
            TargetState(
                organization_id=a.org_id,
                target_id=target.id,
                challenge_hash=digest(secrets.token_urlsafe(32)),
                verified_at=now(),
                expires_at=now() + timedelta(days=30),
            )
        )
        if settings().is_local and account.status == "unassigned":
            account.plan = "pilot"
            account.status = "manual_pilot"
            account.trial_limit = 500
            account.max_systems = 3
            audit(s, a.org_id, a.user_id, "pilot.synthetic_budget_assigned")
        audit(s, a.org_id, a.user_id, "demo.setup", system.id)
        return {
            "system": serialize(system),
            "property": serialize(prop),
            "target": serialize(target),
        }


@app.get("/v1/runs")
def list_runs(a: Actor = ActorDep):
    with transaction(a.user_id, a.org_id) as s:
        return {"items": [run_view(s, a.org_id, r) for r in records(s, a.org_id, "run")]}


def run_view(s, org_id, r):
    state = s.get(RunState, (org_id, r.id))
    result = (
        get_record(s, org_id, state.result_id, "result").payload
        if state and state.result_id
        else {}
    )
    if result:
        from .adverse_memory import adverse_memory
        from .observers import active_observer

        result = dict(result)
        result["historical_release_action"] = result.get("release_action", "WARN")
        history = adverse_memory(s, org_id, r, result)
        result["adverse_memory"] = history
        try:
            authorized_target(s, org_id, r.payload["target_id"])
            if r.payload.get("observer_id"):
                active_observer(s, org_id, r.payload["observer_id"])
        except HTTPException:
            result["authorization_current"] = False
        if history["blocked"] or result.get("authorization_current") is False:
            result["release_action"] = "BLOCK"
            result["fix_eligible"] = False
            result["current_restrictions"] = [
                "Current authorization or retained adverse evidence prevents release."
            ]
    if not result and s.scalar(
        select(Record.id)
        .where(
            Record.organization_id == org_id,
            Record.kind == "trial_capture",
            Record.payload["run_id"].astext == str(r.id),
            Record.payload["evaluation"]["security_verdict"].astext == "FAIL",
        )
        .limit(1)
    ):
        result = {
            "security_verdict": "FAIL",
            "release_action": "BLOCK",
            "fix_eligible": False,
            "limitations": [
                "A confirmed failure has been captured; remaining execution is still in progress."
            ],
        }
    return {
        **serialize(r),
        **result,
        "id": str(r.id),
        "status": state.status if state else "ERROR",
        "result_id": str(state.result_id) if state and state.result_id else None,
    }


@app.get("/v1/runs/{record_id}")
def run_detail(record_id: UUID, a: Actor = ActorDep):
    with transaction(a.user_id, a.org_id) as s:
        return run_view(s, a.org_id, get_record(s, a.org_id, record_id, "run"))


@app.get("/v1/runs/{record_id}/evidence")
def run_evidence(record_id: UUID, a: Actor = ActorDep):
    with transaction(a.user_id, a.org_id) as s:
        run = get_record(s, a.org_id, record_id, "run")
        state = s.get(RunState, (a.org_id, run.id))
        if not state.result_id:
            raise HTTPException(409, "Evidence is not yet available")
        return get_record(s, a.org_id, state.result_id, "result").payload


@app.post("/v1/runs", status_code=202)
def create_run(body: RunInput, background: BackgroundTasks, a: Actor = ActorDep):
    require(a)
    if body.github and a.mode != "github_oidc":
        raise HTTPException(403, "GitHub release bindings require verified workflow identity")
    with transaction(a.user_id, a.org_id) as s:
        account = s.get(Account, a.org_id, with_for_update=True)
        existing = s.scalar(
            select(RunState).where(
                RunState.organization_id == a.org_id,
                RunState.idempotency_key == body.idempotency_key,
            )
        )
        data = body.model_dump(mode="json")
        spec_digest = digest(json.dumps(data, sort_keys=True))
        if existing:
            if existing.spec_digest != spec_digest:
                raise HTTPException(409, "Idempotency key reused for different execution")
            return run_view(s, a.org_id, get_record(s, a.org_id, existing.run_id, "run"))
        if a.mode == "schedule":
            from .commercial import require_capability

            require_capability(s, a.org_id, "release.automation")
        system = get_record(s, a.org_id, body.system_id, "system")
        prop = get_record(s, a.org_id, body.property_id, "property")
        target = authorized_target(s, a.org_id, body.target_id)
        if prop.payload["system_id"] != str(system.id) or target.payload["system_id"] != str(
            system.id
        ):
            raise HTTPException(422, "Property and target must be bound to the selected system")
        if not prop.payload.get("approved"):
            raise HTTPException(409, "Property requires security-owner approval")
        if body.qualification_case:
            require(a, SECURITY)
            if not body.observer_id or body.trials != 1 or body.variant_count != 1:
                raise HTTPException(
                    422, "Observer qualification requires one assigned active sample"
                )
        if body.observer_id:
            from .observers import active_observer

            observer = active_observer(s, a.org_id, body.observer_id)
            if any(
                observer.payload[k] != data[k] for k in ("system_id", "property_id", "target_id")
            ):
                raise HTTPException(422, "Observer does not cover this exact execution scope")
            if not observer.payload.get("approved") and not body.qualification_case:
                raise HTTPException(
                    409, "Observer requires qualification and security-owner review"
                )
            if target.payload["adapter"] not in {"http", "mcp"}:
                raise HTTPException(422, "Qualified observations require active target acquisition")
            data["observation_binding"] = observer.payload
        if target.payload["adapter"] == "synthetic_procurement" and body.version not in {
            "vulnerable",
            "fixed",
            "regressed",
            "missing_witness",
            "bad_fix",
        }:
            raise HTTPException(422, "Unsupported synthetic version")
        if target.payload["adapter"] == "structured_trace" and not body.observation:
            raise HTTPException(422, "Structured trace observation is required")
        if target.payload["adapter"] == "structured_trace" and (
            body.trials != 1 or body.variant_count != 1
        ):
            raise HTTPException(
                422,
                "A recorded observation is one sample and cannot be counted as repeated execution",
            )
        if target.payload["adapter"] not in {"synthetic_procurement", "structured_trace"}:
            stimulus = body.stimulus or {}
            if (
                stimulus.get("path") not in target.payload["paths"]
                or "POST" not in target.payload["methods"]
            ):
                raise HTTPException(
                    422, "Explicit POST stimulus must use an authorized target path"
                )
            if (
                len(stimulus.get("variants") or [stimulus.get("payload", stimulus.get("body", {}))])
                != body.variant_count
            ):
                raise HTTPException(422, "Every variant requires a frozen explicit stimulus")
        reserve = (
            body.trials
            * body.variant_count
            * (2 if target.payload["adapter"] == "synthetic_procurement" else 1)
        )
        from .commercial import require_verification_capacity
        require_verification_capacity(s, a.org_id, reserve)
        refs = {"system": system.id, "property": prop.id, "target": target.id}
        if body.baseline_id:
            baseline = get_record(s, a.org_id, body.baseline_id, "baseline")
            if baseline.payload["system_id"] != str(system.id) or baseline.payload[
                "property_id"
            ] != str(prop.id):
                raise HTTPException(
                    422, "Baseline is incompatible with this system/property version"
                )
            refs["baseline"] = baseline.id
        candidate = body.candidate or {
            "type": "application_version",
            "id": str(system.id),
            "version": body.version,
            "digest": contract_digest({"fixture": "procurement-v1", "version": body.version})
            if target.payload["adapter"] == "synthetic_procurement" else digest(body.version),
        }
        data.update(
            candidate=candidate,
            property_definition=prop.payload["definition"],
            spec_digest=spec_digest,
            usage_policy={
                "reserved_units": reserve,
                "consumed_when": "execution_starts",
                "refunded_when": "never_started",
            },
        )
        r = add_record(s, a.org_id, "run", data, refs)
        s.add(
            RunState(
                organization_id=a.org_id,
                run_id=r.id,
                idempotency_key=body.idempotency_key,
                spec_digest=spec_digest,
                reserved=reserve,
            )
        )
        account.reserved += reserve
        s.add(Outbox(organization_id=a.org_id, topic="run.dispatch", payload={"run_id": str(r.id)}))
        audit(s, a.org_id, a.user_id, "run.requested", r.id)
        run_id = r.id
    if settings().is_local:
        background.add_task(execute_run, a.org_id, run_id)
    return {"id": str(run_id), "run_id": str(run_id), "status": "QUEUED"}


@app.get("/v1/runs/{run_id}/captures/{capture_id}")
def capture_evidence(run_id: UUID, capture_id: UUID, a: Actor = ActorDep):
    with transaction(a.user_id, a.org_id) as session:
        get_record(session, a.org_id, run_id, "run")
        record = get_record(session, a.org_id, capture_id, "trial_capture")
        if record.payload["run_id"] != str(run_id):
            raise HTTPException(404, "Capture is outside this run")
        from .evidence_storage import load_observation

        return {
            **serialize(record),
            "observation": load_observation(a.org_id, run_id, record.payload["raw_evidence"]),
        }


def execute_run(org_id, run_id):
    """Local control-plane executor; cloud worker uses the isolated broker protocol."""
    from .core import run_procurement

    with transaction(org_id=org_id) as s:
        run = get_record(s, org_id, run_id, "run")
        from .release_integrity import lock_system

        lock_system(s, org_id, run.payload["system_id"])
        state = s.get(RunState, (org_id, run_id), with_for_update=True)
        if state.status != "QUEUED":
            return
        state.status = "RUNNING"
        run = get_record(s, org_id, run_id, "run")
        data = dict(run.payload)
        target = dict(authorized_target(s, org_id, data["target_id"]).payload)
    started = time.monotonic()
    try:
        if target["adapter"] == "synthetic_procurement":
            from .core.finance import run_finance
            execute_fixture = run_finance if target.get("fixture_profile") == "finance-v1" else run_procurement
            result = execute_fixture(
                data["version"],
                property_definition=data["property_definition"],
                trials=data["trials"],
                variant_count=data["variant_count"],
                execution_id=str(run_id),
            )
        else:
            result = execute_external(target, data, org_id, run_id)
        result = jsonable_encoder(result)
    except Exception as exc:
        result = {
            "security_verdict": "INCONCLUSIVE",
            "task_outcome": "UNKNOWN",
            "execution_status": "ERROR",
            "release_action": "WARN",
            "fix_eligible": False,
            "error": type(exc).__name__,
            "limitations": ["Execution did not produce complete qualified evidence."],
        }
    finish_run(org_id, run_id, result, round((time.monotonic() - started) * 1000))


def execute_external(target, data, org_id, run_id):
    import asyncio
    from .execution import acquire, evaluate_acquisition
    from .credentials import read_reference

    headers = {}

    def recheck():
        with transaction(org_id=org_id) as session:
            authorized_target(session, org_id, data["target_id"])
            from .captures import require_capture_capacity

            require_capture_capacity(session, org_id, run_id)
            if data.get("observer_id"):
                from .observers import active_observer

                active_observer(session, org_id, data["observer_id"])

    def capture(item):
        from .captures import persist_capture

        with transaction(org_id=org_id) as session:
            run = get_record(session, org_id, run_id, "run")
            from .adverse_memory import lock_artifact_scope

            lock_artifact_scope(session, org_id, run.payload)
            state = session.get(RunState, (org_id, run_id), with_for_update=True)
            if state.settled or state.status != "RUNNING":
                raise RuntimeError("Run is no longer active")
            persist_capture(session, org_id, run, item)

    refs = target.get("credential_reference_ids", [])
    if refs:
        with transaction(org_id=org_id) as session:
            record = get_record(session, org_id, refs[0], "credential")
            headers["Authorization"] = "Bearer " + read_reference(record)
    captures = asyncio.run(acquire(target, data, run_id, headers, recheck, capture, retain=False))
    if target["adapter"] == "structured_trace":
        return evaluate_acquisition(data, captures)
    from .captures import evaluate_persisted

    with transaction(org_id=org_id) as session:
        return evaluate_persisted(session, org_id, get_record(session, org_id, run_id, "run"))


def finish_run(org_id, run_id, result, duration_ms=0):
    with transaction(org_id=org_id) as s:
        run = get_record(s, org_id, run_id, "run")
        from .adverse_memory import adverse_memory, lock_artifact_scope

        lock_artifact_scope(s, org_id, run.payload)
        state = s.get(RunState, (org_id, run_id), with_for_update=True)
        if not state or state.settled:
            return
        execution_started = state.status == "RUNNING"
        from .captures import captured_trials

        captured = captured_trials(s, org_id, run_id)
        if captured:
            result["capture_ids"] = [str(r.id) for r in captured]
            if any(r.payload["evaluation"]["security_verdict"] == "FAIL" for r in captured):
                result["security_verdict"] = "FAIL"
                result["confirmed_failure_preserved"] = True
        # Revocation/expiry prevents completion from being reported as an authorized fresh result.
        try:
            authorized_target(s, org_id, run.payload["target_id"])
            if run.payload.get("observer_id"):
                from .observers import active_observer

                active_observer(s, org_id, run.payload["observer_id"])
        except HTTPException:
            result = {
                **result,
                "release_action": "BLOCK",
                "authorization_current": False,
                "limitations": result.get("limitations", [])
                + ["Target authorization expired or was revoked during execution."],
            }
        else:
            result["authorization_current"] = True
        history = adverse_memory(s, org_id, run, result)
        result["adverse_memory"] = history
        verdict = result.get("security_verdict", "INCONCLUSIVE")
        task = result.get("task_outcome", "UNKNOWN")
        result["fix_eligible"] = (
            verdict == "PASS"
            and not history["blocked"]
            and task == "SUCCESS"
            and result.get("execution_status") == "COMPLETED"
            and result["authorization_current"]
            and not run.payload.get("qualification_case")
            and (not run.payload.get("observer_id") or result.get("candidate_observed") is True)
        )
        result["regression"] = False
        if run.payload.get("baseline_id"):
            from .core import compare_runs

            baseline = get_record(s, org_id, run.payload["baseline_id"], "baseline")
            previous = get_record(s, org_id, baseline.payload["run_id"], "run")
            prior = run_view(s, org_id, previous)
            comparison = compare_runs(prior, result)
            result["comparison"] = comparison
            result["regression"] = bool(comparison.get("regression"))
        result["release_action"] = (
            "ALLOW"
            if result["fix_eligible"]
            and (
                not run.payload.get("baseline_id")
                or result.get("comparison", {}).get("compatible") is True
            )
            else (
                "BLOCK"
                if verdict == "FAIL"
                or history["blocked"]
                or not result["authorization_current"]
                or run.payload["property_definition"].get("release_policy") == "BLOCK"
                else "WARN"
            )
        )
        result.update(
            system_id=run.payload["system_id"],
            property_id=run.payload["property_id"],
            candidate=run.payload["candidate"],
            duration_ms=duration_ms,
            scope_complete=result.get("execution_status") == "COMPLETED",
            purpose="OBSERVER_QUALIFICATION"
            if run.payload.get("qualification_case")
            else "ASSURANCE",
        )
        result["usage"] = {
            "units": state.reserved
            if execution_started or result.get("execution_status") == "COMPLETED"
            else 0,
            "basis": "Reserved execution units are consumed once execution starts, including error/timeout; only unstarted reservations are refunded.",
        }
        result["evidence_digest"] = digest(json.dumps(result, sort_keys=True))
        record = add_record(
            s, org_id, "result", result, {"run": run.id, "property": run.payload["property_id"]}
        )
        state.result_id = record.id
        state.status = result.get("execution_status", "ERROR")
        state.settled = True
        from .release_integrity import snapshot_evidence

        snapshot_evidence(s, org_id, run, record)
        account = s.get(Account, org_id, with_for_update=True)
        account.reserved -= state.reserved
        account.consumed += result["usage"]["units"]
        decision = add_record(
            s,
            org_id,
            "release_decision",
            {
                "run_id": str(run.id),
                "candidate": run.payload["candidate"],
                "action": result["release_action"],
                "evidence_digest": result["evidence_digest"],
                "property_id": run.payload["property_id"],
                "baseline_id": run.payload.get("baseline_id"),
                "policy_version": 1,
                "github": run.payload.get("github"),
            },
            {"run": run.id, "result": record.id},
        )
        if result["regression"]:
            add_record(
                s,
                org_id,
                "regression",
                {
                    "run_id": str(run.id),
                    "baseline_id": run.payload["baseline_id"],
                    "system_id": run.payload["system_id"],
                    "property_id": run.payload["property_id"],
                    "decision_id": str(decision.id),
                },
                {"run": run.id, "baseline": run.payload["baseline_id"]},
            )
        if verdict == "FAIL" and not run.payload.get("qualification_case"):
            add_record(
                s,
                org_id,
                "finding",
                {
                    "title": "Prohibited action observed",
                    "description": "See run evidence for the scoped confirmed outcome.",
                    "source_type": "execution",
                    "system_id": run.payload["system_id"],
                    "run_id": str(run.id),
                    "property_id": run.payload["property_id"],
                },
                {"run": run.id, "system": run.payload["system_id"]},
            )

    event(
        "run.finished",
        "ERROR" if result.get("execution_status") in {"ERROR", "TIMEOUT"} else "INFO",
        organization_id=str(org_id),
        run_id=str(run_id),
        duration_ms=duration_ms,
        security_verdict=result.get("security_verdict", "INCONCLUSIVE"),
        execution_status=result.get("execution_status", "ERROR"),
    )


@app.get("/v1/fixes")
def list_fixes(a: Actor = ActorDep):
    return list_kind("fix", a)


@app.post("/v1/fixes", status_code=201)
def verify_fix(body: FixInput, a: Actor = ActorDep):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as s:
        failed = get_record(s, a.org_id, body.run_id, "run")
        verified = get_record(s, a.org_id, body.verification_run_id, "run")
        from .adverse_memory import lock_artifact_scope

        lock_artifact_scope(s, a.org_id, verified.payload)
        original = run_view(s, a.org_id, failed)
        candidate = run_view(s, a.org_id, verified)
        if original.get("security_verdict") != "FAIL":
            raise HTTPException(422, "Original run must contain a confirmed failure")
        if any(
            failed.payload[k] != verified.payload[k]
            for k in ("system_id", "property_id", "target_id")
        ):
            raise HTTPException(
                422, "Fix verification must use the same system, property version and target"
            )
        from .core.regression import comparison_signature

        previous_signature, verification_signature = (
            comparison_signature(original),
            comparison_signature(candidate),
        )
        # A larger fixed verification sample is permitted; security stimuli and boundary semantics must persist.
        mismatches = [
            key
            for key in previous_signature
            if key != "experiment" and previous_signature[key] != verification_signature[key]
        ]
        eligible = candidate.get("fix_eligible") is True and not mismatches
        fix = add_record(
            s,
            a.org_id,
            "fix",
            {
                "system_id": failed.payload["system_id"],
                "property_id": failed.payload["property_id"],
                "run_id": str(failed.id),
                "verification_run_id": str(verified.id),
                "description": body.description,
                "verified": eligible,
                "status": "VERIFIED" if eligible else "NOT_VERIFIED",
                "reason": "Security PASS, legitimate task SUCCESS and compatible failure replay"
                if eligible
                else "Incompatible failure replay: " + ", ".join(mismatches)
                if mismatches
                else "Security, task or observation requirements not satisfied",
            },
            {"failure_run": failed.id, "verification_run": verified.id},
        )
        baseline = None
        if eligible:
            baseline = add_record(
                s,
                a.org_id,
                "baseline",
                {
                    "system_id": failed.payload["system_id"],
                    "property_id": failed.payload["property_id"],
                    "target_id": failed.payload["target_id"],
                    "fix_id": str(fix.id),
                    "run_id": str(verified.id),
                    "candidate": verified.payload["candidate"],
                    "evidence_digest": candidate["evidence_digest"],
                    "fingerprint": candidate.get("fingerprint", {}),
                    "property_digest": candidate.get("property_digest"),
                },
                {"fix": fix.id, "run": verified.id, "property": failed.payload["property_id"]},
            )
        audit(s, a.org_id, a.user_id, "fix.verified" if eligible else "fix.rejected", fix.id)
        return {**serialize(fix), "baseline_id": str(baseline.id) if baseline else None}


@app.get("/v1/baselines")
def list_baselines(a: Actor = ActorDep):
    return list_kind("baseline", a)


@app.get("/v1/regressions")
def list_regressions(a: Actor = ActorDep):
    return list_kind("regression", a)


@app.post("/v1/impact")
def impact(body: ImpactInput, a: Actor = ActorDep):
    require(a)
    from .core import analyze_change

    with transaction(a.user_id, a.org_id) as s:
        get_record(s, a.org_id, body.system_id, "system")
        properties = [
            {**r.payload["definition"], "id": str(r.id)}
            for r in s.scalars(
                select(Record)
                .where(
                    Record.organization_id == a.org_id,
                    Record.kind == "property",
                    Record.payload["system_id"].astext == str(body.system_id),
                    Record.payload["approved"].astext == "true",
                )
                .order_by(Record.created_at, Record.id)
            )
        ]
        try:
            result = analyze_change(body.previous, body.candidate, properties)
        except ValueError:
            raise HTTPException(422, "Invalid typed fingerprint") from None
        change = add_record(
            s, a.org_id, "change", body.model_dump(mode="json"), {"system": body.system_id}
        )
        assessment = add_record(
            s,
            a.org_id,
            "impact",
            {**result, "system_id": str(body.system_id), "change_id": str(change.id)},
            {"change": change.id, "system": body.system_id},
        )
        return serialize(assessment)


@app.get("/v1/propagation")
def propagation(a: Actor = ActorDep):
    with transaction(a.user_id, a.org_id) as s:
        systems = records(s, a.org_id, "system")
        props = records(s, a.org_id, "property")
        items = []
        for prop in props:
            if not prop.payload.get("approved"):
                continue
            origin = next((r for r in systems if str(r.id) == prop.payload["system_id"]), None)
            if not origin:
                continue
            for dest in systems:
                if dest.id == origin.id:
                    continue
                shared = set(origin.payload.get("access", [])) & set(dest.payload.get("access", []))
                if shared:
                    items.append(
                        {
                            "source_property_id": str(prop.id),
                            "source_system_id": str(origin.id),
                            "destination_system_id": str(dest.id),
                            "destination_name": dest.payload["name"],
                            "reason": "Shared declared access: " + ", ".join(sorted(shared)),
                            "status": "REQUIRES_LOCAL_BINDING",
                            "verdict": None,
                        }
                    )
        return {"items": items}


@app.post("/v1/propagation/adopt", status_code=201)
def adopt(body: dict, a: Actor = ActorDep):
    require(a)
    with transaction(a.user_id, a.org_id) as s:
        source = get_record(s, a.org_id, body.get("source_property_id"), "property")
        dest = get_record(s, a.org_id, body.get("destination_system_id"), "system")
        prop = add_record(
            s,
            a.org_id,
            "property",
            {
                **{
                    key: value
                    for key, value in source.payload.items()
                    if key not in {"supersedes_id", "approved_by"}
                },
                "system_id": str(dest.id),
                "approved": False,
                "version": 1,
                "propagated_from": str(source.id),
                "binding_status": "REQUIRES_LOCAL_BINDING",
            },
            {"source_property": source.id, "system": dest.id},
        )
        return serialize(prop)


@app.get("/v1/gauntlets")
def list_gauntlets(a: Actor = ActorDep):
    with transaction(a.user_id, a.org_id) as session:
        return {
            "items": [
                gauntlet_view(session, a.org_id, r) for r in records(session, a.org_id, "gauntlet")
            ]
        }


def gauntlet_view(session, org_id, record):
    scope = set(record.payload["property_ids"])
    from sqlalchemy.orm import aliased

    result_record = aliased(Record)
    scoped_runs = select(Record.id).where(
        Record.organization_id == org_id,
        Record.kind == "run",
        Record.payload["system_id"].astext == record.payload["system_id"],
        Record.payload["property_id"].astext.in_(scope),
        Record.created_at >= record.created_at,
        Record.payload["qualification_case"].astext.is_(None),
    )
    query = (
        select(
            Record.id,
            Record.payload["property_id"].astext,
            RunState.status,
            result_record.payload["security_verdict"].astext,
            result_record.payload["fix_eligible"].astext,
        )
        .join(
            RunState,
            (RunState.run_id == Record.id) & (RunState.organization_id == Record.organization_id),
        )
        .outerjoin(
            result_record,
            (result_record.id == RunState.result_id)
            & (result_record.organization_id == Record.organization_id),
        )
        .where(Record.id.in_(scoped_runs))
        .order_by(Record.created_at.desc(), Record.id.desc())
    )
    latest, tested, failed, run_ids, running, total_runs = {}, set(), set(), [], False, 0
    for run_id, prop_id, state, verdict, eligible in session.execute(query).yield_per(100):
        total_runs += 1
        if len(run_ids) < 200:
            run_ids.append(str(run_id))
        latest.setdefault(prop_id, eligible == "true")
        if state == "COMPLETED":
            tested.add(prop_id)
        if verdict == "FAIL":
            failed.add(prop_id)
        if state in {"QUEUED", "DISPATCHED", "RUNNING"}:
            running = True
            current = run_view(session, org_id, get_record(session, org_id, run_id, "run"))
            if current.get("security_verdict") == "FAIL":
                failed.add(prop_id)
    useful = {prop for prop, eligible in latest.items() if eligible}
    installed = set(
        session.scalars(
            select(Record.payload["property_id"].astext).where(
                Record.organization_id == org_id,
                Record.kind == "fix",
                Record.payload["verified"].astext == "true",
                Record.payload["verification_run_id"].astext.in_(
                    select(func.cast(scoped_runs.subquery().c.id, String))
                ),
            )
        )
    )
    status = (
        "SCOPED"
        if not total_runs
        else "RUNNING"
        if running
        else "VERIFIED"
        if scope and useful >= scope
        else "REMEDIATION_REQUIRED"
        if failed - useful
        else "MORE_EVIDENCE_REQUIRED"
    )
    return {
        **serialize(record),
        "status": status,
        "summary": {
            "properties_scoped": len(scope),
            "properties_tested": len(tested),
            "properties_failed": len(failed),
            "fixes_verified": len(installed),
            "permanent_invariants_installed": len(installed),
        },
        "run_ids": run_ids,
        "run_history_total": total_runs,
        "run_ids_truncated": total_runs > 200,
        "next_action": "KEEP_RUNNING_CONTINUOUSLY"
        if status == "VERIFIED"
        else "EXECUTE_AND_VERIFY",
        "report_url": f"/v1/reports/{record.payload['system_id']}",
    }


@app.post("/v1/gauntlets", status_code=201)
def create_gauntlet(body: GauntletInput, a: Actor = ActorDep):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as s:
        get_record(s, a.org_id, body.system_id, "system")
        refs = {"system": body.system_id}
        for index, prop_id in enumerate(body.property_ids):
            prop = get_record(s, a.org_id, prop_id, "property")
            if prop.payload["system_id"] != str(body.system_id):
                raise HTTPException(422, "Properties must belong to the Gauntlet system")
            refs["property_" + str(index)] = prop_id
        return serialize(
            add_record(
                s,
                a.org_id,
                "gauntlet",
                {**body.model_dump(mode="json"), "owner_id": str(a.user_id), "status": "SCOPED"},
                refs,
            )
        )


def system_report(s, org_id, system_id):
    system = get_record(s, org_id, system_id, "system")

    def query(kind):
        return select(Record).where(
            Record.organization_id == org_id,
            Record.kind == kind,
            Record.payload["system_id"].astext == str(system_id),
        )

    def scoped(kind):
        return list(
            s.scalars(query(kind).order_by(Record.created_at.desc(), Record.id.desc()).limit(200))
        )

    def relevant(kind):
        return [serialize(r) for r in scoped(kind)]

    def count(kind, *conditions, expression=None):
        return (
            s.scalar(
                query(kind)
                .with_only_columns(expression if expression is not None else func.count())
                .where(*conditions)
            )
            or 0
        )

    runs = [run_view(s, org_id, r) for r in scoped("run")]
    totals = {
        kind: count(kind)
        for kind in ("run", "property", "fix", "finding", "baseline", "regression")
    }
    fixes = relevant("fix")
    props = relevant("property")
    return {
        "system": serialize(system),
        "generated_at": now().isoformat(),
        "method": "Bounded property execution with qualified observations",
        "properties": props,
        "runs": runs,
        "fixes": fixes,
        "findings": relevant("finding"),
        "baselines": relevant("baseline"),
        "regressions": relevant("regression"),
        "history_window": {
            "limit_per_kind": 200,
            "total_records": totals,
            "truncated": any(n > 200 for n in totals.values()),
            "full_export": "/v1/memory/export",
        },
        "summary": {
            "properties_tested": count(
                "result",
                Record.payload["execution_status"].astext == "COMPLETED",
                expression=func.count(func.distinct(Record.payload["property_id"].astext)),
            ),
            "failures_confirmed": count(
                "result", Record.payload["security_verdict"].astext == "FAIL"
            ),
            "fixes_verified": count("fix", Record.payload["verified"].astext == "true"),
            "permanent_properties": count("property", Record.payload["approved"].astext == "true"),
        },
        "limitations": [
            "Passing sampled properties does not prove universal safety.",
            "Detail tables show up to 200 newest records per type; summary counts cover the full system history. Use memory export for complete records.",
            "Synthetic fixture results describe synthetic systems only.",
        ],
        "continuous_assurance": "Configure GitHub and recurring execution with an explicit usage budget.",
    }


@app.get("/v1/memory/export")
def memory_export(a: Actor = ActorDep):
    from .memory_export import export_memory

    require(a, SECURITY)
    return StreamingResponse(
        export_memory(a.user_id, a.org_id),
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": 'attachment; filename="threatveil-memory.ndjson"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/v1/reports/{system_id}")
def report(system_id: UUID, a: Actor = ActorDep):
    with transaction(a.user_id, a.org_id) as s:
        return system_report(s, a.org_id, system_id)


@app.get("/v1/reports/{system_id}/html", response_class=HTMLResponse)
def report_html(system_id: UUID, a: Actor = ActorDep):
    from html import escape

    with transaction(a.user_id, a.org_id) as s:
        data = system_report(s, a.org_id, system_id)
    rows = "".join(
        "<tr><td>"
        + escape(r.get("version", ""))
        + "</td><td>"
        + escape(r.get("security_verdict", "PENDING"))
        + "</td><td>"
        + escape(r.get("task_outcome", "UNKNOWN"))
        + "</td><td>"
        + escape(r.get("release_action", "WARN"))
        + "</td><td>"
        + escape(r.get("evidence_digest", ""))
        + "</td></tr>"
        for r in data["runs"]
    )
    summary = "".join(
        "<li>" + escape(k.replace("_", " ")) + ": " + str(v) + "</li>"
        for k, v in data["summary"].items()
    )
    html = (
        '<!doctype html><html><head><meta charset="utf-8"><title>ThreatVeil assurance report</title><style>body{font:15px system-ui;max-width:1050px;margin:60px auto;color:#152926;padding:24px}h1{font-size:36px}table{border-collapse:collapse;width:100%;font-size:12px}td,th{padding:12px;border-bottom:1px solid #ccd;word-break:break-all}code{word-break:break-all}@media print{body{margin:0}}</style></head><body><p>THREATVEIL · PROVE. REMEMBER. RE-PROVE.</p><h1>'
        + escape(data["system"]["name"])
        + "</h1><p>Security assurance report · "
        + escape(data["generated_at"])
        + "</p><h2>Executive summary</h2><ul>"
        + summary
        + "</ul><h2>Scope and method</h2><p>"
        + escape(data["method"])
        + "</p><p>"
        + escape(data["system"].get("description", ""))
        + "</p><h2>Evidence and release results</h2><table><tr><th>Version</th><th>Security</th><th>Legitimate task</th><th>Decision</th><th>Evidence digest</th></tr>"
        + rows
        + "</table><h2>Limitations</h2><p>"
        + escape(" ".join(data["limitations"]))
        + "</p><h2>Continuous assurance</h2><p>"
        + escape(data["continuous_assurance"])
        + "</p></body></html>"
    )
    return HTMLResponse(
        html,
        headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
            "Content-Disposition": f'attachment; filename="threatveil-{system_id}.html"',
        },
    )


@app.get("/v1/members")
def members(a: Actor = ActorDep):
    with transaction(a.user_id, a.org_id) as s:
        rows = s.execute(
            select(Membership, User)
            .join(User, User.id == Membership.user_id)
            .where(Membership.organization_id == a.org_id)
        )
        return {
            "items": [
                {"id": str(u.id), "email": u.email, "name": u.name, "role": m.role} for m, u in rows
            ]
        }


@app.post("/v1/members/invite")
def invite(body: InviteInput, a: Actor = ActorDep):
    require(a, OWNERS)
    if "@" not in body.email:
        raise HTTPException(422, "Email required")
    token = secrets.token_urlsafe(32)
    with transaction(a.user_id, a.org_id) as s:
        from .commercial import require_capability

        require_capability(s, a.org_id, "team.collaboration")
        existing_member = s.scalar(
            select(Membership.user_id)
            .join(User, User.id == Membership.user_id)
            .where(
                Membership.organization_id == a.org_id, func.lower(User.email) == body.email.lower()
            )
            .limit(1)
        )
        if existing_member:
            raise HTTPException(409, "Already a member; use member role settings")
        pending = list(
            s.scalars(
                select(Invite).where(
                    Invite.organization_id == a.org_id,
                    Invite.email == body.email.lower(),
                    Invite.used_at.is_(None),
                    Invite.expires_at > now(),
                )
            )
        )
        for existing in pending:
            delivery = s.scalar(
                select(Outbox).where(
                    Outbox.organization_id == a.org_id,
                    Outbox.topic == "invitation.email",
                    Outbox.payload["invitation_token_hash"].astext == existing.token_hash,
                )
            )
            if existing.role == body.role and delivery:
                return {
                    "status": delivery.status,
                    "delivery_id": str(delivery.id),
                    "invite_url": delivery.payload["url"],
                    "expires_at": existing.expires_at.isoformat(),
                    "reused": True,
                }
            existing.expires_at = now()
        s.add(
            Invite(
                token_hash=digest(token),
                organization_id=a.org_id,
                email=body.email.lower(),
                role=body.role,
                expires_at=now() + timedelta(days=7),
            )
        )
        audit(s, a.org_id, a.user_id, "membership.invited")
        delivery = Outbox(
            organization_id=a.org_id,
            topic="invitation.email",
            payload={
                "email": body.email.lower(),
                "url": settings().web_origin + "/invite?token=" + token,
                "invitation_token_hash": digest(token),
            },
        )
        s.add(delivery)
        s.flush()
        delivery_id = str(delivery.id)
    cfg = settings()
    enabled = bool(cfg.resend_api_key and cfg.email_from and cfg.resend_delivery_enabled)
    return {
        "status": "queued" if enabled else "manual_delivery_required",
        "delivery_id": delivery_id,
        "invite_url": cfg.web_origin + "/invite?token=" + token,
        "expires_in_days": 7,
    }


@app.post("/v1/members/accept")
def accept_invite(body: dict, a: Actor = ActorDep):
    token = str(body.get("token", ""))
    with transaction(a.user_id, a.org_id) as s:
        s.execute(text("SELECT set_config('tv.invite',:v,true)"), {"v": digest(token)})
        invitation = s.get(Invite, digest(token), with_for_update=True)
        if (
            not invitation
            or invitation.used_at
            or invitation.expires_at <= now()
            or invitation.email != a.email
        ):
            raise HTTPException(403, "Invitation is unavailable for this verified identity")
        context(s, a.user_id, invitation.organization_id)
        if s.get(Membership, (invitation.organization_id, a.user_id)):
            raise HTTPException(409, "Already a member")
        s.add(
            Membership(
                organization_id=invitation.organization_id, user_id=a.user_id, role=invitation.role
            )
        )
        invitation.used_at = now()
        audit(s, invitation.organization_id, a.user_id, "membership.accepted")
    return {"ok": True}


@app.patch("/v1/members/{user_id}")
def member_role(user_id: UUID, body: dict, a: Actor = ActorDep):
    require(a, OWNERS)
    role = body.get("role")
    if role not in {"admin", "security", "developer", "viewer"}:
        raise HTTPException(422, "Invalid role")
    with transaction(a.user_id, a.org_id) as s:
        from .release_integrity import lock_organization_systems

        lock_organization_systems(s, a.org_id)
        org = s.get(Organization, a.org_id, with_for_update=True)
        member = s.get(Membership, (a.org_id, user_id), with_for_update=True)
        if not member:
            raise HTTPException(404, "Member unavailable")
        if member.role == "owner" or org.owner_user_id == user_id:
            raise HTTPException(409, "Organization owner cannot be demoted")
        member.role = role
        audit(s, a.org_id, a.user_id, "membership.role_changed", user_id)
    return {"ok": True}


@app.get("/v1/deliveries")
def deliveries(a: Actor = ActorDep):
    from .integrations.revenue_delivery import delivery_status

    require(a, OWNERS)
    return delivery_status(a.org_id)


@app.get("/v1/billing")
def billing(a: Actor = ActorDep):
    from .entitlements import property_usage

    with transaction(a.user_id, a.org_id) as s:
        acc = s.get(Account, a.org_id)
        return {
            **property_usage(s, a.org_id, acc),
            "plan": acc.plan,
            "status": acc.status,
            "paid": acc.paid,
            "trial_limit": acc.trial_limit,
            "consumed": acc.consumed,
            "reserved": acc.reserved,
            "remaining": max(0, acc.trial_limit - acc.consumed - acc.reserved),
            "max_systems": acc.max_systems,
            "stripe_configured": bool(settings().stripe_secret_key),
            "allowances_validated": bool(settings().stripe_trial_allowances),
            "offers": [
                {
                    "id": key, **plan.model_dump(),
                    "pricing": "Agreed protected-system scope; authoritative amount is supplied by Stripe checkout",
                    "checkout_configured": bool(settings().stripe_prices.get(key) and settings().stripe_trial_allowances.get(key)),
                } for key, plan in settings().commercial_plans.items()
            ],
            "note": "Execution allowances require an explicit measured budget. Reserved units are consumed once execution starts, including error or timeout; only unstarted work is refunded. No automatic paid overages. Manual pilot entitlement is not payment.",
        }


@app.post("/v1/billing/pilot")
def pilot(body: PilotInput, a: Actor = ActorDep):
    require(a, OWNERS)
    if not settings().is_local:
        raise HTTPException(403, "Pilot budgets require the operator provisioning command")
    with transaction(a.user_id, a.org_id) as s:
        acc = s.get(Account, a.org_id, with_for_update=True)
        if acc.paid or acc.status in {"active", "past_due"}:
            raise HTTPException(409, "Managed subscription cannot be replaced by a local pilot")
        if body.trial_limit < acc.reserved + acc.consumed:
            raise HTTPException(409, "Allowance cannot be below existing use")
        acc.trial_limit = body.trial_limit
        acc.max_systems = body.max_systems
        acc.plan = "pilot"
        acc.status = "manual_pilot"
        audit(s, a.org_id, a.user_id, "pilot.entitlement_changed")
        add_record(
            s,
            a.org_id,
            "entitlement",
            {"reason": body.reason, "trial_limit": body.trial_limit, "paid": False},
        )
    return {"status": "manual_pilot", "paid": False}


@app.post("/v1/billing/checkout")
def checkout(body: dict, a: Actor = ActorDep):
    require(a, OWNERS)
    from .integrations.billing import create_checkout

    return create_checkout(a, body.get("plan"))


@app.post("/v1/billing/portal")
def portal(a: Actor = ActorDep):
    require(a, OWNERS)
    from .integrations.billing import create_portal

    return create_portal(a)


@app.post("/v1/webhooks/stripe")
async def stripe_hook(request: Request):
    from .integrations.billing import process_webhook

    return process_webhook(await request.body(), request.headers.get("stripe-signature", ""))


@app.get("/v1/integrations")
def integrations(a: Actor = ActorDep):
    from .db import GitHubBinding

    cfg = settings()
    with transaction(a.user_id, a.org_id) as session:
        bindings = list(
            session.scalars(select(GitHubBinding).where(GitHubBinding.organization_id == a.org_id))
        )
        routes = []
        for binding in bindings:
            member = session.get(Membership, (a.org_id, binding.user_id))
            authorized = bool(member and member.role in SECURITY)
            routes.append(
                {
                    "repository_id": binding.repository_id,
                    "repository": binding.repository,
                    "workflow_ref": binding.workflow_ref,
                    "allowed_ref": binding.allowed_ref,
                    "enabled": binding.enabled,
                    "owner_authorized": authorized,
                }
            )
    active = sum(route["enabled"] and route["owner_authorized"] for route in routes)
    return {
        "items": [
            {
                "id": "github",
                "mode": "oidc",
                "configured": bool(active),
                "status": "bound_unverified" if active else "no_active_binding",
                "active_bindings": active,
                "bindings": routes,
                "note": "A registered workflow binding is configuration, not a verified external GitHub execution.",
            }
        ]
        + [
            {
                "id": name,
                "configured": bool(value),
                "status": "configured_unverified" if value else "not_configured",
            }
            for name, value in [
                ("stripe", cfg.stripe_secret_key),
                ("compiler", cfg.openai_api_key),
                ("hubspot", cfg.hubspot_token),
                ("email", cfg.resend_api_key),
                ("gcp", cfg.cloud_project),
            ]
        ]
    }


@app.post("/v1/leads", status_code=202)
def lead(body: LeadInput, request: Request):
    from .integrations.revenue_delivery import enabled

    check_origin(request)
    if "@" not in body.email:
        raise HTTPException(422, "Valid contact email required")
    # Lead intake is the only intentionally non-tenant object. No security payload enters CRM.
    with transaction() as s:
        out = Outbox(topic="lead.crm", payload=body.model_dump())
        s.add(out)
        s.flush()
        identifier = out.id
    return {
        "id": str(identifier),
        "status": "received",
        "routing": "queued" if enabled("lead.crm", settings()) else "awaiting_crm_configuration",
    }


@app.get("/v1/dashboard")
def dashboard(a: Actor = ActorDep):
    from sqlalchemy import func
    from .entitlements import property_usage
    from .workspace_reads import page

    with transaction(a.user_id, a.org_id) as session:
        items, windows = {}, {}
        for plural, kind in [
            ("systems", "system"),
            ("properties", "property"),
            ("findings", "finding"),
            ("fixes", "fix"),
            ("gauntlets", "gauntlet"),
            ("baselines", "baseline"),
            ("runs", "run"),
            ("targets", "target"),
        ]:
            rows, windows[plural] = page(session, a.org_id, kind)
            items[plural] = [workspace_value(session, a.org_id, row) for row in rows]
        acc = session.get(Account, a.org_id)
        items["usage"] = {
            "limit": acc.trial_limit,
            "consumed": acc.consumed,
            "reserved": acc.reserved,
            "plan": acc.plan,
            "paid": acc.paid,
            **property_usage(session, a.org_id, acc),
        }

        def count(kind, *conditions):
            return session.scalar(
                select(func.count())
                .select_from(Record)
                .where(Record.organization_id == a.org_id, Record.kind == kind, *conditions)
            )

        items["summary"] = {
            "systems": windows["systems"]["total"],
            "properties": items["usage"]["active_properties"],
            "runs": windows["runs"]["total"],
            "failures": count("result", Record.payload["security_verdict"].astext == "FAIL"),
            "verified_fixes": count("fix", Record.payload["verified"].astext == "true"),
            "regressions": count("result", Record.payload["regression"].astext == "true"),
            "scope": "Organization totals; failure/regression counts use finalized results.",
        }
        items["pagination"] = windows
        items["regressions"] = [run for run in items["runs"] if run.get("regression")]
        items["integrations"] = integrations(a)["items"]
        return items


@app.get("/v1/api-tokens")
def api_tokens(a: Actor = ActorDep):
    from .db import ApiToken

    require(a, OWNERS)
    with transaction(a.user_id, a.org_id) as s:
        rows = s.scalars(select(ApiToken).where(ApiToken.organization_id == a.org_id))
        return {
            "items": [
                {
                    "id": str(r.id),
                    "name": r.name,
                    "permission": r.permission,
                    "expires_at": r.expires_at.isoformat(),
                    "revoked": bool(r.revoked_at),
                }
                for r in rows
            ]
        }


@app.post("/v1/api-tokens", status_code=201)
def create_api_token(body: dict, a: Actor = ActorDep):
    from .db import ApiToken

    require(a, OWNERS)
    permission = body.get("permission", "read")
    days = body.get("expires_in_days", 30)
    if permission not in {"read", "execute"} or not isinstance(days, int) or not 1 <= days <= 30:
        raise HTTPException(422, "Invalid token scope or expiry")
    token = "tvk_" + secrets.token_urlsafe(32)
    with transaction(a.user_id, a.org_id) as s:
        key = ApiToken(
            organization_id=a.org_id,
            user_id=a.user_id,
            token_hash=digest(token),
            name=str(body.get("name", "API token"))[:120],
            permission=permission,
            expires_at=now() + timedelta(days=days),
        )
        s.add(key)
        s.flush()
        identifier = key.id
        audit(s, a.org_id, a.user_id, "api_token.created", identifier)
    return {
        "id": str(identifier),
        "token": token,
        "permission": permission,
        "expires_in_days": days,
    }


@app.delete("/v1/api-tokens/{record_id}")
def revoke_api_token(record_id: UUID, a: Actor = ActorDep):
    from .db import ApiToken

    require(a, OWNERS)
    with transaction(a.user_id, a.org_id) as s:
        key = s.scalar(
            select(ApiToken)
            .where(ApiToken.id == record_id, ApiToken.organization_id == a.org_id)
            .with_for_update()
        )
        if not key:
            raise HTTPException(404, "Token unavailable")
        key.revoked_at = now()
        audit(s, a.org_id, a.user_id, "api_token.revoked", record_id)
    return {"revoked": True}


@app.get("/v1/schedules")
def list_schedules(a: Actor = ActorDep):
    from .db import Schedule

    with transaction(a.user_id, a.org_id) as s:
        return {
            "items": [
                {
                    "id": str(r.id),
                    "name": r.name,
                    "run_template": r.run_template,
                    "interval_hours": r.interval_hours,
                    "next_at": r.next_at.isoformat(),
                    "enabled": r.enabled,
                }
                for r in s.scalars(select(Schedule))
            ]
        }


@app.post("/v1/schedules", status_code=201)
def create_schedule(body: dict, a: Actor = ActorDep):
    from .db import Schedule

    require(a, SECURITY)
    try:
        plan = RunInput.model_validate(
            {**body.get("run_template", {}), "idempotency_key": "schedule-validation"}
        )
        interval = int(body.get("interval_hours", 24))
        if not 1 <= interval <= 720:
            raise ValueError()
    except Exception:
        raise HTTPException(
            422, "Valid bounded run template and 1–720 hour cadence required"
        ) from None
    with transaction(a.user_id, a.org_id) as s:
        from .commercial import require_capability

        require_capability(s, a.org_id, "release.automation")
        target = authorized_target(s, a.org_id, plan.target_id)
        prop = get_record(s, a.org_id, plan.property_id, "property")
        if (
            not prop.payload.get("approved")
            or target.payload["system_id"] != str(plan.system_id)
            or prop.payload["system_id"] != str(plan.system_id)
        ):
            raise HTTPException(422, "Incompatible schedule scope")
        row = Schedule(
            organization_id=a.org_id,
            user_id=a.user_id,
            name=str(body.get("name", "Scheduled verification"))[:120],
            run_template=plan.model_dump(mode="json"),
            interval_hours=interval,
            next_at=now() + timedelta(hours=interval),
        )
        s.add(row)
        s.flush()
        s.add(
            Outbox(
                organization_id=a.org_id,
                topic="schedule.tick",
                status="active",
                payload={"schedule_id": str(row.id)},
            )
        )
        audit(s, a.org_id, a.user_id, "schedule.created", row.id)
        return {"id": str(row.id), "enabled": True, "next_at": row.next_at.isoformat()}


@app.delete("/v1/schedules/{record_id}")
def disable_schedule(record_id: UUID, a: Actor = ActorDep):
    from .db import Schedule

    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as s:
        row = s.get(Schedule, record_id)
        if not row:
            raise HTTPException(404, "Schedule unavailable")
        row.enabled = False
        audit(s, a.org_id, a.user_id, "schedule.disabled", row.id)
    return {"enabled": False}


@app.get("/v1/credentials")
def credentials(a: Actor = ActorDep):
    require(a, SECURITY)
    return list_kind("credential", a)


@app.post("/v1/credentials", status_code=201)
def credential_reference(body: CredentialInput, a: Actor = ActorDep):
    require(a, OWNERS)
    from .credentials import validate_reference

    validate_reference(body.secret_version, a.org_id)
    with transaction(a.user_id, a.org_id) as s:
        return serialize(add_record(s, a.org_id, "credential", body.model_dump()))


@app.post("/v1/github/runs", status_code=202)
def github_run(request: Request, background: BackgroundTasks):
    from .integrations.github import verify_token, resolve_binding

    claims = verify_token(request.headers.get("authorization", "").removeprefix("Bearer "))
    with transaction() as session:
        binding, identity = resolve_binding(session, claims)
        target = get_record(session, identity.org_id, binding.run_template["target_id"], "target")
        if target.payload["adapter"] in {"synthetic_procurement", "structured_trace"}:
            raise HTTPException(
                422, "Release gates require an actively observed customer candidate"
            )
        plan = RunInput.model_validate(
            {
                **binding.run_template,
                "version": claims["sha"],
                "candidate": {
                    "type": "git_commit",
                    "id": claims["repository_id"],
                    "version": claims["sha"],
                    "digest": claims["sha"],
                },
                "github": {
                    "repository_id": claims["repository_id"],
                    "repository": claims["repository"],
                    "sha": claims["sha"],
                    "verified_workflow": True,
                },
                "idempotency_key": f"github:{claims['repository_id']}:{claims['run_id']}:{claims['run_attempt']}",
            }
        )
    return create_run(plan, background, identity)


@app.get("/v1/github/runs/{run_id}")
def github_result(run_id: UUID, request: Request):
    from .integrations.github import verify_token, resolve_binding, gate_result

    claims = verify_token(request.headers.get("authorization", "").removeprefix("Bearer "))
    with transaction() as session:
        _, identity = resolve_binding(session, claims)
        from .adverse_memory import lock_artifact_scope

        record = get_record(session, identity.org_id, run_id, "run")
        lock_artifact_scope(session, identity.org_id, record.payload)
        run = run_view(session, identity.org_id, record)
        return gate_result(run, claims)


@app.get("/v1/observers")
def list_observers(a: Actor = ActorDep):
    with transaction(a.user_id, a.org_id) as session:
        rows = records(session, a.org_id, "observer")
        revoked = {
            p["family_id"]
            for p in session.scalars(
                select(Record.payload).where(
                    Record.organization_id == a.org_id, Record.kind == "observer_revocation"
                )
            )
        }
        replacements = {
            r.payload["supersedes_id"]: str(r.id) for r in rows if r.payload.get("supersedes_id")
        }
        return {
            "items": [
                {
                    **serialize(r),
                    "revoked": r.payload.get("supersedes_id", str(r.id)) in revoked,
                    "superseded_by": replacements.get(str(r.id)),
                }
                for r in rows
            ]
        }


@app.post("/v1/observers", status_code=201)
def register_observer(body: ObserverInput, a: Actor = ActorDep):
    require(a, SECURITY)
    from .core.contracts import PropertyDefinition

    with transaction(a.user_id, a.org_id) as session:
        target = authorized_target(session, a.org_id, body.target_id)
        prop = get_record(session, a.org_id, body.property_id, "property")
        definition = PropertyDefinition.model_validate(prop.payload["definition"])
        if (
            target.payload["adapter"] not in {"http", "mcp"}
            or not prop.payload.get("approved")
            or any(r.payload["system_id"] != str(body.system_id) for r in (target, prop))
            or body.source_id not in definition.observation_contract.required_witnesses
        ):
            raise HTTPException(
                422, "Observer must cover an approved property on an active authorized system"
            )
        record = add_record(
            session,
            a.org_id,
            "observer",
            {
                **body.model_dump(mode="json"),
                "approved": False,
                "status": "QUALIFICATION_REQUIRED",
                "registered_by": str(a.user_id),
            },
            {"system": body.system_id, "property": body.property_id, "target": body.target_id},
        )
        audit(session, a.org_id, a.user_id, "observer.registered", record.id)
        return serialize(record)


@app.post("/v1/observers/{observer_id}/approve")
def approve_observer(observer_id: UUID, body: ObserverApproval, a: Actor = ActorDep):
    require(a, SECURITY)
    from .observers import active_observer

    with transaction(a.user_id, a.org_id) as session:
        observer = active_observer(session, a.org_id, observer_id)
        if observer.payload.get("approved"):
            return serialize(observer)
        cases = [
            ("KNOWN_PERMITTED", body.permitted_run_id, "PASS"),
            ("KNOWN_PROHIBITED", body.prohibited_run_id, "FAIL"),
            ("MISSING_OBSERVATION", body.missing_run_id, "INCONCLUSIVE"),
        ]
        if len({r[1] for r in cases}) != 3:
            raise HTTPException(422, "Three distinct assigned qualification runs are required")
        refs = {"source": observer.id}
        evidence = []
        for case, identifier, verdict in cases:
            run = get_record(session, a.org_id, identifier, "run")
            result = run_view(session, a.org_id, run)
            authorized_target(session, a.org_id, run.payload["target_id"])
            if (
                run.payload.get("observer_id") != str(observer_id)
                or run.payload.get("qualification_case") != case
                or result.get("security_verdict") != verdict
                or result.get("witness_attested") is not True
                or result.get("execution_status") != "COMPLETED"
                or case == "KNOWN_PERMITTED"
                and result.get("task_outcome") != "SUCCESS"
            ):
                raise HTTPException(
                    422,
                    "Qualification needs assigned, independently signed permitted/prohibited/missing controls",
                )
            evidence.append(
                {
                    "case": case,
                    "run_id": str(identifier),
                    "verdict": verdict,
                    "evidence_digest": result["evidence_digest"],
                }
            )
            refs[case] = identifier
        qualification = add_record(
            session,
            a.org_id,
            "observer_qualification",
            {
                "cases": evidence,
                "review_note": body.review_note,
                "reviewed_by": str(a.user_id),
                "scope": "Reviewed customer collectors, signed ground truth and active challenge execution; not collector certification.",
            },
            refs,
        )
        approved = add_record(
            session,
            a.org_id,
            "observer",
            {
                **observer.payload,
                "approved": True,
                "status": "QUALIFIED",
                "supersedes_id": str(observer.id),
                "qualification_id": str(qualification.id),
                "approved_by": str(a.user_id),
            },
            {"supersedes": observer.id, "qualification": qualification.id},
        )
        return serialize(approved)


@app.post("/v1/observers/{observer_id}/revoke")
def revoke_observer(observer_id: UUID, a: Actor = ActorDep):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        observer = get_record(session, a.org_id, observer_id, "observer")
        from .release_integrity import lock_system

        lock_system(session, a.org_id, observer.payload["system_id"])
        record = add_record(
            session,
            a.org_id,
            "observer_revocation",
            {
                "family_id": observer.payload.get("supersedes_id", str(observer.id)),
                "revoked_by": str(a.user_id),
            },
            {"observer": observer.id},
        )
        return serialize(record)


@app.get("/v1/build-info")
def build_info(a: Actor = ActorDep):
    """Exactly what is running: source revision, image digest, schema head and catalog versions."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    from .assurance_packs import packs
    from .claim_builder import catalog as claim_catalog
    from .commercial import catalog as plan_catalog

    config, unknown = settings(), "UNKNOWN"
    try:
        heads = sorted(ScriptDirectory.from_config(Config("alembic.ini")).get_heads())
    except Exception:  # noqa: BLE001 - a packaged image need not ship migration scripts
        heads = []
    with transaction(a.user_id, a.org_id) as session:
        applied = sorted(session.scalars(text("SELECT version_num FROM alembic_version")))
    return {
        "schema_version": "build-info/v1", "environment": config.env,
        "source_revision": config.source_revision or unknown,
        "image_digest": config.image_digest or unknown,
        "build_time": config.build_time or unknown,
        "migration_head": heads[-1] if heads else unknown,
        "schema_applied": applied[-1] if applied else unknown,
        "catalog_version": plan_catalog().version,
        "claim_templates_version": claim_catalog().version,
        "assurance_packs": {pack.id: f"{pack.version} ({pack.status})" for pack in packs().values()},
        "note": "UNKNOWN means this deployment did not bind that value at build time. A conclusion is "
                "always bound to the records that established it, never to this build.",
    }


app.include_router(assurance_router)

app.include_router(release_machine_router)
app.include_router(commercial_router)
app.include_router(connector_router)
app.include_router(change_assurance_router)
app.include_router(measurements_router)
app.include_router(memory_router)
app.include_router(tool_contract_router)

app.include_router(release_integrity_router)
app.include_router(integrity_launch_router)
app.include_router(github_app_router)
app.include_router(integration_intake_router)
app.include_router(governance_router)
app.include_router(trust_router)
app.include_router(assurance_intelligence_router)
app.include_router(activation_router)
app.include_router(business_router)
app.include_router(proposed_change_router)
app.include_router(observer_platform_router)
app.include_router(claim_builder_router)
app.include_router(dependency_mapping_router)
app.include_router(ai_router)
app.include_router(auto_reproof_router)
app.include_router(assurance_pack_router)
app.add_middleware(SafeErrorBoundary)
