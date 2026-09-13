import hashlib
import secrets
from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID

from fastapi import HTTPException, Request, Response
from sqlalchemy import select
from .config import settings
from .db import (
    User,
    Organization,
    Membership,
    LoginSession,
    transaction,
    context,
    now,
    audit,
    ApiToken,
)

COOKIE = "tv_session"
MUTATORS = {"owner", "admin", "security", "developer"}
SECURITY = {"owner", "admin", "security"}
OWNERS = {"owner", "admin"}


def digest(value: str):
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass
class Actor:
    user_id: UUID
    org_id: UUID
    role: str
    email: str
    name: str
    csrf: str
    mode: str


def actor(request: Request):
    token = request.cookies.get(COOKIE)
    credential = request.headers.get(
        "x-threatveil-token", request.headers.get("authorization", "").removeprefix("Bearer ")
    )
    if not token and credential.startswith("tvk_"):
        with transaction() as s:
            key = s.scalar(select(ApiToken).where(ApiToken.token_hash == digest(credential)))
            if not key or key.revoked_at or key.expires_at <= now():
                raise HTTPException(401, "API token expired or revoked")
            context(s, key.user_id, key.organization_id)
            membership = s.get(Membership, (key.organization_id, key.user_id))
            user = s.get(User, key.user_id)
            if not membership or not user:
                raise HTTPException(401, "API token membership is inactive")
            role = (
                "viewer" if key.permission == "read" or membership.role == "viewer" else "developer"
            )
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                from .governance import ensure_active

                ensure_active(s, key.organization_id)
            return Actor(user.id, key.organization_id, role, user.email, user.name, "", "api_token")
    if not token:
        raise HTTPException(401, "Sign in required")
    with transaction() as s:
        session = s.get(LoginSession, digest(token))
        if not session or session.expires_at <= now():
            raise HTTPException(401, "Session expired")
        context(s, session.user_id, session.organization_id)
        membership = s.get(Membership, (session.organization_id, session.user_id))
        user = s.get(User, session.user_id)
        if not membership or not user:
            raise HTTPException(401, "Membership no longer active")
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            check_origin(request)
            if not secrets.compare_digest(request.headers.get("x-csrf-token", ""), session.csrf):
                raise HTTPException(403, "CSRF check failed")
            if not request.url.path.startswith("/v1/governance/deletion-requests") and request.url.path not in {
                "/v1/auth/logout", "/v1/auth/switch", "/v1/memory/query"
            }:
                from .governance import ensure_active

                ensure_active(s, session.organization_id)
        return Actor(
            user.id,
            session.organization_id,
            membership.role,
            user.email,
            user.name,
            session.csrf,
            session.identity_mode,
        )


def require(a: Actor, roles=MUTATORS):
    if a.role not in roles:
        raise HTTPException(403, "Your role does not permit this action")


def check_origin(request):
    origin = request.headers.get("origin")
    if origin != settings().web_origin:
        raise HTTPException(403, "Untrusted request origin")


def create_session(
    request: Request, response: Response, *, subject, email, name, organization_name, mode
):
    check_origin(request)
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    with transaction() as s:
        user = s.scalar(select(User).where(User.subject == subject))
        if user is None:
            user = User(subject=subject, email=email.lower(), name=name)
            s.add(user)
            s.flush()
        context(s, user.id)
        memberships = list(s.scalars(select(Membership).where(Membership.user_id == user.id)))
        if memberships:
            org_id = memberships[0].organization_id
            context(s, user.id, org_id)
        else:
            org = Organization(name=organization_name, owner_user_id=user.id)
            s.add(org)
            s.flush()
            org_id = org.id
            context(s, user.id, org_id)
            s.add(Membership(organization_id=org_id, user_id=user.id, role="owner"))
            from .commercial import provision_free

            provision_free(s, org_id)
        s.add(
            LoginSession(
                token_hash=digest(token),
                user_id=user.id,
                organization_id=org_id,
                csrf=csrf,
                expires_at=now() + timedelta(hours=8),
                identity_mode=mode,
            )
        )
        audit(s, org_id, user.id, "session.created")
    response.set_cookie(
        COOKIE,
        token,
        httponly=True,
        secure=not settings().is_local,
        samesite="lax",
        max_age=28800,
        path="/",
    )
    return {"ok": True, "csrf_token": csrf, "mode": mode}


def verify_firebase(token):
    import firebase_admin
    from firebase_admin import auth

    cfg = settings()
    try:
        app = firebase_admin.get_app()
    except ValueError:
        app = firebase_admin.initialize_app(options={"projectId": cfg.firebase_project})
    try:
        claims = auth.verify_id_token(token, app=app, check_revoked=True)
        if not claims.get("email_verified") or now().timestamp() - claims.get("auth_time", 0) > 300:
            raise ValueError("A recent verified sign-in is required")
        return claims
    except Exception:
        raise HTTPException(401, "Managed identity token rejected") from None
