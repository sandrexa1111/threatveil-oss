"""Security-approved, exact-plan machine issuance without general execution authority.

Capabilities are stored only as hashes. Policies, grants, revocations and use are
append-only records. The capability is understood only by the dedicated issuer.
"""

import secrets
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field
from sqlalchemy import select

from .assurance import ExactCandidate, _properties
from .auth import Actor, SECURITY, actor, digest as token_digest, require
from .core.contracts import digest
from .db import Membership, Record, add_record, audit, get_record, now, serialize, transaction
from .release_integrity import ReleaseInput, ReleasePolicy, issue_release, lock_system
from .schemas import Input

router = APIRouter(prefix="/v1", tags=["release-machine"])
PROFILE = "threatveil.release-machine.v1"


def current_policy(session, org, system):
    return session.scalar(select(Record).where(
        Record.organization_id == org, Record.kind == "release_policy",
        Record.payload["system_id"].astext == str(system),
    ).order_by(Record.created_at.desc(), Record.id.desc()).limit(1))


def property_scope(session, org, system):
    return {str(p.id): digest(p.payload) for p in _properties(session, org, str(system))}


def current_machine_authority(session, org, decision):
    """Current authorization projection; never alter the original signed decision."""
    authority = decision.get("machine_authority")
    if not authority:
        return []
    reasons = []
    try:
        grant = get_record(session, org, authority["authorization_id"], "release_authorization")
        security_owner(session, org, grant.payload["authorized_by"])
        policy = current_policy(session, org, decision["system_id"])
        if not policy or str(policy.id) != authority["policy_id"] or policy.payload["epoch"] != authority["policy_epoch"]:
            reasons.append("Security-approved machine release policy has changed")
        elif policy:
            security_owner(session, org, policy.payload["approved_by"])
        if datetime.fromisoformat(grant.payload["expires_at"]) <= now():
            reasons.append("Machine release authorization has expired")
        revoked = session.scalar(select(Record.id).where(
            Record.organization_id == org, Record.kind == "release_authorization_revocation",
            Record.payload["authorization_id"].astext == str(grant.id)))
        if revoked:
            reasons.append("Machine release authorization was revoked")
    except HTTPException:
        reasons.append("Machine release authorizer is no longer active")
    return reasons


def security_owner(session, org, user):
    membership = session.get(Membership, (org, UUID(str(user))))
    if not membership or membership.role not in SECURITY:
        raise HTTPException(403, "Release authorizer no longer has security authority")


class PolicyInput(Input):
    system_id: UUID
    policy: ReleasePolicy
    reason: str = Field(min_length=10, max_length=2000)


@router.post("/release-policies", status_code=201)
def approve_policy(body: PolicyInput, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        get_record(session, a.org_id, body.system_id, "system")
        lock_system(session, a.org_id, body.system_id)
        security_owner(session, a.org_id, a.user_id)
        scope = property_scope(session, a.org_id, body.system_id)
        if not scope or set(body.policy.property_modes) - set(scope):
            raise HTTPException(422, "Policy requires the system's complete approved property scope")
        previous = current_policy(session, a.org_id, body.system_id)
        row = add_record(session, a.org_id, "release_policy", {
            "profile": PROFILE, **body.model_dump(mode="json"),
            "epoch": previous.payload["epoch"] + 1 if previous else 1,
            "approved_by": str(a.user_id), "scope": scope,
        }, {"system": body.system_id})
        audit(session, a.org_id, a.user_id, "release_policy.approved", row.id)
        return serialize(row)


class GrantInput(Input):
    plan_id: UUID
    policy_id: UUID
    expires_in_seconds: int = Field(default=900, ge=1, le=3600)


@router.post("/release-authorizations", status_code=201)
def authorize_release(body: GrantInput, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        plan = get_record(session, a.org_id, body.plan_id, "proof_plan")
        system = plan.payload["system_id"]
        lock_system(session, a.org_id, system)
        security_owner(session, a.org_id, a.user_id)
        policy = current_policy(session, a.org_id, system)
        if not policy or str(policy.id) != str(body.policy_id):
            raise HTTPException(409, "The current security-approved policy is required")
        security_owner(session, a.org_id, policy.payload["approved_by"])
        scope = property_scope(session, a.org_id, system)
        if policy.payload["scope"] != scope or set(plan.payload["scope_property_ids"]) != set(scope):
            raise HTTPException(409, "Approved property scope changed; refresh policy and plan")
        candidate = plan.payload["candidate"]
        repository = candidate["id"] if candidate["type"] == "git_commit" else None
        installation = None
        if repository:
            from .integrations.github_release import active_installation
            installed = active_installation(session, a.org_id, repository)
            if not installed or installed.payload["system_id"] != system:
                raise HTTPException(403, "An active repository installation for this system is required")
            installation = str(installed.id)
        identifier = uuid4()
        token = f"tvrel_{a.org_id}.{identifier}.{secrets.token_urlsafe(32)}"
        row = add_record(session, a.org_id, "release_authorization", {
            "profile": PROFILE, "system_id": system, "plan_id": str(plan.id),
            "policy_id": str(policy.id), "policy_epoch": policy.payload["epoch"],
            "policy_digest": digest(policy.payload["policy"]), "scope": scope,
            "candidate": candidate, "candidate_fingerprint_digest": plan.payload["candidate_fingerprint_digest"],
            "repository_id": repository, "installation_record_id": installation,
            "authorized_by": str(a.user_id), "token_hash": token_digest(token),
            "expires_at": (now() + timedelta(seconds=body.expires_in_seconds)).isoformat(),
        }, {"plan": plan.id, "policy": policy.id, "system": system}, record_id=identifier)
        audit(session, a.org_id, a.user_id, "release_authorization.created", row.id)
        value = serialize(row)
        value.pop("token_hash", None)
        return {**value, "token": token, "usage": "Exact release decision only; no execution, policy or admin authority"}


@router.post("/release-authorizations/{identifier}/revoke", status_code=201)
def revoke_authorization(identifier: UUID, a: Actor = Depends(actor)):
    require(a, SECURITY)
    with transaction(a.user_id, a.org_id) as session:
        grant = get_record(session, a.org_id, identifier, "release_authorization")
        lock_system(session, a.org_id, grant.payload["system_id"])
        row = add_record(session, a.org_id, "release_authorization_revocation", {
            "profile": PROFILE, "authorization_id": str(identifier),
            "system_id": grant.payload["system_id"], "revoked_by": str(a.user_id),
        }, {"authorization": identifier})
        audit(session, a.org_id, a.user_id, "release_authorization.revoked", identifier)
        return serialize(row)


class MachineDecisionInput(Input):
    organization_id: UUID
    system_id: UUID
    plan_id: UUID
    repository_id: str | None = Field(default=None, max_length=200)
    candidate: ExactCandidate
    candidate_fingerprint_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    property_ids: list[UUID] = Field(min_length=1, max_length=500)
    policy_id: UUID
    policy_epoch: int = Field(ge=1)


@router.post("/release-machine/decide", status_code=201)
def machine_decision(body: MachineDecisionInput, request: Request):
    credential = request.headers.get("authorization", "").removeprefix("Bearer ")
    try:
        if not credential.startswith("tvrel_") or len(credential) > 300:
            raise ValueError()
        organization, identifier, secret = credential[6:].split(".")
        org, grant_id = UUID(organization), UUID(identifier)
        if not secret or org != body.organization_id:
            raise ValueError()
    except ValueError:
        raise HTTPException(401, "Exact release authorization required") from None
    with transaction(org_id=org) as session:
        grant = get_record(session, org, grant_id, "release_authorization")
        value = grant.payload
        if not secrets.compare_digest(value["token_hash"], token_digest(credential)):
            raise HTTPException(401, "Release authorization rejected")
        lock_system(session, org, value["system_id"])
        from .governance import ensure_active
        ensure_active(session, org)
        security_owner(session, org, value["authorized_by"])
        if datetime.fromisoformat(value["expires_at"]) <= now():
            raise HTTPException(403, "Release authorization expired")
        revoked = session.scalar(select(Record.id).where(
            Record.organization_id == org, Record.kind == "release_authorization_revocation",
            Record.payload["authorization_id"].astext == str(grant_id)))
        if revoked:
            raise HTTPException(403, "Release authorization revoked")
        supplied = body.model_dump(mode="json")
        for key in ("system_id", "plan_id", "repository_id", "candidate", "candidate_fingerprint_digest", "policy_id", "policy_epoch"):
            if supplied[key] != value[key]:
                raise HTTPException(403, "Request differs from the exact approved release binding")
        scope = property_scope(session, org, value["system_id"])
        if (len(set(supplied["property_ids"])) != len(supplied["property_ids"])
                or set(supplied["property_ids"]) != set(scope) or value["scope"] != scope):
            raise HTTPException(409, "Request must include every current approved property unchanged")
        policy = current_policy(session, org, value["system_id"])
        if (not policy or str(policy.id) != value["policy_id"]
                or policy.payload["epoch"] != value["policy_epoch"]
                or digest(policy.payload["policy"]) != value["policy_digest"]
                or policy.payload["scope"] != scope):
            raise HTTPException(409, "Release policy changed; a fresh authorization is required")
        security_owner(session, org, policy.payload["approved_by"])
        if value["repository_id"]:
            from .integrations.github_release import active_installation
            installed = active_installation(session, org, value["repository_id"])
            if not installed or str(installed.id) != value["installation_record_id"]:
                raise HTTPException(403, "Repository installation was revoked or replaced")
        used = session.scalar(select(Record).where(
            Record.organization_id == org, Record.kind == "release_authorization_use",
            Record.payload["authorization_id"].astext == str(grant_id)))
        if used:
            # Explicitly historical. No rerun or fresh positive authorization on replay.
            raise HTTPException(409, {"message": "Authorization already consumed", "release_id": used.payload["release_id"]})
        issuer = Actor(UUID(value["authorized_by"]), org, "security", "", "", "", "release_machine")
        decision = issue_release(session, ReleaseInput(plan_id=body.plan_id,
            policy=ReleasePolicy.model_validate(policy.payload["policy"])), issuer,
            machine_authority={"profile": PROFILE, "authorization_id": str(grant_id),
                "policy_id": str(policy.id), "policy_epoch": value["policy_epoch"],
                "expires_at": value["expires_at"], "audience": "threatveil.release-machine/decide"})
        add_record(session, org, "release_authorization_use", {
            "profile": PROFILE, "authorization_id": str(grant_id),
            "release_id": decision["id"], "system_id": value["system_id"],
        }, {"authorization": grant_id, "release": decision["id"]})
        return decision
