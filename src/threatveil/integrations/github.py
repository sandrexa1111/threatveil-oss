"""GitHub OIDC release gate. A frozen repository binding selects execution scope."""

import re
import time

import httpx
import jwt
from fastapi import HTTPException

from ..auth import Actor, SECURITY
from ..db import GitHubBinding, Membership, User, context

ISSUER = "https://token.actions.githubusercontent.com"
AUDIENCE = "threatveil-verify"
_jwks = (0, {})


def verify_token(token):
    global _jwks
    if not 100 <= len(token) <= 16000:
        raise HTTPException(401, "GitHub identity rejected")
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256":
            raise ValueError()
        if _jwks[0] < time.monotonic():
            with httpx.Client(timeout=10, trust_env=False, follow_redirects=False) as client:
                response = client.get(ISSUER + "/.well-known/jwks")
                response.raise_for_status()
                _jwks = (time.monotonic() + 300, response.json())
        key = next(k for k in _jwks[1]["keys"] if k["kid"] == header["kid"])
        claims = jwt.decode(
            token,
            jwt.PyJWK.from_dict(key).key,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "nbf", "sub", "jti"]},
        )
        if not re.fullmatch(r"[0-9a-f]{40}", claims.get("sha", "")):
            raise ValueError()
        if claims.get("event_name") not in {"push", "workflow_dispatch"}:
            raise ValueError()
        if not re.fullmatch(r"[0-9]+", claims.get("run_id", "")) or not re.fullmatch(
            r"[0-9]+", claims.get("run_attempt", "")
        ):
            raise ValueError()
        return claims
    except Exception:
        raise HTTPException(401, "GitHub identity, event or candidate rejected") from None


def resolve_binding(session, claims):
    binding = session.get(GitHubBinding, claims.get("repository_id", ""))
    if not binding or not binding.enabled:
        raise HTTPException(403, "Repository has no active ThreatVeil binding")
    expected = {
        "repository": binding.repository,
        "repository_owner_id": binding.owner_id,
        "workflow_ref": binding.workflow_ref,
        "ref": binding.allowed_ref,
    }
    if any(claims.get(k) != value for k, value in expected.items()):
        raise HTTPException(403, "Workflow is outside the registered release policy")
    context(session, binding.user_id, binding.organization_id)
    member = session.get(Membership, (binding.organization_id, binding.user_id))
    user = session.get(User, binding.user_id)
    if not member or member.role not in SECURITY:
        raise HTTPException(403, "Binding owner no longer has security authority")
    actor = Actor(
        user.id, binding.organization_id, "developer", user.email, user.name, "", "github_oidc"
    )
    return binding, actor


def gate_result(run, claims):
    binding = run.get("github") or {}
    if (
        binding.get("repository_id") != claims["repository_id"]
        or binding.get("sha") != claims["sha"]
    ):
        raise HTTPException(403, "Release evidence belongs to a different repository or candidate")
    # A claimed deployment SHA is not evidence of what the target actually ran.
    allow = (
        run.get("release_action") == "ALLOW"
        and run.get("candidate_observed") is True
        and run.get("status") == "COMPLETED"
    )
    return {
        "run_id": run["id"],
        "status": run["status"],
        "sha": binding["sha"],
        "security_verdict": run.get("security_verdict", "INCONCLUSIVE"),
        "release_action": "ALLOW" if allow else "BLOCK",
        "evidence_digest": run.get("evidence_digest"),
        "reason": "Qualified exact-candidate evidence"
        if allow
        else "Exact-candidate qualified assurance has not passed",
    }
