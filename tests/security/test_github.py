import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from fastapi import HTTPException

from threatveil.integrations import github


@pytest.fixture
def identity(monkeypatch):
    key = generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    public.update(kid="test-key", alg="RS256", use="sig")
    monkeypatch.setattr(github, "_jwks", (time.monotonic()+300, {"keys": [public]}))
    current = int(time.time())
    claims = {"iss": github.ISSUER, "aud": github.AUDIENCE, "sub": "repo:company/agent:ref:refs/heads/main",
              "iat": current, "nbf": current, "exp": current+300, "jti": "unique-job-token",
              "sha": "a"*40, "event_name": "push", "run_id": "123", "run_attempt": "1",
              "repository_id": "456", "repository_owner_id": "789", "repository": "company/agent",
              "workflow_ref": "company/agent/.github/workflows/verify.yml@refs/heads/main", "ref": "refs/heads/main"}
    def token(**changes):
        return jwt.encode({**claims, **changes}, key, algorithm="RS256", headers={"kid": "test-key"})
    return claims, token


def test_real_signature_verification_rejects_wrong_audience_expiry_and_fork_events(identity):
    claims, token = identity
    assert github.verify_token(token())["sha"] == claims["sha"]
    for changes in ({"aud": "different-service"}, {"iss": "https://attacker.invalid"},
                    {"exp": int(time.time())-1}, {"event_name": "pull_request_target"},
                    {"event_name": "pull_request"}, {"sha": "main"}):
        with pytest.raises(HTTPException) as error:
            github.verify_token(token(**changes))
        assert error.value.status_code == 401
    forged = token().rsplit(".", 1)[0]+"."+"A"*342
    with pytest.raises(HTTPException):
        github.verify_token(forged)


def test_release_gate_requires_exact_candidate_and_observed_identity(identity):
    claims, _ = identity
    run = {"id": "run", "status": "COMPLETED", "release_action": "ALLOW", "security_verdict": "PASS",
           "candidate_observed": False, "github": {"repository_id": claims["repository_id"], "sha": claims["sha"]}}
    assert github.gate_result(run, claims)["release_action"] == "BLOCK"
    run["candidate_observed"] = True
    assert github.gate_result(run, claims)["release_action"] == "ALLOW"
    for bad in ({**claims, "repository_id": "another"}, {**claims, "sha": "b"*40}):
        with pytest.raises(HTTPException) as error:
            github.gate_result(run, bad)
        assert error.value.status_code == 403
    run["status"] = "TIMEOUT"
    assert github.gate_result(run, claims)["release_action"] == "BLOCK"
