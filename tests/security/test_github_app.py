import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from threatveil.integrations.github_app import (
    API_ORIGIN,
    CHECK_NAME,
    GitHubAppClient,
    GitHubAppError,
    GitHubWriteAmbiguous,
    check_payload,
    push_candidate,
    verify_webhook,
)


@pytest.fixture
def decision():
    return {
        "id": "release-1",
        "candidate": {"type": "git_commit", "id": "456", "version": "a" * 40, "digest": "a" * 40},
        "release_action": "WARN",
        "underlying_action": "BLOCK",
        "policy": {"mode": "WARN", "property_modes": {}},
        "properties": [
            {
                "property_id": "property-1",
                "security_verdict": "FAIL",
                "task_outcome": "SUCCESS",
                "validity": "VOID",
            }
        ],
        "exceptions": [],
    }


def test_webhook_uses_github_reference_hmac_vector():
    with pytest.raises(GitHubAppError, match="JSON"):
        verify_webhook(
            b"Hello, World!",
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
            "It's a Secret to Everybody",
        )
    body, secret = b'{"repository":{"id":456}}', "test-secret"
    signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_webhook(body, signature, secret)["repository"]["id"] == 456
    for corrupted in (signature.replace("sha256", "sha1"), signature[:-1] + "x", ""):
        with pytest.raises(GitHubAppError):
            verify_webhook(body, corrupted, secret)
    with pytest.raises(GitHubAppError):
        verify_webhook(body + b" ", signature, secret)
    with pytest.raises(GitHubAppError):
        verify_webhook(body, signature, "")


def test_signed_duplicate_json_does_not_create_ambiguous_repository():
    body, secret = b'{"repository":{"id":456,"id":789}}', "test-secret"
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    with pytest.raises(GitHubAppError, match="ambiguous"):
        verify_webhook(body, sig, secret)


def test_signed_push_is_bound_to_owner_repo_ref_installation_and_sha():
    binding = SimpleNamespace(
        repository_id="456",
        repository="company/agent",
        owner_id="789",
        allowed_ref="refs/heads/main",
        enabled=True,
    )
    payload = {
        "repository": {"id": 456, "full_name": "company/agent", "owner": {"id": 789}},
        "installation": {"id": 123},
        "ref": "refs/heads/main",
        "after": "a" * 40,
        "deleted": False,
    }
    assert push_candidate(payload, binding, "123")["digest"] == "a" * 40
    for updates in (
        {"ref": "refs/heads/attacker"},
        {"after": "main"},
        {"after": "0" * 40},
        {"deleted": True},
        {"installation": {"id": 999}},
        {"repository": {"id": 457, "full_name": "company/agent", "owner": {"id": 789}}},
    ):
        with pytest.raises(GitHubAppError):
            push_candidate({**payload, **updates}, binding, "123")


@pytest.mark.parametrize(
    "mode,action,conclusion",
    [
        ("WARN", "WARN", "neutral"),
        ("OBSERVE", "WARN", "neutral"),
        ("BLOCK", "BLOCK", "failure"),
        ("BLOCK", "ALLOW", "success"),
        ("WARN", "BLOCK", "failure"),
    ],
)
def test_checks_project_server_policy_keep_real_fail_visible(decision, mode, action, conclusion):
    decision["policy"]["mode"], decision["release_action"] = mode, action
    result = check_payload(
        decision, "456", "a" * 40, "https://threatveil.example/releases/release-1"
    )
    assert result["head_sha"] == "a" * 40 and result["conclusion"] == conclusion
    assert "FAIL" in result["output"]["summary"] and "underlying" in result["output"]["title"]
    for repo, sha in (("457", "a" * 40), ("456", "b" * 40)):
        with pytest.raises(GitHubAppError, match="different exact Git"):
            check_payload(decision, repo, sha, "https://threatveil.example/release")


def client(handler):
    key = generate_private_key(public_exponent=65537, key_size=2048)
    return GitHubAppClient(
        "12", key, http_client=httpx.Client(transport=httpx.MockTransport(handler))
    ), key


def token_response():
    return {
        "token": "test-installation-token-value",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=59)).isoformat(),
        "permissions": {"checks": "write"},
    }


def check_response(decision, identifier=11):
    return {
        "id": identifier,
        "app": {"id": 12},
        "head_sha": "a" * 40,
        "name": CHECK_NAME,
        "external_id": "threatveil-release:" + decision["id"],
    }


def test_app_jwt_and_installation_token_are_bounded_to_reviewed_repository(decision):
    calls = []

    def handler(request):
        calls.append(request)
        assert str(request.url).startswith(API_ORIGIN)
        if request.url.path.endswith("/installation"):
            return httpx.Response(
                200,
                json={
                    "id": 123,
                    "app_id": 12,
                    "account": {"id": 789},
                    "permissions": {"checks": "write"},
                    "suspended_at": None,
                },
            )
        if request.url.path.endswith("/access_tokens"):
            assert json.loads(request.content) == {
                "repository_ids": [456],
                "permissions": {"checks": "write"},
            }
            return httpx.Response(201, json=token_response())
        return httpx.Response(
            200, json={"id": 456, "full_name": "company/agent", "owner": {"id": 789}}
        )

    github, key = client(handler)
    result = github.repository_installation("company/agent", "456", "789", "123")
    assert result["repository_id"] == "456"
    claims = jwt.decode(
        calls[0].headers["authorization"].removeprefix("Bearer "),
        key.public_key(),
        algorithms=["RS256"],
    )
    assert claims["iss"] == "12" and claims["exp"] - claims["iat"] == 600


@pytest.mark.parametrize(
    "changes",
    [
        {"id": 999},
        {"app_id": 99},
        {"account": {"id": 777}},
        {"suspended_at": "2026-01-01T00:00:00Z"},
        {"permissions": {"checks": "read"}},
    ],
)
def test_registration_rejects_installation_identity_or_permission_mismatch(changes):
    def handler(request):
        return httpx.Response(
            200,
            json={
                "id": 123,
                "app_id": 12,
                "account": {"id": 789},
                "permissions": {"checks": "write"},
                "suspended_at": None,
                **changes,
            },
        )

    github, _ = client(handler)
    with pytest.raises(GitHubAppError, match="not authorized"):
        github.repository_installation("company/agent", "456", "789", "123")


def test_reconciliation_updates_known_exact_check_without_duplicate_create(decision):
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        if request.method == "GET":
            return httpx.Response(200, json={"check_runs": [check_response(decision)]})
        assert request.method == "PATCH" and request.url.path.endswith("/check-runs/11")
        return httpx.Response(200, json=check_response(decision))

    github, _ = client(handler)
    marker = []
    result = github.publish_check(
        "company/agent",
        "123",
        "456",
        decision,
        "https://threatveil.example/releases/release-1",
        permit_create=False,
        before_write=lambda: marker.append("claimed"),
    )
    assert result["check_id"] == "11" and marker == ["claimed"]
    assert not any(r.method == "POST" and r.url.path.endswith("/check-runs") for r in calls)


def test_ambiguous_create_is_not_automatically_repeated(decision):
    def handler(request):
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        return httpx.Response(200, json={"check_runs": []})

    github, _ = client(handler)
    with pytest.raises(GitHubWriteAmbiguous, match="duplicate creation refused"):
        github.publish_check(
            "company/agent",
            "123",
            "456",
            decision,
            "https://threatveil.example/releases/release-1",
            permit_create=False,
        )


def test_first_create_and_lost_response_are_distinguished(decision):
    writes = []

    def handler(request):
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json=token_response())
        if request.method == "GET":
            return httpx.Response(200, json={"check_runs": []})
        writes.append(request)
        raise httpx.ReadTimeout("injected lost response")

    github, _ = client(handler)
    with pytest.raises(GitHubWriteAmbiguous):
        github.publish_check(
            "company/agent", "123", "456", decision, "https://threatveil.example/releases/release-1"
        )
    assert len(writes) == 1


def test_duplicate_checks_and_other_app_cannot_be_adopted(decision):
    def handler(request):
        return httpx.Response(
            200, json={"check_runs": [check_response(decision), check_response(decision, 12)]}
        )

    github, _ = client(handler)
    with pytest.raises(GitHubAppError, match="Duplicate"):
        github.find_check(
            "company/agent", "a" * 40, "threatveil-release:release-1", "installation-token"
        )
    github.client = httpx.Client(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(
                200, json={"check_runs": [{**check_response(decision), "app": {"id": 99}}]}
            )
        )
    )
    assert (
        github.find_check(
            "company/agent", "a" * 40, "threatveil-release:release-1", "installation-token"
        )
        is None
    )


def test_client_blocks_path_injection_and_credentials_in_details(decision):
    github, _ = client(lambda r: pytest.fail("Invalid route must not contact GitHub"))
    for repository in (
        "../evil",
        "company/../evil",
        "company/agent?token=x",
        "https://evil.example",
    ):
        with pytest.raises(GitHubAppError):
            github.repository_installation(repository, "456", "789", "123")
    with pytest.raises(GitHubAppError):
        check_payload(decision, "456", "a" * 40, "https://secret@threatveil.example")
