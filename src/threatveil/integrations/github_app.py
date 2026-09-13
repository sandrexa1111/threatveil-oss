"""GitHub App protocol boundary, strict webhook intake and exact-SHA checks.

Persistent routing, replay claims and release authorization are control-plane
responsibilities. This module never selects a tenant from a webhook-supplied org.
"""

import hashlib
import hmac
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
import jwt

from ..sdk.receipts import read_receipt

API_ORIGIN = "https://api.github.com"
API_VERSION = "2022-11-28"
CHECK_NAME = "ThreatVeil Release Integrity"
MAX_WEBHOOK_BYTES = 1_000_000
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


class GitHubAppError(ValueError):
    """A GitHub identity, protocol or scope assertion failed."""


class GitHubWriteAmbiguous(GitHubAppError):
    """A write may have reached GitHub; reconcile before attempting another write."""


def _numeric(value, label):
    if isinstance(value, bool) or not re.fullmatch(r"[1-9][0-9]{0,19}", str(value)):
        raise GitHubAppError("Invalid " + label)
    return str(value)


def _repository(repository):
    if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository):
        raise GitHubAppError("Expected a repository owner/name")
    if any(part in {".", ".."} for part in repository.split("/")):
        raise GitHubAppError("Invalid repository path")
    return repository


def verify_webhook(body: bytes, signature: str, secret: str) -> dict:
    """Authenticate exact request bytes before parsing any event fields."""
    if not secret:
        raise GitHubAppError("GitHub webhook secret is not configured")
    if not isinstance(body, bytes) or not 1 <= len(body) <= MAX_WEBHOOK_BYTES:
        raise GitHubAppError("Webhook body exceeds the bounded intake limit")
    if not isinstance(signature, str) or not re.fullmatch(r"sha256=[0-9a-f]{64}", signature):
        raise GitHubAppError("GitHub webhook signature is invalid")
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise GitHubAppError("GitHub webhook signature is invalid")
    try:
        return read_receipt(body)
    except ValueError:
        raise GitHubAppError("GitHub webhook JSON is invalid or ambiguous") from None


def push_candidate(payload: dict, binding, installation_id: str) -> dict:
    """Match a signed push to the trusted repository/ref and registered App."""
    repository = payload.get("repository")
    installation = payload.get("installation")
    if not isinstance(repository, dict) or not isinstance(installation, dict):
        raise GitHubAppError("A repository push with an App installation is required")
    owner = repository.get("owner") or {}
    checks = (
        (_numeric(repository.get("id"), "repository ID"), str(binding.repository_id)),
        (repository.get("full_name"), binding.repository),
        (_numeric(owner.get("id"), "owner ID"), str(binding.owner_id)),
        (payload.get("ref"), binding.allowed_ref),
        (_numeric(installation.get("id"), "installation ID"), str(installation_id)),
    )
    if not binding.enabled or any(actual != expected for actual, expected in checks):
        raise GitHubAppError("Push is outside the registered repository release scope")
    sha = payload.get("after")
    if payload.get("deleted") is not False or not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise GitHubAppError("Push must identify a live exact candidate")
    if not sha.strip("0"):
        raise GitHubAppError("Deleted Git reference is not a candidate")
    return {"type": "git_commit", "id": str(binding.repository_id), "version": sha, "digest": sha}


def check_payload(decision: dict, repository_id: str, sha: str, details_url: str) -> dict:
    """Project an authorized decision without laundering FAIL in WARN/OBSERVE."""
    repository_id = _numeric(repository_id, "repository ID")
    candidate = decision.get("candidate") or {}
    if (
        not isinstance(sha, str)
        or not SHA.fullmatch(sha)
        or candidate.get("type") != "git_commit"
        or candidate.get("id") != repository_id
        or candidate.get("version") != sha
        or candidate.get("digest") != sha
    ):
        raise GitHubAppError("Release decision belongs to a different exact Git candidate")
    parsed = urlsplit(details_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise GitHubAppError("Receipt details require an HTTPS URL without credentials")
    action, underlying = decision.get("release_action"), decision.get("underlying_action")
    mode = (decision.get("policy") or {}).get("mode")
    if action not in ("ALLOW", "WARN", "BLOCK") or underlying not in ("ALLOW", "WARN", "BLOCK"):
        raise GitHubAppError("Release decision has no explicit effective and underlying action")
    if mode not in ("OBSERVE", "WARN", "BLOCK"):
        raise GitHubAppError("Release decision has no registered gate mode")
    identifier = decision.get("id")
    if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", identifier):
        raise GitHubAppError("Invalid release decision ID")
    rows = decision.get("properties")
    if not isinstance(rows, list) or len(rows) > 500:
        raise GitHubAppError("Bounded property-level decision details are required")
    summary = [
        f"Candidate: `{sha}`",
        f"Policy mode: **{mode}**",
        f"Release decision: **{action}**; underlying result: **{underlying}**.",
        "This check records a scoped release decision; it is not a security certification.",
    ]
    historical_action = decision.get("historical_release_action", action)
    if historical_action != action:
        summary.append(
            f"The signed historical action was **{historical_action}**. "
            f"Its current authorization is **{action}**; refresh the release decision."
        )
    if decision.get("exceptions"):
        summary.append(
            "An authorized exception is recorded; the original result remains in the receipt."
        )
    for row in rows[:100]:
        # Only bounded identifiers/enums are rendered; untrusted free-form property
        # descriptions cannot inject links or masquerade as this check's instructions.
        prop_id = str(row.get("property_id", "unknown"))
        safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", prop_id)[:100]
        security = row.get("security_verdict")
        task = row.get("task_outcome")
        validity = row.get("validity")
        if security not in ("PASS", "FAIL", "INCONCLUSIVE", "UNKNOWN"):
            raise GitHubAppError("Invalid property security verdict")
        if task not in ("SUCCESS", "FAILURE", "UNKNOWN"):
            raise GitHubAppError("Invalid property task verdict")
        if validity not in ("STILL_VALID", "VOID", "UNKNOWN", "INCOMPATIBLE"):
            raise GitHubAppError("Invalid property validity")
        summary.append(
            f"- `{safe_id}`: security **{security}**, task **{task}**, evidence **{validity}**."
        )
    if len(rows) > 100:
        summary.append(f"{len(rows) - 100} additional properties appear in the complete receipt.")
    # The decision's effective action already includes server-owned per-property
    # policies and approved exceptions. Do not accept a separate caller mode.
    conclusion = "success" if action == "ALLOW" else ("failure" if action == "BLOCK" else "neutral")
    return {
        "name": CHECK_NAME,
        "head_sha": sha,
        "external_id": "threatveil-release:" + identifier,
        "status": "completed",
        "conclusion": conclusion,
        "details_url": details_url,
        "output": {"title": f"{action} — underlying {underlying}", "summary": "\n\n".join(summary)},
    }


class GitHubAppClient:
    """Fixed-origin, repository-scoped GitHub client. No automatic write retries."""

    def __init__(self, app_id, private_key, *, http_client=None):
        self.app_id = _numeric(app_id, "App ID")
        if not private_key:
            raise GitHubAppError("GitHub App private key is not configured")
        self.private_key = private_key
        self._owns_client = http_client is None
        self.client = http_client or httpx.Client(
            timeout=10, trust_env=False, follow_redirects=False
        )

    def _jwt(self):
        current = int(time.time())
        return jwt.encode(
            {"iat": current - 60, "exp": current + 540, "iss": self.app_id},
            self.private_key,
            algorithm="RS256",
        )

    def _request(self, method, path, token, body=None, params=None):
        try:
            response = self.client.request(
                method,
                API_ORIGIN + path,
                json=body,
                params=params,
                headers={
                    "Authorization": "Bearer " + token,
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": API_VERSION,
                },
            )
        except httpx.HTTPError:
            error = GitHubWriteAmbiguous if method in ("POST", "PATCH") else GitHubAppError
            raise error("GitHub request did not return a confirmed response") from None
        if not response.is_success:
            # Server errors/timeouts may occur after a write has committed. Never
            # log a request/token or expose response bodies containing credentials.
            if method in ("POST", "PATCH") and response.status_code >= 500:
                raise GitHubWriteAmbiguous("GitHub write outcome needs reconciliation")
            raise GitHubAppError(f"GitHub rejected the request ({response.status_code})")
        try:
            result = response.json()
        except ValueError:
            raise GitHubAppError("GitHub returned invalid JSON") from None
        if not isinstance(result, dict):
            raise GitHubAppError("GitHub returned an invalid response object")
        return result

    def repository_installation(self, repository, repository_id, owner_id, installation_id):
        repository = _repository(repository)
        installation_id = _numeric(installation_id, "installation ID")
        result = self._request("GET", f"/repos/{repository}/installation", self._jwt())
        account = result.get("account") or {}
        if (
            str(result.get("id")) != installation_id
            or str(result.get("app_id")) != self.app_id
            or str(account.get("id")) != _numeric(owner_id, "owner ID")
            or result.get("suspended_at") is not None
            or (result.get("permissions") or {}).get("checks") != "write"
        ):
            raise GitHubAppError("Repository is not authorized for this active App installation")
        token = self.installation_token(installation_id, repository_id)
        repo = self._request("GET", f"/repos/{repository}", token)
        if (
            str(repo.get("id")) != _numeric(repository_id, "repository ID")
            or repo.get("full_name") != repository
            or str((repo.get("owner") or {}).get("id")) != str(owner_id)
        ):
            raise GitHubAppError(
                "Installed repository identity does not match the reviewed binding"
            )
        return {
            "installation_id": installation_id,
            "repository_id": str(repository_id),
            "repository": repository,
            "owner_id": str(owner_id),
            "app_id": self.app_id,
        }

    def installation_token(self, installation_id, repository_id):
        installation_id = _numeric(installation_id, "installation ID")
        repository_id = _numeric(repository_id, "repository ID")
        result = self._request(
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            self._jwt(),
            {"repository_ids": [int(repository_id)], "permissions": {"checks": "write"}},
        )
        token = result.get("token")
        try:
            expires = datetime.fromisoformat(result.get("expires_at", ""))
            remaining = (expires - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError):
            raise GitHubAppError("Installation token expiry is unavailable") from None
        if not isinstance(token, str) or not 20 <= len(token) <= 16000 or not 0 < remaining <= 3660:
            raise GitHubAppError("GitHub returned an invalid or expired installation token")
        if (result.get("permissions") or {}).get("checks") != "write":
            raise GitHubAppError("Installation token cannot publish checks")
        return token

    def find_check(self, repository, sha, external_id, token):
        repository = _repository(repository)
        if not isinstance(sha, str) or not SHA.fullmatch(sha):
            raise GitHubAppError("Exact candidate SHA required")
        found = []
        for page in range(1, 11):
            response = self._request(
                "GET",
                f"/repos/{repository}/commits/{sha}/check-runs",
                token,
                params={"check_name": CHECK_NAME, "filter": "all", "per_page": 100, "page": page},
            )
            rows = response.get("check_runs")
            if not isinstance(rows, list):
                raise GitHubAppError("Cannot reconcile GitHub checks")
            found.extend(
                row
                for row in rows
                if row.get("external_id") == external_id
                and str((row.get("app") or {}).get("id")) == self.app_id
                and row.get("head_sha") == sha
                and row.get("name") == CHECK_NAME
            )
            if len(rows) < 100:
                break
        else:
            raise GitHubAppError("GitHub check reconciliation exceeded its bounded page limit")
        if len(found) > 1:
            raise GitHubAppError("Duplicate release checks require operator reconciliation")
        return found[0] if found else None

    def publish_check(
        self,
        repository,
        installation_id,
        repository_id,
        decision,
        details_url,
        *,
        permit_create=True,
        before_write=None,
    ):
        repository = _repository(repository)
        sha = (decision.get("candidate") or {}).get("digest")
        payload = check_payload(decision, repository_id, sha, details_url)
        token = self.installation_token(installation_id, repository_id)
        existing = self.find_check(repository, sha, payload["external_id"], token)
        if existing:
            identifier = _numeric(existing.get("id"), "check ID")
            if before_write:
                before_write()
            result = self._request(
                "PATCH",
                f"/repos/{repository}/check-runs/{identifier}",
                token,
                {key: value for key, value in payload.items() if key != "head_sha"},
            )
        elif permit_create:
            if before_write:
                before_write()
            result = self._request("POST", f"/repos/{repository}/check-runs", token, payload)
        else:
            raise GitHubWriteAmbiguous(
                "Prior check creation is unresolved; automatic duplicate creation refused"
            )
        if (
            result.get("head_sha") != sha
            or result.get("external_id") != payload["external_id"]
            or str((result.get("app") or {}).get("id")) != self.app_id
        ):
            raise GitHubWriteAmbiguous("Published GitHub check identity could not be confirmed")
        return {
            "check_id": _numeric(result.get("id"), "check ID"),
            "sha": sha,
            "external_id": payload["external_id"],
            "conclusion": payload["conclusion"],
        }

    def close(self):
        if self._owns_client:
            self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
