"""Small synchronous Python API client; no implicit execution retries."""

import time
from typing import Any
from urllib.parse import urlencode, urlsplit
from uuid import UUID, uuid4

import httpx


class ThreatVeilClient:
    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        *,
        http_client: httpx.Client | None = None,
        csrf_token: str | None = None,
    ):
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "::1")
        ):
            raise ValueError(
                "ThreatVeil API requires HTTPS except for explicit loopback development"
            )
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("API base URL must not contain credentials, query or fragment")
        self.base_url = base_url.rstrip("/")
        self._owns_client = http_client is None
        self.client = http_client or httpx.Client(
            timeout=30, follow_redirects=False, trust_env=False
        )
        self.headers = {"Accept": "application/json"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        if csrf_token:
            self.headers["X-CSRF-Token"] = csrf_token

    def _request(self, method: str, path: str, body: dict | None = None,
                 headers: dict[str, str] | None = None) -> dict[str, Any]:
        response = self.client.request(
            method, self.base_url + path, json=body, headers={**self.headers, **(headers or {})}
        )
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("ThreatVeil API returned an invalid response envelope")
        return result

    def create_run(
        self,
        *,
        system_id: str,
        property_id: str,
        target_id: str,
        version: str,
        trials: int = 5,
        variant_count: int = 1,
        baseline_id: str | None = None,
        idempotency_key: str | None = None,
        observer_id: str | None = None,
        candidate: dict | None = None,
        fingerprint: dict | None = None,
        stimulus: dict | None = None,
        observation: dict | None = None,
        qualification_case: str | None = None,
    ) -> dict:
        from threatveil.schemas import RunInput

        payload = RunInput.model_validate(
            {
                "system_id": system_id,
                "property_id": property_id,
                "target_id": target_id,
                "version": version,
                "trials": trials,
                "variant_count": variant_count,
                "baseline_id": baseline_id,
                "idempotency_key": idempotency_key or str(uuid4()),
                "observer_id": observer_id,
                "candidate": candidate,
                "fingerprint": fingerprint or {"components": []},
                "stimulus": stimulus,
                "observation": observation,
                "qualification_case": qualification_case,
            }
        )
        return self._request("POST", "/v1/runs", payload.model_dump(mode="json", exclude_none=True))

    def get_run(self, run_id: str) -> dict:
        return self._request("GET", f"/v1/runs/{UUID(run_id)}")

    def get_evidence(self, run_id: str) -> dict:
        return self._request("GET", f"/v1/runs/{UUID(run_id)}/evidence")

    def get_capture(self, run_id: str, capture_id: str) -> dict:
        return self._request("GET", f"/v1/runs/{UUID(run_id)}/captures/{UUID(capture_id)}")

    def query_memory(self, **filters) -> dict:
        return self._request("POST", "/v1/memory/query", filters)

    def list_templates(self) -> dict:
        return self._request("GET", "/v1/templates")

    def _page(
        self, path: str, *, system_id: str | None = None, limit: int = 25, cursor: str | None = None
    ) -> dict:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200:
            raise ValueError("Page limit must be between 1 and 200")
        query = {"limit": str(limit)}
        if system_id is not None:
            query["system_id"] = str(UUID(system_id))
        if cursor is not None:
            if not isinstance(cursor, str) or len(cursor) > 512:
                raise ValueError("Invalid page cursor")
            query["cursor"] = cursor
        return self._request("GET", path + "?" + urlencode(query))

    def list_properties(self, **filters) -> dict:
        return self._page("/v1/workspace/properties", **filters)

    def list_releases(self, **filters) -> dict:
        return self._page("/v1/releases", **filters)

    def get_release(self, release_id: str) -> dict:
        return self._request("GET", f"/v1/releases/{UUID(release_id)}")

    def get_release_receipt(self, release_id: str) -> dict:
        return self._request("GET", f"/v1/releases/{UUID(release_id)}/receipt")

    def list_evidence_records(self, **filters) -> dict:
        return self._page("/v1/evidence-ledger", **filters)

    def get_evidence_record(self, evidence_id: str) -> dict:
        return self._request("GET", f"/v1/evidence-ledger/{UUID(evidence_id)}")

    def list_proof_plans(self, **filters) -> dict:
        return self._page("/v1/proof-plans", **filters)

    def get_proof_plan(self, plan_id: str) -> dict:
        return self._request("GET", f"/v1/proof-plans/{UUID(plan_id)}")

    def create_proof_plan(
        self,
        *,
        system_id: str,
        candidate: dict,
        fingerprint: dict,
        previous_fingerprint: dict | None = None,
        trials_per_variant: int = 5,
        variant_count: int = 1,
    ) -> dict:
        if not 1 <= trials_per_variant <= 100 or not 1 <= variant_count <= 5:
            raise ValueError("Invalid bounded proof-plan budget")
        payload = {
            "system_id": str(UUID(system_id)),
            "candidate": candidate,
            "fingerprint": fingerprint,
            "trials_per_variant": trials_per_variant,
            "variant_count": variant_count,
        }
        if previous_fingerprint is not None:
            payload["previous_fingerprint"] = previous_fingerprint
        return self._request("POST", "/v1/proof-plans", payload)

    def create_release(
        self, plan_id: str, *, policy: dict | None = None, exception_ids: list[str] | None = None
    ) -> dict:
        return self._request(
            "POST",
            "/v1/releases",
            {
                "plan_id": str(UUID(plan_id)),
                "policy": policy or {"mode": "WARN"},
                "exception_ids": [str(UUID(identifier)) for identifier in exception_ids or []],
            },
        )

    def decide_authorized_release(self, binding: dict) -> dict:
        """Consume a separate exact-plan tvrel_ grant; never request arbitrary policy."""
        from threatveil.release_machine import MachineDecisionInput

        payload = MachineDecisionInput.model_validate(binding).model_dump(mode="json")
        return self._request("POST", "/v1/release-machine/decide", payload)

    def import_integration(
        self,
        kind: str,
        *,
        system_id: str,
        payload: dict,
        context: dict | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        from threatveil.integrations.intake import FORMATS

        if kind not in FORMATS:
            raise ValueError("Unsupported integration format")
        return self._request(
            "POST",
            f"/v1/integrations/intake/{kind}",
            {
                "system_id": str(UUID(system_id)),
                "payload": payload,
                "context": context,
                "idempotency_key": idempotency_key or str(uuid4()),
            },
        )

    def get_intake(self, intake_id: str) -> dict:
        return self._request("GET", f"/v1/integrations/intake/{UUID(intake_id)}")

    def list_intakes(self, **filters) -> dict:
        return self._page("/v1/integrations/intake", **filters)

    def wait_run(
        self, run_id: str, *, timeout_seconds: float = 300, poll_seconds: float = 1
    ) -> dict:
        if not 0 < timeout_seconds <= 600 or not 0.1 <= poll_seconds <= 10:
            raise ValueError("Polling requires a bounded timeout and interval")
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            result = self.get_run(run_id)
            if result.get("status") in ("COMPLETED", "ERROR", "CANCELLED", "TIMEOUT"):
                return result
            time.sleep(min(poll_seconds, max(0, deadline - time.monotonic())))
        raise TimeoutError(
            "ThreatVeil execution did not reach a terminal state before the deadline"
        )

    def current_assurance(self, system_id: str, *, environment_id: str | None = None,
                          action: str | None = None, expected_state_digest: str | None = None,
                          consumer: str | None = None) -> dict:
        """The Assurance Gate: is this system still cleared to act? It never authorizes."""
        import re

        params = {}
        if environment_id:
            params["environment_id"] = str(UUID(str(environment_id)))
        if action is not None:
            if not action or len(action) > 200:
                raise ValueError("Invalid action")
            params["action"] = action
        if expected_state_digest is not None:
            if not re.fullmatch(r"[0-9a-f]{64}", expected_state_digest):
                raise ValueError("Invalid state digest")
            params["expected_state_digest"] = expected_state_digest
        headers = {}
        if consumer is not None:
            if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,39}", consumer):
                raise ValueError("Invalid consumer label")
            headers["X-ThreatVeil-Consumer"] = consumer
        path = f"/v1/systems/{UUID(str(system_id))}/assurance/current"
        return self._request("GET", path + ("?" + urlencode(params) if params else ""), headers=headers)

    @staticmethod
    def is_cleared(response: dict, *, at=None) -> bool:
        """Fail closed: only a fresh CURRENT + ALLOW answer is cleared. UNKNOWN never is."""
        from datetime import datetime, timezone

        try:
            valid_until = datetime.fromisoformat(response["freshness"]["valid_until"])
        except (KeyError, TypeError, ValueError):
            return False
        return (response.get("cleared") is True and response.get("status") == "CURRENT"
                and response.get("action") == "ALLOW" and valid_until > (at or datetime.now(timezone.utc)))

    def system_intelligence(self, system_id: str, *, environment_id: str | None = None) -> dict:
        query = f"?environment_id={UUID(str(environment_id))}" if environment_id else ""
        return self._request("GET", f"/v1/systems/{UUID(str(system_id))}/intelligence{query}")

    def issue_passport(self, system_id: str, *, audience: str = "Enterprise security review",
                       valid_days: int = 30, environment_id: str | None = None) -> dict:
        body = {"audience": audience, "valid_days": valid_days}
        if environment_id:
            body["environment_id"] = str(UUID(str(environment_id)))
        return self._request("POST", f"/v1/systems/{UUID(str(system_id))}/passports", body)

    def get_passport(self, passport_id: str) -> dict:
        return self._request("GET", f"/v1/passports/{UUID(str(passport_id))}")

    def issue_passport_disclosure(self, passport_id: str) -> dict:
        """Exactly what an external recipient would see, before any link exists."""
        return self._request("GET", f"/v1/passports/{UUID(str(passport_id))}/disclosure-preview")

    def propose_change(self, system_id: str, *, installation_id: str, payload: dict,
                       reference: dict | None = None, idempotency_key: str | None = None) -> dict:
        """What would this change break? Read-only with respect to current clearance."""
        from uuid import uuid4

        body = {"installation_id": str(UUID(str(installation_id))), "payload": payload,
                "idempotency_key": idempotency_key or str(uuid4())}
        if reference:
            body["reference"] = reference
        return self._request("POST", f"/v1/systems/{UUID(str(system_id))}/proposed-changes", body)

    def list_proposed_changes(self, system_id: str) -> dict:
        return self._request("GET", f"/v1/systems/{UUID(str(system_id))}/proposed-changes")

    def replay_configuration_history(self, system_id: str, *, installation_id: str, revisions: list[dict],
                                     idempotency_key: str | None = None) -> dict:
        """Consequences of real past configuration changes, judged by today's claims."""
        from uuid import uuid4

        return self._request("POST", f"/v1/systems/{UUID(str(system_id))}/history-replay", {
            "installation_id": str(UUID(str(installation_id))), "revisions": revisions,
            "idempotency_key": idempotency_key or str(uuid4())})

    def claims(self, system_id: str, *, environment_id: str | None = None) -> dict:
        """Every claim with its verification level: DECLARED, NOT_YET_VERIFIED, QUALIFIED or CURRENT."""
        query = f"?environment_id={UUID(str(environment_id))}" if environment_id else ""
        return self._request("GET", f"/v1/systems/{UUID(str(system_id))}/claims{query}")

    def guidance(self, system_id: str, *, environment_id: str | None = None) -> dict:
        """Named limitations, what ThreatVeil refuses to claim under each, and the next step."""
        query = f"?environment_id={UUID(str(environment_id))}" if environment_id else ""
        return self._request("GET", f"/v1/systems/{UUID(str(system_id))}/guidance{query}")

    def claim_templates(self) -> dict:
        return self._request("GET", "/v1/claim-templates")

    def confirm_consequence(self, system_id: str, consequence_id: str, *, verdict: str,
                            comment: str | None = None, idempotency_key: str | None = None) -> dict:
        """Was this right? Recorded beside the consequence; it changes nothing about it."""
        from uuid import uuid4

        if verdict not in {"CORRECT", "PARTIALLY_CORRECT", "INCORRECT", "NOT_SURE"}:
            raise ValueError("Unknown verdict")
        return self._request("POST", f"/v1/systems/{UUID(str(system_id))}/consequences/"
                                     f"{UUID(str(consequence_id))}/feedback",
                             {"verdict": verdict, "comment": comment,
                              "idempotency_key": idempotency_key or str(uuid4())})

    def business_measurement(self) -> dict:
        return self._request("GET", "/v1/measurements/business")

    def observed_effect(self, definition_id: str, correlation_value: str) -> dict:
        """What a qualified observer establishes about one attempted business effect."""
        return self._request("GET", f"/v1/observer-definitions/{UUID(str(definition_id))}/effects"
                                    f"?{urlencode({'correlation_value': correlation_value})}")

    def build_info(self) -> dict:
        return self._request("GET", "/v1/build-info")

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
