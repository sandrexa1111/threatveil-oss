"""Real local HTTP commercial + change-assurance demonstration with synthetic SQL effects.

Requires a running local API and an independently provisioned public signing key.
No external connector request, cloud mutation, customer message or charge occurs.
"""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import time
from urllib.parse import urlsplit
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import httpx

from threatveil.sdk.change_records import verify_change_record
from threatveil.sdk.receipts import verify_release_receipt


def run_demo(api_url: str, origin: str, public_key_path: Path, output: Path):
    parsed = urlsplit(api_url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("The demonstration requires an explicit loopback HTTP API")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("API URL cannot contain credentials, query or fragment")
    public_bytes = public_key_path.read_bytes()
    public = serialization.load_pem_public_key(public_bytes)
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError("Independently configured Ed25519 public key is required")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    (output / "trusted-public-key.pem").write_bytes(public_bytes)
    started = time.monotonic()
    summary = {"profile": "threatveil.category-foundation-demo.v1", "completed": False,
        "api_url": api_url, "scope": "Local HTTP, PostgreSQL and synthetic committed finance SQL effects",
        "trusted_public_key_sha256": hashlib.sha256(public_bytes).hexdigest(), "steps": [],
        "limitations": ["Synthetic data and local sandbox activation only; no real money or customer system.",
            "MCP input is explicitly IMPORTED, not a live connection or authoritative observation.",
            "Mock Pro is commercial test state; no money was collected and no Stripe call was made.",
            "Exact-state identity comes from qualified local test execution, not a running cloud deployment.",
            "Elapsed time measures this prepared fixture, not real customer onboarding."]}

    def save(name, data):
        path = output / (name + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        return path.name

    def step(name, **details):
        summary["steps"].append({"step": name, **details})
        save("summary", summary)

    try:
        with httpx.Client(base_url=api_url.rstrip("/"), timeout=90, trust_env=False, follow_redirects=False) as client:
            def request(method, path, payload=None):
                response = client.request(method, "/v1" + path, json=payload)
                response.raise_for_status()
                return response.json()

            login = client.post("/v1/auth/local", json={"email": f"category-demo-{uuid4()}@local.invalid",
                "name": "Finance assurance demonstration", "organization_name": "Finance assurance local acceptance"},
                headers={"origin": origin})
            login.raise_for_status()
            client.headers.update({"origin": origin, "x-csrf-token": login.json()["csrf_token"]})
            identity = request("GET", "/auth/me")
            summary["organization_id"] = identity["organization"]["id"]
            free = request("GET", "/commercial")
            assert free["plan"] == "free" and free["paid"] is False
            assert free["mock_available"], "This demonstration requires local mock billing"
            save("commercial/free-provisioned", free)
            setup = request("POST", "/change-assurance/finance/setup", {
                "owner": "Finance assurance owner", "confirm_synthetic_scope": True})
            summary.update(system_id=setup["system_id"], environment_id=setup["environment_id"])
            save("system-boundary", setup)
            assert len(setup["property_ids"]) == 3
            step("new_organization_free_provisioned", plan=free["plan"], properties=3)

            def assessment(label, version):
                result = request("POST", "/change-assurance/finance/assess", {
                    "system_id": setup["system_id"], "version": version, "idempotency_key": str(uuid4())})
                save(f"assessments/{label}/assessment", result)
                decision = request("GET", f"/change-assurance/decisions/{result['authorization_id']}")
                save(f"assessments/{label}/authorization", decision)
                for index, run_id in enumerate(result["run_ids"]):
                    save(f"assessments/{label}/run-{index + 1}", request("GET", f"/runs/{run_id}"))
                    save(f"assessments/{label}/evidence-{index + 1}", request("GET", f"/runs/{run_id}/evidence"))
                verify_change_record(decision["envelope"], public, organization_id=summary["organization_id"],
                    system_id=setup["system_id"], environment_id=setup["environment_id"],
                    state_digest=decision["state_digest"], audience=decision["audience"],
                    at=datetime.now(timezone.utc))
                save(f"receipts/{label}-authorization.dsse", decision["envelope"])
                released = request("GET", f"/releases/{result['release_id']}")
                receipt = request("GET", f"/releases/{result['release_id']}/receipt")
                verify_release_receipt(receipt["envelope"], public,
                    expected_candidate_fingerprint_digest=released["candidate_fingerprint_digest"],
                    expected_organization_id=summary["organization_id"], expected_candidate=released["candidate"])
                save(f"receipts/{label}-release.dsse", receipt["envelope"])
                step(label, authorization_id=decision["id"], action=result["action"], security=result["security"],
                    legitimate_task=result["legitimate_task"], signed_records_independently_verified=2)
                return result, decision

            def activate(label, decision):
                assert decision["enforcement"] == "NOT_REQUESTED"
                body = {"authorization_id": decision["id"], **{k: decision[k] for k in (
                    "environment_id", "state_digest", "audience", "expected_prior_epoch", "request_nonce")},
                    "mechanism": "synthetic_compare_and_set"}
                queued = request("POST", "/change-assurance/enforcement", body)
                save(f"enforcement/{label}-request", queued)
                detail = request("GET", f"/change-assurance/decisions/{decision['id']}")
                assert detail["enforcement"] == "ACKNOWLEDGED"
                ack = detail["acknowledgement"]
                assert ack["actual_state_digest"] == decision["state_digest"]
                assert ack["authority"] == "SYNTHETIC_LOCAL"
                assert ack["applied_epoch"] == decision["expected_prior_epoch"] + 1
                save(f"enforcement/{label}-acknowledgement", ack)
                step(label + "_activation", enforcement=detail["enforcement"], applied_epoch=ack["applied_epoch"],
                    scope="Local sandbox registry only")
                return ack

            baseline, baseline_decision = assessment("free-baseline", "fixed")
            assert (baseline["security"], baseline["legitimate_task"], baseline["action"]) == ("PASS", "SUCCESS", "ALLOW")
            activate("free-baseline", baseline_decision)
            blocked_capacity = client.post("/v1/systems", json={"name": "Second protected boundary"})
            assert blocked_capacity.status_code == 402, blocked_capacity.text
            save("commercial/free-limit", {"status": blocked_capacity.status_code, "response": blocked_capacity.json()})
            before_upgrade = request("GET", f"/change-assurance/decisions/{baseline_decision['id']}")
            upgraded = request("POST", "/commercial/subscription", {"action": "upgrade", "plan": "pro",
                "idempotency_key": str(uuid4())})
            assert upgraded["plan"] == "pro" and upgraded["paid"] is False
            assert upgraded["usage"]["consumed"] > 0
            after_upgrade = request("GET", f"/change-assurance/decisions/{baseline_decision['id']}")
            assert after_upgrade["envelope"] == before_upgrade["envelope"]
            second = request("POST", "/systems", {"name": "Additional protected boundary after mock Pro"})
            save("commercial/mock-pro", upgraded)
            save("commercial/additional-system", second)
            step("mock_pro_upgrade", history_unchanged=True, paid=False,
                additional_system_id=second["id"], measured_verification_units=upgraded["usage"]["consumed"])

            installed = request("POST", "/connectors", {"system_id": setup["system_id"],
                "environment_id": setup["environment_id"], "connector_id": "mcp", "mode": "IMPORT",
                "roles": ["DISCOVER", "CHANGE"], "name": "Imported finance MCP permission configuration",
                "configuration": {}, "expires_at": (datetime.now(timezone.utc)+timedelta(days=1)).isoformat()})
            save("source/installation", installed)
            for sequence, approval in [(1, "required"), (2, "not_required")]:
                batch = request("POST", f"/connectors/{installed['id']}/import", {
                    "event_id": str(uuid4()), "sequence": sequence,
                    "valid_at": datetime.now(timezone.utc).isoformat(),
                    "payload": {"protocol_version": "2025-11-25", "complete": True,
                        "tools": [{"name": "beneficiary.update", "inputSchema": {"type": "object"}},
                                  {"name": "invoice.update", "inputSchema": {"type": "object"}}],
                        "authorization": {"tenant": "synthetic-tenant-a", "approval": approval}}})
                assert batch["acquisition"] == "IMPORTED" and batch["qualification"] == "UNREVIEWED"
                save(f"source/batch-{sequence}", batch)
            current = request("GET", f"/change-assurance/states/{baseline['state_id']}/current")
            assert not current["all_supported"] and current["policy_action"] != "ALLOW"
            assert any(any("Source change" in reason for reason in item["reasons"]) for item in current["properties"])
            source = request("GET", f"/connectors/{installed['id']}")
            assert source["health"]["status"] == "IMPORTED" and source["health"]["connected"] is False
            save("source/changed-current-assurance", current)
            save("source/change-history", request("GET", f"/connectors/{installed['id']}/history"))
            step("noncode_permission_change", acquisition="IMPORTED", live_connected=False,
                previous_support_affected=True, resulting_policy=current["policy_action"])

            regressed, failed_decision = assessment("regressed-committed-effect", "regressed")
            assert regressed["security"] == "FAIL" and regressed["action"] == "BLOCK"
            bad, _ = assessment("bad-fix-useful-task-failed", "bad_fix")
            assert (bad["security"], bad["legitimate_task"], bad["action"]) == ("PASS", "FAILURE", "BLOCK")
            restored, restored_decision = assessment("proper-fix", "fixed")
            assert (restored["security"], restored["legitimate_task"], restored["action"]) == ("PASS", "SUCCESS", "ALLOW")
            final_ack = activate("proper-fix", restored_decision)
            assert final_ack["applied_epoch"] == 2
            journey = request("GET", f"/change-assurance/systems/{setup['system_id']}")
            assert journey["environments"][0]["stage"] == "PROTECTED"
            save("final-journey", journey)
            failed_before = request("GET", f"/change-assurance/decisions/{failed_decision['id']}")
            downgrade = request("POST", "/commercial/subscription", {"action": "downgrade", "plan": "free",
                "idempotency_key": str(uuid4())})
            assert downgrade["subscription"]["scheduled_change"]["plan"] == "free"
            failed_after = request("GET", f"/change-assurance/decisions/{failed_decision['id']}")
            assert failed_before["envelope"] == failed_after["envelope"] and failed_after["security"] == "FAIL"
            save("commercial/downgrade-scheduled", downgrade)
            step("downgrade_scheduled", effective_at=downgrade["subscription"]["scheduled_change"]["effective_at"],
                historical_fail_unchanged=True, existing_systems_preserved=True)
            summary.update(completed=True, signed_records_independently_verified=8,
                final_authorization_id=restored_decision["id"], final_sandbox_epoch=2,
                local_elapsed_seconds=round(time.monotonic()-started, 3))
            save("summary", summary)
            return summary
    except Exception as error:
        summary.update(completed=False, error_type=type(error).__name__,
            local_elapsed_seconds=round(time.monotonic()-started, 3))
        save("summary", summary)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", default="http://127.0.0.1:8100")
    parser.add_argument("--origin", default="http://127.0.0.1:3000")
    parser.add_argument("--trusted-public-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(".local/category-foundation/demo"))
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(run_demo(args.api_url, args.origin, args.trusted_public_key, args.output), indent=2))
