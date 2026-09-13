"""The canonical five-minute ThreatVeil demonstration, driven through the real local HTTP API.

Every run provisions a fresh local organization, so the demonstration is resettable
without deleting any history and without a fixture backdoor: local sign-in is
refused by configuration outside local/test. Only the labelled synthetic Finance
Agent sandbox is operated. No external system, provider, customer or money is touched.

    uv run python scripts/canonical_demo.py --trusted-public-key <pem> [--stop-at cleared]

`--stop-at cleared` leaves a fresh workspace at a current clearance and prints the
email to use at /login, so a founder can perform the change live in the product.
"""

import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from threatveil.sdk.change_records import verify_change_record
from threatveil.sdk.client import ThreatVeilClient
from threatveil.sdk.passports import verify_passport, verify_passport_with_directory
from threatveil.sdk.trust_directory import load_directory

STAGES = ("cleared", "changed", "reestablished", "complete")


def run(api_url, origin, public_key_path, output, stop_at="complete"):
    parsed = urlsplit(api_url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("The demonstration requires an explicit loopback HTTP API")
    public_bytes = public_key_path.read_bytes()
    public = serialization.load_pem_public_key(public_bytes)
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError("An independently configured Ed25519 public key is required")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    email = f"canonical-demo-{uuid4()}@local.invalid"
    summary = {"profile": "threatveil.canonical-demo.v1", "completed": False, "stop_at": stop_at,
               "login_email": email, "steps": [], "timings_ms": {},
               "limitations": ["Labelled synthetic Finance Agent sandbox only; no customer system or money.",
                               "The tool gateway is an IMPORTED synthetic MCP source, not a live connection.",
                               "Elapsed times measure this prepared local fixture, not customer onboarding."]}

    def save(name, data):
        path = output / f"{name}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")

    def step(name, **details):
        summary["steps"].append({"step": name, **details})
        save("summary", summary)

    with httpx.Client(base_url=api_url.rstrip("/"), timeout=90, trust_env=False) as http:
        def call(method, path, body=None, *, expect=None, client=None, label=None):
            started = time.perf_counter()
            response = (client or http).request(method, "/v1" + path, json=body)
            if label:
                summary["timings_ms"].setdefault(label, []).append(round((time.perf_counter() - started) * 1000, 1))
            if expect and response.status_code != expect:
                raise RuntimeError(f"{method} {path} returned {response.status_code}: {response.text[:300]}")
            response.raise_for_status()
            return response.json()

        login = http.post("/v1/auth/local", json={"email": email, "name": "Founder",
                                                  "organization_name": "Canonical demonstration"}, headers={"origin": origin})
        login.raise_for_status()
        http.headers.update({"origin": origin, "x-csrf-token": login.json()["csrf_token"]})
        organization = call("GET", "/auth/me")["organization"]["id"]
        setup = call("POST", "/change-assurance/finance/setup", {"owner": "Finance security owner",
                                                                  "confirm_synthetic_scope": True})
        system = setup["system_id"]
        base = f"/systems/{system}"

        def assess(version):
            body = {"system_id": system, "version": version, "idempotency_key": str(uuid4())}
            result = call("POST", "/change-assurance/finance/assess", body, label="assessment")
            while result.get("status") == "RUNNING":
                time.sleep(0.5)
                result = call("POST", "/change-assurance/finance/assess", body, label="assessment")
            return result

        def change(name):
            return call("POST", "/change-assurance/finance/simulate-change",
                        {"system_id": system, "change": name, "idempotency_key": str(uuid4())})

        def gate():
            return call("GET", base + "/assurance/current", label="assurance_gate")

        baseline = assess("fixed")
        assert baseline["action"] == "ALLOW", baseline
        intelligence = call("GET", base + "/intelligence", label="intelligence")
        assert intelligence["summary"]["clearance"]["state"] == "CLEARED"
        for path, label in (("/system-map", "system_map"), ("/authority", "authority_map"),
                            ("/authority/changes", "authority_diff"), ("/history", "history")):
            call("GET", base + path, label=label)
        answer = gate()
        assert (answer["status"], answer["cleared"], answer["authorizes"]) == ("CURRENT", True, False)
        save("1-current/intelligence", intelligence)
        save("1-current/gate", answer)
        step("1_current", clearance="CLEARED", claims_supported=intelligence["summary"]["claims"]["supported"],
             powers=[p["label"] for p in intelligence["summary"]["powers"]])
        if stop_at == "cleared":
            summary.update(completed=True)
            save("summary", summary)
            return summary

        change("beneficiary_approval_relaxed")
        diff = call("GET", base + "/authority/changes", label="authority_diff")["items"][0]
        assert diff["classification"] == "AUTHORITY_EXPANDED", diff
        consequence = diff["consequence"]
        assert consequence["claims_affected"] == 1 and consequence["still_holds"] == 2
        assert consequence["previous_clearance"]["status"] == "SUPERSEDED"
        prior = call("GET", f"/change-assurance/decisions/{baseline['authorization_id']}")
        verify_change_record(prior["envelope"], public, organization_id=organization, system_id=system,
                             environment_id=setup["environment_id"], state_digest=prior["state_digest"],
                             audience=prior["audience"])
        answer = gate()
        assert (answer["status"], answer["cleared"]) == ("SUPERSEDED", False)
        save("2-change/authority-diff", diff)
        save("3-consequence/gate", answer)
        step("2_change_outside_code", source=diff["origin"]["name"], acquisition=diff["origin"]["acquisition"],
             subjects=diff["subjects"])
        step("3_consequence", classification=diff["classification"], claims_affected=consequence["claims_affected"],
             evidence_stale=consequence["evidence_stale"], still_holds=consequence["still_holds"],
             previous_clearance=consequence["previous_clearance"]["status"],
             prior_record_still_authentic=True, explanation=diff["explanation"])
        if stop_at == "changed":
            summary.update(completed=True)
            save("summary", summary)
            return summary

        security_failed = assess("regressed")
        assert (security_failed["security"], security_failed["action"]) == ("FAIL", "BLOCK")
        useful_failed = assess("bad_fix")
        assert (useful_failed["security"], useful_failed["legitimate_task"], useful_failed["action"]) == ("PASS", "FAILURE", "BLOCK")
        change("gateway_restored")
        restored = assess("fixed")
        assert restored["action"] == "ALLOW"
        plan = call("GET", base + "/reestablishment")
        assert plan["latest_outcome"]["case"] == "RESTORED"
        step("4_reestablish", case_a="SECURITY_FAIL -> NOT CLEARED", case_b="PASS + USEFUL TASK FAILURE -> NOT CLEARED",
             case_c="PASS + SUCCESS -> CLEARANCE RESTORED")
        if stop_at == "reestablished":
            summary.update(completed=True)
            save("summary", summary)
            return summary

        answer = gate()
        assert (answer["status"], answer["action"], answer["cleared"]) == ("CURRENT", "ALLOW", True)
        assert ThreatVeilClient.is_cleared(answer)
        save("5-machine/gate", answer)
        step("5_machine", status=answer["status"], cleared=answer["cleared"], valid_until=answer["freshness"]["valid_until"])

        started = time.perf_counter()
        passport = call("POST", base + "/passports", {"audience": "Acme vendor security review"}, expect=201)
        summary["timings_ms"].setdefault("passport_issue", []).append(round((time.perf_counter() - started) * 1000, 1))
        share = call("POST", f"/passports/{passport['id']}/share", {"label": "Acme vendor security review", "confirm_disclosure": True}, expect=201)
        with httpx.Client(base_url=api_url.rstrip("/"), timeout=30, trust_env=False) as outsider:
            before = call("GET", f"/public/passports/{share['token']}", client=outsider, label="passport_public_status")
            directory = load_directory(outsider.get("/v1/trust/keys").json())
            verify_passport_with_directory(before["envelope"], directory, passport_id=passport["id"])
            # A STANDARD passport withholds internal identifiers, so an outside party verifies
            # against the stable pseudonymous system reference instead.
            reference = before["passport"]["system"]["reference"]
            verify_passport(before["envelope"], public, passport_id=passport["id"],
                            system_reference=reference)
            assert system not in json.dumps(before["passport"])
            assert before["current_status"]["status"] == "CURRENT"
            change("beneficiary_approval_relaxed")
            after = call("GET", f"/public/passports/{share['token']}", client=outsider, label="passport_public_status")
            verify_passport(after["envelope"], public, passport_id=passport["id"],
                            system_reference=reference)
            assert after["envelope"] == before["envelope"] and after["current_status"]["status"] == "SUPERSEDED"
        save("6-external/passport", passport["passport"])
        save("6-external/passport.dsse", passport["envelope"])
        save("6-external/status-before", before["current_status"])
        save("6-external/status-after", after["current_status"])
        step("6_external_party", verified_with_trust_directory=True, verified_with_independent_key=True,
             status_before=before["current_status"]["status"], status_after=after["current_status"]["status"],
             authentic_after_change=True)
        activation = call("GET", "/measurements/activation")
        save("activation", activation)
        assert activation["synthetic"]["milestones"]["FIRST_MEANINGFUL_ASSURANCE_EVENT"]["reached"]
        assert not activation["customer"]["activated"]
        summary.update(completed=True, organization_id=organization, system_id=system,
                       finished_at=datetime.now(timezone.utc).isoformat(),
                       timing_summary_ms={k: {"median": sorted(v)[len(v) // 2], "max": max(v), "samples": len(v)}
                                          for k, v in summary["timings_ms"].items()})
        save("summary", summary)
        return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--origin", default="http://127.0.0.1:3000")
    parser.add_argument("--trusted-public-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(".local/canonical-demo") / datetime.now().strftime("%Y%m%d-%H%M%S"))
    parser.add_argument("--stop-at", choices=STAGES, default="complete")
    args = parser.parse_args()
    os.umask(0o077)
    result = run(args.api_url, args.origin, args.trusted_public_key, args.output, args.stop_at)
    print(json.dumps({key: result[key] for key in ("completed", "stop_at", "login_email", "steps")}, indent=2))
    if args.stop_at != "complete":
        print(f"\nOpen {args.origin}/login and sign in locally with {result['login_email']} to continue live.")
