#!/usr/bin/env python
"""Latency of the hot paths this wave added, against real PostgreSQL.

Measured in-process through the ASGI test client, so the numbers are server work: routing,
row security, projection and serialisation, without network or browser time. They are a
regression signal on one developer machine, not a capacity model for a deployment.

    uv run python scripts/performance_check.py [--repeat 15] [--output .local/performance.json]
"""

import argparse
import json
import statistics
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests" / "integration"))

ORIGIN = "http://127.0.0.1:3000"


def client():
    from fastapi.testclient import TestClient

    from threatveil.api import app
    from threatveil.config import settings

    settings.cache_clear()
    # A loopback peer, so the local identity route applies exactly as it does for a developer.
    value = TestClient(app, client=("127.0.0.1", 50000))
    login = value.post("/v1/auth/local", json={"email": f"{uuid.uuid4()}@local.invalid",
                                               "name": "Performance", "organization_name": "Performance check"},
                       headers={"origin": ORIGIN})
    assert login.status_code == 200, login.text
    value.headers.update({"origin": ORIGIN, "x-csrf-token": login.json()["csrf_token"]})
    return value


def timed(label, call, repeat):
    samples = []
    for _ in range(repeat):
        started = time.perf_counter()
        response = call()
        samples.append((time.perf_counter() - started) * 1000)
        status = getattr(response, "status_code", 200)
        assert status < 400, f"{label} returned {status}: {getattr(response, 'text', '')[:200]}"
    samples.sort()
    return {"path": label, "samples": repeat,
            "p50_ms": round(statistics.median(samples), 1),
            "p95_ms": round(samples[min(len(samples) - 1, int(len(samples) * 0.95))], 1),
            "max_ms": round(samples[-1], 1)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeat", type=int, default=15)
    parser.add_argument("--output", type=Path, default=None)
    arguments = parser.parse_args()

    import os

    os.environ["TV_LOCAL_AUTH"] = "true"
    from threatveil import commercial

    commercial.can_use_connector_role = lambda *_: True  # connector entitlement is tested elsewhere
    customer = client()

    # The synthetic demonstration gives a cleared system with claims, evidence and a change.
    setup = customer.post("/v1/change-assurance/finance/setup",
                          json={"owner": "Performance owner", "confirm_synthetic_scope": True})
    assert setup.status_code == 201, setup.text
    setup = setup.json()
    system = setup["system_id"]
    for version in ("fixed",):
        assessed = customer.post("/v1/change-assurance/finance/assess",
                                 json={"system_id": system, "version": version,
                                       "idempotency_key": str(uuid.uuid4())})
        assert assessed.status_code == 201, assessed.text
    changed = customer.post("/v1/change-assurance/finance/simulate-change",
                            json={"system_id": system, "change": "beneficiary_approval_relaxed",
                                  "idempotency_key": str(uuid.uuid4())})
    assert changed.status_code == 201, changed.text
    views = customer.get(f"/v1/systems/{system}/changes").json()["items"]
    consequence = next(v["id"] for v in views if v["kind"] == "SOURCE_CHANGE" and not v["initial"])
    installation = setup["gateway_installation_id"]
    from threatveil.change_assurance_api import GATEWAY_BASELINE, gateway_payload

    results = [
        timed("GET /v1/home (the attention queue)",
              lambda: customer.get("/v1/home"), arguments.repeat),
        timed("GET /v1/systems/{id}/intelligence (system workspace snapshot)",
              lambda: customer.get(f"/v1/systems/{system}/intelligence"), arguments.repeat),
        timed("GET /v1/systems/{id}/assurance/current (gate)",
              lambda: customer.get(f"/v1/systems/{system}/assurance/current"), arguments.repeat),
        timed("GET /v1/systems/{id}/guidance",
              lambda: customer.get(f"/v1/systems/{system}/guidance"), arguments.repeat),
        timed("GET /v1/systems/{id}/claims (verification ladder)",
              lambda: customer.get(f"/v1/systems/{system}/claims"), arguments.repeat),
        timed("GET /v1/systems/{id}/changes (consequences)",
              lambda: customer.get(f"/v1/systems/{system}/changes"), arguments.repeat),
        timed("GET /v1/systems/{id}/consequence-feedback",
              lambda: customer.get(f"/v1/systems/{system}/consequence-feedback"), arguments.repeat),
        timed("GET /v1/systems/{id}/mappings-overview",
              lambda: customer.get(f"/v1/systems/{system}/mappings-overview"), arguments.repeat),
        timed("GET /v1/systems/{id}/mapping-suggestions",
              lambda: customer.get(f"/v1/systems/{system}/mapping-suggestions",
                                   params={"installation_id": installation}), arguments.repeat),
        timed("GET /v1/measurements/business (provenance, precision, RPS)",
              lambda: customer.get("/v1/measurements/business"), arguments.repeat),
        timed("GET /v1/measurements/activation",
              lambda: customer.get("/v1/measurements/activation"), arguments.repeat),
        timed("GET /v1/measurements/ai-usage",
              lambda: customer.get("/v1/measurements/ai-usage"), arguments.repeat),
        timed("GET /v1/example-gallery",
              lambda: customer.get("/v1/example-gallery"), arguments.repeat),
        timed("GET /v1/claim-templates",
              lambda: customer.get("/v1/claim-templates"), arguments.repeat),
        timed("POST /v1/systems/{id}/proposed-changes (dry run)",
              lambda: customer.post(f"/v1/systems/{system}/proposed-changes", json={
                  "installation_id": installation, "payload": gateway_payload(GATEWAY_BASELINE),
                  "idempotency_key": str(uuid.uuid4())}), arguments.repeat),
        timed("POST /v1/systems/{id}/consequences/{id}/feedback",
              lambda: customer.post(f"/v1/systems/{system}/consequences/{consequence}/feedback", json={
                  "verdict": "CORRECT", "idempotency_key": str(uuid.uuid4())}), arguments.repeat),
    ]
    report = {"schema_version": "performance-check/v1", "repeat": arguments.repeat,
              "environment": "local developer machine, in-process ASGI, real PostgreSQL",
              "fixture": "finance-v1 synthetic demonstration: 3 claims, 1 source, 1 change, 1 decision",
              "results": results,
              "limitations": [
                  "One tenant with a small record set. Latency grows with history; large-tenant "
                  "targets are not validated.",
                  "In-process measurement excludes network, TLS and browser rendering.",
                  "Measured on a developer machine with a local database, not deployed hardware.",
              ]}
    print(json.dumps(report, indent=2))
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(json.dumps(report, indent=2) + "\n")
    slow = [item for item in results if item["p95_ms"] > 1500]
    if slow:
        print("SLOW PATHS:", [item["path"] for item in slow], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
