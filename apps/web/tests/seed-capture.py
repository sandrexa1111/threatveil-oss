"""Persist a signed sink fixture using simulated transport for browser evidence QA."""

import json
import os
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[3]
local_config = root / ".local/database.env"
if not local_config.exists():
    raise RuntimeError("Capture browser fixture requires the provisioned local database")
for line in local_config.read_text().splitlines():
    if line.startswith("TV_DATABASE_URL="):
        os.environ["TV_DATABASE_URL"] = line.split("=", 1)[1].strip("\"'")
os.chdir(root)
sys.path.insert(0, str(root / "tests/integration"))

import pytest  # noqa: E402
from test_observers import observer_customer, qualify, execute  # noqa: E402

with pytest.MonkeyPatch.context() as patch:
    generator = observer_customer.__wrapped__(patch)
    fixture = next(generator)
    try:
        source = qualify(fixture)
        result = execute(fixture, source, "vulnerable", candidate="candidate-v0")
        assert result["security_verdict"] == "FAIL" and result["trials"][0]["capture_id"]
        fixed = execute(fixture, source, "fixed", candidate="candidate-v1")
        fix = fixture[0].post("/v1/fixes", json={"run_id": result["id"], "verification_run_id": fixed["id"], "description": "Browser fixture: qualify the independently signed beneficiary boundary fix."}).json()
        assert fix["verified"] and fix["baseline_id"]
        candidate = execute(fixture, source, "fixed", candidate="candidate-v1")
        impact = fixture[0].post("/v1/impact", json={"system_id": candidate["system_id"], "previous": candidate["fingerprint"], "candidate": candidate["fingerprint"]}).json()
        email = fixture[0].get("/v1/auth/me").json()["user"]["email"]
        print("BROWSER_FIXTURE:" + json.dumps({"email": email, "run_id": result["id"], "baseline_id": fix["baseline_id"], "candidate_run_id": candidate["id"], "candidate": candidate["candidate"], "impact_id": impact["id"]}))
    finally:
        generator.close()
