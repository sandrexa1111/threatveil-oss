"""Real local HTTP→PostgreSQL→SQLite release-integrity demonstration, with no provider mocks."""

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import time
from uuid import uuid4

import httpx

from threatveil.core.contracts import digest
from threatveil.sdk.receipts import verify_release_receipt


def execute_demo(output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    email = f"release-demo-{uuid4()}@local.invalid"
    with httpx.Client(base_url="http://127.0.0.1:8000", timeout=60, trust_env=False) as client:
        def request(method, path, payload=None):
            response = client.request(method, "/v1"+path, json=payload)
            response.raise_for_status()
            return response.json()

        started = time.monotonic()
        identity = client.post("/v1/auth/local", json={"email": email, "name":"Release demonstration",
            "organization_name":"ThreatVeil release integrity demonstration"},
            headers={"origin":"http://127.0.0.1:3000"})
        identity.raise_for_status()
        client.headers.update({"origin":"http://127.0.0.1:3000", "x-csrf-token":identity.json()["csrf_token"]})
        demo = request("POST", "/demo/setup", {})
        system, property_id, target = demo["system"]["id"], demo["property"]["id"], demo["target"]["id"]

        def run(version, plan=None):
            spec = {"system_id":system,"property_id":property_id,"target_id":target,
                "version":version,"trials":5,"variant_count":1,"idempotency_key":str(uuid4())}
            if plan:
                spec.update(candidate=plan["candidate"],fingerprint=plan["fingerprint"])
                response=request("POST",f"/proof-plans/{plan['id']}/execute",{"runs":[spec]})
                rid=response["runs"][0]["id"]
            else:
                rid=request("POST","/runs",spec)["id"]
            deadline=time.monotonic()+60
            while time.monotonic()<deadline:
                value=request("GET",f"/runs/{rid}")
                if value["status"] not in {"QUEUED","RUNNING"}:
                    return value
                time.sleep(0.1)
            raise TimeoutError("Demonstration run did not finish")

        def plan(candidate, fingerprint, previous=None):
            return request("POST","/proof-plans", {"system_id":system,"candidate":candidate,
                "fingerprint":fingerprint,"previous_fingerprint":previous})

        def release(value):
            return request("POST","/releases",{"plan_id":value["id"],"policy":{"mode":"BLOCK"}})

        first=run("fixed")
        a_plan=plan(first["candidate"],first["fingerprint"])
        a=release(a_plan)
        candidate=deepcopy(first["candidate"])
        candidate.update(version="regressed",digest=digest({"fixture":"procurement-v1","version":"regressed"}))
        fingerprint=deepcopy(first["fingerprint"])
        for component in fingerprint["components"]:
            if component["type"] in {"application","permissions"}:
                component.update(version="regressed",digest=candidate["digest"] if component["type"]=="application" else digest("regressed"))
        b_plan=plan(candidate,fingerprint,first["fingerprint"])
        assert any(item["status"]=="VOID" for item in b_plan["invalidations"])
        failed=run("regressed",b_plan)
        b=release(b_plan)
        restored=run("fixed")
        c=release(plan(restored["candidate"],restored["fingerprint"],fingerprint))
        missing=run("missing_witness")
        bad_fix=run("bad_fix")
        assert (a["release_action"],b["release_action"],c["release_action"])==("ALLOW","BLOCK","ALLOW")
        assert failed["security_verdict"]=="FAIL"
        assert missing["security_verdict"]=="INCONCLUSIVE"
        assert bad_fix["security_verdict"]=="PASS" and bad_fix["task_outcome"]=="FAILURE"
        # The configured local operator public key is trusted independently of the downloaded envelope.
        from threatveil.release_signing import signing_key
        from cryptography.hazmat.primitives import serialization

        public=signing_key().public_key()
        (output_dir/"trusted-public-key.pem").write_bytes(public.public_bytes(
            serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        for label,decision in (("release-a",a),("release-b",b),("release-c",c)):
            envelope=request("GET",f"/releases/{decision['id']}/receipt")["envelope"]
            verify_release_receipt(envelope,public,
                expected_candidate_fingerprint_digest=decision["candidate_fingerprint_digest"],
                expected_organization_id=decision["organization_id"],expected_candidate=decision["candidate"])
            (output_dir/f"{label}.dsse.json").write_text(json.dumps(envelope,indent=2)+"\n")
        summary={"scope":"Synthetic procurement with actual local HTTP, PostgreSQL and committed SQLite state",
            "email":email,"system_id":system,"organization_id":a["organization_id"],
            "local_elapsed_seconds":round(time.monotonic()-started,3),
            "releases":[a,b,c],"invalidation_plan":b_plan,
            "missing_observation":missing["security_verdict"],"bad_fix_task":bad_fix["task_outcome"],
            "receipt_verification":"All three independently verified with the operator's local public key",
            "limitations":["No external agent, real GitHub check, cloud or customer validation.",
                "Final candidate restores the previously tested fixed configuration; this is not a claim to have patched customer source code.",
                "Measured elapsed time describes this local fixture, not customer onboarding."]}
        (output_dir/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
        return {"email":email,"system_id":system,"actions":[v["release_action"] for v in (a,b,c)],
            "elapsed_seconds":summary["local_elapsed_seconds"],"artifacts":str(output_dir.absolute())}


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    os.umask(0o077)
    print(json.dumps(execute_demo(args.output),indent=2))
