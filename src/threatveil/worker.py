"""Cloud worker: no database/storage/Secret Manager clients or credentials."""

import base64
import hashlib
import json
import os
import secrets
import time

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def service_token(audience):
    if os.environ.get("TV_ENV", "production") in {"local", "test"}:
        from pathlib import Path

        identity = os.environ.get("TV_WORKER_IDENTITY", "local-worker")
        return (
            (
                Path(".local/service-identities")
                / (hashlib.sha256(identity.encode()).hexdigest() + ".token")
            )
            .read_text()
            .strip()
        )
    from google.auth.transport.requests import Request
    from google.oauth2.id_token import fetch_id_token

    return fetch_id_token(Request(), audience)


def main():
    run_id = os.environ["TV_RUN_ID"]
    bootstrap = os.environ.pop("TV_BOOTSTRAP_TOKEN")
    url = os.environ["TV_BROKER_URL"].rstrip("/")
    audience = os.environ.get("TV_BROKER_AUDIENCE", "threatveil-broker")
    if os.environ.get("TV_ENV", "production") not in {"local", "test"} and not url.startswith(
        "https://"
    ):
        raise RuntimeError("Cloud broker requires HTTPS")
    private = Ed25519PrivateKey.generate()
    public = base64.b64encode(
        private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    nonce = secrets.token_urlsafe(24)
    claim = {"run_id": run_id, "bootstrap_token": bootstrap, "worker_key": public, "nonce": nonce}
    msg = f"{run_id}\n{hashlib.sha256(bootstrap.encode()).hexdigest()}\n{nonce}".encode()
    claim["signature"] = base64.b64encode(private.sign(msg)).decode()
    with httpx.Client(base_url=url, timeout=30, trust_env=False, follow_redirects=False) as client:

        def call(path, body):
            r = client.post(
                path, json=body, headers={"Authorization": "Bearer " + service_token(audience)}
            )
            r.raise_for_status()
            return r.json()

        lease = call("/v1/claim", claim)
        del claim, bootstrap

        def scoped(action, payload=None):
            body = {
                "lease_id": lease["lease_id"],
                "fence": lease["fence"],
                "nonce": secrets.token_urlsafe(24),
                "timestamp": int(time.time()),
                "payload": payload or {},
            }
            h = hashlib.sha256(
                json.dumps(body["payload"], sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            msg = f"{body['lease_id']}\n{body['fence']}\n{action}\n{body['nonce']}\n{body['timestamp']}\n{h}".encode()
            body["signature"] = base64.b64encode(private.sign(msg)).decode()
            return call("/v1/" + action, body)

        specification = scoped("spec")
        plan, target = specification["spec"], specification["target"]
        try:
            if target["adapter"] == "synthetic_procurement":
                from .core import run_procurement
                from .core.finance import run_finance

                execute_fixture = run_finance if target.get("fixture_profile") == "finance-v1" else run_procurement
                result = execute_fixture(
                    plan["version"],
                    plan["property_definition"],
                    plan["trials"],
                    plan["variant_count"],
                    execution_id=run_id,
                )
                scoped("complete", {"result": result})
            else:
                import asyncio
                from .execution import acquire

                headers = {}
                refs = target.get("credential_reference_ids", [])
                if refs:
                    headers["Authorization"] = (
                        "Bearer "
                        + scoped("credential", {"credential_reference_id": refs[0]})["value"]
                    )
                asyncio.run(
                    acquire(
                        target,
                        plan,
                        run_id,
                        headers,
                        before_trial=lambda: scoped("renew"),
                        after_trial=lambda item: scoped("observe", item),
                        retain=False,
                    )
                )
                scoped("complete", {})
        except Exception:
            # Report only a non-passing terminal state; never return exception details/secrets.
            scoped("fail", {})
            raise RuntimeError("Worker execution failed; inspect the scoped run record") from None
    print(json.dumps({"run_id": run_id, "status": "completed"}))


if __name__ == "__main__":
    main()
