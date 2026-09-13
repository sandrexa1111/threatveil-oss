"""Run the canonical synthetic demonstration inside the local Docker Compose stack.

    docker compose --profile demo run --rm demo [--stop-at cleared]

The container shares the API's network namespace, so it reaches the API over loopback
exactly as the local web relay does. The trusted public key is derived from the local
demonstration signing key on the shared state volume, never from an API response.
Only the labelled synthetic Finance Agent sandbox is operated.
"""

import argparse
import json
import os
import time
from pathlib import Path
from tempfile import mkdtemp

import httpx
from cryptography.hazmat.primitives import serialization

from canonical_demo import STAGES, run

API_URL = "http://127.0.0.1:8000"
SIGNING_KEY = Path("/app/.local/receipt-signing/key.pem")


def trusted_public_key(directory):
    # The first read of the published trust keys creates the local demonstration key.
    httpx.get(API_URL + "/v1/trust/keys", timeout=30, trust_env=False).raise_for_status()
    for _ in range(30):
        if SIGNING_KEY.exists():
            break
        time.sleep(1)
    private = serialization.load_pem_private_key(SIGNING_KEY.read_bytes(), None)
    path = directory / "trusted-public-key.pem"
    path.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--stop-at", choices=STAGES, default="complete")
    args = parser.parse_args()
    origin = os.environ.get("TV_WEB_ORIGIN", "http://127.0.0.1:3000")
    work = Path(mkdtemp(prefix="threatveil-demo-"))
    result = run(API_URL, origin, trusted_public_key(work), work / "canonical-demo", args.stop_at)
    print(json.dumps({key: result[key] for key in ("completed", "stop_at", "login_email", "steps")}, indent=2))
    print("\nSYNTHETIC DEMONSTRATION: labelled Finance Agent sandbox, no customer system or money.")
    if args.stop_at != "complete":
        print(f"Open {origin}/login and sign in locally with {result['login_email']} to continue live.")


if __name__ == "__main__":
    main()
