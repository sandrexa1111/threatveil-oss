"""Exercise the actual Next relay handler over HTTP against the actual FastAPI app.

Runs isolated loopback ports with a fresh synthetic HMAC secret. The minimal Next
host copies the current production relay source, so an existing dev UI can stay up.
No GitHub provider request, customer message or cloud resource is created.
"""

import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import httpx


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    root = Path(__file__).resolve().parents[1]
    output = root / ".local/p0-acceptance"
    output.mkdir(parents=True, exist_ok=True)
    api_port, web_port = free_port(), free_port()
    node = shutil.which("node")
    if not node:
        raise RuntimeError("Node.js is required for actual Next relay acceptance")
    env = os.environ.copy()
    secret = os.urandom(32).hex()
    env.update(TV_ENV="local", TV_LOCAL_AUTH="false", TV_GITHUB_WEBHOOK_SECRET=secret,
        TV_API_URL=f"http://127.0.0.1:{api_port}", NODE_ENV="development")
    env.pop("TV_API_AUDIENCE", None)
    processes = []
    with tempfile.TemporaryDirectory(prefix="relay-", dir=output) as temporary:
        web = Path(temporary)
        route = web / "app/api/backend/[...path]/route.ts"
        route.parent.mkdir(parents=True)
        shutil.copyfile(root / "apps/web/src/app/api/backend/[...path]/route.ts", route)
        (web / "package.json").write_text('{"name":"relay-acceptance","private":true}')
        (web / "node_modules").symlink_to(root / "apps/web/node_modules", target_is_directory=True)
        with (output / "api.log").open("w") as api_log, (output / "web.log").open("w") as web_log:
            try:
                processes.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "threatveil.api:app",  # noqa: S603 - fixed local executable and arguments
                    "--host", "127.0.0.1", "--port", str(api_port), "--no-access-log"],
                    cwd=root, env=env, stdout=api_log, stderr=api_log))
                processes.append(subprocess.Popen([node, str(root / "apps/web/node_modules/next/dist/bin/next"),  # noqa: S603 - resolved local runtime, fixed script
                    "dev", "--webpack", "--hostname", "127.0.0.1", "--port", str(web_port)],
                    cwd=web, env=env, stdout=web_log, stderr=web_log))
                with httpx.Client(timeout=30, trust_env=False) as client:
                    for port, path in [(api_port, "/healthz"), (web_port, "/api/backend/v1/health")]:
                        for _ in range(100):
                            try:
                                client.get(f"http://127.0.0.1:{port}{path}")
                                break
                            except httpx.HTTPError:
                                time.sleep(0.1)
                        else:
                            raise RuntimeError("Isolated relay acceptance service did not start")
                    body = b'{ "zen" : "synthetic relay acceptance", "unicode": "\\u20ac" }\n'
                    headers = {"content-type": "application/json", "x-github-event": "ping",
                        "x-github-delivery": "p0-local-synthetic",
                        "x-hub-signature-256": "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()}
                    base = f"http://127.0.0.1:{web_port}/api/backend/v1/webhooks/github"
                    direct = client.post(f"http://127.0.0.1:{api_port}/v1/webhooks/github", content=body, headers=headers)
                    relay = client.post(base, content=body, headers=headers)
                    tampered = client.post(base, content=body + b" ", headers=headers)
                    missing = client.post(base, content=body, headers={"content-type": "application/json"})
                    result = {"profile": "local-real-http-next-fastapi", "handler_sha256": hashlib.sha256(route.read_bytes()).hexdigest(),
                        "direct_status": direct.status_code, "relay_status": relay.status_code,
                        "same_response": direct.json() == relay.json(), "tampered_status": tampered.status_code,
                        "missing_signature_status": missing.status_code, "cloud_accepted": False}
                    (output / "github-relay.json").write_text(json.dumps(result, indent=2) + "\n")
                    print(json.dumps(result, indent=2))
                    assert direct.status_code == relay.status_code == 202 and result["same_response"]
                    assert tampered.status_code == missing.status_code == 401
            finally:
                for process in processes:
                    process.terminate()
                for process in processes:
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


if __name__ == "__main__":
    main()
