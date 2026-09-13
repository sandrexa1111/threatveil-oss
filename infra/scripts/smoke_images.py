"""Exercise published-runtime entrypoints in isolated, credential-free containers."""

import argparse
import json
import re
import shutil
import subprocess
import time


def main():
    def reference(value):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@-]*", value):
            raise argparse.ArgumentTypeError("Expected an image reference without options or whitespace")
        return value

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python-image", required=True, type=reference)
    parser.add_argument("--web-image", required=True, type=reference)
    args = parser.parse_args()
    docker = shutil.which("docker")
    if not docker:
        parser.error("Docker CLI is required")

    def command(*arguments, check=True):
        # Fixed CLI, separate argv, no shell or host mounts; image references are operator inputs.
        # nosemgrep: local.semgrep-rules.python.lang.security.audit.dangerous-subprocess-use-audit
        return subprocess.run(  # noqa: S603
            [docker, *arguments], check=check, capture_output=True, text=True, timeout=45
        )

    for image, expected_user in [(args.python_image, "10001:10001"), (args.web_image, "65532:65532")]:
        config = json.loads(command("image", "inspect", image).stdout)[0]
        if config["Config"]["User"] != expected_user:
            raise SystemExit(f"Unexpected runtime user for {image}")

    imports = (
        "import os,sys,shutil,sqlite3,numpy,grpc,psycopg,cryptography; "
        "import threatveil.api,threatveil.broker,threatveil.launcher,threatveil.worker; "
        "assert sys.version_info[:2]==(3,13); assert os.getuid()==10001; "
        "assert sqlite3.sqlite_version_info >= (3,53,2); "
        "assert all(shutil.which(p) is None for p in ('pip','uv','sh','bash')); "
        "print('Python native dependencies and service imports passed')"
    )
    print(command("run", "--rm", "--network", "none", "--entrypoint", "python",
                  "-e", "TV_ENV=test", args.python_image, "-c", imports).stdout.strip())

    probes = [
        # SQL role verification is tested against real PostgreSQL in the Python CI job.
        # This networkless ABI/HTTP probe deliberately skips only that startup hook.
        (args.python_image, ["uvicorn", "threatveil.api:app", "--host", "127.0.0.1", "--port", "8080", "--lifespan", "off"], ["python", "-c", "import json,urllib.request; assert json.load(urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=2))['ok'] is True"]),
        (args.web_image, [], ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:8080/login').then(r=>{if(r.status!==200)process.exit(1)}).catch(()=>process.exit(1))"]),
    ]
    for image, start, probe in probes:
        container = command("run", "--detach", "--network", "none", "-e", "TV_ENV=test", image, *start).stdout.strip()
        try:
            ready = False
            for _ in range(30):
                if command("exec", container, *probe, check=False).returncode == 0:
                    ready = True
                    break
                time.sleep(1)
            if not ready:
                logs = command("logs", container, check=False)
                print(logs.stdout, logs.stderr)
                raise SystemExit(f"Runtime health probe failed for {image}")
            print(f"Runtime HTTP compatibility passed (no database or cloud services): {image}")
        finally:
            command("rm", "--force", container, check=False)


if __name__ == "__main__":
    main()
