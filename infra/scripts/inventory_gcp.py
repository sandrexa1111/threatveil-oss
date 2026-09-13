"""Read-only resource inventory. Requires an explicit project and existing gcloud access."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--project", required=True)
parser.add_argument("--region", required=True)
args = parser.parse_args()
if not re.fullmatch(r"[a-z][a-z0-9-]{4,61}[a-z0-9]", args.project):
    parser.error("Supply a real project ID, not a display name or shell expression.")
if not re.fullmatch(r"[a-z]+-[a-z]+[0-9]+", args.region):
    parser.error("Supply a region such as europe-west1.")
gcloud = shutil.which("gcloud")
if not gcloud:
    raise SystemExit("gcloud is unavailable; no inventory performed.")
commands = {
    "project": ["projects", "describe", args.project],
    "enabled_apis": ["services", "list", "--enabled"],
    "cloud_run_services": ["run", "services", "list", "--region", args.region],
    "cloud_run_jobs": ["run", "jobs", "list", "--region", args.region],
    "sql_instances": ["sql", "instances", "list"],
    "buckets": ["storage", "buckets", "list"],
    "secret_names": ["secrets", "list"],
    "image_repositories": ["artifacts", "repositories", "list", "--location", args.region],
    "task_queues": ["tasks", "queues", "list", "--location", args.region],
    "schedulers": ["scheduler", "jobs", "list", "--location", args.region],
    "service_accounts": ["iam", "service-accounts", "list"],
    "networks": ["compute", "networks", "list"],
    "iam": ["projects", "get-iam-policy", args.project],
}
os.umask(0o077)
directory = Path(".local/gcp-inventory") / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
directory.mkdir(parents=True, mode=0o700)
failures = []
for name, command in commands.items():
    # Fixed read-only operations and validated IDs are passed as argv, never to a shell.
    # nosemgrep: local.semgrep-rules.python.lang.security.audit.dangerous-subprocess-use-audit, local.semgrep-rules.python.lang.security.audit.dangerous-subprocess-use-tainted-env-args
    result = subprocess.run([gcloud, *command, "--project", args.project, "--format=json", "--quiet"], text=True, capture_output=True)  # noqa: S603
    if result.returncode:
        failures.append(name)
        (directory / f"{name}.error.txt").write_text(result.stderr)
        print(f"{name}: unavailable; inspect local error file")
    else:
        data = json.loads(result.stdout)
        (directory / f"{name}.json").write_text(json.dumps(data, indent=2))
        print(f"{name}: inventoried")
print(f"Read-only inventory saved to {directory}; no secret payloads requested.")
if failures:
    raise SystemExit("Inventory incomplete: " + ", ".join(failures))
