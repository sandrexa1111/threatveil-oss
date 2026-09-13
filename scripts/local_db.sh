#!/usr/bin/env bash
# Project-owned PostgreSQL. Never registers or changes a global service.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 - "$SCRIPT_DIR/.." "${1:-status}" <<'PY'
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
action = sys.argv[2]
if action not in {"start", "stop", "status"}:
    raise SystemExit("Usage: scripts/local_db.sh start|stop|status")
state = root / ".local"
data = state / "pgdata"
candidates = [os.environ.get("TV_PG_BIN", ""), "/opt/homebrew/opt/postgresql@17/bin", "/usr/local/opt/postgresql@17/bin"]
pg_ctl = next((Path(p) / "pg_ctl" for p in candidates if p and (Path(p) / "pg_ctl").is_file()), None)
if pg_ctl is None and shutil.which("pg_ctl"):
    pg_ctl = Path(shutil.which("pg_ctl"))
if pg_ctl is None:
    raise SystemExit("PostgreSQL 17 not found. Install it, or set TV_PG_BIN to its bin directory.")
bindir = pg_ctl.parent

def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)

def running():
    return data.exists() and subprocess.run([str(pg_ctl), "-D", str(data), "status"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

if action == "status":
    print("ThreatVeil PostgreSQL: " + ("running at 127.0.0.1:55432" if running() else "stopped"))
    raise SystemExit(0 if running() else 1)
if action == "stop":
    if running():
        run([pg_ctl, "-D", data, "-m", "fast", "-w", "stop"], stdout=subprocess.DEVNULL)
    print("ThreatVeil PostgreSQL stopped; project data preserved.")
    raise SystemExit(0)

os.umask(0o077)
state.mkdir(mode=0o700, exist_ok=True)
secret_file = state / "database-secrets.json"
if secret_file.exists():
    passwords = json.loads(secret_file.read_text())
else:
    passwords = {name: secrets.token_hex(32) for name in ("cluster", "admin", "app")}
    secret_file.write_text(json.dumps(passwords))
secret_file.chmod(0o600)
bootstrap_pw = state / "pg-superuser-password"
bootstrap_pw.write_text(passwords["cluster"] + "\n")
bootstrap_pw.chmod(0o600)
if not (data / "PG_VERSION").exists():
    run([bindir / "initdb", "-D", data, "--username=threatveil_cluster", f"--pwfile={bootstrap_pw}", "--auth-local=scram-sha-256", "--auth-host=scram-sha-256", "--encoding=UTF8", "--locale=C"], stdout=subprocess.DEVNULL)
    with (data / "postgresql.conf").open("a") as config:
        config.write("\n# ThreatVeil project-local overrides\nlisten_addresses = '127.0.0.1'\nport = 55432\nunix_socket_directories = ''\npassword_encryption = 'scram-sha-256'\n")
if not running():
    run([pg_ctl, "-D", data, "-l", state / "postgresql.log", "-w", "start"], stdout=subprocess.DEVNULL)
pg_env = dict(os.environ, PGHOST="127.0.0.1", PGPORT="55432", PGUSER="threatveil_cluster", PGPASSWORD=passwords["cluster"], PGDATABASE="postgres")
psql = [bindir / "psql", "-X", "-v", "ON_ERROR_STOP=1", "--no-psqlrc", "--quiet"]
# Only generated hexadecimal passwords enter SQL, through stdin, never argv/logs.
sql = """
SELECT 'CREATE ROLE threatveil_admin LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='threatveil_admin')\gexec
SELECT 'CREATE ROLE threatveil_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='threatveil_app')\gexec
ALTER ROLE threatveil_admin NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '%s';
ALTER ROLE threatveil_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '%s';
SELECT 'CREATE DATABASE threatveil OWNER threatveil_admin'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='threatveil')\gexec
REVOKE ALL ON DATABASE threatveil FROM PUBLIC;
GRANT CONNECT ON DATABASE threatveil TO threatveil_admin, threatveil_app;
\\connect threatveil
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO threatveil_admin;
GRANT USAGE ON SCHEMA public TO threatveil_app;
ALTER DEFAULT PRIVILEGES FOR ROLE threatveil_admin IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO threatveil_app;
ALTER DEFAULT PRIVILEGES FOR ROLE threatveil_admin IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO threatveil_app;
""" % (passwords["admin"], passwords["app"])
run(psql, input=sql, text=True, env=pg_env, stdout=subprocess.DEVNULL)
config = state / "database.env"
config.write_text(
    "# Generated local credentials. Never commit or print this file.\n"
    f"TV_DATABASE_URL=postgresql+psycopg://threatveil_app:{passwords['app']}@127.0.0.1:55432/threatveil\n"
    f"TV_ADMIN_DATABASE_URL=postgresql+psycopg://threatveil_admin:{passwords['admin']}@127.0.0.1:55432/threatveil\n"
)
config.chmod(0o600)
print("ThreatVeil PostgreSQL running at 127.0.0.1:55432; credentials saved to .local/database.env (0600).")
print("Runtime role: threatveil_app (non-owner, NOSUPERUSER, NOBYPASSRLS); migration role: threatveil_admin.")
PY
