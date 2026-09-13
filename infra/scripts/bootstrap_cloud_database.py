"""Initialize a newly reviewed EMPTY Cloud SQL database through an authenticated proxy.

Never rotate existing roles, print credentials, write Terraform state, or upload secrets.
The operator supplies TV_CLOUD_BOOTSTRAP_DSN in a protected environment.
"""
import argparse
import os
from pathlib import Path
import re
import secrets

import psycopg
from psycopg import sql

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--connection-name", required=True)
parser.add_argument("--initialize-empty-database", action="store_true", required=True)
args = parser.parse_args()
if not re.fullmatch(r"[a-z0-9-]+:[a-z0-9-]+:[a-z0-9-]+", args.connection_name):
    parser.error("Expected PROJECT:REGION:INSTANCE connection name.")
dsn = os.environ["TV_CLOUD_BOOTSTRAP_DSN"]
os.umask(0o077)
directory = Path(".local/cloud-database-secrets")
if directory.exists():
    raise SystemExit("Existing local secret directory found. Reconcile its previous initialization before retrying.")
passwords = {role: secrets.token_hex(32) for role in ("threatveil_admin", "threatveil_app")}
# PostgreSQL role/ownership/grant DDL participates in this single transaction.
# Save credentials before mutation so a lost COMMIT response never loses them.
with psycopg.connect(dsn, dbname="threatveil") as connection:
    connection.execute("SELECT pg_advisory_xact_lock(16653298)")
    if connection.execute("SELECT count(*) FROM pg_tables WHERE schemaname='public'").fetchone()[0]:
        raise SystemExit("Refusing to initialize a nonempty database. Inventory and reuse its roles explicitly.")
    if connection.execute("SELECT count(*) FROM pg_roles WHERE rolname IN ('threatveil_admin','threatveil_app')").fetchone()[0]:
        raise SystemExit("Existing ThreatVeil roles found. No credentials or role ownership changed.")
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    for service, role in [("api", "threatveil_app"), ("broker", "threatveil_app"), ("migration", "threatveil_admin")]:
        value = f"postgresql+psycopg://{role}:{passwords[role]}@/threatveil?host=/cloudsql/{args.connection_name}"
        target = directory / f"{service}.txt"
        with target.open("x", encoding="utf-8") as secret_file:
            secret_file.write(value)
            secret_file.flush()
            os.fsync(secret_file.fileno())
        target.chmod(0o600)
    for role, password in passwords.items():
        connection.execute(sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
    connection.execute("ALTER DATABASE threatveil OWNER TO threatveil_admin")
    connection.execute("REVOKE ALL ON DATABASE threatveil FROM PUBLIC")
    connection.execute("GRANT CONNECT ON DATABASE threatveil TO threatveil_admin, threatveil_app")
    connection.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
    connection.execute("GRANT USAGE, CREATE ON SCHEMA public TO threatveil_admin")
    connection.execute("GRANT USAGE ON SCHEMA public TO threatveil_app")
    connection.execute("ALTER DEFAULT PRIVILEGES FOR ROLE threatveil_admin IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO threatveil_app")
    connection.execute("ALTER DEFAULT PRIVILEGES FOR ROLE threatveil_admin IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO threatveil_app")
print("New database roles initialized. Secret payload files saved locally (0600); nothing uploaded.")
