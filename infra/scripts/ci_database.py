"""Create isolated CI database roles. Credentials never enter argv or logs."""
import os
from pathlib import Path
import secrets

import psycopg
from psycopg import sql

admin_password, app_password = secrets.token_hex(32), secrets.token_hex(32)
with psycopg.connect(os.environ["TV_CI_ADMIN_URL"], autocommit=True) as connection:
    for role, password in [("threatveil_admin", admin_password), ("threatveil_app", app_password)]:
        connection.execute(sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
    connection.execute("CREATE DATABASE threatveil OWNER threatveil_admin")
    connection.execute("REVOKE ALL ON DATABASE threatveil FROM PUBLIC")
    connection.execute("GRANT CONNECT ON DATABASE threatveil TO threatveil_admin, threatveil_app")
with psycopg.connect(os.environ["TV_CI_ADMIN_URL"], dbname="threatveil", autocommit=True) as connection:
    connection.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
    connection.execute("GRANT USAGE, CREATE ON SCHEMA public TO threatveil_admin")
    connection.execute("GRANT USAGE ON SCHEMA public TO threatveil_app")
    connection.execute("ALTER DEFAULT PRIVILEGES FOR ROLE threatveil_admin IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO threatveil_app")
    connection.execute("ALTER DEFAULT PRIVILEGES FOR ROLE threatveil_admin IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO threatveil_app")
directory = Path(".local")
directory.mkdir(mode=0o700, exist_ok=True)
target = directory / "database.env"
target.write_text(
    f"TV_DATABASE_URL=postgresql+psycopg://threatveil_app:{app_password}@127.0.0.1:5432/threatveil\n"
    f"TV_ADMIN_DATABASE_URL=postgresql+psycopg://threatveil_admin:{admin_password}@127.0.0.1:5432/threatveil\n"
)
target.chmod(0o600)
print("CI roles configured: runtime NOSUPERUSER/NOBYPASSRLS/non-owner.")
