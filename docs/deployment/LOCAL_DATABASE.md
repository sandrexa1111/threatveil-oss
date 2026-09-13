# Project-local PostgreSQL

`scripts/local_db.sh start` starts PostgreSQL 17 on `127.0.0.1:55432`. `status` reports readiness; `stop` stops only this project cluster and preserves data. It does not register a Homebrew service. Set `TV_PG_BIN` if PostgreSQL binaries are elsewhere.

The script initializes `.local/pgdata`, uses SCRAM authentication, disables Unix-domain sockets, and generates independent 256-bit passwords. `.local/database.env` is mode 0600 and supplies `TV_DATABASE_URL` for `threatveil_app` and `TV_ADMIN_DATABASE_URL` for `threatveil_admin`. Both roles are NOSUPERUSER, NOCREATEROLE, NOCREATEDB and NOBYPASSRLS. The migration role owns the database and tables; runtime receives only schema usage and table/sequence grants. The separate cluster administrator exists only for local initialization and is never an application setting.

After start:

```sh
uv sync --locked
uv run alembic upgrade head
TV_ENV=test TV_LOCAL_AUTH=true uv run pytest
```

Settings read `.local/database.env` and then `.env`; an explicit `.env` can override local connection settings. Never paste either file into logs. Do not run migrations using the runtime URL or run the API with migration credentials. Database initialization does not establish RLS by itself: migrations create the policies, and integration tests must prove tenant isolation with the runtime role.

The cluster is for synthetic local development, not a supported customer-hosted deployment. `.local/database-secrets.json`, the cluster password file, PostgreSQL logs and data remain on this machine until deliberately removed. Avoid stopping the cluster while other development processes are testing it. No destructive reset command is provided.

The CI service uses a separate ephemeral PostgreSQL 17 container. `infra/scripts/ci_database.py` creates genuinely distinct owner/runtime roles before applying the same migrations; testing through a superuser would conceal RLS failures.
