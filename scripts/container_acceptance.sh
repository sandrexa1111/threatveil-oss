#!/usr/bin/env bash
# Isolated local acceptance in containers: production web build, full browser suite
# against real PostgreSQL 17 (non-superuser NOBYPASSRLS runtime role), TypeScript SDK
# and the canonical demonstration. No network egress beyond package downloads, no
# cloud resource, no provider call. Results are copied to $OUT.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT:-$ROOT/.local/container-acceptance}"
PLAYWRIGHT_IMAGE="${PLAYWRIGHT_IMAGE:-mcr.microsoft.com/playwright:v1.63.0-noble}"
ID="tv-accept-$$"
mkdir -p "$OUT"
WORK="$(mktemp -d)"
COPYFILE_DISABLE=1 tar -C "$ROOT" --exclude=node_modules --exclude=.venv --exclude='.next*' --exclude=.local \
  --exclude='*.pdf' --exclude=.git --exclude='._*' --exclude=__pycache__ \
  --exclude='*.tsbuildinfo' --exclude=dist -czf "$WORK/src.tgz" .
cleanup() { docker rm -f "$ID-pg" "$ID-run" >/dev/null 2>&1 || true; docker network rm "$ID" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT
docker network create "$ID" >/dev/null
docker run -d --name "$ID-pg" --network "$ID" -e POSTGRES_PASSWORD=cluster postgres:17-alpine >/dev/null
until docker exec "$ID-pg" pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
sleep 2
docker exec -i "$ID-pg" psql -v ON_ERROR_STOP=1 -U postgres >/dev/null <<'SQL'
CREATE ROLE threatveil_admin LOGIN PASSWORD 'admin' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE threatveil_app LOGIN PASSWORD 'app' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE DATABASE threatveil OWNER threatveil_admin;
\connect threatveil
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO threatveil_admin;
GRANT USAGE ON SCHEMA public TO threatveil_app;
ALTER DEFAULT PRIVILEGES FOR ROLE threatveil_admin IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO threatveil_app;
ALTER DEFAULT PRIVILEGES FOR ROLE threatveil_admin IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO threatveil_app;
SQL
docker run -d --name "$ID-run" --network "$ID" "$PLAYWRIGHT_IMAGE" sleep infinity >/dev/null
docker cp "$WORK/src.tgz" "$ID-run:/tmp/src.tgz"
run() { docker exec "$ID-run" bash -lc "$1"; }
ENV="export PATH=\$HOME/.local/bin:\$PATH TV_ENV=local TV_LOCAL_AUTH=true TV_WEB_ORIGIN=http://127.0.0.1:3000 \
TV_DATABASE_URL=postgresql+psycopg://threatveil_app:app@$ID-pg:5432/threatveil \
TV_ADMIN_DATABASE_URL=postgresql+psycopg://threatveil_admin:admin@$ID-pg:5432/threatveil"
run "mkdir -p /work/.local && tar -xzf /tmp/src.tgz -C /work && curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1"
# Browser fixtures that seed pagination/capture history require the explicitly provisioned
# database file, exactly as scripts/local_db.sh writes it for a developer machine.
run "umask 077 && printf 'TV_DATABASE_URL=postgresql+psycopg://threatveil_app:app@$ID-pg:5432/threatveil\nTV_ADMIN_DATABASE_URL=postgresql+psycopg://threatveil_admin:admin@$ID-pg:5432/threatveil\n' > /work/.local/database.env"
run "$ENV; cd /work && uv sync --locked >/work/.local/uv.log 2>&1 && uv run alembic upgrade head >/work/.local/alembic.log 2>&1"
echo "== web install and production build"
run "cd /work && corepack enable && CI=true pnpm install --frozen-lockfile >/work/.local/pnpm-install.log 2>&1 && pnpm build >/work/.local/web-build.log 2>&1" \
  && echo "web build: passed" || { echo "web build: FAILED"; docker cp "$ID-run:/work/.local/." "$OUT/"; exit 1; }
echo "== TypeScript SDK"
run "cd /work && pnpm test:sdk >/work/.local/sdk.log 2>&1" && echo "sdk: passed" || echo "sdk: FAILED"
run "$ENV; cd /work && nohup uv run uvicorn threatveil.api:app --host 127.0.0.1 --port 8000 >/work/.local/api.log 2>&1 &"
run "cd /work/apps/web && cp -r .next/static .next/standalone/apps/web/.next/static && \
  (HOSTNAME=127.0.0.1 PORT=3000 TV_ENV=local TV_LOCAL_AUTH=true TV_API_URL=http://127.0.0.1:8000 nohup node .next/standalone/apps/web/server.js >/work/.local/web.log 2>&1 &)"
run "for i in \$(seq 1 90); do curl -sf http://127.0.0.1:8000/healthz >/dev/null && curl -sf http://127.0.0.1:3000/ >/dev/null && exit 0; sleep 1; done; exit 1"
echo "== browser suite"
set +e
run "cd /work/apps/web && TV_TEST_WEB_URL=http://127.0.0.1:3000 npx playwright test >/work/.local/browser.log 2>&1"
BROWSER=$?
echo "== canonical demonstration"
run "$ENV; cd /work && uv run python -c \"from cryptography.hazmat.primitives import serialization as s; k=s.load_pem_private_key(open('.local/receipt-signing/key.pem','rb').read(),None); open('.local/trusted-public-key.pem','wb').write(k.public_key().public_bytes(s.Encoding.PEM,s.PublicFormat.SubjectPublicKeyInfo))\" && \
  uv run python scripts/canonical_demo.py --api-url http://127.0.0.1:8000 --trusted-public-key .local/trusted-public-key.pem --output .local/canonical-demo >/work/.local/canonical-demo.log 2>&1"
DEMO=$?
set -e
docker cp "$ID-run:/work/.local/." "$OUT/"
tail -3 "$OUT/browser.log"
echo "browser exit=$BROWSER demo exit=$DEMO"
exit $(( BROWSER || DEMO ))
