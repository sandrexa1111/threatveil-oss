# Contributing to ThreatVeil

Thank you for looking. ThreatVeil is an experimental open-source project; see
[what works today](README.md#what-works-today). Contributions are licensed under the
[Apache License 2.0](LICENSE), the same license as the project: by submitting a pull request you
agree your contribution is provided under it.

## Where help matters most

- **Assurance loop:** generic restoration, observer unification, generic verify-and-decide
  ([ROADMAP P0](ROADMAP.md#p0-generic-assurance-loop)).
- **Connectors and adapters:** agent frameworks, tool gateways, deployment platforms.
- **Observer packages:** reference SQL and HTTP business-effect observers.
- **Authority semantics:** numeric limits, schema bounds, MCP annotations.
- **Test cases:** especially adversarial ones that try to make ThreatVeil overstate assurance.
- **Documentation and examples.**
- **Research:** evidence applicability, authority graphs, portable assurance.

Look for issues labelled `good first issue`, `help wanted` or `research`, or open one with the
templates.

## Prerequisites

- **Docker path:** Docker with Compose v2. Nothing else.
- **Host path:** Python 3.13 with [uv](https://docs.astral.sh/uv/), Node 24 with pnpm (version
  pinned in `package.json`), and PostgreSQL 17 binaries (`pg_ctl`, `initdb`, `psql`).

## Setup

### Docker workflow

```sh
make up          # docker compose up --build --detach --wait
make demo        # canonical synthetic demonstration
make logs
make down        # stop; the database is kept
make reset-dev   # delete this project's database and signing key, start fresh
```

### Local workflow (hot reload)

```sh
make setup       # uv sync --locked; pnpm install --frozen-lockfile
make dev-db      # project-local PostgreSQL on 127.0.0.1:55432; credentials in ignored .local/
make migrate
make dev-api     # terminal 1
make dev-web     # terminal 2
```

`scripts/local_db.sh` never registers a system service. Stop it with
`bash scripts/local_db.sh stop`.

## Tests

| Command | What it runs | Needs |
|---|---|---|
| `make lint` | Ruff | uv |
| `make test-python` | ~700 unit, integration and security tests against real PostgreSQL | `make dev-db migrate` |
| `make typecheck` | Strict TypeScript for `apps/web` | pnpm |
| `make test-sdk` | TypeScript SDK build and tests | pnpm |
| `make test-web` | Playwright browser suite | API and web running; `pnpm --filter @threatveil/web exec playwright install chromium` |
| `make test-terraform` | Terraform validate and mocked-provider tests | Docker |
| `make demo` | End-to-end demonstration with signature verification | Docker |

CI runs these plus secret scanning, Semgrep, osv-scanner, image builds and the Compose quick start
on every pull request. Container vulnerability scanning and SBOMs run weekly
(`.github/workflows/image-scan.yml`). No credentials are needed.

## Branches and pull requests

- Branch from `main` and name the branch by intent: `feat/…`, `fix/…`, `docs/…`, `test/…`,
  `research/…`.
- Keep each pull request to one concern. Describe what changed, why, and how you tested it.
- CI must pass. Pull requests are squash-merged.
- Update documentation in the same pull request when behaviour changes.
- Keep generated output, `.local/` artefacts and screenshots out of commits unless they are the
  point of the change.
- Fixtures must be obviously synthetic (`*.invalid`, `example.com`).

## Architecture expectations

- **Records are append-only.** New facts are new records and edges. Operational tables (leases,
  quotas, outbox) are the only mutable state.
- **Migrations are forward-only.** Never edit a merged Alembic revision. New tables stay under
  row-level security, accessed by the non-owner `NOSUPERUSER NOBYPASSRLS` runtime role.
- **Unknown stays unknown.** Adapters count what they cannot interpret; they do not guess.
- **Imports are not evidence.** Connectors and adapters report declared or observed facts. Only
  qualified observers produce evidence.
- **Pin what you add.** Lockfiles are committed and CI rejects drift. Actions and base images are
  pinned by digest. State the reason for any new dependency.
- Python 3.13, 100-column lines, `ruff check` clean. TypeScript strict. Match the surrounding code.

## The assurance-semantics rule

**Any change that modifies assurance truth must include tests and documentation.**

A change modifies assurance truth if it can change what the product, API, Gate, Passport, CLI or
exports report as supported, current, cleared, stale, invalidated, verified or unknown. That
includes evidence binding, invalidation, dependency mapping, state provenance, observer
qualification, clearance, re-verification, restoration, and the wording of those states.

Such a pull request needs:

1. **Tests**, including a negative or adversarial case showing that declared, imported, synthetic,
   replayed or model-generated input cannot become evidence, and that failure stays closed.
2. **Documentation** in the same pull request: the relevant file under `docs/` and
   [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md) if a limit moves.
3. **Explicit review.** Write "alters assurance semantics" in the description. A maintainer must
   approve it; green CI alone is not enough.

When in doubt, treat the change as modifying assurance truth.

## Security-sensitive changes

Authentication and sessions, tenant isolation, API tokens, receipt and Passport signing and
verification, target transport (SSRF and DNS pinning), credential references, erasure and the
broker/worker identity path are security-sensitive. Changes there need tests under
`tests/security/` and explicit review. Report vulnerabilities privately; see
[SECURITY.md](SECURITY.md).

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
