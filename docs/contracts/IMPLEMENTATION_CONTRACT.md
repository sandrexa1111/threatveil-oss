# Initial implementation contract

7 September 2026. The new execution mandate supersedes V3's planning-only pause. V3 semantics remain authoritative, with typed extensions for future physical autonomy. No physical execution is enabled.

Canonical repository root contains `src/threatveil` (Python modular API/core/worker), `apps/web` (Next.js), `infra`, `scripts`, `tests`, and existing strategy/reference material. Root owner integrates API, persistence, auth and security. Core work owns `core/`, `adapters/`, `sdk/` and its tests. Web work owns `apps/web`, root pnpm package configuration and its tests. Infrastructure work owns `infra/`, `.github/`, Dockerfiles, `scripts/local_db.sh` and deployment documentation. Communicate interface changes before editing another area's files.

API prefix `/v1`. Browser uses same-origin Next proxy `/api/backend/*` to the loopback API; server sessions are HttpOnly, CSRF header `X-CSRF-Token` is required for cookie-authenticated mutations. `/v1/auth/me` returns `{user, organization, memberships, csrf_token, mode}`. Development login `/v1/auth/local` accepts `{email,name,organization_name}` only with explicit loopback development mode; production uses verified managed identity via `/v1/auth/exchange`. No production password service is built. Local identities are conspicuously labelled.

All resource responses use `{id, organization_id, kind, created_at, ...domain_fields}`. Lists use `{items: [...]}`. IDs are UUIDs. Domain records are immutable versions with tenant-safe typed relationships; changes append new records. Mutable memberships, target authorization/revocation, run lifecycle, sessions and usage have separate constrained state. Server derives organization from authenticated membership, never trusts submitted org IDs.

Browser routes:

- `GET /v1/dashboard`: `{systems,properties,findings,runs,fixes,gauntlets,usage,integrations,summary}`; each resource array contains persisted records.
- `GET/POST /v1/systems`: create `{name,description,access:[],actions:[],fingerprint:{components:[]}}`.
- `GET /v1/templates`, `POST /v1/threat-model` `{access,actions}`.
- `GET/POST /v1/findings`: `{title,description,system_id,source_type}`.
- `POST /v1/compiler/propose`: `{finding_id}` returns proposed property, field provenance, unknowns and provider status. Proposal never executes or approves.
- `GET/POST /v1/properties`: `{system_id,title,description,template_id?,definition:{...},finding_id?}`; `POST /v1/properties/{id}/approve` creates approved version and binding. Server returns effective property ID.
- `GET/POST /v1/targets`: `{system_id,name,adapter,origin?,paths:[],methods:[],expires_at,authorization_note}`; verification and revocation have explicit endpoints. Synthetic adapter is fixed local fixture, never user code. Public HTTP verification uses origin challenge.
- `POST /v1/demo/setup` creates one explicitly labelled synthetic procurement system, approved property, fixture target and audited local pilot entitlement; it executes nothing.
- `POST /v1/runs`: `{system_id,property_id,target_id,version,trials,variant_count,baseline_id?,idempotency_key}`. Demo versions: vulnerable, fixed, regressed, missing_witness, bad_fix. Generic adapters take approved plan/fixture/trace. Run is persisted and server authorizes execution. `GET /v1/runs`, `GET /v1/runs/{id}`, `GET /v1/runs/{id}/evidence`.
- `GET/POST /v1/fixes`: `{run_id,verification_run_id,description}`; only compatible security PASS plus legitimate SUCCESS can create verified baseline.
- `POST /v1/impact`: `{system_id,previous:{components:[]},candidate:{components:[]}}` returns explained selection and unknowns.
- `GET/POST /v1/gauntlets`: `{system_id,name,scope,property_ids:[]}`; progress/report computed from actual records.
- `GET /v1/reports/{system_id}` JSON; `/v1/reports/{system_id}/html` escaped HTML download.
- `GET /v1/billing`; `POST /v1/billing/checkout` `{plan}`; `POST /v1/billing/portal`; explicit unavailable integration responses when credentials absent.
- `GET /v1/members`, invitation/role operations; integrations status; `POST /v1/leads` for bounded contact/demo capture and safe CRM delivery when configured.

Security verdict `PASS|FAIL|INCONCLUSIVE` is separate from execution `COMPLETED|ERROR|CANCELLED|TIMEOUT`, task `SUCCESS|FAILURE|UNKNOWN`, regression boolean, fix verification boolean and release `ALLOW|WARN|BLOCK`. Evidence contains observations, qualification/coverage, digest and limitations. A confirmed prohibited action immediately FAILs; missing mandatory witness never PASSes; a mocked boundary cannot be verified. Candidate identity is typed `{type,id,version,digest}` with optional GitHub binding, not universally a commit.

Pure core entry points (owner may refine through coordination): `run_procurement(version, property_definition=None, trials=5, variant_count=1) -> dict`, `canonical_property() -> dict`, `evaluate_trace(property_definition, observation) -> dict`, `templates() -> list[dict]`, `analyze_change(previous, candidate, properties) -> dict`. Core never knows DB credentials. API persists core outputs and binds tenant, candidate and lineage. Separate worker exchanges identity+bootstrap for scoped broker access; local deterministic fixture execution is labelled and does not imply GCP runner acceptance.

Local services: API 127.0.0.1:8000, web 127.0.0.1:3000, PostgreSQL 127.0.0.1:55432. Config names `TV_ENV`, `TV_DATABASE_URL` (non-owner runtime role), `TV_ADMIN_DATABASE_URL` (migrations only), `TV_LOCAL_AUTH`, `TV_WEB_ORIGIN`, `TV_EVIDENCE_DIR`, `TV_WORKER_IDENTITY`, plus provider-specific credentials. Production refuses local-auth mode, local secret storage and missing required security configuration. Secrets never appear in normal target config.

## Integrated contract amendments — 7 September2026

The initial list envelope now includes pagination metadata. `/v1/workspace/{collection}` supports tenant-bound keyset pages, search and relevant system/approval filters. Dashboard totals cover full history; arrays are explicitly recent windows. `/v1/memory/export` streams portable records/relationships; clients must see its `complete` trailer.

Run requests additionally accept `observer_id`, a typed exact `candidate`, frozen `stimulus`, `fingerprint`, or a single imported `observation`. Security-owned qualification runs supply a specific control case. Source registration/approval/revocation lives under `/v1/observers`; see the separate qualification guide. Candidate identity must come from the qualified observed component, not a caller's GitHub label. Verified workflow OIDC is the only public GitHub submission path.

Active external trials use scoped `/v1/observe` broker messages, then `/v1/complete` with an empty payload. The broker reconstructs from persisted captures. Final external `trials` reference `capture_id` and `evidence.capture_ids`; raw observations are read through `/v1/runs/{run}/captures/{capture}`. Raw observations expire explicitly; complete metadata is not duplicated in giant result payloads. Synthetic completion retains its constrained fixture reconstruction protocol.

Organization-bound read/execute API tokens and recurring schedules are implemented. Tokens cannot approve properties or administer billing. Scheduled execution rechecks membership, target/source authorization and explicit budget; claimed ambiguous work is not automatically repeated. Delivery status is owner-visible at `/v1/deliveries`; billing's paid flag requires verified live provider payment state.
