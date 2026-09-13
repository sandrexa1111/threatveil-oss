# ThreatVeil web

Next.js application for the public product and authenticated verification workspace. Product data comes from the FastAPI control plane through the same-origin `/api/backend/v1/*` relay. There are no seeded dashboard metrics in the browser.

## Local development

From the repository root, run `pnpm install` and `pnpm dev`. Start the database and API using the root development instructions. The web service binds `127.0.0.1:3000`; `TV_API_URL` defaults to `http://127.0.0.1:8000`.

The development command explicitly enables `TV_LOCAL_AUTH=true` with a development environment. The sign-in page labels local identities. A production deployment must use managed identity; local identities are never a production fallback.

## Managed identity and cloud relay

Configure these public Firebase application identifiers at build time:

- `NEXT_PUBLIC_FIREBASE_API_KEY`
- `NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN`
- `NEXT_PUBLIC_FIREBASE_PROJECT_ID`
- `NEXT_PUBLIC_FIREBASE_APP_ID`

The client obtains a Google identity token and exchanges it with the API for an HttpOnly session. Cookie-authenticated mutations send the session CSRF token. Neither identity tokens nor API-token secrets are persisted in browser storage.

For a private Cloud Run API, set `TV_API_URL` and `TV_API_AUDIENCE` on the web service. The relay retrieves its own service identity from the fixed metadata endpoint and uses `X-Serverless-Authorization`. The audience is server configuration, never request input. A customer `Bearer tvk_*` credential is separately forwarded as `X-Threatveil-Token`; browser sessions preserve cookies and CSRF.

## Verification

`pnpm typecheck` and `pnpm build` verify the application. `pnpm test:web` runs real browser acceptance against running web/API/database services, including the five candidate cases, useful-fix baseline, regression block, scoped API tokens, schedules, cross-system draft adoption, contact consent, and narrow-screen layout. Tests create isolated local identities and synthetic records. They do not validate GCP IAM, live billing, external provider behavior, or real customer witnesses.

The Integrations page includes observation-source registration and qualification review. Customer collectors supply distinct public keys, an exact candidate fingerprint component, a fixture/state binding, and an independence review. The UI launches three assigned controls, presents their persisted evidence for approval, and respects backend revocation/supersession. Ordinary observed runs also need an explicit expected candidate digest. Signatures identify the collectors; they do not certify their independence or correctness. Browser acceptance verifies the synthetic-target restriction; active customer-collector qualification is covered by backend integration tests with simulated transport and still requires real deployment validation.

Workspace lists show how many records are loaded and how many exist. Older records use tenant-filtered keyset pages; search labels explicitly apply to loaded records. Forms and operating panels can load older selection records. Dashboard totals cover the full organization, while failure/regression totals use finalized outcomes. Billing counts approved property families rather than drafts or retained versions. Full immutable memory export is available from Settings and Reports; raw capture retention is separate.

Change impact includes security canaries and test-selection audits over already completed executions. They accept an exact candidate identity, distinguish immutable saved snapshots from refreshed applicability, and launch no new execution. External compact results load retained captures individually, with explicit expiry handling. The browser fixture setup scripts require the provisioned local database; the collector transport is simulated, while signed sink observations, PostgreSQL records, evidence objects, and browser/API reads are real local fixtures.

API tokens are displayed once in a masked field, can be copied to a secret manager, and are revocable. Scheduled executions still depend on the configured dispatcher and current target authorization/entitlement. Shared access only creates a property suggestion; adoption produces a draft requiring destination-specific review.

## Release integrity workflow

The workspace now starts with the persisted release timeline. `/app/releases` shows exact candidate digests, recorded ALLOW/WARN/BLOCK decisions, property-level applicability, and signed receipt export. Opening a decision fetches its current applicability separately: revoked authorization or stale evidence can change current eligibility without rewriting the historical decision. Receipt payloads include trust limitations; independently verify them using a separately trusted signer key.

`/app/evidence` reads the tenant's evidence ledger, including property versions, recorded security and legitimate-task results, expiry, source run, and inspected ProofScope. A recorded PASS is not presented as current validity for a different candidate. `/app/impact` adds persisted change sets and re-proof plans alongside the existing change-impact/canary/audit tools. A plan records exact candidate identity, previous and candidate fingerprints, invalidation reasons, obligations, trial requirements, and reusable evidence. Configure a re-proof run directly from an obligation; the candidate fingerprint and trial budget are carried into the execution form. Release evaluation checks server-authoritative evidence for all approved properties and defaults to WARN in the form. Creating a decision does not itself deploy a candidate or configure a GitHub required check.

These views use tenant-filtered keyset pages and identify record-loading errors. No release, validity, or installation metric is synthesized in the browser. The public homepage, pricing, product, and trust surfaces use Autonomous Release Integrity and Integrity Launch terminology. Commercial scope is agreed around protected systems; public pages contain no unvalidated price anchors or certification claims.

## Integrity Launch

`/app/gauntlet` retains the historical URL and existing immutable Gauntlet scope contract while presenting **ThreatVeil Integrity Launch**. Existing engagements and scope reports remain readable. The `/v1/integrity-launches` wrapper adds derived onboarding milestones, security-owner reviews, and completed-work time records.

Implementation notes and time entries are append-only and idempotent. Only owner/admin/security roles record reviewed milestones; developers can record their completed work. Notes cannot set installed-gate, security-pass, or paid status. Effort totals use all retained entries; history is paginated. Payment status reflects the current reconciled billing account and is not a launch-specific revenue attestation.

The installed milestone requires a confirmed GitHub check publication with the exact signed WARN release and receipt, a currently enabled repository/installation/security-owner binding, and current release applicability. A configured route or signed local receipt alone remains incomplete. The view considers the latest 200 WARN releases and publications; branch-protection enforcement and independent customer acceptance are not attested by this milestone. Scope execution status remains distinct from installation.

`tests/release-integrity.spec.ts` exercises a real local PostgreSQL/SQLite-backed ALLOW → change/VOID → re-proof/BLOCK → useful fix/ALLOW lifecycle through the browser, receipt export, ProofScope inspection, historical/current authorization separation, launch review, measured hours, and narrow-screen layouts. `tests/integration/test_integrity_launch.py` exercises tenant/role/CSRF boundaries, immutable and concurrent idempotent effort recording, denied fabricated milestones, and provider-publication installation/revocation; its GitHub provider is substituted, so it is not live cloud proof.
