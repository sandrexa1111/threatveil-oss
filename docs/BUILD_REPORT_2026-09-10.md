# Execution report — 2026-09-10

## 1. Executive result

ThreatVeil now has an integrated local Autonomous Release Integrity workflow: exact candidate and fingerprint → ProofScope → invalidation → bounded re-proof → policy decision → signed receipt → immutable history. The existing tenant, observer and runner implementation was extended, not replaced. The live local demonstration and engineering acceptance pass. This is not a deployed or commercially validated SaaS service.

## 2. What changed

The earlier implementation centered on individual runs, fixes, canaries and security memory. The new release objects make the release decision, its complete property obligations, evidence applicability and durable explanation first-class. The workspace now exposes release history, evidence ledger, change explorer, scope details, current eligibility and receipt download. Integrity Launch records scoped installation work and separates synthetic progress, actual delivered checks and payment.

Major new backend surfaces are core/validity.py, release_integrity.py, release_signing.py, sdk/receipts.py, integrations/github_app.py, integrations/github_release.py, integration_intake_api.py, integrity_launch.py, governance.py, erasure.py and sdk/mcp_server.py. Existing auth, broker, capture, billing, SDK, CLI and export paths were integrated. Migrations 0006/0007 are applied locally.

The workspace had no tracked baseline commit and its application files were already untracked. No commit, staging, push or destructive reset was performed; previous strategy/build documents were retained.

## 3. Product

A customer can register a system, import draft findings/telemetry, review properties and fingerprint components, authorize a staging target, qualify independent observation, establish evidence, declare a candidate change, inspect invalidations, execute bounded obligations, evaluate OBSERVE/WARN/BLOCK policy and export a signed historical receipt. All active approved properties are considered. Unknown evidence and failed legitimate tasks cannot authorize positive assurance.

A security owner can request a time-bounded exact-scope exception; another security actor must approve it. The underlying failure remains visible. Historical decisions are immutable; current applicability is reevaluated after expiry, revocation or adverse evidence. A launch records actual effort and only recognizes installed WARN delivery after a matching confirmed publication. Existing billing contracts remain supported; public offers require explicit configured scope.

## 4. Architecture

FastAPI modular control plane, Next.js workspace, PostgreSQL FORCE RLS and append-only Record/Edge ledger, existing broker/worker protocol and content-addressed evidence storage. Mutable operational state stays in dedicated account/lease/route/outbox tables. Release signing and record creation share a transaction; GitHub is a durable asynchronous projection. Each re-proof run has its own durable budget/idempotency transaction, with explicit partial-orchestration outcomes.

System locks serialize release authority and evidence mutations before artifact/run/lease/account locks where combined. Normalized intake cannot bypass qualification. The read-only MCP server uses authenticated fixed-origin HTTP for tenant data and exposes public schemas locally without database credentials.

## 5. Security

Locally tested: tenant RLS, role enforcement, CSRF, real-peer auth rate limiting, immutable evidence, target/observer qualification, exact candidate/fingerprint anchoring, synthetic-to-Git rejection, content-based adverse history across version aliases, expiry, two-person exceptions, source/member revocation, signed receipt tampering/scope mismatch, GitHub HMAC/replay/install ownership, fenced delivery/recovery, worker possession/nonce/lease checks, quotas and missing/bad-fix outcomes.

Review found and fixed candidate relabeling and adverse-history version alias issues, component-key ambiguity, revocation/signing serialization, worker lock ordering, stale check refresh and partial re-proof visibility. Local filesystem storage/erasure rejects symlinked child namespaces; erasure crash recovery uses private authenticated manifests. Runtime credentials cannot bypass append-only deletion restrictions.

Remaining risks include customer collector honesty/qualification, asynchronous external check staleness, signing-key operations, unvalidated large-ledger performance, provider-specific recovery and cloud IAM/egress behavior. Finite tests and signed receipts are not universal safety guarantees or independent certification.

## 6. Cloud

Actually running: local PostgreSQL, loopback API and Next.js application. Terraform fmt/validate and seven mocked infrastructure tests pass. No GCP apply, hosted endpoint, cloud execution, current image rebuild/scan, live IAM test, restore drill or cloud deletion has been performed in this wave. Existing September 7 image results are historical only.

External inputs still missing: selected GCP project/region, authenticated deployment identity and spend ceiling. The private deployment runbook and explicit acceptance checklist are in GCP_DEPLOYMENT.md and deployment/GCP.md. No customer credentials were printed and no external spend was incurred.

## 7. Integrations

| Integration | Implemented | Tested | Live | External blocker |
|---|---|---|---|---|
| GitHub App | Installation verification, push/lifecycle intake, exact Checks and retry/refresh | Real PostgreSQL + mocked GitHub HTTP | No | App/installation, HTTPS webhook, scheduler, branch protection |
| GitHub OIDC Action | Trusted workflow exact-candidate gate | Local identity/contract/security cases | No | Real workflow and independently observed deployed SHA |
| OpenAI Agents / OTel GenAI | Declared fingerprint/trace normalization | Fixtures and intake API | No | Customer instrumentation + qualified collector |
| Anthropic hooks | Event normalization, unknown outcome preserved | Fixtures and intake API | No | Real hooks and ground truth |
| MCP | Catalog discovery, existing execution adapter, read-only ThreatVeil server | Protocol, bounded IO, auth and subprocess cases | Local stdio only | Real agent/server/collector integration |
| CycloneDX / SARIF | Composition and draft-finding intake/review | Schema/normalizer + real DB API | No customer feed | Real repository exports and reviewer |
| Python / TypeScript / CLI | Release, plan, evidence, intake, receipt verification | Python suite + 4 compiled TS tests | Local package | Customer workflow/public packaging |
| Stripe | Configured scope, checkout/portal/payment reconciliation | Provider contracts and real DB | No | Prices/allowances, credentials, real invoice/payment |
| Email / CRM | Existing durable consented delivery | Provider contracts | No | Authorized sender/destination configuration |
| GCP | Infrastructure source | 7 Terraform tests | No | Project, region, identity, spend and live acceptance |

See INTEGRATION_INTAKE.md for supported import formats and their conservative provenance. None of those imports independently creates qualified PASS evidence.

## 8. Test results

| Command / check | Result and scope |
|---|---|
| `uv run pytest --junitxml=.local/acceptance-python-20260910-current.xml` | 469 passed, 15 upstream deprecation warnings; real local PostgreSQL for persistence; providers substituted in marked tests |
| `uv run ruff check src tests infra/scripts migrations scripts` | Passed |
| `pnpm typecheck` | Passed |
| `pnpm test:sdk` | 4 passed after compiling package |
| `pnpm test:web` | 9 passed against local API/PostgreSQL and web |
| `pnpm --filter @threatveil/web test tests/release-integrity.spec.ts` | 2 passed again after receipt deep-link fix |
| `pnpm build` | Optimized production frontend build passed |
| `.local/tools/terraform -chdir=infra fmt -check -recursive`, `validate`, `test` | Passed; 7 Terraform tests; no resources applied |
| `.local/tools/actionlint` | Passed |
| `semgrep scan --config .local/semgrep-rules/python/lang/security --config .local/semgrep-rules/javascript/lang/security --severity ERROR --error --metrics off src apps/web infra/scripts` | 0 findings, 34 selected rules, 115 targets; not a comprehensive audit |
| `.local/security-bin/osv-scanner scan source --lockfile=uv.lock --lockfile=pnpm-lock.yaml` | No issues found; 89 Python / 187 JavaScript packages |
| `.local/security-bin/gitleaks dir src --redact --no-banner` | No leaks found in scanned Python source tree |
| `uv run python scripts/release_demo.py --output .local/release-demo-20260910` | Actual local HTTP demo and three offline-verifiable receipts |

The final Python count is 168 above the original 301-test baseline. Browser screenshots at .local/release-integrity-{desktop,mobile}.png and .local/integrity-launch-{desktop,mobile}.png were visually checked. Logs and JUnit are in ignored .local/. Source/dependency scans do not attest to an unbuilt image or a live environment.

## 9. Demo

Start the local database/API/web according to README.md. Run the demo command above with a new output directory, then use the recorded local identity to inspect the release workspace. The script:

1. Creates an isolated synthetic organization/system/property/target.
2. Executes the fixed procurement configuration and records ALLOW.
3. Changes application/permission identity and records prior evidence VOID.
4. Executes the actual planned regressed configuration and records FAIL/BLOCK.
5. Restores the fixed configuration, re-proves it and records ALLOW.
6. Checks missing-observation and task-disabling bad-fix outcomes.
7. Exports and independently verifies three standard DSSE receipts using the operator's local public key.

Observed local result: **0.864 seconds**, releases **ALLOW / BLOCK / ALLOW**. System `e51fdf38-9507-4f5c-b5ee-5e59327736dc`; organization `f82feeba-cddf-4a42-9835-93392b0eb4eb`; local demo identity `release-demo-894685d1-d77a-41aa-bef6-989f4850b8a4@local.invalid`. Artifacts: `.local/release-demo-20260910/summary.json`, `release-a.dsse.json`, `release-b.dsse.json`, `release-c.dsse.json` and the exported public key.

This uses committed SQLite business state and real local HTTP/PostgreSQL. Final ALLOW demonstrates restoration of the tested fixed configuration, not an automatically generated customer patch. The elapsed time describes a tiny local fixture, not onboarding performance.

## 10. Commercial readiness

The product supports a credible supervised design-partner demonstration and a concrete bounded Integrity Launch proposal. It does not yet support a claim of an accepted hosted production service. Agree protected-system scope, properties, execution allowance and implementation work explicitly. The launch UI cannot substitute a synthetic setup for delivered integration or a pilot for paid conversion.

No customer was contacted, contract sent, subscription charged, external gate installed or public site deployed. Commercial proof remains zero for this wave. COMMERCIAL_ACCEPTANCE.md distinguishes local, cloud, customer and revenue evidence.

## 11. Founder actions

Supply the GCP project/region, deployment identity and spend ceiling; select the first permitted customer staging workflow and its independent collector/ground-truth owner; register/install the GitHub App and authorize exact workflow/ref and eventual branch protection; configure managed identity and operator signing-key trust; supply Stripe products/prices/allowances and a real payment acceptance path. Supply compiler and authorized email/CRM credentials only when those optional flows are used. Agree actual contractual scope, data rights and customer rollout criteria.

No further permission is needed for routine local fixes. These are external dependencies that code cannot truthfully manufacture.

## 12. Remaining P0

Before selling a hosted installation as operational: complete private cloud deployment and identity/secrets configuration; qualify a real customer's independent observation and exact deployment anchor; prove real GitHub delivery and WARN behavior; rebuild/scan current images and execute live isolation/recovery/restore/deletion drills; establish signing-key distribution/rotation and operational ownership; validate the configured checkout/payment path if paid activation is advertised.

Before customer BLOCK: demonstrate the customer-specific failure/useful-fix/missing-witness cases, inspect WARN outcomes, agree exception/recovery handling and validate required-check protection. No unresolved local failing test is being hidden as an external dependency.

## 13. P1

Customer-driven performance profiling/indexing, narrower reviewed scopes and measured re-proof savings; real span/hook integration fixtures; schema/package publication and license review; complete cohort/economics instrumentation from real events; managed signing/key rotation or separately accepted Sigstore profile; cloud/provider/account erasure extensions; additional failure-recovery and independent security review based on the first deployment.

## 14. Deliberately not built

Fleet and insurance products, physical actuation, generalized offensive scanning, autonomous customer source repair/promotion, model-authorized scope/policy, cross-customer raw trace pooling, speculative dashboards/ARR, and fake customer or payment evidence. The existing architecture was not replaced and no service expansion was added merely for breadth.

## 15. Business milestone

| Milestone | Decision |
|---|---|
| Private design partner | Ready for supervised local demonstration and scoped integration; hosted installation conditional on deployment |
| Paid Integrity Launch | Ready to propose a bounded service honestly; live fulfillment/payment acceptance still pending |
| Production customer | Not accepted yet |
| Customer BLOCK mode | Implemented/tested locally; not approved for an unvalidated customer environment |

The completed result is a deeper, verified local release-integrity product with concrete external acceptance work remaining. It is not a claim that the full decade vision or commercial mandate has been achieved.
