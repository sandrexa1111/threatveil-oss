# ThreatVeil category and /uscommercial foundation — execution report

10 September 2026. This is an implemented, locally accepted foundation for Autonomous Change Assurance, entering through Autonomous Release Integrity. It is not evidence of a deployed or commercially accepted hosted service. Private GCP, real provider, Stripe TEST and customer acceptance remain distinct gates.

## A. What existed before

A substantial FastAPI/Next.js/PostgreSQL modular monolith already implemented approved properties, qualified observation, immutable ProofScopes/evidence, conservative invalidation, bounded execution and useful-task controls, complete-property release decisions, exceptions, DSSE receipts, historical memory, GitHub integration, provider/import adapters, SDK/CLI, tenant RLS and broker/worker isolation. Local procurement effects were real SQLite commits. Baseline execution passed **469 Python tests**, with 15 warnings (`.local/category-foundation/baseline.log` and `baseline.xml`).

The v4 canonical/reconstruction/falsification strategy, v3 ambition/thesis, latest pre-GCP audit, repository product/architecture and original blueprint were read before the architectural changes. Existing code and historical semantics were retained. The workspace was entirely untracked at baseline; no destructive reset, table rewrite or invented clean Git diff was used.

## B. What changed

- Added system/environment/authority/state and current-assurance projections over the existing kernel, typed source roles and history, bounded scoped authorization and separate acknowledgement.
- Added three-claim Finance Agent onboarding with committed business effects, non-code change reassessment, useful-task preservation and exact independent signed-record verification.
- Added the Connect → Define → Protect → Baseline → Watch → Decide UI, source health and scoped explanations; existing release/evidence workflows remain accessible.
- Added configurable Free, Pro, Team, Business and contract-defined Enterprise entitlements, subscription/event history, quota enforcement, local billing lifecycle, pricing/settings UI and measured commercial boundaries.
- Corrected the GitHub relay/publisher credential path, implemented narrow complete-decision machine authority and added concrete read-only cloud activation preflight.
- Added minimized tenant operational measurements and explicit separate analytics/research/cross-customer permissions.

Main implementations: `src/threatveil/change_assurance.py`, `change_assurance_api.py`, `core/finance.py`, `connectors/`, `commercial.py`, `commercial_api.py`, `measurements.py`, `release_machine.py`, `activation_readiness.py`, `sdk/change_records.py`, and the corresponding UI/tests. See [domain contract](docs/CHANGE_ASSURANCE.md), [connector contract](docs/CONNECTOR_CONTRACT.md), [commercial definition](docs/COMMERCIAL_PLATFORM.md).

## C. Database/domain migrations

No destructive or data-reinterpreting schema migration. Database head remains **0007**. New immutable record kinds and references use existing Record/Edge tables, append-only triggers, FORCE RLS and tenant/kind indexes. Existing operational Accounts are the locked allowance/reservation projection; new subscription snapshots and billing events retain interpretation over time.

New organizations provision Free atomically. Existing legacy accounts retain their existing interpretation and are not silently upgraded, renamed or reset. Existing signed records are not backfilled or resigned. Old receipt/evaluator profiles remain unchanged; the finance finality qualifier and scoped authorization have new explicit profiles. Deployment requires API/web compatibility and preserved signing keys, not a ledger rewrite. See [migration sequence](docs/CHANGE_ASSURANCE.md#migration-and-deployment-order).

## D. Canonical architecture now implemented

An autonomous `system` can span many component types. Immutable `environment`, `permission_envelope`, `system_state`, source assertions, typed relationships, `change_event`, `assurance_case`, `authorization_decision`, enforcement request/acknowledgement, status and consumer-acceptance records reference the mature property/evidence/proof-plan kernel. Fingerprint components provide component revisions. Deployment configuration is represented through source assertions, without claiming a fully proven running state.

Support requires current complete properties, exact candidate/configuration, qualified evidence in the bound environment after authority review, useful-task success and no unresolved adverse/source history. Unknown coverage remains unknown. Source history has no security-relevant latest-N cutoff; UI lists are separately bounded. Real imported changes need reviewed dependencies and observed after-values, not merely a fresh timestamp. Synthetic fixture reconciliation is explicitly confined to the finance sandbox.

Authorization identifies tenant/system/environment/state/envelope/policy, audience, nonce, prior epoch, issuer, schema/profile, algorithm, key ID and timestamps. Issuance is distinct from current status and enforcement. Ed25519 DSSE/in-toto is implemented; alternate algorithms and keyless verification are future profiles. Typed relationship annotations do not silently grant positive authority; automated generic graph inference is not implemented.

## E. Connector-role architecture

A common manifest declares supported versions, DISCOVER/CHANGE/OBSERVE/VERIFY/EXECUTE/ENFORCE/EXPORT roles where implemented, permissions, read/write scope, fact types, qualification assumptions, freshness, continuity/pagination, failures, classification and cost/rate bounds.

GitHub has bounded repository/provider reads and existing exact Checks delivery. MCP uses bounded verified-target transport and tool discovery. OTel ingestion normalizes observed reports without treating them as business ground truth. GCP Cloud Run v2 reads service/IAM with explicit credential references and consistency checks; configuration/routing does not prove all running revisions. Existing OpenAI Agents, Anthropic hooks, CycloneDX and SARIF intake enter the common normalization path.

Installation, configuration, batch, assertion, change and health records are tenant/environment scoped. Duplicate/reordered events, cursor gaps, outage, expiry, authorization changes and incomplete results remain explicit. IMPORTED is never presented as a live connection. Connector provider behavior has local contract/mocked-transport evidence, not live provider acceptance. No ambient cloud credentials or customer remote reads were exercised.

## F. Onboarding/customer flow

`/app/assurance` presents the six stages around a named system and environment. Customers review authority/actions/resources, three meaningful finance claims and the useful invoice task, establish a bounded baseline, inspect non-code changes/source health, then inspect independent security/task/applicability/enforcement dimensions and export a scoped record.

DECLARED means registered scope; CONNECTED requires source connectivity; OBSERVED requires the qualified exact test observation; PROTECTED additionally requires complete current support plus an acknowledgement bound to the exact displayed state and current decision. Every synthetic protected label is explicitly a sandbox boundary. A historical ALLOW after scope change does not remain a current supported UI action.

The full one-click finance workflow is **local/test only**. The prepared customer workflow uses existing target/observer qualification and worker APIs plus new environment/state APIs; it remains assisted rather than a completed universal hosted onboarding wizard.

## G. Subscription/entitlement model

One authoritative commercial domain resolves a frozen plan version, capabilities, system/environment/property-family quotas, verification units, retention allowance, trial, promotion and contract override. Callers ask capabilities and capacity rather than branching on plan names. Account locking serializes capacity and replay; all-history counts prevent pagination from bypassing limits.

System/environment creation, approved property allocation and reserved/settled verification are checked. Connector roles, schedule creation and scheduled execution recheck capabilities; invitations require collaboration entitlement. Existing access revocation, security explanations and historical truth remain available. Downgrades retain records and existing allocations; new activity stops deterministically when over allowance. In-flight reservations carry forward. An upgrade does not reset consumed units or change a signed decision.

## H. Exact current plan definitions

Bundled catalog version **2026-09-10.1**, externally replaceable through `TV_COMMERCIAL_CATALOG_PATH`. These prices are unvalidated hypotheses, not paid demand or a hosted SLA.

| Plan | Monthly USD hypothesis | Systems | Environments/system | Approved property families | Verification units/period | Retention allowance |
|---|---:|---:|---:|---:|---:|---:|
| Free | $0 | 1 | 1 | 5 | 500 | 14 days |
| Pro | $99 | 3 | 2 | 20 | 2,000 | 90 days |
| Team | $399 | 10 | 3 | 100 | 10,000 | 365 days |
| Business | $2,000 | 30 | 10 | 300 | 30,000 | 730 days |
| Enterprise | Custom annual contract | 30 base; override | 10 base; override | 300 base; override | 30,000 base; override | 730-day base; override |

The full machine-readable capability list is [commercial_plans.json](src/threatveil/data/commercial_plans.json). Free includes genuine signed records, API/CLI, explanations, basic GitHub and bounded MCP discovery/change and legacy imports. Pro increases capacity and adds configured automation/observation allowances; Team adds collaboration/shared approval/CI capability; Business adds advanced governance/production-enforcement allowances; Enterprise adds contract/private-deployment/support configuration. A capability in the catalog does not establish that SSO, private connectivity, a qualified observer or an external enforcement integration has been deployed.

A paired synthetic security trial and legitimate control cost two execution units. The three-property baseline with two trials per property uses 12 units. No automatic paid overages. Retention is currently an allowance, not plan-triggered physical deletion. Startup/student/OSS/partner promotion is a modifier on a plan, not a separate architecture.

## I. Billing implementation status

Local owner/admin mock commands support upgrade, scheduled downgrade/cancel, trial, payment grace/recovery, expiry, promotion and Enterprise overrides. Events are idempotent and revision-aware; conflicting replay is rejected. The browser uses the versioned catalog and exposes the simulation label. No mock event asserts paid revenue.

Stripe has a provider boundary, Checkout/portal, authenticated webhook reconciliation, current subscription/customer/invoice mapping and replay controls. Live charges are disabled by default. Explicit test-entitlement configuration is separate from live revenue and must be accepted with real Stripe TEST credentials after private cloud acceptance. No Stripe network transaction, customer, invoice or card charge was created by this task. Actual hosted lifecycle acceptance remains pending.

Enterprise local override exercises the shared engine. A separately authenticated hosted operator provisioning workflow is not implemented; hosted users cannot self-grant contracts. SSO, SLAs and professional services are scope configuration/future work, not delivered by buying the tier.

## J. P0 status with evidence

| Gate | Local result | Remaining external gate |
|---|---|---|
| P0-1 hosted GitHub path | Real local Next→FastAPI handler: valid direct/relay 202; modified/missing signature 401. Narrow App ID/private-key mounts API+broker, webhook secret API only; workers excluded. Terraform validate and 10 mocked tests pass. | Real hosted signed push, managed service identity, matching exact Check publication, bypass/stale-policy behavior |
| P0-2 machine full decision | Separate expiring exact-plan `tvrel_` grant invokes the canonical complete-property issuer; normal execute token retains developer scope. Wrong scope/policy/property/tenant/replay and authority changes rejected. SDK/CLI supports it. | Fresh security approval per exact plan/candidate and customer CI custody/external workflow; unattended full-release OIDC exchange is not implemented |
| P0-3 coherent onboarding | Three properties, paired useful task, qualified synthetic SQL observer, explicit stages and current exact-state acknowledgement passed HTTP/browser tests | Real system scope, independent observer/ground truth and customer decision acceptance |
| P0-4 cloud readiness | Read-only preflight checks role/FORCE RLS/head, signing/auth/origin/provider/images, budgets/alerts, rollback/recovery/retention profile. Local DB checks pass. | Actual configuration plus private cloud identity/isolation/delivery/restore/retention/rollback drills |

`.local/category-foundation/activation-readiness.json` intentionally has **configuration_ready=false, cloud_accepted=false** and exits 1. This is a correctly blocked activation, not a passing deployment test. See [P0 evidence](docs/P0_ACCEPTANCE_2026-09-10.md) and [GCP runbook](docs/GCP_DEPLOYMENT.md).

## K. Tests executed and failures

- Baseline Python: 469 passed, 15 warnings.
- First integrated Python run: 539 passed, one failure. The old HTML-escaping test created a second system under a newly enforced Free quota. Its setup was corrected to test escaping in the single allowed system; the capacity rule was retained.
- Full Python regression: **564 passed, 21 dependency deprecation warnings, 28.82 seconds**, recorded in `.local/category-foundation/final.log` and `final.xml`. The final measurement addition also passed all **5 focused tests** (`measurements-final.log` / `measurements-final.xml`), distinguishing currently supported scopes from exact current acknowledged protection.
- Production Next build passed; strict TypeScript passed after correcting unknown-valued JSX conditions.
- Full actual-browser suite against production build on isolated port 3100 and actual relay/API on 8200: **12 passed in 19.5 seconds**; after final finance/source changes, all **3 finance/commercial browser tests passed again in 5.1 seconds**. Includes original release/capture/pagination flows, new finance and commercial lifecycle, pricing and mobile overflow.
- TypeScript SDK build and **4 tests passed**. Python SDK exercised by the Python suite.
- Terraform validate and **10 mocked provider tests passed**. Real local GitHub relay HMAC acceptance passed.
- Standalone finance HTTP demo completed, independently verifying **8 signed records** with a configured operator public key rather than trusting the returned API key.

Evidence is under `.local/category-foundation/` and `.local/p0-acceptance/`; browser images are under `.local/browser-tests/`. These are local artifacts, not public service evidence. TestClient/dependency deprecation warnings are retained in logs. No failing assertion, build or type check remains in the executed acceptance. Private activation preflight remains an intentional external configuration failure.

## L. Adversarial scenarios exercised

Tenant/system/environment/candidate/repository/policy-epoch mismatches; omitted approved property; stale/expired/revoked authority; changed approver/policy; forged/tampered signature and wrong trust key; unsupported deployment scope; source outage/cursor loss/duplicate/reordered event; imported unknown/mixed components and declaration-only after-state; expanded envelope attempting old-evidence reuse; reviewed envelope refresh; incomplete/missing/attempted/pending/partial effect; missing useful-task commit; committed forbidden effect retained despite compensation; bad fix; superseded displayed state; wrong audience/nonce/epoch; replay and missing acknowledgement; signing-failure checkpoint retry; ACTIVE→REVOKED exception without erasing FAIL; billing event replay/downgrade/grace/trial/promotion/override expiry, quota exhaustion and history preservation. Legacy receipt verification remains in the regression suite.

These tests prove the specified bounded local semantics. They do not establish resistance to every attack or validate an external business observer.

## M. End-to-end demonstration

Run `uv run python scripts/change_assurance_demo.py --help` for exact invocation and independently trusted public-key argument. The final executed output is [.local/category-foundation/demo-final/summary.json](.local/category-foundation/demo-final/summary.json); the earlier independent run is retained under `demo/`. Final HTTP elapsed time was 1.544 seconds, meaningful only for this prepared local fixture.

1. Fresh organization received Free and registered the Finance Agent with three approved properties.
2. Baseline was PASS + SUCCESS → ALLOW, separately acknowledged in the local registry at epoch 1.
3. A second system was denied with 402. Mock Pro enabled it; no payment or assurance-history change was claimed.
4. Canonical imported MCP permission change affected prior support and produced REQUIRE_APPROVAL. It remained IMPORTED, not live-connected.
5. Regressed approval committed a forbidden beneficiary update from the synthetic original account to the synthetic attacker account. Correlated SQL evidence retained FAIL → BLOCK while legitimate invoice work succeeded.
6. Bad fix denied useful updates: security PASS, useful task FAILURE → BLOCK.
7. Proper fix restored both security and useful work: ALLOW. A separate exact acknowledgement advanced the local registry to epoch 2.
8. Eight old/new-profile records verified independently; Free downgrade was scheduled and retained historical FAIL unchanged.

No real beneficiary, customer data, provider payment or deployed permission was modified. Artifacts retain before/after effect, correlation, evidence, decision and verification results for review.

## N. What is production-ready

No hosted ThreatVeil product is claimed production-ready from this work. The foundation builds, preserves the existing kernel and passes bounded local acceptance. The code is ready to enter the private deployment configuration/acceptance process, subject to its explicit preflight failures. Public signup, charging and customer BLOCK enforcement are not accepted release states.

## O. What remains local/test-only

One-click synchronous finance orchestration; same-process synthetic SQL qualification; mock plan changes/promotions/Enterprise provisioning; sandbox compare-and-set acknowledgement; mocked connector/provider and Terraform acceptance. A local `PROTECTED` label is not evidence of a real customer or running production deployment. There is no synthetic backdoor in hosted identity, mock billing or finance one-click routes.

## P. What requires GCP

Authorized private project/region/deployment identity and spend ceiling; reviewed immutable current/prior images; managed auth/origin; secret references and signing-key custody/trust; role/IAM checks; two-tenant isolation; actual broker/worker denial and delivery; alerts/budget response; backup restore and projection recovery; retention/erasure boundaries; rollback. Read-only preflight has concrete expected inputs and cannot set cloud acceptance true. No infrastructure apply occurred.

## Q. What requires Stripe credentials

After private cloud acceptance: `sk_test_` credentials, signed test webhook secret, configured catalog Price IDs, explicit test-entitlement mode, test customers/payment methods, actual Checkout/portal and upgrade/downgrade/cancel/failure/replay acceptance. Test allowances must remain separate from paid revenue. Live credentials/charges require explicit authorization; flags remain false by default.

## R. What requires a real customer

Reviewed consequential system/environment/resources and decision owner; authentic current component/permission changes; permitted/forbidden and useful-task fixtures; independent qualified business-state observer, reset/correlation/commit semantics; accepted external decision/enforcement consumer; integration reliability and false-warning adjudication; actual support/verification cost, repeat use, second-system adoption, willingness to pay and conversion. Instrumentation can record this evidence; synthetic fixtures cannot supply it.

## S. Deliberately not built

Generic IAM/credential brokerage, an identity provider, an observability backend, universal inventory/firewall/red-team platform, CI/CD or ServiceNow replacement, a graph database, data lake, payment processor, autonomous remediation, wallets/A2A/robotics/physical control, quantum security, public reputation, insurance, fifty shallow integrations or proprietary cryptography. No claims of automatic independent qualification, full runtime discovery or real customer enforcement.

## T. Architectural debt and limits

The immutable Record store avoids a risky rewrite but full-history projections need measured indexing/pagination/caching work before large-scale claims; reads can take system locks. Subscription expiry reconciles on use. Retention allowances do not automate lifecycle/erasure. Connector gaps/configuration changes fail closed and may need manual reviewed reconciliation. Relationship assertions are traceability, not a full reasoning graph. PRODUCTION state qualification needs an actual deployment observer profile before positive support.

The local finance guard holds one DB connection across nested run transactions; high concurrent same-system requests can consume the pool. Durable checkpoints preserve exact state and retry accounting, but this is not a general hosted workflow orchestrator. Crypto rotation/trust distribution remains operational; only one algorithm profile is implemented. External acknowledgement ingestion/delivery and independently authenticated consumer outcome are future qualified adapters. Hosted contract provisioning and actual Stripe TEST acceptance remain separate implementation/external gates. Advanced catalog capabilities describe allowance, not deployed feature completeness.

Operational measurements distinguish currently supported scopes from exact current acknowledged protected scopes, and synthetic systems from customer systems. They are minimized tenant aggregates and optional explicitly consented enum/numeric reports. Self-reported influence, cost and support effort are labeled as such; neither research consent nor a plan upgrade automatically enables training or cross-customer data export.

## U. Exact recommended next action

Have the deployment owner prepare a reviewed private-GCP activation profile from `infra/activation-profile.example.json`, including project/region, immutable images, explicit budget, managed identity, key trust references and rollback/recovery owners. Run the read-only preflight and resolve each failed configuration gate. Then obtain authorization for the private infrastructure operation and execute the documented cloud acceptance drills. Only after that, enable explicit Stripe TEST configuration and perform the real hosted signup/billing lifecycle, followed by one prepared design partner with independent business-effect observation.

The local implementation work does not authorize infrastructure application, real charges, external communications or changes to customer systems.
