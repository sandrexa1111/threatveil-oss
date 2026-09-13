# ThreatVeil — Category-Complete Commercial Platform Report

**Date:** 11 September 2026. **Scope:** the local repository only.

Nothing outside the local machine was touched:

- no GCP resource was created and no Terraform was applied
- no Stripe call was made and no card was charged
- no customer, provider or external system was contacted or modified

Isolated acceptance ran in local Colima containers.

## A. Executive result

# READY_FOR_PRIVATE_GCP

Every pre-existing test still passes, and no security invariant was relaxed. `cloud_accepted` is still false and `configuration_ready` is still false. The read-only preflight fails only on the eleven external deployment inputs it failed on before.

ThreatVeil now answers the four customer questions directly: **What can my AI system do? What changed? Which security conclusions still hold? Is it still cleared to act?** It then provides the **Assurance Gate** for machines and the **Current Assurance Passport** for organizations, and it accumulates **historical assurance memory**.

The wow moment is implemented, tested, and demonstrable in five minutes:

> A tool permission changed outside any repository. ThreatVeil said "Beneficiary update authority expanded". It named the one claim whose evidence stopped applying, confirmed the other two still held, and marked the earlier clearance SUPERSEDED while leaving its signed record authentic.

| Gate | Result |
|---|---|
| Python suite | **654 passed**, 0 failed, 21 dependency warnings (baseline **603**) |
| Ruff | clean |
| Strict TypeScript (web) | clean |
| Next.js 16.3.4 production build | passed (11 routes, including the public `/passport/[token]`) |
| Browser suite (Playwright) | **14 passed** (baseline 13; one new canonical-demo test) |
| TypeScript SDK | build + **5 passed** (baseline 4) |
| Terraform 1.16.1 | `validate` success + **10 mocked tests passed** |
| Canonical demonstration (HTTP, independent verification) | completed; all 6 steps asserted; passport verified by trust directory and independent key; authentic after change, status SUPERSEDED |
| Activation preflight | `configuration_ready=false`, `cloud_accepted=false`; `database` and `provider_contract` pass; the 11 failures are external inputs |

## B. Repository state inherited

- **Database:** head `0007`.
- **Python baseline:** reproduced exactly, 603 passed and 0 failed (`--junitxml` count).
- **Git:** the repository has no commits and everything is untracked, so there is no diff to review. A snapshot was taken before any change (session scratchpad, `threatveil-baseline-snapshot.tgz`).
- **Architecture:** FastAPI/Next.js/PostgreSQL modular monolith.
- **Storage:** an immutable tenant-scoped `records`/`record_edges` store under FORCE RLS with append-only triggers.
- **Change-assurance domain:** environment, permission envelope, system state, source assertions, change events, assurance cases, signed short-lived authorization decisions, and separate enforcement request/acknowledgement.
- **Release integrity:** ProofScopes, complete-property releases and DSSE receipts.
- **Commercial:** a versioned catalog with capability entitlements.
- **Trust:** a trust directory with rotation semantics.
- **MCP:** dual-era support.
- **Hosted execution:** asynchronous, with broker/worker separation.
- **UI:** six primary questions, with advanced surfaces under an Advanced group.

`THREATVEIL_AMBITION_FOUNDATION_REPORT.md` does not exist in the repository.

Conflicts between the mandate and the code were resolved in favor of the code:

- A signed decision lives at most five minutes. So "is it still cleared" is a recomputed **clearance status**, separated from the signed statement's lifetime. It does not auto-issue signatures on reads.
- Today's source-change handling treated every unmapped change as reaching every claim. Precision therefore required reviewed source→dependency mappings, not inference.

## C. Existing functionality preserved

All 603 historical tests still pass. The single test whose assertion changed is `test_connectors.py::test_finance_assurance_reassesses_after_imported_permission_change_and_fresh_proof`. An **observed** source change that moved an ALLOW's support now reads `SUPERSEDED` instead of `REASSESS`. This is deliberate: the system was observed to change. Both statuses are non-current, the test's source-outage counterpart still asserts `REASSESS`, and the change is documented in the test.

These are unchanged:

- decision issuance, signing and verification
- `_decision_status()`, which still returns EXPIRED first
- the enforcement binding checks and the release semantics
- the commercial engine, the MCP protocol handling and the trust directory

The browser navigation test was updated for the new labels, and the journey step labels were renamed; the finance journey browser test still drives the same flow. Customer-facing "experiment" wording was replaced with "verification".

## D. What was added

| Area | Implementation |
|---|---|
| Source semantics | `source_semantics.py`: bounded authorization facts, `authority-semantics/v1` direction lattice, named change subjects, reviewed mapping scope |
| Precise consequence | projection honours fully mapped late source changes; rows record `affected_by`; `save_mapping` (append-only, validated) |
| Clearance status | `clearance_status()` separated from signature lifetime; observed-change SUPERSEDED |
| Assurance intelligence | `assurance_intelligence.py`: system map, authority map, authority diff, change consequences, evidence currency, lifecycle/cycles, re-establishment, memory, summary, gate |
| APIs | `assurance_api.py`: `/v1/systems/{id}/{intelligence,summary,system-map,authority,authority/changes,changes,evidence-currency,lifecycle,reestablishment,history,assurance/current,dependency-mappings,claim-definitions,passports}`, `/v1/passports/{id}[/share|/revoke]`, `/v1/passports/shares/{id}/revoke`, `/v1/public/passports/{token}` |
| Passport | `passports.py` (issue, status, HMAC share capabilities, public view, hourly check records) and `sdk/passports.py` (sign/verify, directory verify) |
| Activation / GTM | `activation.py`: milestones, funnel, PQL signals, upgrade moments, `/v1/commercial/interest` |
| Finance sandbox | a synthetic MCP tool gateway connected at setup with package-reviewed mappings; four enumerated sandbox-only changes |
| MCP facts | `authorization`, `catalog_parts` and `tool_components` retained on batches |
| UI | `intelligence.tsx`: executive summary, canonical demo panel, system map with trace, authority map, authority diff, change feed, evidence currency, re-establish, clearance plus gate plus memory, and Passport. Also three-group navigation, a public `/passport/[token]` page, and browser Ed25519 verification (`lib/verify.ts`) |
| SDK / CLI | Python and TypeScript `current_assurance` / `currentAssurance` with fail-closed `is_cleared` / `isCleared`; passport methods; `threatveil assurance-current --require-cleared`; `threatveil verify-passport` |
| Scripts | `scripts/canonical_demo.py` (resettable, `--stop-at`), `scripts/container_acceptance.sh` |
| Schemas | `schemas/assurance-gate-v1.schema.json`, `schemas/assurance-passport-v1.schema.json` (also in `sdk/schemas/`) |
| Docs | ASSURANCE_GATE, ASSURANCE_PASSPORT, SYSTEM_INTELLIGENCE, SECURITY_REVIEW, CANONICAL_DEMO, DESIGN_PARTNER, FRONTIER_EXTENSIBILITY, ACTIVATION_METRICS; updates to CHANGE_ASSURANCE, COMMERCIAL_PLATFORM, INTEGRITY_LAUNCH, CONNECTOR_CONTRACT, KNOWN_LIMITATIONS, README, public product page |
| Tests | 51 new Python tests in 6 files; 1 new browser test (the canonical demo end to end, including external verification in a separate browser context); 1 new TS SDK test |

## E. Why the additions strengthen the business

Each addition, and the business test it serves:

- **Authority Map + Authority Diff** — comprehension and the wow moment. The prospect sees their agent's real powers, and sees exactly how one of them moved.
- **Mapped change consequence** — the difference between "something changed, re-test everything" (noise, churn) and "one claim needs re-proof, two still hold". The mapping is customer-specific and compounds: switching cost comes from accepted history, not lock-in.
- **Assurance Gate** — the beginning of operational dependency. A CI job or an agent runtime asks ThreatVeil. Gate consumption is measured.
- **Passport** — revenue acceleration for the customer, since it shortens their enterprise security reviews. It is external acceptance for ThreatVeil, and a distribution loop: every buyer sees ThreatVeil and can verify without an account.
- **Re-establish + useful-task rule** — differentiation from blockers. Clearance returns only when the bad outcome is prevented *and* the good outcome still works.
- **Memory** — retention. It becomes more useful after 10, 50 and 100 changes, and it is honest about small samples.
- **Activation and PQL instrumentation, upgrade moments** — time to value and conversion, measured from server records. Synthetic activity is never counted.
- **Claim definitions, security-review answers, Integrity Launch** — design-partner and enterprise readiness.

## F. Target customer

AI-native B2B companies (about 20–250 employees) whose agents take consequential write actions: AP/invoice, procurement, claims, CRM/revenue, provisioning, support/refunds, finance operations. They release weekly or faster, sell to enterprises, and have a small security team.

## G. Buyer jobs

| Buyer | Job | Served by |
|---|---|---|
| Founder/CEO | enterprise trust without six-month reviews | Passport, security review answers |
| CTO/VP Eng | ship fast while knowing what still applies | change consequence, re-establish plan |
| AppSec | exact change, assumptions, current evidence | authority diff, evidence currency, system map |
| Head of AI Platform | a machine-readable answer | Assurance Gate, SDK/CLI |
| Enterprise buyer | evidence about today's agent | shared Passport with current status |

## H. System Intelligence

The System Map is a projection of the record store. There is no graph database.

- **Node kinds:** AGENT, MODEL, PROMPT, TOOL, MCP_SERVER, API, IDENTITY, PERMISSION, MEMORY, DATA_SOURCE, DEPLOYMENT, CODE, SUBAGENT, AUTHORITY_BOUNDARY, AUTHORITY, AUTHORITY_FACT, BUSINESS_RESOURCE, BUSINESS_EFFECT, CLAIM, EVIDENCE, DECISION, SOURCE, CHANGE, UNKNOWN.
- **Provenance per node:** DECLARED, CONNECTED, OBSERVED, VERIFIED, IMPORTED or UNKNOWN.
- **Edges:** every edge cites its record.

The UI traces COMPONENT → AUTHORITY → CLAIM → EVIDENCE → CHANGE → DECISION. Tests assert:

- only the reviewed boundary PERMITS authority
- no tool or source ever grants it
- delegation is inert
- unknown dependencies stay unknown
- tenant isolation holds

## I. Authority Intelligence

For each declared action the map shows:

- label and resources
- principal and environment
- tools and interfaces, each with its basis
- declared constraints, plus source-declared conditions labelled unreviewed
- source and freshness
- governing claims and the assurance status

The basis is DECLARED, CONNECTED, OBSERVED or VERIFIED. Tools reported outside the boundary are listed with basis UNKNOWN and are never permissions. A test covers DECLARED → VERIFIED → OBSERVED as the evidence moves, and UNKNOWN for an unreviewed interface.

## J. Authority Diff

`authority-semantics/v1` classifies direction from structured facts only:

- restriction conditions (approval, tenant binding, read-only, …)
- scope lists
- interface exposure
- declared-boundary revisions

Everything else is UNKNOWN_IMPACT. Mixed movement is EXPANDED, because the new boundary is not contained in the old. A new interface's own restrictions do not read as a contraction. Server metadata changes are EQUIVALENT, and a reworded constraint is UNKNOWN.

Canonical output: BEFORE `approval_required=true, tenant_bound=true` → AFTER `approval_required=false, tenant_bound=true`, **AUTHORITY EXPANDED**. The consequence reads: 1 claim affected, 1 evidence package stale, 2 claims still hold, previous clearance SUPERSEDED, and "Required: Re-establish 'Beneficiary changes require finance approval'".

Tests cover expansion, contraction, equivalence, unknown, ambiguous/mixed, one-sided capture, bounds, new interfaces and envelope revisions.

## K. Change Intelligence

Each change (source change, state transition, boundary revision) reports:

- what changed, as named subjects
- origin, acquisition, qualification and time
- the authority diff
- the claims it reaches, and through which dependency
- the evidence that relied on the previous state
- what still holds
- whether it is open, covered by later verification, or affected no claim
- the prior clearance's recomputed status
- a deterministic explanation, whose stability is tested

Scoping requires **every** named subject to carry a reviewed mapping. One unmapped subject — for example a newly exposed payment tool — keeps every claim in review (tested).

## L. Evidence Currency

"Security evidence has a shelf life" is the headline of the What still holds view. Each claim shows CURRENT, STALE, INVALID or UNKNOWN in customer language, plus:

- when its evidence was produced, and whether that was for this state
- the change that affected it
- the forbidden outcome and the useful task
- the security and useful-task outcomes

Business-language claim definitions show as "Defined; not yet executable".

## M. Clearance Lifecycle

The lifecycle runs BASELINE ESTABLISHED → CURRENT → RELEVANT CHANGE → CLEARANCE SUPERSEDED → REASSESSMENT REQUIRED → RE-PROOF → CLEARANCE RESTORED. It is computed in one chronological pass over decisions and loss moments. Historical decisions are immutable, and current status is recomputed.

Tests cover:

- a prior ALLOW that becomes SUPERSEDED while its DSSE envelope stays byte-identical and still verifies
- completed cycles with a cause, attempts and restore seconds

## N. Re-establish Assurance

The re-establishment plan has seven steps:

1. what changed
2. affected claims
3. what still holds
4. what needs fresh evidence
5. security checks to run, rendered from predicates
6. the legitimate task that must still succeed
7. what restores clearance

The latest outcome is SECURITY_FAILED (not cleared), USEFUL_TASK_FAILED (not cleared, even though security passed) or RESTORED. The sandbox runs cases A, B and C (tested through the API and the browser). ThreatVeil coordinates; it never remediates.

## O. Assurance Gate

`GET /v1/systems/{id}/assurance/current` returns a compact contract with:

- system, environment, state digest, and authority/envelope digest with policy epoch
- status and decision action
- `cleared` and `authorizes:false`
- a scoped-action answer and the affected claims
- obligations, and the decision ID with its status and record URIs
- freshness, issuer/profile, and a consumer contract

Read-only API tokens can call it. Consumption is recorded at most once per consumer label per hour.

## P. Gate semantics and consumer contract

Tests cover:

| Case | Asserted outcome |
|---|---|
| Clearance holds | CURRENT; `cleared=true` |
| Observed change | SUPERSEDED |
| Scoped action | an action can remain SUPPORTED while the system is SUPERSEDED |
| Authority or observation lapsed | EXPIRED |
| Live source outage | REASSESS |
| Clearance withdrawn | REVOKED |
| No environment | UNKNOWN, never cleared |
| Stale expected state | SUPERSEDED |
| Wrong tenant | 404 |
| Machine token | read-only access works; it cannot issue passports |

Freshness is at most 60 seconds, and HTTP responses remain `no-store` because they carry tenant data. Offline authenticity (DSSE) is separate from online current state. Availability policy — fail-open or fail-closed — belongs to the consumer. Future consumers (GitLab, Kubernetes admission, runtimes and gateways, IAM, ServiceNow, buyer systems) all read this contract. See [docs/ASSURANCE_GATE.md](docs/ASSURANCE_GATE.md).

## Q. Current Assurance Passport

It comes in three forms:

- a human view, both in-app and on a public page that needs no account
- machine JSON with a published schema
- a signed DSSE/in-toto record (new predicate type, existing Ed25519 key and trust directory)

It carries:

- system, environment and state
- consequential authority in plain language
- supported, needs-fresh-evidence, failed and unknown claims
- evidence status
- clearance at issue
- where to check status
- limitations and explicit non-claims: not a certification, not a trust score

Internal machinery is not exported (tested).

## R. External Verification

Authenticity can be verified three ways:

- offline, with a key or a trust directory (`verify_passport*`, `threatveil verify-passport`, tested for success and for tampering, wrong key and wrong scope)
- in the browser, with WebCrypto Ed25519 over the DSSE pre-authentication encoding, checking the directory status and validity window
- via the directory, rotation-aware

Current status is separate: CURRENT, SUPERSEDED, REASSESS, EXPIRED or REVOKED. Tested: after the system changes, the shared passport is **still authentic** and reads **SUPERSEDED**; forged tokens return 404; a revoked share returns 410; a revoked passport reads REVOKED.

## S. Historical Assurance Memory

It reports:

- observed changes by authority class
- decisions, clearances, restorations and re-proof attempts
- how many changes reached each claim, and how many it survived
- restoration durations
- sources not current

A pattern is reported only after three comparable observations (tested below and above the threshold). There is no ML and no prediction.

## T. Customer Activation Journey

The path is: Start free → name the system → confirm the environment → connect the first source → define consequential actions → define or confirm critical claims (business-language definitions for real systems, templates or approved checks) → baseline → current clearance → observe a change → see its assurance consequence.

The journey steps were relabelled: System & source · Authority · Claims · Baseline · Watch · Decide. The Systems screen then leads with the protected-system summary and, for the sandbox, the six-step demonstration panel.

## U. Activation Event

The activation event is `FIRST_MEANINGFUL_ASSURANCE_EVENT`: after a current clearance, ThreatVeil observed a change and established its consequence for at least one claim. It is derived from the same lifecycle the customer sees, and synthetic systems are tracked separately (tested).

## V. Time-to-Value instrumentation

`/v1/measurements/activation` reports each milestone's time from signup, each funnel conversion with elapsed seconds, 30-day consumption (gate hours, machine gate hours, external passport checks, shares, changes, decisions), expansion (systems, environments, members), and self-reported support minutes.

It is tenant-private, carries no names or evidence (tested), and uses no browser tracker.

## W. Product-Qualified Lead signals

The endpoint records:

- production environment created
- third system requested
- BLOCK policy attempted
- external Passport shared
- collaborators active or collaboration requested
- high verification usage
- qualified observer requested
- external assurance consumer attempted
- private deployment, enterprise retention, production enforcement or design partner requested (explicit, idempotent interest records)

No one is contacted.

## X. Subscription and upgrade logic

The catalog, prices and engine are unchanged. Upgrade moments come from capabilities and facts, never from plan-name branches; the plan offered is the least expensive self-service plan in the catalog that carries the missing capability.

| Moment | Plan offered |
|---|---|
| First clearance without `enforcement.ci` | Pro |
| System allowance used | the next plan with more systems |
| PRODUCTION environment without `enforcement.production` | Business, "where a qualified enforcer exists" |
| A second reviewer, or a refused invitation, without `approval.workflow` | Team |
| ≥80% of the verification budget used | the next plan with a larger budget |

Free experiences the whole category, including the Gate and Passport sharing (tested). Business fabricates no integration: external requests stay `AWAITING_QUALIFIED_ENFORCER`. Every assurance view is identical before and after an upgrade (tested).

Expansion from 1 to 10 systems follows naturally, because each consequential workflow is its own protected system with its own history.

## Y. Design-Partner Readiness

A partner can define:

- system and environment
- consequential actions
- permitted and forbidden outcomes
- a legitimate control task and a ground-truth source (claim definitions)
- critical claims (definitions, then approved executable properties)
- observers and sources
- reviewed mappings
- evidence
- decision, Gate and Passport

No architectural reconstruction is required. See [docs/DESIGN_PARTNER.md](docs/DESIGN_PARTNER.md).

## Z. Integrity Launch

Integrity Launch is an installed-product activation program, not consulting. It delivers:

- one system and one workflow
- 3–5 critical claims
- a baseline
- connected monitoring with reviewed mappings
- current clearance and a Passport
- an Assurance Gate consumer where supported
- 30 days of history

Production outcomes are not promised without a qualified enforcer. See [docs/INTEGRITY_LAUNCH.md](docs/INTEGRITY_LAUNCH.md).

## AA. Canonical Five-Minute Demo

The demo is run with `scripts/canonical_demo.py` (fresh local organization per run; `--stop-at cleared` hands a live workspace to the founder) or in the product UI. See [docs/CANONICAL_DEMO.md](docs/CANONICAL_DEMO.md).

1. **Current:** Cleared, 3 of 3 claims.
2. **Change:** the gateway relaxes beneficiary approval.
3. **Consequence:** authority expanded; 1 claim affected; 2 hold; prior clearance SUPERSEDED.
4. **Re-establish:** A, security fail, BLOCK; B, useful work broke, BLOCK; C, restored, ALLOW.
5. **Machine:** the Gate returns CURRENT and cleared.
6. **External:** the passport is shared and verified by the trust directory and by an independent key; after a second change it is still authentic and its status reads SUPERSEDED.

The script asserts every step.

## AB. Enterprise Buyer Experience

The buyer opens a link, needs no account, and reads a plain-language passport:

- system
- powers
- which claims current evidence supports
- what needs fresh evidence
- limitations and non-claims
- the current status, recomputed now

They press "Verify authenticity in this browser" and see the signing key and its status.

## AC. Security Review Readiness

[docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) answers each required question:

- data collected and never collected
- credentials, execution, storage and signing
- production access
- observation qualification
- unavailability
- what ALLOW and UNKNOWN mean
- independent verification, and authenticity versus status
- isolation, billing, and explicit non-claims

No certification is claimed.

## AD. Frontier Agentic Extensibility

[docs/FRONTIER_EXTENSIBILITY.md](docs/FRONTIER_EXTENSIBILITY.md) maps the frontier platforms onto SYSTEM · COMPONENT · STATE · AUTHORITY · RELATIONSHIP · CHANGE · EFFECT · EVIDENCE · DECISION, as sources and consumers. **None of these integrations is implemented beyond what existed before:**

- Anthropic (ConfigChange)
- OpenAI (Connector Registry)
- AWS AgentCore (Gateway, Identity)
- Microsoft Agent 365 / Entra Agent ID
- Google Vertex/ADK
- MCP (implemented)
- A2A (inert seam)
- multi-agent delegation (containment check with the same lattice, when qualified)
- browser agents
- autonomous commerce and mandates

Two boundaries hold. The delegation seam stays inert. On identity, ThreatVeil never becomes an identity provider; its question remains "does current assurance support the authority associated with this identity?"

## AE. Vibe-Code Resilience

**Cloneable in weeks:**

- the projections and UI
- the authority lattice
- the gate and passport formats (intentionally distributable)
- the verifier and schemas

**Compounds only through real use:**

- accepted baselines per customer system
- **customer-reviewed dependency mappings**
- authority history, change→consequence history and re-proof cycles with restore times
- passport shares and external status checks, meaning buyers who expect them
- machine consumers wired to the gate
- claim-survival memory
- qualified observers per workflow

The implementation records each of these from day one, in tenant-private, append-only form.

## AF. Security invariants

These are preserved, with the full historical suite passing unchanged:

- explicit UNKNOWN
- no fake positive evidence (mappings narrow scope but never discharge, qualify or grant)
- append-only history, tenant isolation and FORCE RLS (new kinds inherit them; cross-tenant 404 is tested for every new endpoint)
- billing/security separation (tested)
- exact state, envelope, audience, nonce and policy-epoch binding (untouched)
- decision status recomputation (refined, still non-current for every failing case)
- qualified evidence and useful-task checks
- sandbox isolation (simulate-change accepts only four enumerated changes on finance-v1 SANDBOX systems; no payload input)
- key rotation and trust-directory verification (passports reuse them)
- authenticity/status separation
- broker/worker separation (no new execution path)

Share tokens use an HKDF-derived HMAC key, so the attestation key never signs capabilities. The public route exposes one passport per capability, and is rate-limited.

## AG. Performance

Local measurements (`.local/intelligence-performance.json`), median of 5 requests in ms, as observed source changes accumulate:

| Changes | System map | Authority | Authority diff | Gate | History | Intelligence (all views) | Passport issue |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | 30.5 | 19.7 | 19.6 | 29.7 | 19.3 | 32.6 | 59.7 |
| 10 | 23.0 | 21.1 | 22.6 | 21.8 | 21.2 | 43.0 | 41.3 |
| 50 | 27.5 | 25.7 | 31.2 | 26.4 | 27.6 | 77.6 | 51.6 |
| 100 | 34.5 | 32.1 | 40.1 | 34.7 | 44.5 | 147.4 | 67.7 |

The number of projections per request is bounded and independent of history (tested). Change views are memoized per request and limited to the latest 50. History aggregates read all changes, so growth is linear, and they remain the documented record-store debt. The record store was not rewritten.

## AH. Full regression results

| Command | Result |
|---|---|
| `uv run pytest -p no:cacheprovider` | **654 passed**, 0 failed, 21 warnings, 44.2 s |
| `uv run ruff check src/ tests/ scripts/` | clean |
| `tsc --noEmit -p apps/web/tsconfig.json` (host, borrowed Node 24) | clean |
| `pnpm build` (container, Next 16.3.4) | passed |
| `npx playwright test` (container, isolated Postgres 17, non-superuser NOBYPASSRLS runtime role) | **14 passed** in 28.2 s |
| `pnpm test:sdk` (container) | **5 passed** |
| `terraform init -backend=false && validate && test` (container, 1.16.1) | valid; **10 passed** |
| `scripts/canonical_demo.py` (container, independently exported key) | completed (gate median 38 ms, passport issue 146 ms, public status 69 ms) |
| `python -m threatveil.activation_readiness --profile infra/activation-profile.example.json` | correctly blocked (§AJ) |

New Python test files, all passing:

- `tests/core/test_source_semantics.py` (10)
- `tests/core/test_passport_cli.py` (2)
- `tests/integration/test_assurance_intelligence.py` (16)
- `tests/integration/test_assurance_gate.py` (10)
- `tests/integration/test_assurance_passport.py` (6)
- `tests/integration/test_activation_commercial.py` (7)

Browser suite changes: `apps/web/tests/assurance-intelligence.spec.ts` is new. MCP, commercial and trust-directory suites are all within the Python total. Container logs are in `.local/container-acceptance/`; the reusable harness is `scripts/container_acceptance.sh`.

Defects found and fixed during the session:

- a shadowed `scoped()` name in the projection
- a clearance cycle lost only through a source change was not counted as restored
- a passport issued while reassessment was already pending read SUPERSEDED immediately
- a new interface's restrictions read as a contraction
- mixed timezone offsets in outputs

## AI. What was deliberately NOT built

Per the anti-roadmap, none of the following was built:

- generic inventory, a runtime or prompt firewall, DLP
- an identity provider, a secrets broker
- a red-team or evals platform, CSPM, SIEM or SOC, a compliance dashboard, a CVE dashboard
- a universal score, a marketplace
- a graph database, cross-customer ML
- autonomous remediation
- robotics, quantum or insurance products
- a second synthetic vertical
- new provider connectors (AgentCore, Agent 365, Vertex, Connector Registry, Anthropic ConfigChange, A2A execution)

Also not built:

- automatic signature renewal on read
- a pattern predictor
- a transparency log
- a second signature algorithm

## AJ. Remaining GCP requirements

These are unchanged external inputs (`.local/activation-readiness-category-complete.json`):

- `managed_auth_origin`, `receipt_signing`, `trust_directory`, `managed_storage`, `cloud_dispatch`
- `github_app`, `immutable_images`, `rollback`, `alerts`, `cost_guardrails`, `recovery_retention`

Passing: `database` (head `0007`, non-superuser NOBYPASSRLS role, FORCE RLS) and `provider_contract`.

Cloud acceptance still pending:

- managed login
- two-tenant isolation in the deployed runtime
- real signed GitHub ingress and check delivery
- worker IAM, bootstrap and replay denials
- signed-record verification against the provisioned trust root
- a reachable public trust directory and passport page on the hosted origin
- delivered alerts
- backup restore
- rollback

## AK. Exact next action

# PRIVATE GCP ACTIVATION

1. Prepare and review the private activation profile from `infra/activation-profile.example.json`.
2. Provision the operator signing key and an operator-managed trust directory before the first hosted record or passport is signed. Passport share links derive from that key.
3. Review the Terraform plan, cost and IAM changes, then obtain explicit authorization for the apply.
4. Perform cloud acceptance: two-tenant isolation, a real worker completing a hosted Free assessment, and the Assurance Gate and a shared passport on the hosted origin.
5. Then recruit the first design partner, using an Integrity Launch against one real consequential workflow.

Local product expansion stops here. The limiting resource is now real customers.

## Appendix — how acceptance was run

This machine still has no Node on PATH. Strict TypeScript ran with the Node 24 bundled in ChatGPT.app, read-only. The production build, browser suite, SDK and canonical demonstration ran in `mcr.microsoft.com/playwright:v1.63.0-noble` against an isolated `postgres:17-alpine`, using the same role model as `scripts/local_db.sh`; the harness is `scripts/container_acceptance.sh`. Terraform ran in `hashicorp/terraform:1.16.1`, on a copy of `infra/`.

Harness problems found and fixed during this session (none were product defects):

- the web server was started without `TV_ENV`/`TV_LOCAL_AUTH`, so the local sign-in form never rendered
- the browser fixtures' seed scripts need `.local/database.env`, which the harness did not create

**Before deploying, re-run `pnpm build` and `pnpm test:web` on a machine with a normal Node installation.**
