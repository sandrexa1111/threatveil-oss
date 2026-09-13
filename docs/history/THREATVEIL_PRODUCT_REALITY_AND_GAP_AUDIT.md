# ThreatVeil — Product Reality and Gap Audit

**Date:** 2026-09-13
**Tree audited:** commit `f111858` plus the uncommitted working tree (three UI waves)
**Status on entry:** `READY_FOR_PRIVATE_GCP`, `cloud_accepted = false`
**Question:** does the product we have deliver the company we believe we are building, and what must exist before ThreatVeil goes into the real world?

---

## How this audit was done

Every rating uses this confidence ladder:

| Level | Meaning |
|---|---|
| L1 | Real working customer flow. **None exists**: there is no real customer and no hosted deployment. |
| L2 | Tested product/API implementation, re-verified live in this session. |
| L3 | Backend implementation with no customer surface. |
| L4 | Architectural seam. |
| L5 | Documented intention. |
| L6 | Idea only. |

Evidence produced in this session (artifacts in git-ignored `.local/reality-audit/`):

| ID | What was run | Result |
|---|---|---|
| **E1** | Full Python suite on this tree, real PostgreSQL 17 | **710 passed, 0 failed, 0 skipped** (52 s), `pytest.xml` |
| **E2** | Canonical Finance demo against a live local API | Completed. `approval_required true→false` → `AUTHORITY_EXPANDED` → 1 claim affected, 1 evidence stale, 2 hold → prior clearance `SUPERSEDED` and still authentic → re-establish (FAIL → not cleared; PASS + useful-task failure → not cleared; PASS + SUCCESS → restored) → Gate `CURRENT` → Passport verified with the trust directory and an independent key, `CURRENT → SUPERSEDED`, authentic after the change. `demo.log` |
| **E3** | Non-fixture customer flow over HTTP: Claude Code `settings.json`, CrewAI `agents.yaml`, a raw MCP `tools/list` catalog; 2 declared claims, 2 reviewed mappings, 10 proposed changes, 1 observed import, "was this right?" feedback, a declared state, Gate, Passport | 45 API calls, 0.5 s machine time; first claim-level answer at call 17. `live-flow.json` |
| **E4** | Probe of operator surfaces around an evidence-less state | Three truth defects confirmed. `probe.json` |
| **E5** | Non-synthetic clearance experiment: signed customer collector over an HTTP target (simulated transport, the technique `tests/integration/test_observers.py` uses), then an agent-definition import into the same environment, then two full re-verifications | **CLEARED → SUPERSEDED → never restored.** `experiment2.log` |

**Not re-run in this session:** Playwright (22 reported by the completion wave), TypeScript SDK (5), Terraform (10), container acceptance. No GCP, GitHub App, Stripe, email or real customer target was touched. Statements about the web UI come from reading components, not from a browser run today.

The temporary experiment test was deleted after it ran, and the API and database started for the audit were stopped. Local audit organizations ("Reality Audit Co", "Probe Co") remain in the local development database.

---

## A. Executive verdict

**The architecture implements the thesis. The product delivers it only to the synthetic Finance fixture.**

### What is genuinely there, and verified

- **A conservative assurance kernel.** Evidence is bound to an exact state and invalidated per claim through reviewed mappings. `PASS + useful-task failure = not cleared`. Clearance is recomputed from append-only records and a historical decision stays authentic while no longer current (E1, E2, E5-A).
- **A Gate that never authorizes and a Passport with two separate facts.** Its authenticity is signed and verifiable offline; its current status is recomputed on request (E2).
- **A self-serve "what would this change break?" for declared agent configuration** that works on real formats. It handles Claude Code permission rules, CrewAI delegation and tools, the ThreatVeil manifest, and MCP interface exposure, and never mutates current assurance (E3).
- **A non-synthetic system can reach CLEARED** through the generic signed-collector path (E5-A).

### What breaks the company loop outside the fixture

1. **Assurance cannot be restored after a source-observed change on a real system.** In E5, an imported Claude settings file superseded a real clearance (correct). Two complete, passing re-verifications then left the Gate not cleared: *"Source change … requires reviewed coverage and observed after-state; fresh execution alone cannot reconcile omitted source facts."* Only `finance-v1` discharges such a change without exact observed digests (`src/threatveil/change_assurance.py:242-265`, bypass at `:250-251`; blocking rule at `:440-448`). The flagship lose → restore loop is **demo-only**.
2. **The observer customers are told to qualify does not produce evidence.** The Business Effect Observer Contract (`src/threatveil/observer_platform.py`) accepts **self-reported** harness results (`:144-159`) and facts that no assurance projection reads. Its only consumers are guidance, auto re-proof and export. Evidence comes exclusively from a different, older mechanism, which requires:
   - two Ed25519 collector keys;
   - a public HTTPS target serving a challenge file;
   - three assigned qualification runs;
   - at least two trials per claim;
   - a signed fingerprint listing every claim dependency.

   The Setup checklist computes "Qualify an observer" from the first mechanism and links to the second (`apps/web/src/components/system.tsx:401-405`). The Assurance Launch sells deliverable #4 on the first.
3. **"Live" sources are not watched.** Nothing schedules collection. `POST /v1/connectors/{id}/collect` is the only trigger (`src/threatveil/connector_api.py:233`). A live source's freshness is 300 s (`src/threatveil/connectors/contracts.py:66`). A non-imported source that is not fresh makes **every** claim unsupported (`src/threatveil/change_assurance.py:426-430`). Connecting a live source today degrades clearance within five minutes unless someone runs an external cron.
4. **Clearance is bounded to a day, and to non-production environments.**
   - Evidence expires at most 24 h after execution (`src/threatveil/core/validity.py:100`), which expires the clearance.
   - Nothing except the fixture composes run → plan → release → state → decision (`src/threatveil/change_assurance_api.py:590-688`).
   - A `PRODUCTION` environment can never obtain qualified state provenance (`src/threatveil/change_assurance.py:157`).

   ThreatVeil clears a **staging boundary**, not the production system.
5. **Operator surfaces can tell a comforting story the Gate does not** (E4). Recording an evidence-less state:
   - relabels an earlier authority expansion "covered by later verification";
   - files the system under Home → *current* with next action *Share*.

   A signed Passport can also be issued and shared for a system with **zero verified claims**, and its public status reads *CURRENT — "This passport still describes the system as it is now."* The Gate stays `UNKNOWN` throughout, so security truth holds. Product truth does not.
6. **Plans are mostly labels.**
   - Of 21 plan capabilities outside connector roles, **4** gate any code: `enforcement.ci`, `enforcement.production`, `release.automation`, `team.collaboration`.
   - **6** are product features with no implementation: `notifications`, `approval.workflow`, `policy.shared`, `evidence.sharing`, `governance.advanced`, `observer.advanced`.
   - Plan `retention_days` is not enforced.
   - Pro ($99) is single-user, because invitations require `team.collaboration`.

### How close are we?

The complete company loop has 13 steps (§C.3):

| Outside the fixture | Steps |
|---|---|
| Work self-serve on a real system | 5 |
| Work only expert-led, with custom engineering | 3 |
| Broken or missing | 3 |
| Unproven, because no customer exists | 2 |

- **Software:** a rigorous, honest late prototype of the category.
- **Product:** exists for one job only — declared change impact.
- **Business:** does not exist yet.

### Verdict: **PURSUE WITH SPECIFIC CORRECTIONS**

The core idea is correctly modelled and not trivially substitutable: *the evidence that justified an agent's authority stops applying when the agent changes*. The next money should buy one real system that reaches, loses and regains verified assurance, observed by a machine consumer. It should not go to GCP breadth, connectors or UI.

Recommended classification: `READY_FOR_PRIVATE_GCP` for infrastructure, plus **`NOT_READY_FOR_HOSTED_DESIGN_PARTNER`** until Bucket A (§AM) is done.

---

## B. What ThreatVeil claims to be

| Where | Claim |
|---|---|
| Public hero, `apps/web/src/components/public.tsx:12` | "Your AI agent changed. Which security conclusions are still true? … ThreatVeil determines which security conclusions still apply, which no longer do, and what must be re-established before consequential authority continues." |
| `README.md` | "Category-complete assurance … What can it do? What changed? Which security conclusions still hold? Is it still cleared to act?" A dry run "publishes as a non-blocking pull request check". "Connect your own agent in under fifteen minutes." |
| Setup, `apps/web/src/components/system.tsx:416` | "From here ThreatVeil watches for change, names the claims each one affects, and tells you what must be re-established." |
| Integrations and stack | GitHub and Cloud Run labelled *live source*; setup stage *Live monitoring connected* |
| Pricing, `public.tsx:13` | "Pro adds the enforcing CI gate. Business is where ThreatVeil can participate in production enforcement for consequential systems." |
| `docs/ASSURANCE_LAUNCH_KIT.md` | $12–15K, four weeks: three claims, one live source, "one qualified business-effect observer — all ten harness scenarios pass", Gate in WARN, Passport, one confirmed consequence, one restoration cycle |
| `THREATVEIL_PRE_GCP_PRODUCT_COMPLETION_REPORT.md` | "The product now shows the whole ThreatVeil loop without documentation" |
| Canonical thesis (this mandate) | System → operating state → authority → claims → evidence → change → invalidation → re-verification → current assurance → machine/external consumption → history |

Credit where due: `docs/KNOWN_LIMITATIONS.md` already discloses many limits candidly. It covers auto re-proof being sandbox-only, AI being mock-tested, declared claims not being evidence, and historical impact using today's mappings. The claims above that exceed the code are itemized in §U and §AD.

---

## C. What ThreatVeil actually is today

### C.1 In one paragraph

ThreatVeil is a multi-tenant FastAPI + PostgreSQL service with an append-only record store (`records` plus typed `record_edges`, row-level security) and a Next.js workspace. Two layers matter on top of it:

1. **Declared change impact.** Deterministic parsers for agent definitions and MCP catalogs, an authority-direction classifier, reviewed dependency mappings, declared claims and a proposed-change dry run. It is self-serve and works on real files.
2. **Verified current assurance.** Executable properties, authorized targets, signed collectors, runs, evidence records with ProofScope invalidation, releases, system states, signed decisions, the Gate and the Passport. It is rigorous, but reachable end to end only through the synthetic fixture or custom engineering. It cannot currently restore clearance after a source-observed change on a non-synthetic system.

### C.2 Two products under one name

| | Declared change impact | Verified current assurance |
|---|---|---|
| Inputs | Definition or catalog import, declared claims, mappings | Executable properties, target, signed collectors, runs |
| Customer surface | Connect, Security claims, Evidence → mapping, Check a change, CLI, GitHub Action | Setup checklist links into legacy `/app/runs` and Settings → Developer → Observers; no generic orchestration |
| Works on a real system | **Yes** (E3) | Baseline yes, with custom engineering (E5-A); watching no; restore **no** (E5-C) |
| Who can operate it | A developer, alone | The founder plus customer engineers |
| Substitutability | High (LLM + git diff) | Low |

### C.3 The complete company loop

| # | Step | State outside the fixture | Evidence |
|---|---|---|---|
| 1 | Sign up | WORKING locally; hosted identity not accepted | `auth.py`, GCP pending |
| 2 | Connect a real system | WORKING by import; "live" means a manual collect | E3; `connector_api.py:233` |
| 3 | Get a first change-impact result | WORKING, on declared claims | E3 |
| 4 | Establish verified assurance | CUSTOM ENGINEERING: collector, target, 5 API calls per cycle | E5-A |
| 5 | Watch change | MISSING: no scheduler, and 300 s freshness voids support | `contracts.py:66`, `change_assurance.py:426-430` |
| 6 | Lose assurance correctly | WORKING | E5-B (`SUPERSEDED`) |
| 7 | Restore assurance | **BROKEN** for source-observed changes | E5-C |
| 8 | A machine consumes the Gate | WORKING: HTTP, SDK `is_cleared`, CLI, API token | `tests/integration/test_assurance_gate.py`, `sdk/client.py:258-268` |
| 9 | A customer verifies a Passport | WORKING; defect: issuable without evidence | E2, E4 |
| 10 | A team operates it | MISSING: no notifications, assignment or audit viewer; invites need Team | §Y–AC |
| 11 | Stays current day to day | CUSTOM: 24 h evidence, no generic re-verification | `validity.py:100` |
| 12 | Plan expands | UNPROVEN: mock billing, capabilities mostly labels | §AD |
| 13 | Renews | UNPROVEN | — |

---

## D. Feature reality matrix

Classes: **A** Complete · **B** Implemented but hidden · **C** Partial · **D** Demo-only · **E** Foundation only · **F** Missing · **G** Should not be built yet.

| Capability | Intended promise | Actual state | Evidence | Customer-visible? | Generic or differentiated | Gap | Recommendation |
|---|---|---|---|---|---|---|---|
| System Intelligence | Know what the AI system is made of | **C**: definitions, MCP catalogs, Git SHA, Cloud Run digests; no data, memory, IdP scopes or deployed state | `agent_definitions.py:352-397`, `collectors.py:136-262`, `assurance_intelligence.py:1661-1721` | Yes (stack, map) | Inventory is generic; provenance labels differentiate | Running-state binding; GitHub reads no files | Complete with the partner's stack |
| Authority Intelligence | What it can do, and which way authority moved | **C**: structured direction for a fixed vocabulary; limits and schemas `UNKNOWN` | `source_semantics.py:23-37,113-165`; E3 M1 | Yes | Differentiated | Numeric limits, MCP approval semantics, flat envelope | Complete for the partner's tools |
| Security Claims (declared) | State what must stay true | **A** | `assurance_api.py:176-219`; E3 | Yes | Generic | — | KEEP |
| Security Claims (executable) | Claims evidence can support | **B**: JSON `PropertyDefinition` via API only | `api.py:438-519`, `core/contracts.py:117-161` | Legacy pages only | Differentiated | No claim → property bridge | Build with customer |
| Dependency Mapping | Which fact each claim depends on | **A** mechanism; weak suggestions | `change_assurance.py:202-239`, `dependency_mapping.py`; E3 (0 of 9 suggested) | Yes (Evidence disclosure) | Differentiated | Fact-picker UX; mappings die with the installation | KEEP; UX later |
| Evidence | Bound to state, target, observer and time | **B**: rigorous record; production path expert-only | `release_integrity.py:90-150`; E5-A | Records visible; creation hidden | Differentiated | Collector kit; private staging | Build with customer |
| Evidence Applicability | Current, stale, invalid, unknown | **B**: computed, partly by text-matching reasons | `change_assurance.py:365-367` | Only meaningful with evidence | Differentiated | Replace text matching with reason codes | COMPLETE |
| Evidence Invalidation | A changed fact invalidates exactly the dependent evidence | **C**: scoped invalidation works; restore broken; recomputed with today's mappings | `validity.py:115-180`, `change_assurance.py:425-465`; E2, E5 | Yes | **Core moat** | G1 | COMPLETE (P0) |
| Business-effect Observation | Establish committed outcomes | **C** overall: signed collectors **B**; Observer Contract **E**; SQL observer library **E** (`observer_sql.py` has no caller) | `observers.py`, `api.py:2341-2420`, `observer_platform.py` | Contract API-only | Potential moat | Two disconnected systems | COMPLETE by unifying (P0) |
| Change Detection | Meaningful change beyond Git | **C**: import-driven, manual polling | §L | Yes | Mixed | Scheduler, file contents, deploy state | COMPLETE |
| Proposed Change | What would this change break? | **A** for `agent_definition` and `mcp` | `proposed_changes.py`; E3 | Yes, plus CLI and Action | Commoditizable alone | GitHub fetch; Checks API | KEEP |
| Change Impact (UI) | Source → before → after → effect → claims | **A**: presentation over canonical fields | `signature.tsx:144-257` | Yes | Presentation | — | KEEP |
| Assurance Chain | System → authority → claim → evidence → assurance | **A**; setup stages derive a conclusion in the UI | `signature.tsx:68-118,367-401` | Yes | Presentation | Setup progress belongs in the backend | KEEP, fix |
| Current Assurance | Recomputed clearance bound to time, state, authority | **B**: semantics complete; unreachable in-product for real systems | `change_assurance_api.py:122-158`, `assurance_intelligence.py:306-331` | Label yes | Differentiated | Production is never clearable | KEEP; decide production semantics |
| Restore Assurance | Re-establish what was lost | **D** | `auto_reproof.py:204-210`; E5-C | Plan text yes; execution fixture-only | Differentiated | G1, G7 | COMPLETE (P0) |
| Useful-task Verification | PASS + broken task = not cleared | **A** invariant; **B** in practice | `change_assurance.py:373`, `change_assurance_api.py:198-199`; E2 | Yes | Differentiated | Needs a customer legitimate control | KEEP |
| Assurance Gate | Machine-readable assurance truth | **A** locally; not cloud-accepted | `assurance_intelligence.py:1433-1519` | Yes | Differentiated | `status` vs `cleared` naming | KEEP, add `answer` |
| Passport | Authentic ≠ current, shareable | **A** with a defect | `passports.py`; E2, E4 | Yes | Differentiated | Issuable with zero evidence | KEEP, fix (P0) |
| Trust Directory | Resolvable keys with rotation | **C**: verifier semantics real; directory derived from one running key | `sdk/trust_directory.py`, `trust.py` | Public endpoint | Differentiated | Operator rotation history; KMS custody | Complete at GCP |
| Signed Records | DSSE Ed25519 decisions, receipts, passports | **A** | `sdk/change_records.py`, `sdk/passports.py`, `cli.py verify-passport` | Yes | Differentiated | ThreatVeil's own build is unsigned | KEEP |
| Assurance History | Longitudinal memory | **C** | `assurance_intelligence.py:994-1113`, `memory_export.py` | Activity, export | Moat if used | Consequences not persisted; no outcome linkage | COMPLETE later |
| Integrations | Discover, observe, verify across the stack | **C** | §U | Yes | Mostly generic | "Live" is manual | Complete selectively |
| Onboarding | Connect → first real result | **C** | E3; §V | Yes | — | Verified path | COMPLETE |
| Guides | Learn the mental model | **C**: strong repo docs, thin in-app help | `docs/` | Docs | — | Troubleshooting, in-app | Build minimal |
| Inbox | What needs my attention | **C** with defects | `assurance_intelligence.py:1537-1641`; E4 | Home | Generic | Truth defects | FIX (P0) |
| Team Workflow | Review, assign, collaborate | **C**: roles and a review gate only | `auth.py:24`, `dependency_mapping.py:314` | Partial | Generic | Assignment, comments | DEFER |
| Notifications | Tell someone when assurance is lost | **F**: capability label, no code | no references to `notifications` | No | Generic | Everything | Build minimal (P1) |
| Reports | Evidence for reviewers | **C**: legacy JSON/HTML report, Passport, export | `api.py` `/v1/reports`, `workspace-parts.tsx:65` | Yes | Mixed | Security-review pack | DEFER |
| Audit Log | Who did what | **B**: written and exported, no viewer | `db.py:282-292`, `memory_export.py:20` | No | Generic | Viewer | DEFER (Business) |
| Plan Differentiation | Distinct value per tier | **C**: mostly labels | `data/commercial_plans.json`, `commercial.py:346-358` | Pricing table | — | 6 unimplemented features | HIDE labels (P0) |
| Upgrade Journeys | Upgrade at value moments | **C**: upgrade moments plus mock billing | `activation.py`, `commercial.py:386-465` | Yes | Generic | Stripe acceptance | GCP |
| Search | Find anything | **C**: ⌘K navigation, systems, recent | `command-menu.tsx` | Yes | Generic | Content search | DEFER |
| AI Assistance | Reduce onboarding work safely | **B**: mock/OpenAI seam, off by default, no UI | `ai.py` | No | Generic | UI, evaluation | DEFER |
| External Verification | Verify without an account | **A** | `passports.py:374-399`, `lib/verify.ts` | Yes | Differentiated | — | KEEP |
| Auto re-proof | Repeat approved verification automatically | **D** | `auto_reproof.py:204-210` | No | — | Dispatcher | DEFER |
| Live collection scheduling | Watch without customer pushes | **F** | `connector_api.py:233` | "Live" labels imply it | Generic | Scheduler | BUILD (P0) |
| Generic verify-and-decide | One action to re-establish | **F**: fixture-only | `change_assurance_api.py:590-688` | No | Differentiated workflow | Orchestration | BUILD (P0) |
| Production enforcement | Participate in enforcement | **E**: request recorded, awaits an enforcer | `change_assurance_api.py:287-295` | Pricing copy | — | Enforcer | **G** |

---

## E. System Intelligence

### What ThreatVeil can represent, and how it learns it

| Element | Discovered live | Imported | Declared by user | Verified | Otherwise |
|---|---|---|---|---|---|
| System identity | — | — | `POST /v1/systems` | — | — |
| Environment | — | — | Name, purpose, boundary, owner | — | — |
| Models | — | Advertised string in settings, manifest, subagent, CrewAI, OTel (`identity_basis: ADVERTISED_CONFIGURATION`) | — | Never behavioural identity | `behavioral_revision: null` |
| Prompts / instructions | — | Digest only (manifest, subagent, CrewAI role/goal/backstory) | — | — | Content never compared |
| Tools | MCP `tools/list` only via a verified target, with manual collect | Definitions; MCP catalog | Envelope actions | Via runs against a target | Code-defined tools `UNKNOWN` |
| MCP servers | — | `.mcp.json`, settings (transport, host, env/header **names**) | — | — | Server behaviour unknown |
| APIs | — | — | Target origin, paths, methods | Challenge verification of origin | — |
| Subagents / delegation | — | Subagent file (`INHERITED_ALL` recorded), CrewAI `allow_delegation`, manifest `delegates_to` | Relationship assertions (inert) | — | — |
| Identities / principals | Cloud Run service account (digest) | — | Envelope principals | — | No IdP |
| Permissions | Cloud Run IAM (digest; effective permissions `UNKNOWN`) | Claude settings allow/deny/ask/defaultMode; manifest; CrewAI | Envelope constraints (natural language) | — | API scopes `UNSUPPORTED` |
| Resources / business resources | — | — | Envelope resources; claim forbidden outcomes | Via collector fingerprint | — |
| Data sources / memory | — | — | System `access` free text | — | Not modelled |
| Deployment / infrastructure / routing | Cloud Run control plane (digests, traffic status) | Cloud Run snapshot | — | — | `running_state_proven: false` everywhere |
| Observed components | — | — | — | Fingerprint components with `provenance: OBSERVED` from signed collectors | — |

### Is the distinction visible to customers?

Yes, and this is a genuine strength. The stack carries a basis (`LIVE_SOURCE`, `INSTRUMENTED`, `IMPORTED`, `DECLARED`; `assurance_intelligence.py:1661-1721`). Authority carries `DECLARED`, `CONNECTED`, `OBSERVED`, `VERIFIED` or `UNKNOWN` (`:425-431`). Every system-map node cites the record that established it (`:1222-1382`). No vendor is inferred from a model string; E3 confirmed that `gpt-5` in CrewAI produced no OpenAI identity.

### Assessment of the System Stack and Overview

The stack is **factual but shallow**. It names ecosystems (Claude Code, MCP, CrewAI), not the facts a security reviewer needs: which tools are allowed, which permission mode is active, which MCP servers are reachable. Those facts exist in the definition preview (E3 `preview.permissions`, `models`) and in authority facts, but the Overview reduces them to chips.

### Missing system intelligence that materially affects the thesis

1. **Running-state identity.** Nothing binds a declared definition or a Git SHA to what is deployed. Every source says `running_state_proven: false`. The thesis asks "is the *current system* still cleared?"; today the honest answer is always "the declared configuration and the tested staging state".
2. **Effective permissions.** IdP roles, OAuth or API scopes of the credentials the agent actually holds.
3. **Tool input constraints.** Limits such as refund caps, which live in tool schemas or backend policy. E3 M1 showed a refund `maximum` of 500 → 50000 classified `UNKNOWN_IMPACT`.
4. **Code-defined agents** (OpenAI Agents SDK, LangGraph tools). These are refused or `UNKNOWN` by design, which is correct but covers a large share of real agents.

---

## F. Authority Intelligence

### The model

| Element the thesis wants | ThreatVeil today |
|---|---|
| Acting principal | Envelope `principals[]`: a flat list, not bound to actions |
| Action | Envelope `actions[]`; source tool names |
| Resource | Envelope `resources[]`: a flat list |
| Environment | Envelope is per environment |
| Permission / scope | Source-declared authorization facts, flattened to bounded path → value (`source_semantics.py:73-98`) |
| Approval conditions | Only as source facts (`approval_required`, Claude `ask`) or natural-language constraints |
| Limits | **Not modelled** (numeric values are "no reviewed semantics") |
| Business consequence | Only in claims (forbidden outcome, legitimate task) |
| Authority source | `CUSTOMER_ACCEPTED`, `SOURCE_DECLARED` (unreviewed), `SYNTHETIC_PACKAGE` |
| Verification status | `basis` DECLARED → CONNECTED → OBSERVED → VERIFIED |

The envelope is a set of four lists, not (principal, action, resource, condition) tuples. It cannot say "the support agent may refund tenant A's orders up to $500 with approval"; it can only say that principals, actions and resources exist.

### Direction classification (`source_semantics.py:113-177`)

Restrictions (`approval_required`, `tenant_bound`, `read_only`, `mfa_required`, …), scope lists (`allow`, `tools`, `scopes`, …), denial lists (`deny`, `ask`, …), grant flags (`allow_delegation`, `allow_code_execution`, `enable_all_project_servers`), and one ordered mode (`default_mode: plan < default < acceptEdits < bypassPermissions`). Interface exposure and withdrawal are classified; everything else is `UNKNOWN_IMPACT`. A combined change is `EXPANDED` if any dimension expanded.

### Verified classifications

| Change (source) | Result | Correct? |
|---|---|---|
| `approval_required true→false` (Finance synthetic MCP gateway) | `AUTHORITY_EXPANDED` (E2) | Yes |
| Claude `ask` entry removed | `AUTHORITY_EXPANDED` (E3 P1a) | Yes |
| Claude tool moved from `ask` to `allow` | `AUTHORITY_EXPANDED`, two dimensions (P1b) | Yes |
| Claude `defaultMode default → bypassPermissions` | `AUTHORITY_EXPANDED` (P2) | Yes |
| Claude `deny` entry added | `AUTHORITY_CONTRACTED` (P4) | Yes |
| Claude model change only | `AUTHORITY_EQUIVALENT` (P3), yet it reaches both claims because `model:settings` is unmapped | Yes: conservative |
| CrewAI `allow_delegation false→true`, tool added | `AUTHORITY_EXPANDED` (C1) | Yes |
| MCP catalog: new `account_delete` tool | `AUTHORITY_EXPANDED` (M2) | Yes |
| MCP catalog: refund `maximum` 500 → 50000 | `UNKNOWN_IMPACT` (M1) | Conservative, but it misses the thesis's own example |
| Envelope natural-language constraint reworded | `UNKNOWN_IMPACT` (`assurance_intelligence.py:449-462`) | Conservative |

### Does `approval_required true → false` work generically?

| Source | Works? | Why |
|---|---|---|
| Finance fixture | Yes | Its gateway payload carries a non-standard `authorization` block (`change_assurance_api.py:420-426`) |
| ThreatVeil manifest | Yes | `tools.<name>.approval_required` / `requires_approval` (`agent_definitions.py:126-133`) |
| Claude Code | Equivalent via `ask` / `allow` / `deny` | Verified (E3) |
| CrewAI | No approval field in the format | — |
| Real MCP `tools/list` | **No** | The MCP catalog has no approval field; ThreatVeil records "Effective authorization configuration was not captured" (E3 `mcp_import`) |
| GitHub | **No** | The connector reads the branch SHA, not file contents (`collectors.py:136-196`) |

### Intelligibility

Good. The Change Impact transition shows subject, before → after and a direction pill, and explanations are fixed templates over facts (`assurance_intelligence.py:609-652`). Two coarse behaviours will confuse customers:

- **Any envelope revision reaches every claim** (`_declaration_view` sets `reached = all properties`, `:778-799`), even adding one resource.
- **Every declared action must be governed by an approved executable claim, or nothing clears** (`change_assurance.py:330-333`). This is correct and conservative, but onboarding cost scales with the number of actions.

---

## G. Security Claims

### Data model and lifecycle

| Object | Record | Created by | Plan cap | Can ever be supported? |
|---|---|---|---|---|
| Declared claim | `claim_definition` | UI claim builder / API (`assurance_api.py:195-219`) | **Unlimited on every plan** | **No**: never enters projection rows |
| Executable claim | `property` with `PropertyDefinition`: predicates, phases, observation contract, legitimate control, dependencies (`core/contracts.py:117-161`) | `POST /v1/properties` JSON, then security-role approval (`api.py:438-519`); fixture setup | `approved_property_limit` | Yes, only with qualified evidence |

- Templates: 10 starter templates, labelled `STARTER TEMPLATE / NOT VERIFIED FOR YOUR SYSTEM`: approval required, tenant isolation, maximum transaction limit, read-only boundary, production deploy approval, refund limit, external message approval, privileged action requires human, no cross-tenant write, tool allowlist.
- Assurance packs: 4 DRAFT packs (support/refund, revenue/CRM, infrastructure, generic write agent), API only.

### Status semantics

| Thesis state | ThreatVeil representation |
|---|---|
| Declared | Ladder `DECLARED` (no dependencies) |
| Not verified | Ladder `NOT_YET_VERIFIED` (declared with dependencies); status `DEFINED` |
| Qualified | Ladder `QUALIFIED`, which in code means **property approved**, not "qualified observer exists", although its meaning text says so (`assurance_intelligence.py:514,525-526`). A naming defect. |
| Current | Ladder `CURRENT`; status `SUPPORTED`; applicability `CURRENT` |
| Stale | Applicability `STALE`; status `NEEDS_FRESH_EVIDENCE` |
| Invalid | Applicability `INVALID`; status `NEEDS_FRESH_EVIDENCE` |
| Unknown | Applicability `UNKNOWN`; status `UNKNOWN` |
| Failed | Status `FAILED` (security `FAIL` or task `FAILURE`) |

### Can a claim become "supported" merely because it was declared?

**No.** This is verified live: after declaring claims, mapping them and recording a declared state, the ladder still says `NOT_YET_VERIFIED`, the Gate says `UNKNOWN` with `scope.status: UNGOVERNED`, and the authority map says `UNGOVERNED` (E3, E4). It is also structural: `supported` requires evidence, no local reasons, `PASS` and `SUCCESS` (`change_assurance.py:373`).

### Gaps

1. **No bridge from a business claim to an executable claim.** A design partner writes predicates and an observation contract as JSON.
2. **No numeric thresholds in predicates.** Kinds are `missing_approval`, `cross_tenant`, `unauthorized_action`, `untrusted_action`, `forbidden_action`, `forbidden_value` (exact values). "Refunds above $500 require approval" cannot be expressed as a predicate; the threshold must live in the collector or stimulus.
3. **Applicability is partly derived by matching the words "expir" and "stale" in reason strings** (`change_assurance.py:365-367`). This is fragile truth logic.

---

## H. Dependency Mapping

### Mechanism

- **Mapping:** an append-only statement, per source installation, that a reported subject maps to a set of claim dependencies. The latest mapping per subject applies (`change_assurance.py:202-239`, `source_semantics.py:350-380`).
- **Guards:** the subject must be a fact that source actually reported (`:227-233`), and targets must be dependencies of approved or declared claims (`:219-226`).
- **Review:** proposal → security-role review → mapping (`dependency_mapping.py:277-340`). Origins are `DETERMINISTIC`, `CUSTOMER` or `AI_PROPOSED`, and all land in the same queue.
- **Suggestions:** name and token overlap (`dependency_mapping.py:42-175`). In E3, the 9 reported subjects produced **0 suggestions** against semantically named dependencies (`permissions:refund-approval`, `permissions:protected-paths`). Real customers will map by hand.
- **AI seam:** mock or OpenAI, off by default, proposals only, subjects restricted to reported facts (`ai.py:219-269`).

### Can ThreatVeil say "this change affects only Claim A; B and C remain current"?

**Yes, under four preconditions** (verified: E2 1 affected / 2 hold; E3 P1a reaches one claim, P4 reaches the other):

1. The source supplies structured facts (an agent definition or MCP catalog), not just a digest.
2. **Every** changed subject has an approved mapping (`scope_change`, `source_semantics.py:362-380`).
3. The claims it should spare have declared dependencies. A claim with no dependencies is reached by every change (`assurance_intelligence.py:486`).
4. For executable claims, the mapped dependencies are within the approved claims' dependency set (`:484`).

### When no mapping exists

The whole change stays conservative. Every claim it could reach needs fresh evidence (P1b: the unmapped `allow` dimension widened a one-claim answer to two; P2, P3, C1, M1, M2). This is the correct conservative behaviour.

### Weaknesses

- Mapping subjects embed the installation identity (`permissions:source:<uuid>`, `tool:source:<uuid>:<name>`). Reconnecting a source orphans every mapping.
- Historical consequences are evaluated with **today's** mappings (disclosed in `KNOWN_LIMITATIONS.md`).
- A proposed-change summary reports `scoped: false` even when declared claims were narrowed by a fully mapped change, because `scoped` counts executable claims only (E3 P4). This is a small inconsistency.

---

## I. Evidence

### Binding (`release_integrity.py:90-150`, `change_assurance.py:140-173,308-373`)

| Thesis binding | Present? | How |
|---|---|---|
| Claim | Yes | `property_id`, `property_digest`, version |
| System | Yes | `system_id` |
| Environment | Yes, indirectly | The target must have an environment binding **older** than the evidence (`change_assurance.py:352-360`) |
| Operating state | Yes | Fingerprint digest must equal the state's fingerprint digest (`:151-152`) |
| Authority state | Yes, temporally | Evidence must postdate the current envelope (`:358-360`); the state carries the envelope digest |
| Target | Yes | `target_id`; authorized, unexpired, challenge-verified |
| Observer | Yes | `observer_id`; two-key signed attestations (`observers.py:60-84`) |
| Time | Yes | `established_at`, `expires_at ≤ 24 h` (`validity.py:100`) |
| Scope | Yes | ProofScope bindings, coverage, compatibility (`validity.py:78-112`) |
| Useful task | Yes | `task_outcome` with a legitimate control |
| Prohibited outcome | Yes | Predicates evaluated over receipts |
| Policy | At decision | Release policy digest in the signed decision |

### Does it distinguish exists / applies / current / stale / invalid / unknown?

Yes, in the projection: evidence may exist but be discarded when it predates the authority or binding, or targets another target; applicability is `CURRENT`, `STALE`, `INVALID` or `UNKNOWN`. This is fundamentally sound.

### Four hard requirements a real customer meets only by custom engineering (E5)

1. **At least two trials per claim.** The projection hard-codes `trials_per_variant: 2` (`change_assurance.py:315`); 1-trial evidence is rejected with "Evidence does not meet the plan's minimum trial and variant budget".
2. **The signed fingerprint must enumerate every claim dependency** with `provenance: OBSERVED`. Otherwise ProofScope records "Unresolved proof dependency" and the evidence is `UNKNOWN` (`validity.py:129-143`). E5's first attempt failed exactly this way.
3. **The target must be a public HTTPS origin on port 443** serving `/.well-known/threatveil-authorization` (`api.py:546-614`). Private staging behind a VPN cannot be a target.
4. **The target must answer ThreatVeil's stimulus envelope with a ThreatVeil `Observation`** signed by both keys (`adapters/http.py:34-61`). The customer must build this shim.

---

## J. Evidence Invalidation

### Two engines

| Engine | Where | What it does | Verified |
|---|---|---|---|
| ProofScope invalidation | `core/validity.py:115-180` | Transitive dependency closure over fingerprints; `EXACT`/`FAMILY`/`SEMANTIC` compatibility with enumerated digests; unknown identity → `UNKNOWN`; changed dependency → `VOID`; else `STILL_VALID` | E1, `test_validity.py`, `test_release_integrity.py` |
| Source-change invalidation | `change_assurance.py:374-465` | After-state source changes are scoped by mappings: dependent claims `INVALID`, unmapped `UNKNOWN`; before-state changes must reconcile or block; stale non-imported sources unsupport everything | E2, E5 |

### Depth rating

| Level | Definition | ThreatVeil |
|---|---|---|
| 0 | "Change detected; rerun everything" | Surpassed |
| 1 | Component-level change sets | Yes |
| 2 | Dependency-scoped claim invalidation | Yes |
| 3 | Mapping-scoped invalidation that preserves unaffected evidence and keeps unknowns conservative | **Yes: this is real** (E2: "The claim … depends on permissions:finance-approval, which a reviewed mapping links to what changed … 2 other claims remain supported") |
| 4 | Restorable, temporally faithful invalidation: mappings in force at the time, persisted consequences, restore after re-observation | **No** |

The primitive the thesis names — *this evidence supported Claim X under State A; the system is now State B; the changed fact invalidates the assumption* — **exists**, and it is ThreatVeil's strongest code. Three defects stop it being a product:

1. **Restore is impossible after a pre-state source change** (E5-C). Reconciliation needs every changed component key to be a literal claim dependency, and the signed fingerprint must reproduce ThreatVeil's internal digest of that component (`change_assurance.py:253-265`). For an imported definition that means keys like `permissions:source:<uuid>` digested from ThreatVeil's own normalization. No real collector can reasonably do that.
2. **Consequences are recomputed at read time with current mappings and claims.** Historical immutability holds for decisions and assurance cases, not for change consequences.
3. **Declaration changes are unscoped**: any envelope revision reaches all claims.

---

## K. Business-effect Observation

This deserves the most attention, because it is the potential moat and today it is split in two.

### Inventory

| Component | What it is | Generic / specific | Operational? |
|---|---|---|---|
| Signed collectors (`observers.py`, `/v1/observers`, `api.py:2307-2420`) | Two Ed25519 keys (observer and independent ground truth), initial-state digest, fixture reference, independence review; qualification by three assigned runs (known permitted, known prohibited, missing observation) that must produce PASS, FAIL and INCONCLUSIVE | Generic | **Yes**: this path produces evidence (E5-A) |
| Receipt model (`core/contracts.py:40-109`) | Action phases `ATTEMPTED`, `AUTHORIZED`, `DISPATCHED`, `COMMITTED`, `DENIED`, `COMPENSATED`; witness authority `SELF_REPORTED` → `INDEPENDENT`; correlation IDs | Generic | Yes |
| Observer Contract (`observer_platform.py`) | System of record, resource, effects, correlation method, read method, commit semantics, observation window, coverage limits, failure semantics; contract digest; 10-scenario harness; 90-day requalification; `effect_summary` that never reads absence as "no effect" | Generic and well designed | **No**: harness results are submitted by the customer, never executed by ThreatVeil (`:144-159,339-361`); facts are never read by the projection |
| SQL observer (`observer_sql.py`) | Read-only PostgreSQL observer with validated identifiers, statement timeout, row limit | SQL-specific | **No caller** in `src` |
| Finance fixture ground truth (`core/finance.py`) | Committed SQLite ledger | Synthetic | Demo |

### Against the thesis

| Requirement | Status |
|---|---|
| Observer contract | Designed (E); signed collectors carry an implicit contract (B) |
| Qualification states | `UNQUALIFIED` / `PENDING` / `QUALIFIED` / `REVOKED` / `STALE` in the contract (E); approved or unapproved for collectors (B) |
| Correlation | Correlation ID per trial (`trial_correlation`), bound into signatures (B) |
| Observation windows | Declared in the contract (E); evidence max age ≤ 24 h (B) |
| Ground truth | Separate ground-truth key (B); contract names the system of record (E) |
| Committed vs attempted | Receipt phases, and predicates default to `COMMITTED` (B) |
| Compensation | "A compensation never erases a commit" in `effect_summary` (E) |
| Negative evidence | Absence is `DENIED` only with declared commit coverage (E); `MISSING_OBSERVATION` → `INCONCLUSIVE` for collectors (B) |
| Useful-task evidence | Legitimate control per property (B) |
| Uncertainty | `UNKNOWN` everywhere (A) |

### What is production-ready

None of it, until a real system of record is read by a real collector. The design is excellent. The fix is structural: **one observer abstraction** in which a qualified Observer Contract (with ThreatVeil *executing* the harness against the observer, or at least reviewing recorded runs) is what binds evidence. Make `observer_sql.py` (and an HTTP read observer) the first reference implementation. Until then the Assurance Launch's "qualified observer" deliverable produces no assurance.

---

## L. Change Detection

| Change class | State | Notes |
|---|---|---|
| Code | **Detected live, manually triggered** | GitHub branch SHA only; no diff, no files (`collectors.py:136-196`) |
| Model | **Imported** | Advertised model string in definitions; OTel advertised model |
| Prompt | **Imported** | Digest only; the direction of a prompt change is always `UNKNOWN` |
| Tool | **Imported**; MCP **detected live, manual** with a verified target | Definition tool lists; MCP catalog |
| MCP server | **Imported** | `.mcp.json`, settings enable/disable lists |
| Tool schema | **Imported** | Schema change → `UNKNOWN_IMPACT` (`source_semantics.py:263-265`) |
| Permissions | **Imported** (structured); Cloud Run IAM **live, manual** (digest) | Claude settings, manifest, CrewAI |
| Identity | **Supported by model, partly connected** | Cloud Run service account digest; envelope principals declared |
| Scope | **Imported** as lists | API/OAuth scopes **unsupported** |
| Data | **Unsupported** | `access` free text only |
| Memory | **Unsupported** | `memory` component kind exists; no source |
| Deployment | Cloud Run **live, manual** / **imported** (digest) | `running_state_proven: false` |
| Infrastructure | **Unsupported** beyond Cloud Run | — |
| Routing | Cloud Run traffic status digest | — |
| Environment | **Declared** | Environment records |
| Policy | **Imported** (Claude hooks digest); envelope revisions **declared** | — |
| Subagent / delegation | **Imported** (subagent files, CrewAI, manifest) | Relationship assertions are inert |
| Proposed changes | **Proposed-only** for `agent_definition` and `mcp` | `proposed_changes.py:34` |

Nothing is "detected live" in the sense a buyer understands. There is no scheduler, no webhook ingestion for configuration sources, and no GitHub file fetch.

---

## M. Proposed-change Analysis

Flow verified in E3 (`proposed_changes.py:271-300`):

| Step | Implemented | Verified |
|---|---|---|
| Current system | The last `projects_current` batch for that source | Yes |
| Candidate change | Upload, paste, CLI `--file`, GitHub Action reading the checked-out file | Yes (API) |
| Diff | Component digests, then `explain_source_change` | Yes |
| Authority effect | Classification and dimensions | Yes (10 cases) |
| Affected claims | Reviewed mappings; conservative when unmapped | Yes |
| Unaffected claims | Only when fully mapped | Yes (P1a vs P1b) |
| Evidence needing re-establishment | `WOULD_NEED_FRESH_EVIDENCE` per currently supported executable claim | By code (no evidence in E3) |
| Current status / if-shipped status | `clearance.current` / `if_applied` | Yes |

### Invariants

| Invariant | Holds? |
|---|---|
| Proposed changes do not mutate current assurance | **Yes.** Batches 1 → 1 and clearance unchanged before/after 10 proposals (E3 `non_mutation`); only `proposed_change_assessment` is written |
| Before → after is real | Yes, against the last observation |
| Affected claims are not guessed | Yes: mappings or conservative fallback |
| Unchanged claims are current only when justified | Yes |
| UNKNOWN stays conservative | Yes: `UNKNOWN_IMPACT` still reaches claims |
| Candidate state is bound precisely | Request digest and idempotency key; the reference (PR, commit) is a label ThreatVeil never fetches |
| GitHub check behaviour is truthful | **Partly.** The Action writes a job summary and exits 0/1 (`integrations/github-change-assurance/propose.mjs:91-102`); no Checks-API check named "ThreatVeil — Change Assurance" is published. The README's "publishes as a non-blocking pull request check" overstates this. GitHub App check publication exists only for release decisions (`integrations/github_release.py:375`) |

### Beyond the Finance fixture?

**Yes.** This is the one flagship workflow that works on real systems today. Two limits:

- The comparison baseline is the last *imported* snapshot, not the last *cleared* state.
- `if_applied` is meaningful only for systems with evidence. For declared-only systems it echoes `NOT_ESTABLISHED`.

---

## N. Change Impact (and the other signature visuals)

### Assurance Chain (`signature.tsx:68-118`)

Every link reads canonical fields: summary clearance, authority entries or the open change's classification, claim counts, evidence counts. The final link is the canonical clearance, so the chain cannot contradict the header. **No security conclusion is invented in the UI.** The chain's intermediate "attention"/"none" tones are presentation choices over counts.

### Change Impact (`signature.tsx:144-257`)

Presentation only. `impactOfChange` maps `prior.action == ALLOW` to "Cleared" and shows the canonical current clearance. The one place the UI states more than the API: "Before this change → Current system" is rendered from `prior_clearance` even when the change effect is `COVERED_BY_LATER_VERIFICATION` caused by a merely *declared* later state (E4). The root defect is in the backend.

### Setup progress (`signature.tsx:367-401`)

This **does derive conclusions in the UI**:

- "Verified evidence established" is true when *any* decision exists, including `BLOCK` (`:377`).
- "Proposed-change analysis ready" and "Live monitoring connected" are inferred from source types and stack flags.

All three belong in a backend `setup_progress` projection.

**Verdict:** the visuals represent genuine canonical facts. Move setup progress to the backend, and fix the backend truth defects the visuals faithfully display.

---

## O. Current Assurance

### Statuses

| Layer | Values | Where |
|---|---|---|
| System clearance | `CLEARED`, `NEEDS_REASSESSMENT`, `NOT_CLEARED`, `REVOKED`, `NOT_ESTABLISHED` | `assurance_intelligence.py:48-54,306-331` |
| Decision status (recomputed) | `CURRENT`, `SUPERSEDED`, `REASSESS`, `EXPIRED`, `REVOKED` | `change_assurance_api.py:122-158` |
| Gate | Adds `UNKNOWN`; `cleared` true only for `CURRENT` + `ALLOW` | `assurance_intelligence.py:1433-1519` |
| Passport | `CURRENT`, `SUPERSEDED`, `REASSESS`, `EXPIRED`, `REVOKED`, `UNKNOWN` | `passports.py:180-220` |

### Bindings

| Binding | Present? |
|---|---|
| Recomputation | Yes |
| Time | Signed decision 5 min (`change_assurance_api.py:202`); evidence ≤ 24 h; envelope ≤ 366 days; Gate freshness 60 s |
| Expiry | Yes |
| Revocation | Yes (`status_event`) |
| State | Yes (state digest; `expected_state_digest` on the Gate) |
| Authority | Yes (envelope digest and epoch) |
| Environment | Yes |
| Audience | Decision audience, checked on enforcement |
| Policy | Policy digest |
| Historical decisions | Immutable |

### A historical CLEARED decision remains authentic while no longer current

**Verified** (E2 step 3: previous clearance `SUPERSEDED`, prior record still authentic; E5-B).

### Findings

- **Production cannot be cleared** (`change_assurance.py:157`). This is a deliberate truth decision ("a qualified test establishes its bounded test destination, not what is serving production"), and a *commercial* problem. Buyers ask about production. ThreatVeil must say plainly that it clears a tested staging boundary bound to a declared or imported configuration, and build deployment-identity binding with a partner.
- **Gate `status: CURRENT` can coexist with `cleared: false`** when the current decision is `REQUIRE_APPROVAL` (E5-A first run, E5-C). The consumer contract documents this and the SDK's `is_cleared` fails closed, but a hand-written consumer checking `status == "CURRENT"` would be wrong. Add an explicit `answer: CLEARED | NOT_CLEARED | UNKNOWN`.
- **Clearance needs daily re-verification.** Nothing generic does it.

---

## P. Restore Assurance

### What the plan answers (`assurance_intelligence.py:907-968`)

| Question | Answered? |
|---|---|
| What changed | Yes |
| Which claim is affected | Yes |
| What still holds | Yes |
| What evidence needs replacement | Yes |
| What checks must run | A templated sentence ("Attempt: {forbidden outcome}. It must not commit a business effect.") |
| Whether unauthorized behaviour is prevented | Yes, as security `PASS` |
| Whether legitimate behaviour still works | Yes, as task `SUCCESS` |

### Capability by degree of automation

| Capability | State |
|---|---|
| Manually re-run | API: runs → proof plan → release → state → decision (five calls; E5) |
| Automatically planned | Yes (the plan above; `auto_reproof` eligibility) |
| Automatically dispatched | **Finance sandbox only**; elsewhere `NO_QUALIFIED_DISPATCHER` (`auto_reproof.py:204-210`) |
| Automatically restored | **Finance sandbox only**. For real systems, restore after a source-observed change is **impossible** (E5-C) |

### Invariant `SECURITY PASS + USEFUL TASK FAILURE = NOT CLEARED`

Holds at three layers:

- projection `supported` (`change_assurance.py:373`);
- decision `BLOCK` when a task fails (`change_assurance_api.py:198-199`);
- verified live (E2 case B).

**Do not oversell auto re-proof.** It is a well-bounded policy object with no dispatcher.

---

## Q. Useful-task Verification

This is one of ThreatVeil's most distinctive ideas, and it is implemented correctly. Each executable claim carries a `legitimate_task` and an optional `LegitimateControl` (operation, resource type, expected state, required phase). Task outcome `FAILURE` blocks clearance, `UNKNOWN` never supports it, and the Finance bad-fix scenario proves that breaking useful work is not a fix. In practice a real customer must supply a collector that observes the legitimate effect in the system of record. That is the same bespoke work as §I and §K.

---

## R. Assurance Gate

| Aspect | Finding |
|---|---|
| Endpoint | `GET /v1/systems/{id}/assurance/current`, with `environment_id`, `action` and `expected_state_digest` (`assurance_api.py:41-52`) |
| Authentication | Session or API token (machine) (`test_a_machine_read_token_can_consume_the_gate`) |
| System binding | Tenant-scoped; cross-tenant refused (tested) |
| Freshness | `valid_until` = min(60 s, envelope expiry, observation expiry) |
| State | State ID, digest and envelope digest; a stale held digest → `SUPERSEDED` |
| Response contract | `status`, `cleared`, `authorizes: false`, claims, obligations, reasons, `consumer_contract` |
| UNKNOWN semantics | "Never treat UNKNOWN as authorization" (verified: E3/E4 `UNKNOWN`, `cleared: false`) |
| Recomputation | On every call |
| Current vs historical | The decision `record_uri` is for offline authenticity only |
| Consumer tracking | Self-declared `X-ThreatVeil-Consumer` label, one record per consumer per hour (`passports.py:345-359`) |
| Entitlements | None; Free has the Gate |
| SDK / CLI | `ThreatVeilClient.current_assurance` + fail-closed `is_cleared` (`sdk/client.py:232-268`); `threatveil assurance-current` |
| **Grants permission?** | **No** (`authorizes: false`; UI copy "never grants permission") |

**Assessment:** usable today and locally demonstrable. Real value is cloud-dependent and evidence-dependent. It is not production-ready: no hosted latency or availability evidence, and the consumer label is not an identity. It is discoverable on the Overview (GateState) and in Integrations. The contract is the best-defined thing in the product. Add the unambiguous `answer` field.

---

## S. Passport

| Aspect | Finding |
|---|---|
| Creation | Security role; requires only that a state exists (`passports.py:159-160`) |
| Signing | DSSE / in-toto, Ed25519 (`sdk/passports.py`) |
| Trust directory | `/v1/trust/keys`; `ACTIVE`/`RETIRED`/`REVOKED` semantics in the verifier; **the served directory is derived from the running key** ("rather than an operator-managed rotation history") |
| Key rotation | Semantics yes; operational rotation no |
| Disclosure profiles | `STANDARD` withholds identifiers, resources and interface names; `INTERNAL` includes them |
| Sharing confirmation | `confirm_disclosure: true` after a disclosure preview |
| Pseudonymization | Stable `sha256(org:system)` reference |
| External verification | CLI `verify-passport`, SDK, browser WebCrypto (`lib/verify.ts`) |
| Online status | HMAC capability link, rate-limited public endpoint (`passports.py:374-399`) |
| Revocation | Passport and share revocation |
| Superseded status | Yes |
| Browser verification | Yes, where WebCrypto Ed25519 is available |

### Authentic ≠ current

**Verified end to end** (E2 step 6: verified with the trust directory and an independent key; status `CURRENT → SUPERSEDED`; authentic after the change).

### Defect (E4)

A Passport issued for a system with a *declared* state and **zero** verified claims:

- is signed and shareable;
- shows clearance "No clearance yet" and 2 claims unknown;
- has public status `CURRENT — "This passport still describes the system as it is now."`

The document is technically honest, but a signed "Current Assurance Passport" that proves nothing, with a green-sounding status, will be misread by an external reviewer. **Refuse issuance unless at least one claim is supported, or introduce a distinct status `NO_ASSURANCE_ESTABLISHED`.**

---

## T. Historical Assurance Memory

| Relationship | Exists | Derived | Missing |
|---|---|---|---|
| System → state | Records + edges | — | — |
| State → authority | Envelope digest in state | — | — |
| Authority → claim | — | Governs (operations) | Persisted binding |
| Claim → evidence | Evidence record | Selection at projection | — |
| Evidence → change | — | Recomputed at read time (`affected_by`) | Persisted invalidation record |
| Change → invalidation | — | Recomputed with **current** mappings | Mappings in force at the time |
| Invalidation → re-proof | — | `cycles()` (`assurance_intelligence.py:994-1020`) | — |
| Re-proof → business effect | Run evidence | — | Observer Contract facts are not linked |
| Business effect → decision | Assurance case snapshot in decision | — | — |
| Decision → outcome | Enforcement ack (synthetic), consumer acceptance, Gate reads, feedback | — | Real enforcement outcomes |

- **Append-only:** records are insert-only with RLS; corrections are new records.
- **Exportable:** full NDJSON memory export with edges (`memory_export.py`).
- **Survives plan changes:** yes; billing never deletes and plan retention is not enforced.
- **Cross-customer corpus:** none (consent records exist, no pipeline). Correct for now.

**Can it become a differentiated corpus?** Yes, but only if (a) consequences and mappings-in-force are persisted as records, not recomputed, and (b) real systems run the loop. Today the richest history in any workspace is the synthetic fixture's.

---

## U. Integrations

### Matrix

| Integration | Discover | Change | Observe | Verify | Enforce | Export / Consume | Live / Import | Production-ready? |
|---|---|---|---|---|---|---|---|---|
| GitHub (read connector) | Repo identity, branch SHA | SHA moved | — | — | — | — | LIVE SOURCE, **manual collect**; needs a credential reference | No |
| GitHub App checks | — | — | — | — | Exact-SHA check for **release** decisions | CONSUMER | Outbox publication (tested with mocks) | No |
| GitHub Action: change assurance | — | Proposed change from the checked-out file | — | — | Exit code via `fail-on` | CONSUMER (job summary) | Calls the API | Plausible; not accepted |
| GitHub Action: release gate | — | — | — | — | CI gate with OIDC identity | CONSUMER | — | No |
| Claude Code (settings, subagents, `.mcp.json`) | Permissions, MCP servers, model | Structured authority diff | — | — | — | — | IMPORT | Parsing yes |
| MCP | Tool catalog, protocol era | New/removed tool; contract change `UNKNOWN` | — | MCP adapter for runs (allowed tools) | — | — | IMPORT, or LIVE SOURCE with verified target (manual) | Import yes; live no |
| LangGraph | Graph entry points only | Graph digest | — | — | — | — | IMPORT | Minimal value |
| CrewAI | Agents, tools, delegation, code execution | Structured diff | — | — | — | — | IMPORT | Parsing yes |
| OpenAI Agents SDK | — | — | Invocations, outcome `UNKNOWN` | — | — | — | TRACE IMPORT | Trace only |
| Claude Agent SDK hooks | — | — | Invocations | — | — | — | TRACE IMPORT | Trace only |
| Cloud Run | Service config, IAM, identity, routing (digests) | Digest change → `UNKNOWN` direction | Control plane | — | — | — | LIVE SOURCE (manual) or IMPORT; Pro+ | No |
| OpenTelemetry | Advertised model | — | GenAI spans, sampling `UNKNOWN` | — | — | — | PUSH (instrumented) or IMPORT; Pro+ | No |
| SARIF | Findings (unverified) | — | — | — | — | — | IMPORT | Parsing yes |
| CycloneDX | Composition | — | — | — | — | — | IMPORT | Parsing yes |
| Signed collectors | — | — | — | **EVIDENCE SOURCE** | — | — | Per run | Kernel yes; no reference collector |
| Observer Contract | — | — | Customer-recorded facts | — (no evidence effect) | — | — | API | No |
| Assurance Gate | — | — | — | — | — | CONSUMER endpoint, SDK, CLI | Pull | Local yes |
| Passport | — | — | — | — | — | EXPORT, external verification | Share link | Local yes |
| HTTP / OpenAI-compatible targets | — | — | — | Run adapters | — | — | Per run | Kernel yes |

### UI and copy that overstate support

1. **"Live source" / "Live monitoring connected"** (`integrations.tsx:146,205`; `signature.tsx:394`) implies ThreatVeil watches continuously. Collection happens only when someone calls `collect`, and freshness lapses after 300 s.
2. **"From here ThreatVeil watches for change"** (`system.tsx:416`) is true only for data someone sends.
3. **"Publishes as a non-blocking pull request check"** (README) describes a job summary, not a Checks-API check.
4. **"Pro adds the enforcing CI gate"** (`public.tsx:13`). `enforcement.ci` gates only BLOCK release policies. The proposed-change Action's `fail-on` is a client flag available on Free.
5. **"Business is where ThreatVeil can participate in production enforcement"**: external enforcement requests sit at `AWAITING_QUALIFIED_ENFORCER` forever.
6. **Assurance Launch "one qualified business-effect observer"** yields no evidence (§K).

---

## V. Onboarding

### Ideal flow vs today

| Step | Today | Manual work | Expert knowledge |
|---|---|---|---|
| Connect system | Upload or paste a definition, auto-detected (`agent_definitions.py:313-345`); plus name, environment (4 fields) and implicit source creation | Low | Low |
| ThreatVeil discovers what it can | Preview lists agents, tools, MCP servers, models, permissions (E3) | None | None |
| User confirms what it cannot know | "Confirm what ThreatVeil cannot know" step | Low | Low |
| Define one claim | Template + 6 business fields + a declared dependency ID | Medium | **Medium**: invent a dependency name such as `permissions:refund-approval` |
| Map | Propose + review (security role) | Medium | **High**: understand subject paths like `authorization/permissions/ask`; suggestions matched 0 of 9 |
| Check one change | Upload the candidate | Low | Low |
| First real result | Claim-level, authority-aware answer | — | Reading "declared, not yet verified" |

### Measured (API, machine time, not human time)

- **17 calls to the first claim-level answer**, including 2 claims and 2 mappings; **11** for one claim and one mapping.
- 0.21 s machine time.
- Form surface: connect ≈ 13 labelled inputs (`systems.tsx`), claim builder and mapping in `intelligence.tsx` (≈ 20 labels), check a change ≈ 9 labels (`changes.tsx`).

### Estimates (no customer data exists; these are estimates)

| Customer | Declared change impact | Verified current assurance |
|---|---|---|
| Developer, self-service | 30–60 min first time if the agent uses a supported format (15 min only for someone who already knows the mapping model); **not reachable** for code-defined agents without writing a manifest | **Not reachable** |
| Design partner (assisted) | 2–4 h in a workshop | **60–120 founder hours + 40–100 customer engineering hours** for the first system (§AI) |
| Business customer | Half a day, assisted | Weeks, today custom engineering |

### Where users get stuck

1. Dependency naming and mapping. The concept is right; the UX asks users to name abstract dependencies and then map to raw paths.
2. Code-defined agents.
3. The jump from "declared, not yet verified" to verified. The Setup checklist links into legacy developer pages and an unrelated observer system.
4. No notification when anything happens.

---

## W. Self-service Readiness

| Area | Classification | Reason |
|---|---|---|
| System import | **SELF-SERVICE** | Detection, preview, content-free errors |
| Claim creation (declared) | **SELF-SERVICE** | Templates, builder |
| Claim creation (executable) | **EXPERT-LED** | JSON `PropertyDefinition` |
| Mapping | **ASSISTED** | Paths, weak suggestions |
| Proposed change | **SELF-SERVICE** | UI, CLI, Action |
| Evidence setup | **CUSTOM ENGINEERING REQUIRED** | Target shim, signed collectors, dependency-complete fingerprint, public HTTPS |
| Observer qualification | **EXPERT-LED + CUSTOM** | Three runs that force prohibited and missing outcomes in staging |
| Gate | **SELF-SERVICE** (meaningless without evidence) | — |
| Passport | **SELF-SERVICE** (dangerous without evidence) | — |
| Integrations: imports | **SELF-SERVICE** | — |
| Integrations: live sources | **ASSISTED** | Operator-registered credential references; manual collect |
| Baseline and restore | **CUSTOM ENGINEERING REQUIRED** | Orchestration via API; restore broken |

**Where ThreatVeil risks becoming a consultancy:** evidence production. Every verified system today needs a bespoke stimulus shim, a bespoke two-key collector, a bespoke ground-truth reader, fingerprint engineering and an orchestration script. The Assurance Launch as scoped *is* that consultancy. It escapes only if the collector SDK, the reference observers and the verify-and-decide orchestration are productized after partner #1.

---

## X. Guides and Support

### Can a user learn…

| Question | From the product? | From docs? |
|---|---|---|
| What is a security claim? | Yes (builder copy, ladder meanings) | `QUICKSTART.md` |
| Why is my evidence stale? | Partly: reason strings are precise but raw ("Source change … requires reviewed coverage and observed after-state") | `EVIDENCE_SEMANTICS.md`, `FAILURE_STATES.md` |
| Why is assurance superseded? | Yes (change narrative, Gate reasons) | `ASSURANCE_GATE.md` |
| Gate vs IAM? | One sentence in the UI | `ASSURANCE_GATE.md` |
| Why does PASS + broken legitimate task fail? | Yes (re-establishment outcome text) | `CANONICAL_DEMO.md` |
| How do I produce evidence for my own system? | **No** | Only an API table in `DESIGN_PARTNER.md` |
| What to do when a live source goes stale? | No | No |

There is no troubleshooting guide. In-app help is limited to inline explanations and the synthetic guided tour.

### Guides that should exist, in priority order

1. **Declared vs verified: what ThreatVeil can and cannot tell you today**, in-app, one screen.
2. **Produce your first evidence**: target contract, observation schema, signing both keys, fingerprint dependencies, two trials, qualification runs. This is the missing guide, and writing it will expose the productization work.
3. **Reason-code glossary and troubleshooting**: every reason string → meaning → next action (stale source, unmapped change, unresolved dependency, trial budget, predates boundary).
4. **Dependency mapping in ten minutes**, with worked Claude settings, MCP and CrewAI examples.
5. **Gate consumer contract**: `cleared` vs `status`, fail-open/fail-closed, caching, "not IAM".
6. **Passport: authentic vs current, and what to send a reviewer.**
7. **Code-defined agents: writing a ThreatVeil manifest** (OpenAI Agents SDK, LangGraph).
8. **PASS + broken task**, a short concept page.

---

## Y. Customer Operating Layer

| Capability | Exists? | Before first design partner? | Before self-serve GA? | Unnecessary now? | Owning plan |
|---|---|---|---|---|---|
| Setup Center | Partial (Setup checklist, SetupProgress; UI-derived, links into legacy) | Fix truth and links | Yes | — | All |
| Assurance Inbox | Partial (Home attention; defects E4) | **Fix defects** | Yes | — | Free |
| Guided workflows | Synthetic tour; setup checklist | Verified-path workflow | Yes | — | All |
| Contextual help | Thin | Minimal (§X 1, 3) | Yes | — | All |
| Review assignment | No | No | Team | — | Team |
| Comments | No | No | No | Yes, for now | Team (later) |
| Mentions | No | No | No | Yes | — |
| Notification center | No | No | Yes | — | Pro |
| Email / webhook notifications | Invitations only | **Yes (assurance loss)** | Yes | — | Free (email), Pro (webhook) |
| Saved views | No | No | No | Yes | — |
| Reports | Legacy report, Passport, export | Passport suffices | Security-review pack | — | Business |
| Workspace audit | Written, exported, no viewer | No | Yes | — | Business |
| Roles | Yes (owner, admin, security, developer, viewer) | Yes | Yes | — | Team (multi-user) |
| Upgrade journeys | Upgrade moments, mock billing | No | Stripe live | — | All |
| Integration health | Source health rows | With scheduler | Yes | — | Pro |
| Support | Contact label, leads | Founder channel | Ticketing | — | Business priority |
| Search | ⌘K navigation | No | Basic content search | — | All |
| Onboarding progress | Six-stage SetupProgress | Backend projection | Yes | — | All |

Do not build a SaaS operating layer before a design partner. Build exactly two things — assurance-loss notifications and truthful Home/Setup — then let the partner's workflow decide the rest.

---

## Z. Collaboration

What exists:

- five roles;
- security-role gates on mappings, envelopes, decisions, observers and Passports;
- invitations (Team+), with a second approver for release exceptions;
- attributed append-only records (`reviewed_by`, `approved_by`).

What does not exist: assignment, comments, mentions, review queues with owners, or notifications to reviewers. Home's `awaiting_review` counter is wrong because it counts reviewed proposals (`assurance_intelligence.py:1616-1617`; E4: list endpoint says `open: 0` while Home says 1). The Team plan's collaboration value today is "more than one person can log in".

## AA. Notifications

**None for assurance.** The `notifications` capability appears in Pro, Team, Business and Enterprise and is referenced by no code. The outbox topics are `run.dispatch`, `invitation.email`, `lead.crm`, `schedule.tick` and GitHub check publication. A product whose job is to say "your agent is no longer cleared" and never tells anyone is not yet an operating product.

**Minimum to build:** clearance lost, restored, or a proposed change reaching a claim → email to the system owner plus a signed webhook. Nothing else.

## AB. Reports

- `GET /v1/reports/{system}` (JSON and printable HTML) from the legacy workspace: properties, runs, failures.
- Passports, which are the right external artifact.
- NDJSON memory export.

There is no security-questionnaire or reviewer pack built from current assurance. Defer until a buyer asks; the Passport is the report.

## AC. Audit and Administration

- **Audit:** `audit` records written on key mutations (`db.py:282-292`), exportable, with no viewer or query.
- **Data governance:** raw evidence retention policy (≤ 30 days), deletion requests with a cancel window (API only, no UI), scoped organization erasure script.
- **Tokens:** scoped API tokens with expiry and revocation.
- **Missing:** SSO/SCIM, an audit viewer, admin impersonation, deletion UI.

For a first design partner this is adequate; for Business and Enterprise an audit viewer and SSO are table stakes.

---

## AD. Subscription Plans

### What each plan actually changes in code

| Plan | Enforced differences | Advertised but unimplemented | Real job it could do today |
|---|---|---|---|
| **Free** $0 | 1 system, 2 environments, 5 approved properties, **unlimited declared claims**, 1,000 units; `enforcement.warn` (unreferenced); agent definition, MCP and GitHub connectors | `change.explain`, `workflow.warn` (labels) | Understand the product: declared change impact for one agent; CI job summary |
| **Pro** $99 | 3 systems; `enforcement.ci` (BLOCK release policy); `release.automation` (schedules create runs); OTel, Cloud Run and MCP observe connectors | `notifications`; `connector.github.enforce/export` (unreferenced) | Little beyond Free for the declared path; **single-user** |
| **Team** $399 | 10 systems; `team.collaboration` (invitations) | `approval.workflow`, `policy.shared` | Multiple seats |
| **Business** ~$2,000, contact | 30 systems; `enforcement.production` (request recorded, never acknowledged) | `evidence.sharing`, `governance.advanced`, `observer.advanced`, `support.priority` | None beyond Team today |
| **Enterprise**, custom | Contract override engine (bounded entitlement patch, expiry) | `deployment.private`, `contract.custom`, `support.dedicated` | Contract wrapper |

`retention_days` (14 / 90 / 365 / 730) is not enforced (`evidence_storage.py` caps raw evidence at ≤ 30 days via governance; history is never purged).

### Evaluation

- **Free lets a user understand the product?** Partly. It lets them understand *declared* change impact. It also lets them issue a Passport that proves nothing (§S). Keep Free; block evidence-less Passports.
- **Pro creates operational engineering value?** No. A developer would pay $99 for continuous watching of their agent configuration: GitHub file fetch at the PR head, a real PR check with history, scheduled collection, loss notifications. None exists.
- **Team has collaboration value?** Seats only.
- **Business has governance, evidence and production value?** Not yet. Its value *should* be the verified loop — qualified observer, current clearance, Gate, Passport, retention — which is what Bucket A and B build.
- **Enterprise is credible without false claims?** Only if pricing copy stops implying production enforcement and private deployment exist.

### What to build and what not to

- **Build for plans:** loss notifications (Free email / Pro webhook), GitHub contents + Checks API (Pro), verify-and-decide scheduling (Business), audit viewer (Business), later SSO (Enterprise).
- **Do not build yet:** `policy.shared`, `evidence.sharing`, `governance.advanced`, `observer.advanced` as features. Remove them from the catalog until a customer defines them.

---

## AE. Pricing

| Level | Justified by today's product? | Recommendation |
|---|---|---|
| Free $0 | Yes, for declared impact | Keep |
| Pro ~$99 | **No**: no watching, notifications or PR check | Keep the hypothesis; **do not sell** until GitHub fetch + Checks + scheduled collection + notifications exist |
| Team ~$399 | **No**: seats only | Keep hidden until review workflow exists |
| Business ~$2,000 | **No** self-serve; plausible as the landing plan after an Assurance Launch that produced a verified loop | Sell only as the continuation of a Launch |
| Enterprise custom | Contract shell only | Keep "custom"; remove unimplemented promises |
| Assurance Launch $10–20K | **Necessary before self-service** for the verified tier | Keep ~$15K, but rescope deliverables #4 and #8 to what the code can deliver after Bucket A |

### Where value jumps

The large jump is not seats or systems. It is **declared impact → verified current assurance consumed by a machine or a reviewer**. That jump deserves a price step of ~20×, from ~$99 to ~$2,000. It is also the step the product cannot yet deliver without the founder. The pricing hypothesis is directionally right. The capability ladder under it is missing.

Tie the Launch to product exit criteria: the partner reaches CLEARED, loses clearance to a real change, restores it without founder code changes, and a machine consumer reads the Gate. If a Launch cannot finish without custom ThreatVeil code, record that as a product gap, not a services success.

---

## AF. AI Opportunities

| Assistant | Value | Safety | Human approval | Deterministic logic authoritative? | Now or later |
|---|---|---|---|---|---|
| Claim Authoring (requirement → declared claim) | Medium | High (draft only; exists as a seam, `ai.py:272-286`) | Yes | Yes | Later: templates cover it |
| **Claim → executable property compiler** (declared claim + facts → `PropertyDefinition` predicates, observation contract, legitimate control) | **High** | Medium | **Yes, security role** | Yes: validation plus qualification runs | **With the first partner**, as a founder tool first |
| Dependency Mapping (facts → dependency proposals) | High for self-serve (0/9 deterministic hits in E3) | High (inert until reviewed; subjects restricted, `ai.py:249-251`) | Yes | Yes | After partner #1 proves mapping volume |
| Change Explanation (facts → prose) | Low (templates already deterministic and bounded) | Risk: saying more than the records | — | — | **Do not build** |
| Evidence Setup (recommend collector and observer configuration) | High | Medium | Yes | Yes (harness decides) | After two partners |
| Assurance Analyst (summarize history and obligations) | Low–Medium | Medium | — | — | Defer |

**Invariants to keep (already structural):** no model output changes status; `UNKNOWN → CURRENT`, `FAIL → PASS` and `STALE → VALID` are impossible (`ai.py:31-36`). A chatbot is not needed.

---

## AG. Competitive Substitution

"Could a customer do this with GitHub + IAM + CI + an LLM + spreadsheets + security testing?"

| Capability | Substitutable? | What ThreatVeil uniquely adds |
|---|---|---|
| Parse agent config and diff it | **Yes, easily** | Deterministic, content-free, bounded parsing; conservative `UNKNOWN` |
| Authority direction of a config change | Mostly (LLM + reviewer) | A versioned, reproducible classifier the same across runs |
| Which claims a change reaches | Partly (spreadsheet of owners) | **Reviewed, append-only mappings that narrow impact only when complete** |
| Evidence applicability to current state | **No** (CI tests do not know which past pass still applies) | State-bound evidence with ProofScope invalidation |
| Evidence invalidation, preserving unaffected claims | **No** | Core primitive (§J) |
| PASS + useful-task preservation | Partly (a disciplined test suite) | Enforced as a clearance invariant |
| Committed business-effect observation | Partly (bespoke assertions against the DB) | Signed two-party observation; qualification against controls |
| Current assurance status + Gate | No (CI says pass/fail at build time, not "still current") | Recomputed current truth for machines |
| Passport (authentic ≠ current) | No | Signed, externally verifiable, status-checked |
| Longitudinal assurance history | Only as logs | Structured, exportable, attributable history (if used) |

The self-serve product today sits almost entirely in the first three rows.

## AH. LLM Commoditization Risk

| Tasks an LLM commoditizes | Tasks requiring persistent trusted infrastructure |
|---|---|
| Compare two config files and describe what changed | Canonical system state over time |
| Say "allow list grew, so authority expanded" | Approved, attributed dependency mappings that decide scope |
| Draft claims from a requirement | Qualified evidence with independent ground truth |
| Suggest which claim a change might touch | Recomputed current status after every change |
| Summarize a PR's security relevance | Cryptographic records, trust directory, external verification |
| | Machine consumption with freshness and fail-closed semantics |
| | Workflow dependency: CI blocks on it; reviewers rely on it |
| | Longitudinal history that cannot be recreated later |

**Honest reading:** the proposed-change dry run on declared claims is, on its own, an expensive way to do an LLM comparison with better determinism. It is valuable only as the **front door** to the right-hand column. If the verified loop does not become operable, ThreatVeil is a config-diff linter competing with free LLM usage and with incumbents (agent security posture vendors, CSPM vendors adding "AI-SPM").

---

## AI. First Design Partner

### AI.1 Commercial buyer test

| Persona | Would buy ThreatVeil for | Screen that makes it click | Feature that makes them pay | What prevents purchase | Missing feature that matters |
|---|---|---|---|---|---|
| AI-native startup CTO | Answering customers' "how do you know the agent is still safe after you changed it?" | Passport with Current / Superseded | Shareable, verifiable current assurance | Engineering effort to produce evidence; no production answer | Collector kit; generic re-verification |
| Security lead | Knowing which conclusions a config change invalidated | Change Impact: Affected / Still current | Gate in CI blocking unverified authority expansions | Only declared claims without evidence; no notifications | Loss notifications; verified baseline |
| Enterprise buyer / security reviewer | Evidence a vendor's agent is controlled *now* | Public Passport: Authenticity + Current status | External verification | "Staging only"; no SOC 2; evidence-less Passports undermine trust | Passport minimum-evidence rule; production binding |
| Platform engineer | A machine-readable "cleared?" before deploy or promotion | Gate answer line | SDK `is_cleared`, CLI | 24 h evidence expiry without automation; manual collect | Scheduler; verify-and-decide |
| Compliance / risk | Longitudinal record of changes and re-verification | Activity / assurance history | Export | No audit viewer; no report pack; no certification claims | Audit viewer; persisted consequences |
| Developer integrating a write-capable agent | "Will my PR loosen permissions?" | Check a change | PR check in GitHub | Uploading files manually; code-defined agents unsupported | GitHub contents fetch + Checks API; manifest guide |

### AI.2 Can ThreatVeil protect one real customer system today?

Target: an AI-native B2B company with a support/refund agent that uses MCP tools against its billing system. Hours are estimates, with no customer data behind them.

| # | Step | Status | Founder h | Customer eng h |
|---|---|---|---|---|
| 1 | Hosted workspace | MISSING until GCP acceptance; then WORKING | — | — |
| 2 | Import agent definition (Claude settings / MCP catalog / manifest) | WORKING | 0.5 | 0.5 |
| 2b | Code-defined agent → write a manifest | CUSTOM WORK | 2 | 4 |
| 3 | Authority envelope (principals, actions, resources, constraints) | ASSISTED | 2 | 1 |
| 4 | 3 declared claims | WORKING | 2 | 1 |
| 5 | Mappings | ASSISTED | 2 | 1 |
| 6 | Proposed-change Action in CI | WORKING (job summary) | 1 | 2 |
| 7 | 3 executable properties (predicates, observation contract, legitimate control) | CUSTOM WORK | 12–24 | 2 |
| 8 | Target shim: accept stimulus, return an `Observation` | CUSTOM WORK | 4 | 16–40 |
| 9 | Two-key collectors reading the billing ledger; fingerprint listing dependencies | CUSTOM WORK | 8 | 16–40 |
| 10 | Public HTTPS challenge on staging (or MISSING private runner) | ASSISTED / MISSING | 2 | 2–8 |
| 11 | Qualification runs (permitted, prohibited, missing) | ASSISTED | 4–8 | 4–8 |
| 12 | Baseline: runs (2 trials) → plan → release → state → decision | ASSISTED (API script) | 4 | 2 |
| 13 | Daily re-verification (24 h evidence) | CUSTOM WORK (cron + script) | 4 | 2 |
| 14 | Watch the source (collect every < 5 min or imports from CI) | MISSING / CUSTOM | 4 | 2 |
| 15 | Correct loss on a real change | WORKING | — | — |
| 16 | Restore after the change | **MISSING** for source-observed changes | — | — |
| 17 | Gate consumer in CI | WORKING | 1 | 2 |
| 18 | Passport to a real reviewer | WORKING | 1 | 1 |
| 19 | Someone is told when clearance is lost | MISSING | — | — |
| | **Total** (ESTIMATE) | | **~60–120** | **~60–120** |

**The biggest source of bespoke work is evidence production** (steps 7–13): stimulus shim, signed collectors, fingerprint coupling and orchestration. **Step 16 is a hard blocker.**

---

## AJ. Reference Customer Standard

| Element | Minimum bar | Product support today |
|---|---|---|
| Real agent | A consequential agent in the customer's staging | Supported (any HTTP/MCP target) |
| Real source | Definition or catalog, watched without manual pushes | Import yes; watching **no** |
| Real security claims | 3 claims the customer's owner signs off | Declared yes; executable expert-only |
| Real dependency map | All changed subjects mapped for the watched sources | Yes |
| Real change | A change the customer actually shipped | Yes (import or CI) |
| Real business-effect observer | Reads the system of record independently of the agent | Kernel yes; **no reference observer**; Observer Contract disconnected |
| Real evidence | Qualified, current, bound to state | Yes, with custom engineering (E5-A) |
| Real current assurance | CLEARED → lost → **restored** | **Restore broken** (E5-C) |
| Real Gate consumer | CI or a deployment gate reading `cleared` | Yes |
| Real Passport / external verification | A third party verifies and checks status | Yes (fix evidence-less issuance) |
| Customer confirmation | Customer says the consequence was right | Yes ("was this right?") |
| Machine or external reliance | Gate reads or Passport checks recorded | Yes |
| Payment | Signed Launch or Business contract | Stripe unaccepted; contract offline |

**Supported today: 9 of 13 elements, with custom engineering. Blocked: restore, watching, a reference observer, payment rails.**

---

## AK. Defensibility

**Defensible if built out**

- Evidence applicability and invalidation semantics.
- Authentic ≠ current Passports with a trust directory.
- The Gate contract embedded in customers' CI and deploy flows.
- Qualified observers against systems of record: hard to build, sticky once qualified.
- Per-customer longitudinal history and mappings.

**Not defensible**

- Config parsing, authority diffs, claim templates, dashboards.

**Today's actual moat: near zero.** No customer data, no qualified observers in the field, no Gate consumers, no Passports with outside recipients. The code is a head start measured in months, not a moat. Defensibility starts accruing only with the first system that runs the verified loop continuously.

---

## AL. Gap Prioritization

Scores 0–10. Cost and risk are costs: higher is worse.

| ID | Gap | Value | Diff | Sales | Self-serve | Defens. | Cost | Risk | Pre-GCP | Pre-DP | Pre-GA | Priority |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| G1 | Restore after a source-observed change (reconcile by mapped re-observation + qualified re-verification instead of exact internal digests) | 10 | 9 | 8 | 7 | 8 | 6 | 8 | NO (design YES) | **YES** | YES | **P0**: blocks the loop |
| G2 | One observer abstraction: Observer Contract produces evidence (ThreatVeil runs or reviews the harness); signed collectors become its implementation | 9 | 9 | 7 | 6 | 9 | 6 | 6 | NO (decide YES) | **YES** | YES | **P0**: before G5 |
| G3 | Scheduled collection; source freshness degrades "watching", not evidence support | 9 | 6 | 7 | 8 | 5 | 4 | 5 | NO (Cloud Scheduler in GCP) | **YES** | YES | **P0** |
| G4 | Truth defects: declared state ≠ "later verification"; Home filing; Passport minimum evidence; review count; setup stages in backend; Gate `answer` | 7 | 6 | 7 | 6 | 5 | 2 | 2 | **YES** | YES | YES | **P0**: cheap |
| G7 | Generic verify-and-decide orchestration (run → plan → release → state → decision) + schedule | 9 | 7 | 7 | 7 | 6 | 5 | 5 | NO | **YES** | YES | **P0**: after G2 |
| G12 | Plan and copy truth: hide unimplemented capabilities; fix "live", "watches", PR check, production enforcement, Launch deliverables | 5 | 2 | 7 | 4 | 2 | 1 | 1 | **YES** | YES | YES | **P0**: hours |
| G11 | Assurance-loss notifications (email + signed webhook) | 8 | 3 | 6 | 7 | 4 | 3 | 2 | NO | **YES** | YES | P1 |
| G25 | Minimal guides: declared vs verified, reason glossary, first evidence | 6 | 3 | 5 | 8 | 2 | 2 | 1 | NO | **YES** | YES | P1 |
| G26 | Hide legacy surfaces not on the verified path (gauntlets, fixes, findings, propagation, tool contracts, release machine) | 4 | 0 | 5 | 6 | 0 | 2 | 3 | **YES** | YES | YES | P1 |
| G5 | Evidence production kit: collector SDK (sign, fingerprint dependencies, trials), private-network runner, reference SQL/HTTP observer | 10 | 8 | 9 | 9 | 8 | 8 | 7 | NO | WITH PARTNER | YES | P1: largest |
| G6 | Claim → executable property authoring | 8 | 6 | 6 | 9 | 5 | 6 | 5 | NO | WITH PARTNER | YES | P1 |
| G15 | Production-environment semantics and deployment identity binding | 8 | 8 | 8 | 3 | 8 | 8 | 8 | NO | WITH PARTNER | YES | P1 |
| G8 | Authority semantics for limits, schema bounds, MCP annotations | 7 | 7 | 6 | 5 | 6 | 5 | 6 | NO | WITH PARTNER | YES | P2 |
| G9 | GitHub contents fetch at PR head + Checks-API check for proposed changes | 8 | 3 | 7 | 9 | 4 | 4 | 3 | NO | If partner is GitHub-based | YES | P2 |
| G18 | Operator-managed trust directory rotation + KMS custody | 6 | 6 | 6 | 1 | 6 | 4 | 5 | GCP acceptance | YES | YES | P1 (GCP) |
| G10 | Mapping UX: fact picker, derive dependency IDs from facts, mappings survive reinstallation | 7 | 5 | 4 | 8 | 6 | 3 | 3 | NO | NO | YES | P2 |
| G16 | Persist consequences and mappings-in-force | 4 | 7 | 3 | 1 | 8 | 5 | 4 | NO | NO | NO | P3 |
| G22 | Code-defined agent export tooling (Agents SDK, LangGraph) | 6 | 3 | 5 | 6 | 2 | 5 | 4 | NO | If partner uses it | YES | P2 |
| G13 | Audit log viewer | 4 | 1 | 5 | 2 | 2 | 2 | 1 | NO | NO | YES (Business) | P3 |
| G14 | Review assignment and comments | 5 | 2 | 4 | 3 | 3 | 4 | 2 | NO | NO | NO | P3 |
| G20 | Auto re-proof dispatcher for real environments | 6 | 6 | 4 | 5 | 5 | 6 | 7 | NO | NO | NO | P3 (after G5, G7) |
| G21 | AI mapping and property assistants in UI | 5 | 3 | 4 | 6 | 2 | 3 | 4 | NO | NO | NO | P3 |
| G24 | GitHub OAuth and repository picker | 5 | 1 | 3 | 8 | 1 | 4 | 3 | NO | NO | YES | P3 |
| G23 | Data, memory and IdP scope sources | 6 | 4 | 5 | 3 | 4 | 7 | 5 | NO | NO | NO | Demand-driven |
| G28 | SSO / SCIM | 3 | 0 | 6 | 1 | 1 | 4 | 3 | NO | NO | NO | Enterprise |
| G29 | Plan retention enforcement | 3 | 1 | 3 | 1 | 1 | 3 | 3 | NO | NO | NO | Remove from table instead |
| G19 | Production enforcement integration | 5 | 5 | 5 | 2 | 5 | 7 | 7 | NO | NO | NO | **Do not build yet** |

### Reasoned ordering, not an average

- **G4 and G12 first.** They are nearly free, and a hosted deployment will otherwise present untrue states.
- **G2 before G5 and G7.** You cannot productize evidence production until there is one observer concept.
- **G1 depends on G2's answer.** Restoration should mean "a qualified observer re-observed the changed fact's after-state, or the mapped claims were re-verified on the new state". It should not mean "a collector reproduced ThreatVeil's internal digest".
- **G3 is independent** and required for "watching" to be true.
- **G7 turns E5's five-call script into a product.**
- **G5, G6 and G15 are the partner build.** G11 is the minimum operating layer.

---

## AM. Before-GCP Build List (and Bucket A: must exist before a hosted design partner)

### Before private GCP (days, not weeks)

1. **G4 truth fixes**:
   - a change is "covered by later verification" only when a `QUALIFIED_TEST_EXECUTION` state followed it;
   - a system with a declared-only state stays in attention with next action `SET_UP`;
   - Passport issuance requires at least one supported claim, or signs `NO_ASSURANCE_ESTABLISHED`;
   - Home counts proposals without a review;
   - the "Verified evidence" stage requires a supported claim, not any decision;
   - the Gate gains `answer`.
2. **G12 copy and catalog truth**: remove the six unimplemented capabilities and the retention column, or label them *planned*; replace "live" with "polled on request"; fix the README PR-check sentence; stop promising production enforcement; rescope Launch deliverables #4 and #8.
3. **G26**: hide legacy surfaces not on the verified path.
4. **Written design decisions (ADRs) for G1, G2, G3.** No implementation required before GCP.

### Bucket A: before a hosted design partner

G1, G2, G3, G4, G7, G11, G12, G25 (minimal), G26, and G18 (trust directory rotation and KMS custody, as part of cloud acceptance).

## AN. Build-With-Customer List (Bucket B)

- **G5** — collector and runner for the partner's staging network and system of record; generalize into the SDK afterwards.
- **G6** — property authoring for the partner's 3–5 claims (a founder tool first).
- **G15** — deployment identity binding for the partner's deploy system (Cloud Run, Kubernetes, Vercel, …) and an explicit production statement.
- **G8** — authority semantics for the partner's tool limits and schemas.
- **G9** — GitHub contents fetch and Checks API, if the partner's agent config lives in GitHub.
- **G22 / G23** — code-defined agent export, data or IdP sources, only if the partner needs them.
- **Reference business-effect observer** for the partner's system of record: wire `observer_sql.py` or an HTTP read observer.

## AO. Deferred List (Bucket C: after repeatable demand)

G10 mapping UX, G13 audit viewer, G14 assignment and comments, G16 persisted consequences and mappings-in-force, G20 auto re-proof dispatcher, G21 AI assistants in UI, G24 GitHub OAuth, G28 SSO/SCIM, search and saved views, report packs, Slack integration, notification center, integration health dashboard, self-serve verified onboarding wizard, cross-environment Passports, usage-based metering.

## AP. Do-Not-Build List (Bucket D)

| Adjacent product | Should ThreatVeil build it? | Instead |
|---|---|---|
| Generic runtime firewall / agent guardrail | No | **Consume evidence** from it (as a witness or enforcer); **export** Gate answers it can enforce |
| Identity provider | No | **Integrate**: read effective scopes as system facts |
| DLP | No | **Consume** DLP events as observations |
| Generic agent inventory | No | **Integrate**: import inventories as sources; ThreatVeil's unit is the protected system |
| SIEM | No | **Export** assurance events (webhook, OTel) |
| Vulnerability scanner | No | **Consume** SARIF as unverified findings (already done) |
| Generic red-team platform | No | **Consume** results as candidate stimuli and findings |
| Generic eval platform | No | **Consume** eval outcomes only as unqualified signals |
| Prompt firewall | No | Integrate as an enforcer |
| GRC suite | No | **Export** Passports and history into GRC |
| Cloud posture platform | No | **Consume** IAM and config facts (Cloud Run pattern) |
| Universal trust score | **Never** | Keep claim-level, state-bound statuses |
| Remediation agent | No | Keep "never changes your system" |
| Production enforcement integrations (now) | No, until a qualified enforcer partner exists | Gate + customer policy engine |
| New connectors without a customer | No | Build with customer |
| AI chatbot / analyst | No | Deterministic explanations |

---

## AQ. 30–60 Day Commercial Kill Test

### Hypotheses and thresholds

| # | Hypothesis | Measure | Pass | Kill / pivot signal |
|---|---|---|---|---|
| H1 | Consequential-agent companies feel change-assurance pain | Qualified conversations using the Launch checklist | ≥ 10 conversations; ≥ 3 meet every qualification item | < 2 qualify → problem not urgent for this segment |
| H2 | They pay for verified assurance before self-serve | Signed Launch at ≥ $10K | ≥ 1 signed within 45 days | 0 after 8 offers with the same objection |
| H3 | Evidence production can be done without ThreatVeil code changes per customer | Customer engineering hours to first CLEARED; ThreatVeil code changes that are not generalizable | ≤ 40 customer hours; 0 non-generalizable changes after Bucket A | > 100 hours or bespoke branches → consultancy |
| H4 | The loop runs on a real system | Real change → correct loss → verified restore → Gate read | ≥ 1 full cycle within 60 days | Restore needs founder intervention every time |
| H5 | The consequence is right | "Was this right?" on real consequences | ≥ 80% CORRECT/PARTIAL over ≥ 10 | < 60% → semantics wrong |
| H6 | Someone relies on it | Machine Gate reads in CI or deploy; external Passport checks | Weekly reads for 4 consecutive weeks | Nobody consumes it after setup |

### Decision rule at day 60

- **H2 + H4 + H6 pass →** STRONG PURSUE; productize G5/G6.
- **H1 + H5 pass, H3/H4 fail →** **PIVOT WEDGE** to declared change assurance in CI (Pro-priced, developer-led, with GitHub fetch + Checks API), keeping the evidence kernel as the upgrade path.
- **H1 fails →** DO NOT PURSUE in this segment; re-target regulated workflows (finance ops, infrastructure agents) before abandoning.

### North Star check

**Relied-upon Protected Systems** (weekly: watched + maintained + relied upon; `business_measurement.py` definitions) is the right long-run North Star. It encodes real systems, a live source, maintained assurance and reliance, and excludes synthetic and replayed activity. But:

- It is **unattainable** today for real systems: "watched" needs polling (G3) and "maintained" needs restore (G1).
- "Maintained" counts a system "lost within the previous 14 days and being re-established", which a permanently broken system (E5-C) can satisfy.

**Recommendation:** keep RPS, tighten "maintained" to require a verified restoration within 14 days of loss, and use a gating metric for the next 90 days: **Verified Restoration Cycles on real systems** — a real change caused correct loss, clearance was restored by qualified evidence, and a machine consumer read the Gate within 7 days. It is harder to game than activation. `FIRST_CONFIRMED_CONSEQUENCE` was reached in E3 in 0.5 s of machine time with zero evidence and one click (`claim_basis: DECLARED`, `qualified: false`), so it is an engagement metric, not activation.

---

## AR. Business Readiness Score

| Dimension | Score | What moves it one point higher |
|---|---:|---|
| Core technical capability | **7** | G1 restore semantics implemented with a non-synthetic integration test (the E5 scenario passing) |
| Product completeness | **4** | G7 verify-and-decide orchestration usable from the UI for a non-synthetic system |
| Product comprehension | **5** | "Declared vs verified" made unmistakable in-app, plus a reason-code glossary |
| Self-service onboarding | **3** | Mapping by picking reported facts, removing invented dependency names |
| Design-partner readiness | **3** | Bucket A done (G1, G2, G3, G4) |
| Enterprise credibility | **4** | Operator-managed trust directory with KMS custody, and an explicit production statement |
| Integration depth | **3** | Scheduled collection that makes one source genuinely live |
| Evidence credibility | **6** | Observer Contract executed, not self-reported, and binding evidence |
| Operational workflow | **2** | Assurance-loss email + webhook |
| Collaboration | **2** | Correct review queue plus assignment of re-establishment work |
| Plan differentiation | **2** | Remove unimplemented capabilities; make Pro = continuous watching |
| Pricing readiness | **2** | One signed Assurance Launch at a tested price |
| GTM readiness | **3** | Copy truth fixed (G12) and a qualified pipeline of 10 conversations |
| Defensibility | **4** | One real system with 30 days of verified history and a Gate consumer |
| Customer dependency potential | **7** | A CI pipeline that blocks on `cleared` for a real partner |

---

## AS. Final Product Description

These describe what exists today; missing capabilities are not described as existing.

**10 words:** Shows which AI-agent security claims each configuration change would reach.

**One sentence:** ThreatVeil reads your AI agent's declared configuration, tells you which of your stated security claims a proposed or observed change reaches and which way its authority moved, and — for a staging boundary you have wired to qualified collectors — maintains a signed, recomputed assurance answer that machines and outside reviewers can check.

**30-second founder explanation:** Agents change constantly — permissions, tools, MCP servers, models — and yesterday's security testing quietly stops describing today's agent. ThreatVeil tracks that. Import the agent's configuration and state what must stay true; before you merge a change, it tells you which claims the change touches and whether it widened the agent's authority, without guessing when it cannot know. With a design partner, we go further: we wire independent observation of real business effects in staging, so ThreatVeil can say the agent is cleared on this exact state. It withdraws that the moment the evidence stops applying, and gives CI and your customers a signed answer they can verify. We are onboarding our first partners now.

**Technical buyer:** A deterministic change-impact engine for agent configuration — Claude Code settings, subagents, `.mcp.json`, MCP tool catalogs, CrewAI, a ThreatVeil manifest — with an authority-direction classifier, reviewed claim-dependency mappings and a read-only proposed-change API, CLI and GitHub Action. Behind it sits an evidence kernel: signed two-party observations bound to exact system state, per-claim invalidation, a PASS-plus-useful-task clearance rule, a machine Assurance Gate that never grants permission, and DSSE-signed Passports with a trust directory. Verified assurance today covers staging boundaries and requires collector integration, delivered with our team.

**Enterprise buyer:** ThreatVeil gives your security reviewers a current, verifiable statement of which critical claims about an AI agent are supported by evidence for the exact configuration under test, which are stale, and why. Every statement is signed, recomputed on request and never presented as a certification or trust score. Today it is delivered as an assisted engagement on one consequential workflow in staging. Production-deployment binding, SSO and private deployment are not yet available.

**Homepage hero:**
> **Your agent's permissions changed in this pull request.**
> **Which security claims does that touch?**
> ThreatVeil reads your agent's configuration, names the claims a change reaches and which way its authority moved — and, when you connect independent evidence, tells CI whether the agent is still cleared.
> *Start free with your agent's config* · *Apply for an Assurance Launch*

---

## AT. Final Pursue / Pivot / Kill Verdict

| Test | Answer |
|---|---|
| Is the problem real? | Yes, and growing; sharpest for agents with money, permissions, infrastructure or customer-visible effects. Urgency is unproven with buyers. |
| Is the wedge differentiated? | Yes in concept (evidence applicability, authentic ≠ current). No in the part that is self-serve today (config diff). |
| Is the product solving the problem? | Partly: declared impact yes; verified current assurance only in the fixture or with custom engineering; restore broken. |
| Can buyers understand it? | The Change Impact and Passport screens, yes. "Claims, mappings, evidence, qualification" vocabulary, with difficulty. |
| Can deployment be repeatable? | Not yet. Evidence production is bespoke. |
| Can onboarding escape consulting? | Only if G2 + G5 + G7 are productized from the first partner's build. |
| Can incumbents commoditize it immediately? | The config-diff layer, yes. The evidence/currency/Gate/Passport layer, not quickly. |
| Can the company accumulate durable assets? | Yes (history, qualified observers, Gate integrations), but none exist yet. |
| Is there a plausible pricing model? | Yes: Launch → Business for verified systems. Pro/Team are unjustified today. |
| Recurring rather than one-time? | Yes: change is continuous and evidence expires daily, provided watching and re-verification are automated. |

**Verdict: PURSUE WITH SPECIFIC CORRECTIONS.** The corrections are not cosmetic:

1. Make the verified loop (baseline → watch → lose → restore → Gate) work on a non-synthetic system without ThreatVeil code changes.
2. Unify observation.
3. Stop the product saying more than it knows.

If the 60-day kill test (§AQ) fails H3/H4, pivot the wedge to developer-led declared change assurance in CI, and keep the evidence kernel as the premium path.

---

## AU. Exact Next Sequence

### Roadmap

**NOW — before private GCP (≈ 1 week)**
- G4 truth fixes with tests: declared state, Home, Passport minimum evidence, review count, setup stages to backend, Gate `answer`.
- G12 catalog, pricing, README and Launch-kit truth.
- G26 hide legacy surfaces.
- ADRs for G1 (restore semantics), G2 (single observer model), G3 (collection scheduling and freshness semantics).
- Commit the tree.

**PRIVATE GCP / CLOUD ACCEPTANCE** — prove in hosted infrastructure:
- managed identity; RLS under the app role;
- broker/worker isolation for external targets;
- signing key custody (KMS) and a published operator-managed trust directory with a rotation drill;
- evidence storage and retention;
- Cloud Scheduler driving collection (G3) and schedules;
- GitHub App check delivery to a real repository;
- outbound email;
- Stripe test mode end to end;
- public Passport over HTTPS;
- Gate p95 latency;
- backup/restore and erasure drills;
- cost per verification run.

**FIRST DESIGN PARTNER**
- Implement G1, G2, G7, G11.
- Build with the partner: G5 (collector/runner + reference observer on their system of record), G6 (their claims), G15 (their deploy identity), G8/G9 as needed.
- Exit only when the E5 scenario passes on their real staging: CLEARED → real change → SUPERSEDED → restored by qualified re-verification → Gate read in CI, without partner-specific ThreatVeil code.

**FIRST 3 CUSTOMERS — make repeatable**
- Collector SDK (Python/TS) and reference observers (PostgreSQL, one HTTP API, one ticketing/billing SaaS).
- Claim → property compiler for 5 predicate patterns.
- Mapping fact picker.
- GitHub contents + Checks API.
- Audit viewer.
- A persisted consequence record.

**10 CUSTOMERS — productize**
- Self-serve verified onboarding wizard.
- Auto re-proof dispatcher on real environments.
- Assignment, comments and review queues.
- Slack.
- Security-review report pack.
- Mappings-in-force history.
- Metered pricing validated against run cost.

**SELF-SERVE GA**
- Declared tier fully self-serve (GitHub OAuth, contents fetch, PR checks, notifications, live Stripe).
- Verified tier reachable in ≤ 1 engineering day with the SDK.
- In-app guides and troubleshooting; published SLOs.
- Plans re-cut around watching (Pro), seats and review (Team), and verified evidence (Business).

**ENTERPRISE EXPANSION** (only after meaningful traction)
- SSO/SCIM, private runners and deployment, enforced retention and residency, BYOK.
- Policy-engine enforcement integrations (OPA/Cedar-style consumers of the Gate).
- Cross-organization Passport exchange; SOC 2.

### Exact next sequence

1. Fix G4 truth defects; add a test that an evidence-less state never files a system as current or issues a Passport that reads CURRENT.
2. Apply G12: remove unimplemented plan capabilities and overclaiming copy; rescope Launch deliverables #4 and #8.
3. Hide G26 legacy surfaces; commit the working tree.
4. Write the G1/G2/G3 ADRs (one page each).
5. Turn the E5 experiment into a permanent failing integration test (`non_synthetic_restore_after_import`), marked expected-to-fail until G1 lands.
6. Run private GCP activation and cloud acceptance, including Cloud Scheduler and KMS/trust-directory rotation.
7. Implement G2: the Observer Contract binds evidence; ThreatVeil records harness execution; wire `observer_sql.py` as the first reference observer.
8. Implement G1 against the new observer model until step 5's test passes.
9. Implement G7 (generic verify-and-decide + schedule) and G3 (scheduled collection; freshness degrades watching, not support).
10. Implement G11 (loss email + signed webhook) and the minimal G25 guides.
11. Run the 30–60 day kill test (§AQ) with the rescoped Assurance Launch; record hours and every non-generalizable change.
12. At day 60, decide STRONG PURSUE / PIVOT WEDGE / DO NOT PURSUE by the §AQ rule.

---

### KEEP

- The append-only, tenant-isolated record store and the conservative semantics everywhere (`UNKNOWN` never authorizes; declared never supported).
- Evidence applicability and ProofScope invalidation; mapping-scoped claim invalidation that preserves unaffected claims.
- `PASS + useful-task failure = not cleared`.
- The Assurance Gate contract (`authorizes: false`, freshness, fail-closed SDK).
- The Passport's authentic ≠ current design, DSSE signing, disclosure profiles, share capabilities, offline and browser verification.
- Deterministic definition parsing with content-free errors and format detection.
- The proposed-change dry run, its non-mutation guarantee, CLI and GitHub Action.
- Honest provenance labels (imported vs live vs declared), and no vendor identity inferred from content.
- Provenance-separated business measurement (synthetic and replayed never count).

### EXPOSE

- Signed-collector evidence production, as a documented, guided path (today hidden behind legacy developer pages).
- Audit records, via a simple viewer (Business).
- History replay (`threatveil replay-config-history`) as an onboarding "what past changes would have meant" moment.
- Evidence reason codes, as a glossary in-app.

### COMPLETE

- **Restore assurance** after source-observed changes for non-synthetic systems (G1).
- **Business-effect observation**, unified into one observer model that produces evidence (G2); wire `observer_sql.py`.
- **Watching**: scheduled collection and freshness semantics (G3).
- **Verify-and-decide orchestration** for any system (G7).
- **Trust directory**: operator rotation and KMS custody.
- **Operator truth**: Home, Setup progress, Passport issuance rules, Gate `answer` (G4).
- **Assurance history**: persisted consequences and mappings-in-force (later).

### BUILD

- Assurance-loss notifications: email + signed webhook (G11).
- Minimal guides: declared vs verified, reason glossary, produce your first evidence (G25).
- A non-synthetic restore integration test that gates releases.
- Later: GitHub contents fetch + Checks API for proposed changes (G9), mapping fact picker (G10).

### BUILD WITH CUSTOMER

- Collector SDK, private-network runner and reference observer for the partner's system of record (G5).
- Claim → executable property authoring (G6).
- Deployment identity binding and an explicit production-environment answer (G15).
- Authority semantics for the partner's limits and schemas (G8).
- Code-defined agent export, data or IdP sources (G22, G23) — only if the partner needs them.

### DEFER

- Auto re-proof dispatcher for real environments.
- AI mapping, claim and property assistants in the UI.
- Assignment, comments, mentions, saved views, content search, Slack, report packs, notification center.
- GitHub OAuth and repository picker; SSO/SCIM; private deployment.
- Cross-customer corpus and learning.
- Plan retention enforcement.

### DELETE / HIDE

- Unimplemented plan capabilities from the catalog and pricing: `notifications` (until built), `approval.workflow`, `policy.shared`, `evidence.sharing`, `governance.advanced`, `observer.advanced`, `connector.github.enforce`, `connector.github.export`, and the retention column.
- "Live source", "Live monitoring" and "ThreatVeil watches" wording, until collection is scheduled.
- "Business … participate in production enforcement" copy, and external enforcement requests from the UI.
- Evidence-less Passport issuance.
- Customer navigation to legacy surfaces not on the verified path: gauntlets, fixes, findings, propagation, tool contracts, release machine, integrity-launch operator views.
- The Observer Contract's self-reported qualification endpoint as a customer-facing "qualified" state, until it binds evidence.
- AI change-explanation ideas and any trust-score concept, permanently.
