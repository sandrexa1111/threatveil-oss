# ThreatVeil — Pre-GCP Product, Commercial & Competitive Readiness Audit

**Audit date:** 10 September 2026. **Decision:** B — DEPLOY AFTER P0 FIXES.

**Object audited:** the application and source in this repository, running locally on ports 3000 and 8000, with PostgreSQL and the synthetic procurement fixture. This is a diagnostic audit, not a certification, customer study, or implementation mandate. No GCP resources were applied. No product code was changed. New local synthetic organizations, runs, and audit artifacts were created; the temporary audit API credential was revoked and temporary reproduction servers were stopped.

**Evidence standard:** WORKING means exercised within the stated boundary. It does not imply a live customer integration. PARTIAL means meaningful implementation exists but a material part of the promised customer outcome is missing. BACKEND-ONLY means implemented without a usable corresponding customer flow. NOT PRESENT means not found in the inspected implementation. Where provider calls are mocked in tests, that is stated separately from the capability classification. Competitor coverage comes from fresh primary-source research, not competitor account access. Missing public documentation is not proof that a competitor lacks a feature.

## 1. EXECUTIVE DECISION

# B. DEPLOY AFTER P0 FIXES

ThreatVeil has a credible product nucleus: it records bounded security conclusions, reassesses their applicability when an agent changes, requires security and legitimate-task evidence, and records a signed decision for an exact candidate. The local implementation is substantive. Fresh verification produced **469 passing Python tests, nine passing browser tests, seven passing mocked Terraform tests, and a successful ALLOW → BLOCK → ALLOW demonstration with independently verified local signatures**.

That does **not** make the current application a sellable autonomous release platform. I reproduced two gaps that those suites miss: a valid GitHub webhook is rejected through the hosted web relay, and an ordinary execution token cannot issue the complete release decision exposed by the CLI/SDK. Infrastructure inspection also shows that the broker responsible for GitHub publication does not receive the GitHub App credentials supplied to the API. The first-user experience requires manual records, JSON definitions, candidate fingerprints, and specialist observation setup. There is no working “connect your AI system” journey.

**Do not reconstruct the company thesis. Do not launch this exact build as production security infrastructure.** Correct the hosted release path, resolve the narrow machine-authority contract, provide one honest assisted onboarding path, and make deployment readiness testable. Then deploy privately, complete cloud acceptance, and sell a bounded Integrity Launch to a qualified design partner. Four P0 items are specified in section 16; none requires a platform rewrite or universal discovery engine.

The strongest commercial promise is: **“Before you ship a changed agent that can take consequential actions, we show which agreed security conclusions you can still rely on, establish the missing evidence, and retain why that exact release was accepted.”** It is valuable when security review delays enterprise releases or an agent can commit costly actions. It is weak for simple chatbots and teams satisfied with inexpensive full-suite CI.

The principal strategic threat is commoditization and bundling. Testing, outcome verification, regression history, CI gates, and downloadable evidence are already competitive surfaces. The current deterministic validity engine is useful engineering, not a proprietary breakthrough. ThreatVeil has no demonstrated customer corpus, installed release dependency, independent trust asset, or distribution advantage. Those must be earned through real releases.

**Commercial permission:** sell scoped design-partner work after P0 and hosted acceptance, initially in WARN mode. Do not sell proven selective-testing savings, autonomous onboarding, compliance certification, or a production BLOCK service today. Fresh candidate anchoring through property-bound observers may require execution even for apparently reusable evidence (section 10). The next investment should purchase customer evidence, not another broad feature wave.

## 2. WHAT THREATVEIL ACTUALLY IS TODAY

ThreatVeil is an operator-assisted security verification and release-record application for software agents that perform business actions. A team defines a workflow, declares boundaries it must preserve, authorizes a test destination, and supplies observations of what happened. ThreatVeil runs bounded checks, distinguishes a security result from useful task completion, compares the conditions behind old results with a new candidate, and records the release decision.

It is strongest at refusing to turn missing information into a positive assurance claim. A model saying “I did not change the bank account” is insufficient; a qualified observation of the relevant action boundary must support the conclusion. A fix that disables all useful work is also insufficient.

Today this is a **working local product core surrounded by an engineering control panel and an unaccepted cloud deployment design**. It is not an automatically connected inventory of enterprise agents, a runtime firewall, an independent auditor, or an established release authority. A signed record establishes integrity of the recorded claim under a trusted key; it does not establish that the observation or underlying security conclusion was correct.

### Capability verification

| Claimed capability | Classification | What is established; material limit |
|---|---|---|
| Protected systems | WORKING | Created a system through the UI and reopened its persisted record. Registration does not connect an agent. |
| Security properties | WORKING | Created a template-derived draft; review/version approval and scope enforcement are exercised in tests. Business-specific predicates and positive fixtures require human work. |
| Exact candidates and fingerprints | WORKING | Demo binds version/content and component identity. There is no automatic guarantee that an imported repository snapshot is the code running in staging. |
| ProofScopes | WORKING | Persisted dependency coverage, review authority, expiry, and compatibility bindings; observed scope in UI and inspected algorithm. |
| STILL_VALID / VOID / UNKNOWN | WORKING | Fresh demo invalidated prior evidence; tests exercise conservative graph, expiry, and unknown behavior. Not learned causal reasoning. |
| Bounded re-proof planning/execution | WORKING | Demo created and executed an exact-candidate plan. Customer must configure runs and observations; a plan is not execution. |
| Complete approved-property release decision | WORKING | Server rereads approved scope and adverse evidence. Complete decision is distinct from the existing single-property GitHub Action. |
| Legitimate-task verification | WORKING | Bad fix produced security PASS, task FAILURE, release BLOCK. Demonstrated on the controlled fixture. |
| ALLOW / WARN / BLOCK | WORKING | Local result and policy behavior work. Actual deployment prevention requires an accepted external gate and branch/deployment policy. |
| Signed release receipts | WORKING | Three DSSE/in-toto Ed25519 envelopes verified with an independently obtained local public key. Hosted custody/rotation remain unaccepted; no Sigstore transparency log. |
| Immutable history | WORKING | Append-only database records/triggers and historical receipts. A database administrator remains trusted; this is not externally witnessed, tamper-proof infrastructure. |
| GitHub App integration | PARTIAL | Installation/binding, signed event handling, publication outbox and revocation logic exist; provider behavior is largely tested with doubles. Public relay fails reproduced signature test; broker credential wiring is incomplete. No real check was published in this audit. |
| GitHub OIDC / Action | PARTIAL | Narrow repository/workflow authority exists. Current automation operates a frozen single-property scope, not the whole advertised system release lifecycle. |
| OpenTelemetry GenAI | BACKEND-ONLY | Bounded intake normalizes supplied data into reviewable records. No “connect collector” customer wizard or continuously discovered system was demonstrated. |
| OpenAI Agents | BACKEND-ONLY | Import/normalization support exists. It is not a managed installation into a customer's agent platform. |
| Anthropic | BACKEND-ONLY | Hook-data intake exists. It is not automatic Claude/LangGraph application discovery or a verified live provider integration. |
| MCP | PARTIAL | Bounded remote adapter, tool normalization/discovery, and SDK surface exist. No general arbitrary MCP execution; observation authority is separately required. |
| CycloneDX | BACKEND-ONLY | Inventory import proposes composition facts; an SBOM does not become behavioral security proof. |
| SARIF | BACKEND-ONLY | Findings intake retains provenance and drafts. Scanner output does not automatically approve a property or produce PASS. |
| Integrity Launch | PARTIAL | Scope, milestones, effort, installation evidence, and payment distinctions are real records with browser coverage. No real engagement has completed those milestones. |
| Billing | PARTIAL | Entitlements and verified-event processing exist; local UI showed unassigned, unpaid, zero trial budget, no configured Stripe offers. No payment occurred. |
| CLI / Python SDK / TypeScript SDK | PARTIAL | Real source and interfaces exist; ordinary execution credential cannot call the security-only full release issuer. No demonstrated public package distribution. |
| Data governance | PARTIAL | Consent, retention limits, mutation freeze, export and constrained local erasure exist. Cloud/provider/backups erasure is not implemented end to end. |
| Tenant isolation | WORKING locally | Membership, tenant references, FORCE RLS, negative integration tests. Effective deployed IAM/RLS remains to be proven. |
| Automatic repository-to-system onboarding | NOT PRESENT | No repo picker, deployment picker, inferred action review, or “Protect this system” completion flow. |
| Learned invalidation intelligence / reusable corpus | NOT PRESENT | Deterministic rules and private records exist; neither cross-customer learning nor outcome-calibrated scope inference exists. |
| Fleet / third-party trust / insurer consumption | NOT PRESENT as products | Multiple-system primitives and exports are foundations, not delivered fleet or assurance-network products. |

No major capability should be dismissed as UI-ONLY simply because the UI is weak. Conversely, broad provider support must not be promoted from backend parser coverage into a working customer connection.

## 3. WHAT A CUSTOMER CAN DO TODAY

A technical operator can perform this sequence:

1. Open the local application and create a clearly labeled local development identity. Hosted managed authentication is a separate acceptance task.
2. Create a protected system with a name, description, resources, and actions. These are declarations, not discovered infrastructure.
3. Create a security property from a template or definition, bind the actual business predicate and positive task fixture, then have an authorized role approve it.
4. Register a bounded target: adapter, HTTPS origin, allowed paths/methods/tools, credential references, authorization and expiry. Registration alone does not verify the target.
5. Provision/qualify observation sources and distinct ground-truth evidence where required. This is specialist integration work.
6. Obtain an explicit execution allowance. A fresh account's zero trial budget does not give it immediate execution.
7. Execute the approved property against a candidate and inspect security, legitimate-task, observation and evidence results separately.
8. Supply the new exact candidate and complete fingerprint, compare with previous state, and create a re-proof plan.
9. Inspect which old evidence is reusable, invalid or unknown; configure and execute the required runs.
10. Use an authorized interactive security identity to record the system release decision and export its receipt. Inspect historical and current applicability separately.
11. Record launch scope, effort and integration milestones. Real installed delivery and real payment cannot be replaced by a completed checklist.

**Verified demonstration:** the audit ran `scripts/release_demo.py`. It used real local HTTP, PostgreSQL and committed synthetic SQLite business state. Baseline ALLOW became BLOCK after a changed authorization configuration, then ALLOW after restoring the tested fixed configuration. Missing witness returned INCONCLUSIVE; bad fix returned task FAILURE. Three signatures verified. The measured 0.874 seconds describes this deterministic local fixture only. It is not onboarding time, cloud performance, LLM reliability or proof of automated remediation.

## 4. WHAT A CUSTOMER CANNOT DO TODAY

- Connect GitHub and have ThreatVeil discover a usable, approved, instrumented agent automatically.
- Select an existing deployment and know its complete model/prompt/tool/permission/data identity has been captured authoritatively.
- Paste arbitrary traces and obtain trustworthy security evidence without qualifying the observer and binding candidate/target/source semantics.
- Create a useful payment security contract solely by selecting a template. The inspected template contains a positive-task placeholder and `legitimate_control: null`.
- Depend on the documented public GitHub route and deployed reconciliation configuration as a working continuous release integration.
- Use the ordinary execute token to issue the complete signed release decision through the advertised machine client.
- Infer that an ALLOW record means GitHub actually prevented a different commit or that production deployed that exact artifact.
- Obtain automatic, reliable semantic knowledge of which changes are harmless. Reviewed compatibility is an explicit digest allowlist.
- Claim substantial selective-testing savings from the canonical demo: it has one property, and default coverage invalidates on all observed component changes.
- Keep unchanged evidence valid indefinitely: current ProofScope age is bounded to at most 86,400 seconds. That creates recurring verification cost even without a meaningful release change.
- Buy demonstrated uptime, independent security certification, completed cloud erasure, proven recovery, or a production service-level commitment.
- Obtain a useful cross-customer model from a consent checkbox. No such pipeline exists.

These are material scope limits. A consultant can bridge several, but human bridging must be priced and measured rather than described as product automation.

## 5. PRODUCT QUALITY

**Verdict: an engineering control panel with several credible product surfaces. It does not yet feel like a category-defining enterprise product.** The visual design is restrained and coherent; the information architecture exposes too many internal operations before establishing the customer's system and next action.

The homepage communicates change and release value reasonably well. The empty workspace immediately asks for evidence, candidates and re-proof. The new-system form ends in a persisted JSON record. The user must assemble the product from Systems, Properties, Targets, Integrations, Runs and Change explorer. A well-designed card does not solve that coordination problem.

The populated timeline is better: ALLOW/BLOCK cards, exact versions and decision detail make a real result visible. The inspected blocked decision nevertheless concatenated “all dependencies … remain unchanged” with “changed dependency invalidates this evidence.” Those reasons come from different historical comparisons but are presented without that distinction. The decision is conservative; the explanation is confusing. Fixing that explanation has more product value than another dashboard.

### Five-minute technical-buyer test

This is my walkthrough assessment, not a measured study with independent buyers.

| Buyer question | Result | Why |
|---|---|---|
| What is ThreatVeil? | Mostly clear | Security gate for changed AI releases is visible. |
| Why use it? | Partly clear | Stale security evidence is explained; economic consequence is less concrete. |
| What should I connect? | Unclear | Workspace leads with records rather than a connection. |
| What is an AI system? | Partly clear | Resources/actions help, but boundary versus repo/deployment remains ambiguous. |
| Where does the system come from? | Unclear | It is manually declared; the UI does not explain that transition adequately. |
| How do I register my agent? | Weak | Manual form exists, but registration is not operational onboarding. |
| What is automatically discovered? | Unclear | Integration names overstate what an unassisted visitor can activate. |
| What do I configure? | Weak | Requirements appear across separate pages. |
| What is a security property? | Partly clear | Names are comprehensible; JSON predicates are specialist material. |
| What is the current security state? | Partly clear | Empty account has no guidance; populated account mixes latest run and historical decision. |
| What changed? | Clear after setup | Change records identify component differences. |
| Why is old evidence stale? | Partly clear | Explicit reasons exist, but internal component names and combined histories intrude. |
| What is being tested again? | Mostly clear after setup | Plan lists obligations, observer, trials, variants and legitimate task. |
| Why ALLOW/WARN/BLOCK? | Mostly clear | Separate policy/evidence states help; contradictory-looking reasons need attribution. |
| What next? | Weak | No unified system checklist or one primary next action. |

### Screen scores, 1–10

C = clarity; V = visual quality; IA = information architecture; B = business comprehensibility; E = enterprise credibility; T = technical credibility; A = actionability; D = differentiation; P = perceived value. These are editorial judgments from the manual local walkthrough and screen/source inspection, not statistical usability measurements. A missing dedicated screen is scored as the available substitute, not credited as a roadmap item.

| Screen / available surface | C | V | IA | B | E | T | A | D | P | Main observation |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| Homepage | 8 | 8 | 8 | 7 | 7 | 7 | 7 | 6 | 7 | Good promise; illustrative results honestly labeled. |
| Login + first workspace / onboarding | 4 | 7 | 4 | 4 | 5 | 6 | 3 | 3 | 4 | Many destinations, no connected first outcome. |
| Systems list/create | 5 | 7 | 5 | 5 | 5 | 6 | 4 | 3 | 4 | Manual resources/actions and generic suggestions. |
| System overview substitute | 3 | 6 | 3 | 3 | 4 | 6 | 2 | 2 | 3 | Description plus expanded JSON record. |
| Release timeline | 8 | 8 | 7 | 7 | 7 | 8 | 7 | 7 | 7 | Strongest overview once populated. |
| Change explorer | 5 | 7 | 4 | 4 | 5 | 8 | 5 | 7 | 5 | Multiple workflows and JSON inputs compete on one page. |
| Evidence ledger/detail | 6 | 7 | 6 | 5 | 7 | 8 | 6 | 7 | 6 | Correct separation of old result and current applicability; UUID-heavy scope. |
| Property creation/review | 4 | 7 | 4 | 4 | 5 | 7 | 4 | 4 | 4 | Template still needs a usable contract. |
| Re-proof plan | 6 | 7 | 6 | 6 | 6 | 8 | 6 | 7 | 6 | Required work is visible; execution needs manual configuration. |
| Release decision | 6 | 7 | 6 | 6 | 7 | 8 | 6 | 7 | 7 | Exactness is strong; reason attribution and policy UX need work. |
| Receipt panel/export | 5 | 6 | 5 | 4 | 6 | 8 | 6 | 5 | 5 | Portable JSON is useful to engineers, not yet an assurance-consumer experience. |
| Integrity Launch | 6 | 7 | 6 | 6 | 6 | 7 | 5 | 5 | 6 | Honest milestones; records do not perform installation. |
| Billing / usage | 6 | 7 | 6 | 6 | 6 | 7 | 4 | 3 | 4 | Honest unpaid/unassigned state; operator must establish scope/budget. |
| Public pricing | 7 | 8 | 7 | 7 | 6 | 6 | 7 | 4 | 6 | Outcome-based structure; 8–12-property scope lacks measured delivery evidence. |
| Security / trust | 8 | 8 | 7 | 7 | 6 | 8 | 6 | 4 | 6 | Candid limitations; no deployed assurance or operational track record. |
| Target / observation setup | 4 | 7 | 4 | 4 | 6 | 8 | 4 | 5 | 4 | Appropriate security constraints, substantial integration burden. |

Internal terms earn space in inspect/export views. They should not be prerequisites for understanding how to protect an existing agent. The present setup flow fails that standard.

## 6. SYSTEM ONBOARDING

**Is current registration good enough to sell? NO as self-service. CONDITIONAL as an explicitly assisted, tightly scoped engagement.**

I created an “Accounts payable agent,” described invoice processing and finance approval, entered resources/actions, requested property suggestions, and saved it. The application suggested a broad list of 18 property names, then displayed a record. It did not connect GitHub, discover a provider, inspect MCP tools, find telemetry or propose a verified deployment boundary. Selecting a payment template created a draft whose positive control still needed implementation.

The integration page offers setup guidance and status, not a repository installation/picker flow. Its observer registration requires system, approved property, verified target, source identity/version, candidate component, two public keys, initial-state digest, fixture reference and independence review. Those fields represent real trust requirements. A better UI cannot eliminate the need for an independent business observation; it can make setup and failure diagnosis repeatable.

| Desired onboarding step | Today | Gap |
|---|---|---|
| Connect GitHub, choose repo | API/operator binding and guidance | Installation callback/repo selection experience and hosted delivery acceptance. |
| Select agent/deployment | Manual system and target | Explain repo versus runnable workflow versus environment; bind them visibly. |
| Discover framework/provider | Import parsers | Obtain source data and present provenance/confidence for review. |
| Discover MCP/tools | Bounded tooling exists | Connect authorized destination and integrate discoveries into one review flow. |
| Connect OTel | Supplied-data normalization | Collector setup, health, freshness and missing-span diagnosis. |
| Construct candidate components | Manual JSON or reviewed intake | Avoid silent guesses; assemble an explicit reviewable manifest. |
| Propose consequential actions | Manual resource/action fields | Identify actual effects and who owns their authorization. |
| Propose properties | Generic templates | Bind resource, actor, approval, committed effect and positive control. |
| Qualify observations | Specialist registration | Reusable witness installation and a diagnostic smoke test. |
| Protect this system | No unified completion | One system page showing verified prerequisites and next step. |

**Friction measurement:** counted forms, fields, navigation handoffs and missing operations in the actual UI; no real-customer elapsed onboarding time exists. The observed manual journey involves at least six workspace areas before a meaningful release outcome. A prepared operator can create records quickly; record creation is not time to protection.

For a first customer, plan **40–80 ThreatVeil engineering hours and 12–30 customer hours**, potentially more if no independent action ledger or resettable staging fixture exists. These are planning estimates, not measured performance. Two qualified observation paths, customer permissions, positive controls, candidate capture and CI acceptance dominate the work. A three-day promise is not justified before prerequisites are known.

The immediate correction is one supported assisted path and a system readiness checklist. Full automatic discovery is not a pre-GCP requirement. A customer should know what is connected, what is merely declared, what is still missing, who must act, and whether any release is actually protected.

## 7. PAID PRODUCT

The sellable unit is a **scoped installation and verification engagement for one consequential workflow**, followed by continuous operation only if the customer accepts the installed WARN path and continues releasing.

| Stage | Concrete customer outcome | ThreatVeil work | Customer work |
|---|---|---|---|
| Before Day 1 | Agreed workflow, staging access and success criteria | Qualify fit and integration prerequisites | Name engineering/security owners; approve test scope and data handling. |
| Day 1 | Map one action boundary and select initial properties | Translate business rule into testable contracts | Explain authorization, actual side effects and expected legitimate task. |
| Day 3, if access is ready | First useful evidence and a visible observation gap or regression | Integrate collectors, run positive/negative controls, bind exact candidate | Supply staging fixture, credentials by reference and independent ledger access. |
| End of scoped launch | Baseline, changed candidate, re-proof, signed decisions and delivered WARN result | Install and verify the complete release path; train owner; document remaining gaps | Accept scope and integration; own remediation and release policy. |
| Recurring | New releases evaluated; evidence refreshed; gaps and exceptions tracked | Maintain integrations, investigate evidence failures, support release review | Keep observations healthy, review changes, fix product regressions. |

**What remains installed:** authorized target/observer bindings, candidate/change capture, approved properties, release integration, retained history, trust-key configuration, execution budget and operating ownership. A PDF report alone does not complete the launch.

**Why renew:** the system continues changing; the customer continues needing current evidence and an accountable release record. If the customer stops releasing, does not use the decision, or can cheaply run all checks in existing CI, the recurring argument weakens sharply.

**What the app genuinely supports:** retaining agreed scope and effort, linking system/properties, and refusing to label an unverified installation or manual pilot allowance as successful delivery/payment. This is better than a cosmetic sales checklist. But it does not do the missing integration work.

**Consulting risk: HIGH.** Reusable work includes schemas, receipt verification, target transport, fixtures for a repeated tool boundary, policy templates and deployment packaging. Bespoke work includes identifying the real business invariant, establishing authoritative observations, obtaining permissions, translating internal APIs and proving the legitimate task. Customer #10 is easier only if those bespoke steps recur across a narrow ICP. Track hours by task and artifact; do not use the existence of ten connectors as a repeatability metric.

## 8. COMMERCIAL READINESS

| Readiness axis | Score /10 | Current judgment | Required evidence |
|---|---:|---|---|
| Engineering | 7 | Local core works; cross-layer release gaps remain | P0 reproductions become passing acceptance cases. |
| Cloud | 4 | Substantial declarative infrastructure; no effective cloud acceptance | Exact images, identity/IAM, execution, storage and recovery checks on GCP. |
| Product | 5 | Usable by an informed operator | New technical user completes one supported journey without editing assurance JSON. |
| Sales | 6 | Demo and bounded offer can start a conversation | Buyer explains value back and commits to a paid scope. |
| Onboarding | 3 | Manual integration project | Measured first and second customer setup effort. |
| Trust | 4 | Good local boundaries, weak external proof | Hosted denial tests, custody/incident ownership and customer security acceptance. |
| Commercial | 4 | Paid design-partner hypothesis | Real payment tied to accepted installation and continued use. |
| Repeatability | 2 | No customer cohort | Third installation materially cheaper than first, then sustained use. |

**Local:** demonstrable with operator assistance. **Cloud:** ready to begin controlled deployment work after corrections, not ready to claim production. **Customer:** no real target accepted. **Revenue:** no payment or renewal established.

### What customers pay for, and why alternatives may suffice

| Alternative | What it already solves | Why a customer might still pay ThreatVeil | When ThreatVeil loses |
|---|---|---|---|
| Existing CI / GitHub Actions | Executes arbitrary checks and blocks merges | Maintained security semantics, observation qualification, applicability history and complete release decision across tools | Customer can maintain a small full suite cheaply. |
| Pentest | Expert discovery and periodic assessment | Keep agreed findings/properties active through subsequent changes | Releases are rare or the buyer only needs a periodic report. |
| Promptfoo / eval stack | Red-team and regression evaluation integrated into development | Independent effect evidence and scoped historical authorization as an operational service | Equivalent assertions, fixtures and policy can be added to existing evaluations. |
| Runtime security | Enforces controls during actual use | Pre-release behavioral evidence and durable rationale; complementary preventive layer | Runtime controls fully solve the boundary at much lower operational cost. |
| Observability | Shows traces, costs, quality and incidents | Accountable conclusion about an exact release, with explicit missing evidence | The team only needs debugging or quality trends. |
| Internal platform team | Owns context, identity, CI and business APIs | Neutral maintained product reduces scarce specialist work across teams | Integration requires almost the same internal work with or without ThreatVeil. |

The pain owner is usually the engineering leader responsible for the consequential workflow, with AppSec/security approving the control. The budget can sit in engineering platform or security. An external vendor is justified by maintained expertise, cross-stack operations and an accepted evidence record, not by the ability to hash JSON.

### Revenue test

The present standalone application looks economically closer to **$500/month specialist software with substantial setup services** than proven **$50K–$250K/year security infrastructure**. That is a perception/value judgment, not a market price quote. The latter requires demonstrated operational dependency and trust; it cannot be inferred from the word “security.”

| Price level | Credible basis | Judgment today |
|---|---|---|
| $10K launch | One bounded consequential workflow, working observations, installed WARN path and accepted handoff | Plausible experiment after P0; use explicit prerequisites and acceptance, not an unconditional promise. |
| $25K launch | Multiple action boundaries or materially deeper integration with a buyer-funded requirement | Possible services price, not validated product willingness to pay. Beware poor margins. |
| $25K ACV | One high-value system, frequent releases, repeated review effort and an actively used gate | Plausible design-partner hypothesis after real use. |
| $50K ACV | Several protected workflows or one release-critical system, ongoing support and measurable review savings | Requires customer evidence absent today. |
| $100K ACV | Cross-team standard, enterprise revenue dependency, strong operating controls and multiple systems | Not supported by current maturity. |
| $250K+ account | Broad fleet adoption, procurement/audit consumption, support and deployment obligations | Expansion hypothesis only; current product cannot justify this on its own. |

Use customer-specific arithmetic. For example, eight monthly reviews taking six hours at a $150 loaded hourly cost consume $86,400/year. Saving half yields $43,200 before subtracting ThreatVeil setup, execution, administration and residual review cost. This illustrative model can support a $25K conversation; it does not establish actual savings. A delayed enterprise contract or costly unauthorized transfer may justify more, but quantify that with the buyer. Do not invent a breach probability to manufacture ROI.

## 9. COMPETITIVE POSITION

### Research boundary and current market

Fresh web research was performed on 10 September 2026. The comparison below uses official product documentation and vendor announcements. It establishes documented positioning and capabilities, not independently measured quality, pricing, deployment coverage or customer satisfaction. Feature availability varies by plan and preview program.

Three corrections to a simplistic competitive narrative matter:

- TestMu's 17 August Agent Assurance announcement overlaps directly with agent discovery, effect verification, explicit uncertainty, version context, regression history, evidence packs and CI use. Its page also says early access is opening in batches. Treat it as a direct announced/early-access threat, not a fully independently validated GA benchmark. [TestMu launch](https://www.testmuai.com/blog/introducing-agent-assurance/)
- Promptfoo's March announcement was conditional, but its current About page says it is now part of OpenAI. The present ownership statement is stronger current evidence than repeating the old “agreed to acquire” wording. It does not prove every planned Frontier integration has shipped. [Promptfoo About](https://www.promptfoo.dev/about/), [original OpenAI announcement](https://openai.com/index/openai-to-acquire-promptfoo/)
- Palo Alto completed Protect AI in July 2025 and Portkey in May 2026. Model/supply-chain security, agent security and gateway distribution are not independent weak startups to dismiss separately. [Protect AI completion](https://paloaltonetworks.gcs-web.com/news-releases/news-release-details/palo-alto-networks-completes-acquisition-protect-ai), [Portkey completion](https://paloaltonetworks.gcs-web.com/news-releases/news-release-details/palo-alto-networks-completes-acquisition-portkey-secure-ai)

### Products, buyers and control points

| Company / product | What is documented today | Buyer and deployment/control point | Distribution advantage; implication for ThreatVeil |
|---|---|---|---|
| TestMu Agent Assurance | Codebase discovery, generated criteria, observed effects, unverifiable outcomes, version comparisons, evidence packs and headless CI; early access | Agent engineering/quality; local CLI plus organization UI | Existing testing platform and easier advertised entry. Direct overlap. [Source](https://www.testmuai.com/blog/introducing-agent-assurance/) |
| Promptfoo / OpenAI | Red-team/evaluation workflows, custom assertions, CI and MCP security testing | Developers/AppSec; pre-release CLI/API/CI | OSS adoption and model-platform distribution; an inexpensive substitute or evidence supplier. [CI](https://www.promptfoo.dev/docs/integrations/ci-cd/), [MCP](https://www.promptfoo.dev/docs/red-team/mcp-security-testing/) |
| Noma Security | AI inventory/posture, agent-focused red teaming and runtime security | CISO/AI security; lifecycle inventory, testing and runtime | Security-suite consolidation; can sell a broader risk outcome. [Red teaming](https://noma.security/products/ai-red-teaming), [agent security](https://www.noma.security/blog/press-release-noma-security-launches-industrys-first-comprehensive-ai-agent-security-solution) |
| Zenity | Contextual security across configuration, identity, intent and runtime behavior | Enterprise security; agent/SaaS posture and runtime | Enterprise integration and contextual history. “Remembers context” is not unique. [Source](https://zenity.io/blog/continuous-contextual-security) |
| Palo Alto Prisma AIRS | Model scanning, posture, red teaming, runtime and agent-security portfolio | CISO/platform security; development through runtime | Installed security distribution and consolidated buying. [Source](https://paloaltonetworks.gcs-web.com/news-releases/news-release-details/palo-alto-networks-completes-acquisition-protect-ai) |
| Protect AI, within Palo Alto | Model and AI supply-chain security contributes to AIRS | ML/AI security; model/artifact lifecycle | Treat as portfolio capability, not separate neutral distribution. [Source](https://paloaltonetworks.gcs-web.com/news-releases/news-release-details/palo-alto-networks-completes-acquisition-protect-ai) |
| Portkey, within Palo Alto | AI gateway, routing, observability, guardrails and MCP gateway | AI platform engineers; inline model/tool access | Already sees traffic and can insert policy. Specific MCP guardrails page says coming soon; do not credit all combinations as GA. [Gateway](https://portkey.ai/docs/product/ai-gateway), [MCP limitation](https://portkey.ai/docs/product/mcp-gateway/guardrails) |
| Snyk / Invariant Labs | Agent/tool security analysis and contextual runtime policy technology; Snyk acquired Invariant | Developers/AppSec; developer tools, MCP and runtime | Developer-security installed base and research. Labs experiments are not automatically GA. [Acquisition](https://snyk.io/news/snyk-acquires-invariant-labs-to-accelerate-agentic-ai-security-innovation/), [Labs](https://labs.snyk.io/) |
| HiddenLayer | AI discovery, model/supply-chain security, attack simulation and agentic runtime protection | AI security/SOC; platform inventory and execution | Specialized research and integrated security offering. [Runtime docs](https://docs.hiddenlayer.ai/docs/products/runtime/overview), [agentic announcement](https://www.hiddenlayer.com/news/hiddenlayer-unveils-new-agentic-runtime-security-capabilities-for-securing-autonomous-ai-execution) |
| Wiz | AI-SPM inventory, AI-BOM, exposure, permissions and connected cloud risk | Cloud security/CISO; agentless cloud graph | Infrastructure context and buyer access that ThreatVeil lacks. [AI-SPM](https://www.wiz.io/solutions/ai-spm), [agents](https://www.wiz.io/blog/wiz-ai-spm-secures-ai-agents) |
| Microsoft Agent 365 / Defender / GitHub | Agent inventory, identity and security governance; Agent 365 GA May 1; GitHub release controls and artifact attestations | Enterprise IT/security and developers; identity, agents and source delivery | Can combine deployment, identity, runtime and procurement. Individual advanced integrations may have different availability. [GA](https://www.microsoft.com/en-us/security/blog/2026/05/01/microsoft-agent-365-now-generally-available-expands-capabilities-and-integrations/), [Defender](https://learn.microsoft.com/en-us/microsoft-agent-365/leadership/defender-agent-365), [attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) |
| CrowdStrike | AI detection/response and agent security across interactions and enterprise environments | SOC/CISO; endpoint/cloud/SaaS runtime | Existing sensors and response operations. [Product](https://www.crowdstrike.com/en-us/solutions/ai-detection-and-response/), [agent docs](https://aidr-docs.crowdstrike.com/docs/aidr/get-started/agents) |
| Cisco AI Defense | AI validation and runtime protection, expanded agent and supply-chain security | Security/network/platform buyers; validation and execution | Existing network/security distribution. [Announcement](https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2026/m02/cisco-redefines-security-for-the-agentic-era.html), [agent security](https://blogs.cisco.com/ai/cisco-ai-defense-gets-personal-agent-security) |
| Lakera / Check Point | AI guardrails, agent/workforce protection and red teaming within Check Point | Security teams; inline AI protection | Check Point distribution and runtime insertion. [Lakera](https://www.lakera.ai/), [ownership filing](https://www.checkpoint.com/tw/downloads/investor/6K-Q4-FY25.pdf) |
| F5 / CalypsoAI | AI Guardrails and AI Red Team following acquisition | Enterprise application/security teams; gateway and validation | Existing application-delivery relationships. [F5 product explanation](https://www.f5.com/company/blog/what-are-ai-guardrails) |
| Datadog | LLM traces, managed/custom/external evaluations and operational investigation | Engineering/observability; application telemetry | Existing instrumentation and production history; AI Guard availability must be checked separately. [Evaluation docs](https://docs.datadoghq.com/llm_observability/investigate/evaluations/) |
| Arize / Phoenix | Agent tracing, evaluation and candidate experiments | AI engineering; development and production telemetry | Existing evaluation data and OSS distribution. [Source](https://arize.com/resources/ai-agent-tracing-evaluation/) |
| LangSmith | Offline/online evaluations, experiment comparison and agent deployment | Agent developers/platform teams; tracing, tests and hosting | Framework/developer distribution and existing test datasets. [Evaluation](https://docs.langchain.com/langsmith/evaluation), [deployment](https://docs.langchain.com/langsmith/deployment) |
| Braintrust | Evaluations, datasets, immutable experiments and CLI-driven comparison | AI engineering; development and production evaluation | Existing evaluation workflows and history. [Experiments](https://www.braintrust.dev/docs/evaluate/run-evaluations), [CLI](https://www.braintrust.dev/docs/reference/cli/eval) |
| Harness AI Evals | AI-agent quality gates, evaluation, governance and asset context | Engineering/platform leaders; delivery pipeline | Already owns the release workflow. “A gate for agents” alone is insufficient differentiation. [Product](https://www.harness.io/products/ai-evals) |
| GitLab | Security scanning and centrally enforced merge approval policies | DevSecOps/AppSec; repository and delivery policy | Can require evidence and block absent/failed security reports within existing workflows. [Policies](https://docs.gitlab.com/user/application_security/policies/merge_request_approval_policies/) |
| ServiceNow AI Control Tower | AI inventory, governance, observation, security and workflow approval | CIO/CISO/governance; enterprise system of record | CMDB, approvals and enterprise procurement. [Product](https://www.servicenow.com/products/ai-control-tower.html), [June release](https://www.servicenow.com/community/ai-control-tower-articles/ai-control-tower-what-s-new-in-the-june-2026-release/ta-p/3561445) |
| Cloudflare | AI gateway/network security and MCP traffic detection | Platform/security; edge and network gateway | Existing traffic position and broad adoption. [AI security](https://www.cloudflare.com/solutions/ai-security/), [August MCP detection](https://developers.cloudflare.com/changelog/post/2026-08-12-mcp-detection-and-dashboard/) |
| Straiker | Continuous AI red teaming and runtime security products | AI/security teams; testing and execution | Direct specialized competitor; may supply evidence or absorb release features. [Ascend](https://www.straiker.ai/products/ascend-ai) |
| Operant AI | Agent/runtime protection across AI, API and MCP surfaces | Cloud/AI security; runtime infrastructure | Runtime context and control insertion. [Product](https://www.operant.ai/) |
| WitnessAI | Agent/AI visibility and runtime policy over tool access | Enterprise security; AI interaction path | Installed observation can grow into assurance history. [Agentic datasheet](https://witness.ai/wp-content/uploads/2026/01/WitnessAI-Agentic-Security-Datasheet-2.pdf) |

### Capability comparison

**D** = documented by the sources above; **A** = adjacent capability or a gate the customer can compose; **?** = specific capability not established by the reviewed sources; **L** = exercised locally in ThreatVeil; **P** = partial. **EA** = early-access announcement. This matrix does not make blanket absence claims.

T = behavioral/security testing; G = release gating; H = historical results/evidence; C = change/context comparison; Rg = regression comparison/replay; V = explicit validity of previous security evidence under reviewed dependency scope; S = portable cryptographically signed artifacts; Rt = runtime enforcement. Ordinary version history is not V, and a sealed/exported report is not automatically S.

| Product / portfolio | T | G | H | C | Rg | V | S | Rt |
|---|---|---|---|---|---|---|---|---|
| **Current ThreatVeil** | L | P | L | L | L | L | L | Not a runtime enforcement product |
| TestMu Agent Assurance | D/EA | D/EA | D/EA | D/EA | D/EA | ? | ? | ? |
| Promptfoo / OpenAI | D | D | D | A | D | ? | ? | A |
| Noma | D | A | D | A | D | ? | ? | D |
| Zenity | D | A | D | D | A | ? | ? | D |
| Prisma AIRS / Protect AI | D | A | D | A | D | ? | ? | D |
| Portkey | A | A | D | A | A | ? | ? | D |
| Snyk / Invariant | D | A | A | A | A | ? | ? | D |
| HiddenLayer | D | A | D | A | A | ? | ? | D |
| Wiz | A | A | D | D | A | ? | ? | A |
| Microsoft / Defender / GitHub | A | D | D | D | A | ? | D | D |
| CrowdStrike | A | A | D | A | A | ? | ? | D |
| Cisco | D | A | D | A | A | ? | ? | D |
| Lakera / Check Point | D | A | A | A | A | ? | ? | D |
| F5 / CalypsoAI | D | A | D | A | A | ? | ? | D |
| Datadog | D | A | D | D | D | ? | ? | A |
| Arize / Phoenix | D | A | D | D | D | ? | ? | ? |
| LangSmith | D | A | D | D | D | ? | ? | ? |
| Braintrust | D | A | D | D | D | ? | ? | ? |
| Harness AI Evals | D | D | D | A | D | ? | ? | A |
| GitLab | D, general security | D | D | D | A | ? | ? | ? |
| ServiceNow | A | A | D | D | A | ? | ? | A |
| Cloudflare | A | A | D | A | A | ? | ? | D |
| Straiker | D | A | D | A | D | ? | ? | D |
| Operant AI | A | A | A | A | A | ? | ? | D |
| WitnessAI | A | A | D | A | A | ? | ? | D |

Some “D” entries describe a portfolio-level capability, not one unified end-to-end product. ThreatVeil likewise receives no credit for an integration unless the relevant customer path works. The unusually empty V column is a **research finding about the specificity of public documentation**, not proof of an uncontested market. Customers can approximate V with manifests, dependency rules and CI today.

### Competitive conclusion

The useful difference is narrower than the vision's category language: **explicitly maintaining the conditions under which a prior security conclusion can support a later release, while preserving adverse evidence and complete scope**. ThreatVeil must prove that this produces a better release outcome or lower total review cost than rerunning an existing suite. It has not done so with a customer.

It is competitively plausible as a focused integration and assurance product. It is not competitively strong as a broad agent-security suite, generic eval platform or dashboard. Vendor neutrality can help a mixed-stack buyer, but neutrality without accepted evidence and lower effort is merely an extra vendor.

## 10. WHY THREATVEIL IS DIFFERENT

The implementation's meaningful combination is:

1. A result has explicit applicability conditions and expiry, not just a PASS badge attached to a run.
2. Candidate decisions require current approved-property completeness and content-bound evidence; cherry-picking one passing property cannot establish the whole system decision.
3. Missing authority remains uncertainty. Supplied telemetry, imported findings and a claimed version cannot silently become qualified evidence.
4. Adverse observations for the same candidate remain relevant. A favorable record does not simply erase an unresolved failure.
5. The legitimate task must still work. Denying all actions is not a useful fix.
6. A historical decision remains inspectable separately from its current applicability.

These distinctions are structurally implemented, not merely new names. They are also reproducible. Scope is only as good as the reviewed dependencies, and exactness is only as good as the observation that binds the target to the candidate. The “SEMANTIC” binding name denotes reviewed compatibility digests; it is not semantic understanding by a proprietary model.

### Important constraint on selective reuse

The application-level release path is stricter than the standalone validity function. `_observed_candidate_anchor` requires a fresh qualified evidence record for the exact new candidate and full fingerprint at the **same target and observer**. Observer registration/execution is bound to a specific system/property/target. Consequently, in the normal externally observed path, a fresh observation for property A cannot simply anchor reuse for property B when they use different registered observers. At least a fresh qualified run through B’s observer may still be required even when B’s dependency scope is unchanged.

This is a sensible defense against trusting declared deployment metadata, but it materially limits the promised execution savings. The core test showing an unrelated change preserves reviewed scope does **not** demonstrate that the customer can skip that property’s acquisition/execution work in the integrated product. No separate cheap, shared deployment-attestation path was established in this audit. Measure the total cost of fresh anchoring, property execution and scope review before selling “only re-test what changed.” Preserve the safety boundary while investigating whether a trustworthy cheaper anchor is possible; do not remove it to make a demo look selective.

### Technical significance ranking

| Rank | Primitive | Technical/commercial significance | Could become proprietary intelligence? |
|---|---|---|---|
| 1 | Qualified observation + exact target/candidate binding | Prevents a persuasive transcript or wrong build from becoming release evidence | Yes: reusable trusted observation patterns and their failure modes, if grounded in real environments. |
| 2 | Complete property-set and adverse-history enforcement | Prevents incomplete coverage and cherry-picked favorable evidence from authorizing release | Mainly trusted engineering/process, not a learning moat. |
| 3 | Conservative change → evidence invalidation | Maintains the conditions behind old conclusions, including old/new dependency traversal | Best candidate for learned prioritization, after independently labeled outcomes exist. |
| 4 | Security plus legitimate-task verification | Defeats useless fixes; easy for a buyer to understand | Valuable fixtures and domain expertise may compound. Basic logic is cheap. |
| 5 | Exact-candidate historical decision | Gives release review an accountable unit | Workflow and acceptance compound more than the algorithm. |
| 6 | Bounded re-proof planning | Makes required work explicit and avoids spending by merely planning | Savings require credible scope selection; not yet measured. |
| 7 | ProofScope data structure | Encodes assumptions and permits conservative evaluation | Useful schema; no proprietary advantage by itself. |
| 8 | Historical graph/ledger and signed receipt | Preserves provenance and export integrity | Long-lived accepted history can matter; storage and signatures are commodity primitives. |

The R&D opportunity is calibrated invalidation: predict when a class of changes invalidates a particular property, test that prediction against independent re-proof, and minimize expensive unnecessary invalidations without increasing missed regressions. Start as advice; do not let a learned model silently authorize reuse. Evaluation must include temporal/customer holdouts, newly introduced components, adversarial manifests, false-ALLOW cost, false-VOID burden, and observer failure. Current deterministic tests are not those measurements.

## 11. VIBE-CODING RESILIENCE

**Current verdict: not defensible enough on existing assets.** A strong team could reproduce much of the visible software quickly. That does not make the product useless; it makes speed of customer learning and integration crucial.

| Asset class | Current components | Present strength | What must accumulate |
|---|---|---|---|
| CODE-CHEAP | UI, CRUD, parsers, GitHub App, OTel/MCP adapters, CLI/SDK, schema validation, receipts, deterministic invalidation, reports, billing | Most of the repository | Maintainability and interoperability help, but are not a moat. |
| TRUST-HARD | Qualified conclusions, conservative release decisions, key custody, incident response | Local design and tests, no external operating track record | Independent acceptance, reliable operation, transparent error history and recoverability. |
| DATA-HARD | Changes, evidence, observations, outcomes, fixes | Synthetic/private records; no proprietary usable cohort | Permissioned, outcome-labeled longitudinal cases across real releases. |
| WORKFLOW-HARD | Required checks, recurring reviews, exception and release history | Designed and partly implemented; no proven installed dependency | Teams depending on the decision every week, with owners and renewal. |
| DISTRIBUTION-HARD | OSS/SDK, integrations, partners | Source exists; no demonstrated user ecosystem | Maintained packages, repeated developer adoption, partner-sourced installations. |
| CUSTOMER-HARD | Access to action ledgers, staging, security owners and release systems | No customer evidence established | Repeatable trusted integration into consequential workflows. |
| REGULATORY-HARD | Governance, audit exports, operational process | Software controls; no certification or third-party acceptance | Actual assurance consumption and procurement acceptance; never imply regulatory approval from a schema. |

If a competitor reproduces 80% of the code in two weeks, **nothing already demonstrated guarantees ThreatVeil wins**. It wins only if the remaining value is accepted operational history, qualified customer observations, domain-specific fixtures and a trusted place in the release process. Those are currently objectives, not possessions.

## 12. AMBITION

Today: **a product nucleus, not a platform company yet**. The ambition is large enough. The evidence supporting the ambition is much smaller than the PDF's language about a category-grade platform.

An authoritative record of why autonomous systems were allowed to change could be strategically important. But authority is conferred by customers, deployment policy, auditors and ecosystem acceptance. It is not created by naming a table “release” or signing a JSON object.

The architecture is broader than ordinary one-off security regression testing because it separates claims, conditions, observations, candidates and decisions. That creates a credible expansion direction. It does not prove a new category exists or that an independent vendor captures its economics.

## 13. PLATFORM PATH

| Expansion step | Natural or forced? | Model / buyer / trust continuity | Revenue and strategic implication |
|---|---|---|---|
| One protected system | Natural; current wedge | Existing system/property/candidate/evidence model; CTO/AppSec | Prove one paid installed workflow. |
| Multiple systems | Natural | Tenant/system identifiers and draft property reuse exist; same buyer | System-based expansion; measure marginal setup cost. |
| Autonomous fleet | Conditional | Shared data model helps, but fleet posture, ownership, scale and correlated change semantics are missing | Broader account value only after operational adoption. |
| Third-party agent trust | Difficult transition | Portable receipts help; external signer identity, consumer policy, revocation and liability do not yet exist | Potential network effect, but a new trust relationship and two-sided adoption problem. |
| Enterprise-wide release record | Natural within one organization, conditional across stacks | Existing decision/history core; more release owners and CIO/security involvement | Could become a standard record if CI/CD and governance systems consume it. |
| Audit / assurance consumption | Adjacent | Same history, different reader and evidence sufficiency standards | Procurement/review value; requires auditor/customer acceptance, not just export. |
| Risk / insurance | Speculative | Release evidence is an input; underwriting requires exposure, loss and outcome data plus a different buyer | No current product or data basis for insurance economics. |
| Physical autonomy | Forced near term | Abstract claim/evidence idea survives; real-time safety, hardware, hazards and certification change the product | Not an ordinary account upsell; do not fund now. |

### What the current architecture genuinely enables

Multiple tenant-owned systems, reusable draft properties, immutable history, external intake, APIs and receipt exports are real foundations. They support incremental expansion without unrelated products. However, the generic record model and JSON payloads also concentrate correctness in application-level validation. They are flexible, not automatic proof of an enterprise security graph.

Fleet-scale queries, external trust federation, mature audit-reader views, package distribution, partner onboarding and large-tenant latency have not been validated. “Structurally possible” is less than “implemented,” and “implemented” is less than “used.”

The sensible platform order is: repeat one action-boundary integration, add a second system for that buyer, let an existing security tool supply evidence, let an existing release/audit tool consume decisions, then standardize the shared contracts. A marketplace before these consumers exist would be empty infrastructure.

## 14. DEFENSIBILITY

### Data-moat audit

The data model can retain much of a useful sequence: component change, property definition, prior evidence/scope, predicted applicability, re-proof plan, run, security result, legitimate-task result and candidate decision. Fix/lineage records can add remediation context. It is therefore positioned to **record** a validity corpus. It has not established a usable cross-customer corpus or a learned moat.

Important missing assets include stable domain abstractions, independently adjudicated false-valid/false-invalid outcomes, the counterfactual full-suite result, observation-quality labels, customer exposure/context and comparable longitudinal cohorts. A re-proof failure does not automatically prove that the change caused the failure; flaky behavior, fixture changes and observer failures must be separated.

| Governance issue | Actual position | Consequence for a legitimate moat |
|---|---|---|
| Ownership | Intake explicitly marks private customer data and no cross-customer use | Possession is not a reusable right. |
| Consent | Abstract-feature/training opt-ins default off and require contract reference/review | A recorded opt-in does not establish that the contract grants every intended use. |
| Cross-customer processing | Explicitly disabled; no global pipeline | No present shared-learning asset. |
| Anonymization/abstraction | No demonstrated safe extraction pipeline | Hashes, tool names and rare workflow patterns can still identify or reconstruct customer details. |
| Deletion | Freeze/revocation and constrained local primary-record erasure exist | Cloud/provider/log/backup/export handling remains separate. Training-derived deletion is not solved. |
| Residency | Region selection and deployment scope exist | Auto-replicated secrets, backups, logs and providers need a full residency analysis. A regional service is not blanket residency compliance. |
| Private deployments | A plausible architectural direction | Data may stay entirely with the customer; value must work without central collection. |
| Public/global knowledge | Templates, public vulnerabilities and specifications can be reused subject to their rights | Useful inputs, generally available to competitors. |

A defensible future corpus should collect narrowly specified abstract features under explicit contractual rights, retain provenance and consent version, test reconstruction risk, separate private raw evidence, and support withdrawal/deletion obligations. This is a product/legal design task, not a claim that today's consent UI settles data rights. Jurisdiction-specific legal conclusions are outside this audit.

### Compounding asset hierarchy

1. **Accepted release workflow and customer trust** are the first attainable assets.
2. **Reusable observation integrations and business fixtures** can reduce setup cost within a narrow ICP.
3. **Permissioned, independently evaluated invalidation outcomes** could improve selection and diagnosis.
4. **External consumers of the release record** could create switching costs and distribution.

Do not manufacture lock-in by trapping customer evidence. Portable exports and independent verification can increase trust; switching costs should come from useful operating integration and retained context.

### Competitor reproduction attack

These are strategic inferences, not statements of announced roadmaps.

| Attacker | How it attacks | What could survive | What survives today? |
|---|---|---|---|
| Microsoft | Bundle approved-agent policy, identity context, GitHub checks and signed release records into existing enterprise contracts | Cross-vendor observations and a deeply accepted neutral record | Local neutral architecture; no installed advantage. |
| Palo Alto | Combine gateway/runtime observations with red-team results and offer release assurance as part of AIRS | Superior business-effect verification and lower setup effort outside its control path | Some careful semantics; no demonstrated commercial superiority. |
| OpenAI / Promptfoo | Add manifests, evidence scope, property completeness and release receipts to an adopted evaluation workflow | Independence across providers and customer-owned action boundaries | Potential neutrality; no distribution defense. |
| TestMu | Extend versioned test evidence into dependency scope and complete release policy | More rigorous authority binding and accepted security ownership | Local qualification/enforcement design; no customer proof of superiority. |
| Wiz | Connect cloud changes and permissions to agent tests and publish release risk decisions from its graph | Detailed behavioral evidence below infrastructure context and deep release integration | A narrower technical focus, not a market barrier. |

**No current non-code asset decisively survives all five attacks.** The company is strategically weak today, but it has a credible way to become stronger through customer work. If customers do not confer release authority or pay for maintained evidence, the thesis becomes a feature incumbents can absorb.

## 15. GCP READINESS

**The infrastructure is substantial enough to deploy a private development environment after bounded corrections and external configuration. It is not ready to apply blindly or to accept production release authority.** Terraform validates and all seven mocked infrastructure tests pass. No actual cloud plan, IAM denial, managed login, worker execution, restore or deletion result exists from this audit.

### Reproduced and traced blockers

**F1 — public GitHub webhook relay drops required headers.** `apps/web/src/app/api/backend/[...path]/route.ts` forwards a narrow header list and specially handles Stripe signatures, but does not forward GitHub signature/event/delivery headers. I started isolated API/web instances with a synthetic webhook secret and sent identical authenticated `ping` bytes. Direct API: **202**, signature accepted and event correctly ignored. Through web relay: **401**, “GitHub webhook signature is invalid.” This proves broken delivery, not a signature bypass. The deployed API is IAM-protected, so making it public is not the appropriate workaround.

**F2 — GitHub publisher lacks deployed credentials.** `maintenance.reconcile()` calls `reconcile_github_checks()`, which requires `github_app_id` and `github_private_key`. Reconciliation is invoked on the broker path. `infra/runtime.tf` gives generic integration secrets to API only; the broker receives database and enabled revenue-delivery secrets. No GitHub App settings are passed through its normal environment either. The reconciler therefore returns pending external configuration under the inspected deployment model. This is source/configuration evidence, not a deployed failure reproduction.

**F3 — supported machine credential cannot issue the complete decision.** An owner-issued `execute` API token read `/v1/releases` with **200**, then posted a valid existing plan to the release issuer and received **403**, “Your role does not permit this action.” The token was revoked afterward. `auth.py` deliberately maps execute credentials to developer; `create_release` requires owner/admin/security. That is a defensible least-privilege boundary but an incomplete automation contract. Do not “fix” it by making all execute tokens security administrators.

**F4 — healthy process does not mean a ready release service.** Nonlocal settings require managed identity, HTTPS, secret project and evidence bucket, but do not require a usable receipt key at startup. Missing key fails issuance closed with 503. `/healthz` and TCP startup probes can still succeed. Required providers, database role readiness and signing need an explicit activation check. This is a readiness gap, not a false-ALLOW exploit.

### Cloud capability classification

READY TO APPLY below means the inspected configuration for that component has no identified material defect **once reviewed inputs and dependencies exist**. It is not authorization to apply, nor proof of live behavior.

| Capability | Classification | Evidence / remaining condition |
|---|---|---|
| Terraform structure, provider lock, private defaults | READY TO APPLY | Local validate and seven mocked tests pass; review actual plan and state ownership first. |
| Project, billing, region, state bucket | REQUIRES EXTERNAL CONFIG | No approved active project inventory or cost ceiling established. |
| Existing resource adoption | REQUIRES EXTERNAL CONFIG | Inventory/import procedure exists; never create conflicting ownership or replace existing customer resources blindly. |
| Cloud Run web/API/broker/launcher | NEEDS MINOR FIX | Service definitions exist; GitHub relay/runtime credential corrections required. |
| Public application exposure | SHOULD NOT BE DEPLOYED yet | Keep private until P0 and managed identity/tenant acceptance pass. |
| Cloud SQL database | REQUIRES EXTERNAL CONFIG | PG17, connector, encrypted transport and no authorized networks; role bootstrap and migration acceptance required. |
| Database availability | NEEDS MINOR FIX for production | Default ZONAL; regional HA and service expectations require an explicit operating profile. Zonal dev is acceptable. |
| Database roles/RLS | REQUIRES EXTERNAL CONFIG | Non-owner runtime and separate migration role are designed; verify effective grants. API/broker share the same SQL runtime role. |
| Migration job | READY TO APPLY | Separate administrator path; bootstrap values and real migration must precede activation. |
| Secret containers and references | REQUIRES EXTERNAL CONFIG | Values are not supplied by Terraform. Exact secret versions/permissions must be provisioned. |
| GitHub App runtime secrets | NEEDS MINOR FIX | Add explicit broker configuration and secret-level access; keep runner excluded. |
| Receipt signing | REQUIRES EXTERNAL CONFIG | Ed25519 PEM through secret boundary; validate key type and independent public-key distribution. |
| Key rotation/revocation | NEEDS MINOR FIX for pilot | Operator ownership, archive trust, rotation rehearsal and response procedure are missing acceptance. No managed signing service is implemented. |
| Service accounts / invocation IAM | REQUIRES EXTERNAL CONFIG | Separate service identities and narrow invocation design; effective inherited grants and denial probes untested. |
| Ingress | REQUIRES EXTERNAL CONFIG | Internet-addressable URLs protected by IAM, not private-network ingress. Public web must relay only authorized application operations. |
| SQL networking | REQUIRES EXTERNAL CONFIG | Public IP with authenticated connector; not private VPC. Do not promise private-IP isolation. |
| Target egress | READY TO APPLY for bounded adapters | Application transport pins validated public IPs and restricts origins, paths, methods and redirects. Live cloud probes still required. |
| Hostile code network sandbox | SHOULD NOT BE DEPLOYED as a claim | Default runner network does not contain arbitrary customer code. That is outside the supported execution model. |
| Evidence storage | READY TO APPLY with retention acceptance | Uniform access, public-access prevention, bounded lifecycle and limited runtime object permissions. |
| Worker / job | REQUIRES EXTERNAL CONFIG | Shared single-task job, bounded duration, no direct database/secret/storage grants; live bootstrap/lease/replay denial untested. |
| Queue and scheduler | REQUIRES EXTERNAL CONFIG | Bounded rate/concurrency/retry settings; enable authenticated scheduled reconciliation and verify delivery. |
| Duplicate/failure recovery | REQUIRES EXTERNAL CONFIG | Local lease/fence/idempotency tests exist; cloud timeout, duplicate delivery and worker-death drills remain. |
| Backup | READY TO APPLY | Seven retained backups and PITR configured. This is backup configuration, not recovery evidence. |
| Restore | REQUIRES EXTERNAL CONFIG | Runbook exists; isolated restore and role/RLS verification not performed. |
| Raw retention | REQUIRES EXTERNAL CONFIG | 30-day lifecycle plus seven-day soft-delete recovery window; physical purge is not a 30-day promise. |
| Cloud account/provider erasure | NEEDS MAJOR FIX for a complete erasure promise | Local scoped erasure does not cover cloud objects, providers, logs, backups or exported copies. Use an accepted limited data scope until resolved. |
| Logging/redaction | REQUIRES EXTERNAL CONFIG | Structured limits/redaction exist; inspect actual cloud logs and log retention with synthetic sensitive markers. |
| Monitoring/alerts | REQUIRES EXTERNAL CONFIG | Error/backlog definitions exist; notifications disabled when no channels configured. Delivered alerts must be tested. |
| Rate/usage limits | READY TO APPLY with load acceptance | Request/execution budgets and quota records exist. Large-tenant load and noisy-neighbor behavior remain unmeasured. |
| Health/readiness | NEEDS MINOR FIX | Add release-service activation checks beyond process/TCP health. |
| CI image delivery | REQUIRES EXTERNAL CONFIG | Pinned actions, federation, scans, digest publication and gated updates exist; real registry/auth/image acceptance pending. |
| Rollback | NEEDS MINOR FIX operationally | Revision rollback procedure and previous digests required; migrations must remain backward-compatible. No automatic safe database downgrade. |
| Spend protection | NEEDS MINOR FIX + EXTERNAL CONFIG | Bounded instances/jobs/queue/storage help; no hard total spend cap or configured budget notification. Set a ceiling and verify alerts/disable procedure. |

The runner's limited IAM is meaningful, but bounded service concurrency does not guarantee bounded total cost. A queue can continue creating jobs over time. Set an explicit pilot usage budget, provider caps where available, alerts and an operator response; do not call billing alerts a hard cap.

### Pre-GCP security review: real concerns and boundaries

| Area | Observed protection | P0/P1 concern or acceptance requirement |
|---|---|---|
| Secrets | Credential references, scoped broker access, local key permissions; no secret values printed by this audit | P0 activation: correct GitHub/signing mounts. P1: tested rotation, log inspection and provider revocation. |
| Tenant isolation | Membership checks, tenant-safe relationships, FORCE RLS and negative tests | No local cross-tenant bypass reproduced. Verify cloud runtime is non-owner/NOBYPASSRLS; trusted API compromise remains outside RLS's protection. |
| Authentication | Local identity prohibited outside local/test; Firebase project/HTTPS required | Real managed sign-in and domain configuration untested. Never expose local identity mode. |
| CSRF | Cookie mutations require origin and CSRF token; token path distinct | Local checks pass; test same-origin relay with actual hosted cookies and managed login. |
| SSRF | HTTPS:443 only, no credentials in URL, DNS validation/pinning, private/metadata rejection, scoped paths/methods | No local bypass established; cloud probes required. Network sandbox claims must stay narrower than arbitrary code containment. |
| Webhooks | GitHub HMAC validation; Stripe verification; authenticated payload replay handling | P0 F1 is broken delivery, not fail-open. Preserve raw bytes and validate event handling through the real route. |
| GitHub authority | Repository/install/workflow bindings and revocation logic | P0 machine/full-system workflow gap. P1 before BLOCK: branch protection, stale/superseded checks and exact deployed artifact acceptance. |
| Receipt trust | Signed exact decision; external trusted-key verification supported | Key alone supplied inside a receipt cannot establish signer trust. An authentic historical ALLOW is not perpetual deployment permission. |
| Worker authority | Short-lived scoped bootstrap/lease, fencing and authorization checks | Effective cloud IAM and replay/timeout behavior untested; do not grant broad secrets to “make it work.” |
| Destructive operations | Authorized targets, operation bounds, expiry; local demo synthetic | Real target actions may persist. Require customer-approved staging fixtures and reset/observation semantics in the launch scope. |
| Immutability | Database append-only constraints; narrowly privileged erasure | Database administrators and signing authority are trusted. No external transparency or WORM assurance established. |
| Deletion/retention | Freeze/revoke path and tested constrained local erasure | P1 before broader sensitive-data onboarding: complete cloud/provider/backup procedure and contractual scope. |
| Exceptions | Explicit scope, reason, expiry and current checks | No tested generic exception bypass found. Product policy must identify who can choose WARN/OBSERVE or accept risk. |
| Fail-open | Unknowns, absent complete evidence and signing failures do not manufacture ALLOW | WARN deliberately permits progress; it must not be marketed as enforced security. Old successful external checks require fresh-deployment validation. |

**No new exploitable P0 security bypass was demonstrated in this audit.** There are reproduced P0 product-integration defects and several unaccepted cloud trust boundaries. Passing the local suite does not substitute for a penetration test or effective cloud IAM inspection. Prior repository scan reports exist, but this audit did not rerun or certify current container vulnerability feeds; rebuild and scan the exact deployment images.

### What becomes true after successful GCP deployment?

If “successful” means resources and processes are running, ThreatVeil has hosted compute, database, storage, identity configuration and routable endpoints under the chosen deployment policy. If public web exposure and end-to-end acceptance also pass, design partners can reach the workspace and external systems can interact with its verified routes.

It does **not** establish customer utility, willingness to pay, trusted observations, correct business properties, an installed required check, production BLOCK acceptance, an SLA, compliant erasure, low setup effort, renewal, a data moat or product-market fit. Those require separate events. The exact recommended post-GCP state is **a privately accepted pilot service, then a controlled design-partner service in WARN mode, with explicit scope and operating ownership**.

## 16. P0 BEFORE GCP

Four items. These are bounded corrections and activation contracts, not a new platform program. Some cloud drills necessarily happen immediately after private deployment; they are gates before public/customer activation, not reasons to pretend they can be proven locally.

| P0 | Required correction | Completion evidence |
|---|---|---|
| 1. Repair the hosted GitHub path | Preserve GitHub signature/event/delivery headers for the intended webhook route; configure the broker publisher with exact App settings and narrow secret access | Same valid signed payload accepted through relay; tampered payload rejected; Terraform test covers API/broker mounts and runner exclusion. After private deploy: authenticated push and actual delivered check/receipt. |
| 2. Make full-system release automation an explicit supported contract | Add a narrow authorized issuer for a security-approved system/plan/policy, or explicitly ship operator-issued decisions and remove unsupported machine-continuity claims. For the proposed continuously installed offer, the narrow machine path is required | Supported CLI/CI credential can execute approved obligations and obtain the complete signed decision; wrong repo/candidate/tenant, omitted property, changed policy and stale authorization are denied. Ordinary execute tokens do not gain general security authority. |
| 3. Finish one assisted onboarding path and align the offer | One system readiness page/checklist, clear next action, a concrete positive fixture and observation setup guide for the chosen boundary; change unsupported 8–12-property promises to agreed scope | A fresh operator follows the documented path from system to useful result without inventing contract JSON; system distinguishes declared, connected, observed and protected. No universal discovery build required. |
| 4. Make activation readiness concrete | Check usable signing key, intended auth mode/origin, database role/migrations, necessary provider configuration, alert destination and pilot execution budget; document activation/rollback owner | Preflight fails clearly for absent required configuration; exact image digests recorded. Private cloud acceptance covers login, two tenants, worker denials, one signed release, delivered alert and recovery/retention scope before customer use. |

If item 2 becomes a large authorization redesign, do not hide that inside a “small fix.” Deploy a private engineering environment and sell only the explicitly operator-assisted engagement until the continuous gate is accepted. The decision remains B because there is no evidence that a new architecture or company thesis is required; the public continuous-product claim must wait for its actual path.

Do not add broad discovery, fleet features, SSO procurement work for every possible buyer, or learned semantic reasoning to these four gates.

## 17. P1 AFTER GCP

Maximum eight immediate priorities, ordered by real customer impact:

1. **Accept one real system end to end.** Record hours, observation gaps, changed release, delivered WARN, handoff and second release. No local fixture can close this item.
2. **Validate release freshness and external enforcement before BLOCK.** Exact commit/artifact, changed scope, expired evidence, revoked observer, exceptions, superseded checks and bypass privileges need actual branch/deployment tests.
3. **Make explanations and system navigation usable.** Attribute invalidation reasons to the relevant old evidence; distinguish old failure, current evidence and current policy; make next action obvious.
4. **Prove two-property selective value.** Compare a relevant and irrelevant change against full-suite outcomes. Measure saved effort and missed regressions, including the cost of scope review and the current daily expiry bound.
5. **Complete the pilot trust package.** Restore drill, key rotation, incident owner, delivered monitoring, scoped retention/deletion/subprocessor documentation and cloud log review. Broader sensitive-data use waits for its actual requirements.
6. **Package the repeated collector/fixture integration.** Build from the first customer's real action boundary; include freshness, independence and positive-control diagnostics.
7. **Measure recurring economics.** Setup/support hours, execution cost, review time, release frequency, failed/unknown decisions acted upon, and renewal intent. Tie entitlements to measured cost.
8. **Publish and maintain only the developer surface actually used.** Versioned client/install instructions, a working full-release CI example and compatibility checks; distribution claims require adoption.

**Customer-driven, not automatic P1:** SAML/SCIM, private VPC or on-prem execution, regional HA/multi-region, custom retention, more frameworks, fleet rollups, audit-consumer portals, third-party signer federation and specific compliance mappings. Build when a qualified customer requirement or repeated usage establishes value. Some become mandatory before accepting that customer's scope; they are not universal prerequisites for a narrow pilot.

## 18. DO NOT BUILD

- Another generalized scanner, attack marketplace or giant prompt library.
- A replacement for Promptfoo, LangSmith, Datadog or a model gateway.
- An AI agent that autonomously approves its own security policy or silently narrows evidence scope.
- A broad natural-language “connect anything” wizard before one instrumented path is repeatable.
- Fleet, insurance, third-party trust marketplace or physical-autonomy products now.
- A custom blockchain, proprietary signature format or transparency service merely to make receipts sound defensible.
- A large graph visualization without a customer decision it improves.
- More pricing tiers, speculative dollar anchors or CRM automation before accepted delivery and a real payment.
- More dashboards that expose raw implementation records instead of reducing onboarding or release-review effort.
- A rewrite of the working core because it is unfashionable or agent-generated.

The anti-roadmap is intentional: the next hard problem is customer adoption of a release decision, not feature count.

## 19. FIRST CUSTOMER

**First choice:** an AI-native B2B financial-operations vendor whose agent processes invoices or proposes/commits financial account changes, ships at least weekly, has a controllable staging environment and independent action ledger, and is facing concrete enterprise security-review pressure. The first protected boundary should be approval-controlled beneficiary or payment changes. Do not begin with live money movement or a bank-wide platform procurement.

| Candidate | Useful? / buyer | Pain and protected workflow | First deployment / paid outcome | Why not build internally? |
|---|---|---|---|---|
| A. AI-native fintech agent vendor | High conditional fit; CTO + AppSec/security owner | Approval, beneficiary, transaction and tenant boundaries; enterprise trust can affect sales | One staging workflow, independent ledger, positive/negative controls, exact release WARN record | Buy if maintained assurance saves scarce security work. Internal team already owns business semantics, so integration efficiency must be proven. |
| B. Coding-agent vendor | Useful but demanding; platform/security engineering | Repository writes, secrets, command/tool boundaries and unauthorized changes | One constrained tool/action workflow in sandboxed staging; evidence for release review | Strong internal competence and existing evals make build-versus-buy difficult. Do not promise arbitrary-code sandboxing. |
| C. Enterprise support-agent vendor | Strong fit when it acts; CTO/VP Engineering + AppSec | Refund limits, account access, tenant separation and privileged ticket actions | One refund/account-change tool with backend observations and valid customer-service tasks | Reusable integration and customer-facing assurance may beat bespoke evaluation maintenance. Plain answer quality will not. |
| D. Fortune 500 internal multi-agent platform | High potential, poor first-sale speed; platform leader + CISO | Many owners/providers, inconsistent release evidence and policy | One sponsor-owned staging system; integrate with existing CI/identity first | Could centralize internally; vendor must reduce coordination and maintenance. Procurement and private-deployment demands increase burden. |
| E. Simple chatbot SaaS | Low; developer/founder | Mostly answer quality, content safety and ordinary data access | Usually existing evals/guardrails are sufficient | Cheap internal assertions or existing tools solve most need. Do not pursue unless consequential actions change the problem. |

**Ranked first three ICPs:** (1) financial-operations agent vendors with observable actions; (2) support-agent vendors with refunds/account changes; (3) an internal enterprise platform team with a committed sponsor and one bounded pilot. Coding-agent vendors are a valuable later technical test, but their internal tooling and execution complexity make them a harder first repeatable sale.

Qualification must establish an actual release pain, named owner, budget, staging access, independent observation, recurring change and willingness to install a warning. “Interested in AI security” is not qualification.

## 20. FIRST COMMERCIAL OFFER

**Offer:** “Integrity Launch — establish and install release evidence for one consequential AI workflow.”

**Recommended first price experiment:** **$10,000 fixed scoped engagement**, targeting 7–10 business days only after prerequisites are met. Start with approximately **three to five meaningful properties**, not an automatic 8–12. The count is subordinate to actual action boundaries and observation quality. This is a recommendation to test willingness to pay, not validated pricing.

Deliver:

- A named protected workflow, accountable owners, authorized staging target and data scope.
- Reviewed properties with explicit positive business tasks and qualified action observations.
- Baseline, meaningful changed candidate, regression or declared evidence gap, and corrected/re-established evidence.
- Complete exact-candidate decisions, independently verifiable receipts and durable history.
- Verified GitHub WARN delivery for the agreed release path, plus one relevant non-code change input if supported and in scope.
- Customer handoff, recorded integration hours, unresolved gaps and a recurring operating proposal.

**Acceptance:** at least one real customer release event reaches the installed workflow, resolves to the expected exact candidate and receipt, and is acknowledged by the customer owner. A queued job or local demonstration does not count. Agree commercial milestones and remedies in the written scope; do not treat a one-time payment as recurring validation.

After a short period of real use, test **$25K annual recurring scope** for that high-value system, with explicit execution/support/retention limits. Earn $50K+ through additional systems or materially greater operational value. Do not force annual infrastructure pricing on a customer who only bought a one-off assessment.

If observation integration exceeds the agreed bounds, stop and rescope instead of silently subsidizing bespoke consulting. The launch should produce reusable artifacts and a functioning recurring workflow. Otherwise sell it honestly as services and reassess the software thesis.

## 21. KILLER DEMO

**Does the current demo sell? PARTLY.** It is a strong engineering demonstration and a useful founder-led sales aid. It is not yet a self-explanatory killer demo of selective release integrity.

| Demo criterion | Judgment |
|---|---|
| Real problem visible | Yes when explained: unauthorized beneficiary changes are understandable. |
| Actual effects rather than response grading | Yes within controlled local procurement state. |
| Old evidence visibly invalidated | Yes in the re-proof plan; not immediately obvious from the overview alone. |
| Regression blocked | Yes in application decisions; no real GitHub required check demonstrated. |
| Useful fix verified | Yes; bad-fix case clearly distinguishes security from task success. Final ALLOW restores the previously tested fixed configuration. |
| Selective re-proof advantage | Not demonstrated: one property cannot show selective savings across obligations. |
| Visually impressive | Moderate: polished cards, then technical detail and JSON. No coherent guided story. |
| Necessary beyond ordinary CI | Not yet established without a multi-property change and accepted release integration. |
| Leads to paid discussion | Yes for a qualified consequential-action buyer with founder narration. Weak as an unguided trial. |

### Recommended demonstration concept

Use one real-shaped payments/support workflow and three properties. Begin with a release whose security and legitimate tasks pass. Show a harmless presentation change retaining relevant evidence, while making clear any fresh candidate observation still required. Then change approval/tool permissions: only the justified affected obligations become stale; unknown dimensions remain explicit. Re-prove and show an unauthorized committed effect. Publish an actual warning or required-check result against the exact commit in an authorized demonstration repository. Show the customer fix preserving legitimate work, then the accepted release and durable record.

The visual narrative should answer four questions in order: **what changed, why that matters, what must happen, can this release proceed?** Keep hashes, scope internals and envelopes one inspection level deeper. Include one absent-observer case to prove uncertainty is handled, but do not make uncertainty jargon the headline.

Do not present a manually reviewed compatibility exception as learned intelligence, a synthetic restore as automated code repair, or an application BLOCK badge as verified production enforcement.

## 22. SCORECARD

Scores assess **current ThreatVeil**, not the ambition. They are founder/investor judgments tied to evidence, not probabilities or an average that mechanically determines the decision. Every sub-8 score has a concrete route to 8+.

| Dimension | Score /10 | Evidence and what would make it 8+ |
|---|---:|---|
| Immediate usefulness | 6 | Local consequential-action loop works. Reach 8 with a real customer release prevented or review materially improved. |
| Pain intensity | 7 | Strong plausible pain for action-taking agents, weak for chatbots. Reach 8 with documented recurring security/revenue pressure from qualified buyers. |
| Buyer clarity | 6 | CTO/AppSec pairing is plausible; budget owner unverified. Reach 8 with repeated purchases by the same accountable role. |
| Willingness to pay | 3 | No payment evidence. Reach 8 with paid launches converting and renewing at viable margins. |
| Product maturity | 5 | Core verified, fragmented UI and cross-layer defects. Reach 8 with one reliable hosted end-to-end journey and operating evidence. |
| Onboarding | 3 | Manual JSON and specialist observers. Reach 8 with repeat installs completed from supported guidance and measured low effort. |
| Time to value | 4 | Fast synthetic demo; unknown customer setup. Reach 8 when buyers obtain useful evidence within an agreed short window without bespoke contract invention. |
| Differentiation | 6 | Explicit validity/completeness semantics; competitors overlap heavily. Reach 8 with measured advantage over existing CI/eval baselines. |
| Technical depth | 7 | Qualification, conservative scope, adverse history and full decision enforcement. Reach 8 with adversarial external validation and calibrated outcome data. |
| Workflow lock-in | 2 | No demonstrated installed customer gate. Reach 8 with repeated operational reliance and multi-team use. |
| Release-path importance | 5 | Designed at a valuable point but not actually installed. Reach 8 when customers use decisions to authorize consequential releases. |
| Proprietary-data potential | 6 | Suitable record foundations, no corpus/rights pipeline. Reach 8 with consented, independently labeled longitudinal outcomes improving performance. |
| Switching cost | 2 | Little accumulated customer history or integration. Reach 8 through useful multi-system context and accepted workflow, not export restrictions. |
| Enterprise trust | 4 | Local controls, no cloud/recovery/customer track record. Reach 8 with accepted operations, external security review and procurement evidence. |
| OSS distribution potential | 5 | CLI/SDK source, crowded ecosystem. Reach 8 with maintained packages and organic repeated usage converting into protected systems. |
| Category potential | 7 | Temporal release assurance could be important. Reach 8 when independent buyers name and budget the problem without founder education. |
| Bundling resistance | 3 | Large vendors already own neighboring controls. Reach 8 with measurable cross-stack advantage and a record customers insist on retaining. |
| Vibe-coding resistance | 3 | Most code is reproducible; no demonstrated non-code asset. Reach 8 with accepted trust, reusable integrations and permissioned outcomes competitors cannot quickly obtain. |
| Incumbent resistance | 3 | No distribution or enterprise trust advantage. Reach 8 by winning a narrow repeated workflow despite bundled alternatives. |
| Expansion potential | 7 | Multi-system model and history create natural adjacency. Reach 8 with actual second-system expansion at much lower marginal effort. |
| $100M ARR potential | 4 | Architectural ambition exists; no scalable acquisition or retention evidence. Reach 8 with repeatable economics and a credible route to thousands of meaningful accounts or large fleet expansions. |
| Strategic importance | 7 | Accountable decisions for autonomous actions can matter greatly. Reach 8 when release, security and assurance consumers depend on the same record. |

For scale intuition only, $100M ARR requires roughly 2,000 accounts at $50K or 1,000 at $100K. The current founder-assisted integration model does not demonstrate capacity to acquire and support either population. Platform language does not bridge that economic gap.

## 23. BEAR CASE

ThreatVeil becomes a sophisticated wrapper around existing evaluations. Every new customer needs bespoke observers and fixtures; the founder performs the real security work while the software stores the result. Default full-fingerprint invalidation and daily expiry force broad retesting, so selective reuse saves little. Buyers prefer their current eval stack plus CI and a periodic expert review.

Meanwhile, gateway, security and developer-platform incumbents add enough manifests, historical evidence and release policy to eliminate a separate budget. TestMu and other agent-testing products make initial onboarding easier. ThreatVeil's careful scope semantics do not matter commercially because customers neither understand them nor see a measured decision advantage.

One observation-binding failure creates a false sense of safety; one prolonged false-block episode causes customers to disable the gate. Private data cannot legally or practically become a reusable corpus. Launch revenue masks poor services margins; renewals fail because the record is not part of an actual release decision. The company keeps building to avoid confronting that evidence.

**Kill or materially change the thesis if** several qualified paid pilots repeatedly require largely bespoke integration, cannot show recurring decision value over the customer's existing suite, and will not renew or install even WARN after seeing the result. Do not interpret unqualified leads or slow enterprise procurement alone as product falsification. The decisive evidence is informed customers declining the maintained outcome after using it.

## 24. BULL CASE

ThreatVeil repeatedly protects one consequential action boundary with a low-friction trusted observation package. Customers discover that ordinary passing tests do not answer whether the old security conclusion still supports today's candidate. They adopt the release record, integrate the warning, then selectively accept enforcement after observing reliability.

Second systems reuse contracts, observers and operating practice. Existing eval/red-team tools feed evidence; CI, security review and auditors consume decisions. Permissioned outcome records improve invalidation guidance and reduce review cost. The durable asset becomes a trusted account of how autonomous-system changes were evaluated and authorized across heterogeneous stacks.

That is a credible platform direction and a company worth testing. It would be earned by repeated customer use, reliable conclusions and efficient integration. The current repository supplies part of the foundation; it does not supply the customer authority, corpus or distribution.

## 25. FINAL ANSWER

### Is ThreatVeil useful today?

**PARTLY**

### Is it commercially coherent?

**PARTLY**

### Is it competitive in September 2026?

**CONDITIONAL**

### Is it differentiated enough?

**CONDITIONAL**

### Is it ambitious enough?

**YES**

### Is it resistant enough to the vibe-coding era?

**NO**

### Is GCP deployment the correct next move?

**AFTER P0**

### Should we start selling immediately after deployment?

**YES** — the accepted, scoped Integrity Launch to qualified design partners; not a generally available production BLOCK platform. Deployment alone is not the sales acceptance criterion.

### Would you personally build this company?

**YES WITH CONDITIONS**

ThreatVeil has enough working substance and a sufficiently valuable hypothesis to justify a bounded correction-and-customer phase. I would fix the actual integration gaps, make one onboarding path honest and usable, deploy privately, validate the hosted boundaries, then insist on paid evidence from real releases before expanding the product. I would not fund another broad build wave, underwrite a data moat that does not exist, or sell $100K–$250K infrastructure contracts on the strength of this local application. The company earns continuation by becoming useful in a customer's release process at repeatable cost.

### Final founder question

**If we deploy this exact product to GCP next, are we deploying a serious company product that deserves customer attention — or merely putting a sophisticated technical experiment on the internet?**

**This exact, uncorrected product would put a sophisticated technical experiment on the internet.** Its core works, but the advertised hosted release path and customer onboarding do not yet deliver the full commercial promise. Completing the four bounded P0 items and cloud acceptance can turn it into a serious design-partner product worth customer attention. That is the next move; declaring the current build a finished security platform is not.

---

## Evidence appendix — reproducibility and limits

### Fresh verification performed

| Check | Result | Artifact |
|---|---|---|
| API/web health | HTTP 200 locally | API reported service `threatveil-api`, version `0.3.0`; web rendered. |
| Full Python suite | 469 passed, 15 warnings, 20.50 seconds | [Python log](../.local/pre-gcp-audit-20260910/python.log), [JUnit](../.local/pre-gcp-audit-20260910/python.xml) |
| Existing browser suite | 9 passed, 19.8 seconds | [Browser log](../.local/pre-gcp-audit-20260910/browser.log) |
| Terraform validation | Valid configuration | Local command output; no resources applied. |
| Terraform tests | 7 passed, 0 failed; mocked providers | [Terraform log](../.local/pre-gcp-audit-20260910/terraform.log) |
| Canonical demo | ALLOW / BLOCK / ALLOW; missing observation INCONCLUSIVE; bad fix task FAILURE; three receipt signatures verified | [Summary](../.local/pre-gcp-audit-20260910/demo/summary.json) |
| Isolated webhook and API-token reproductions | Direct webhook 202; relay 401; token read 200; token issuance 403; token revoked | [Results](../.local/pre-gcp-audit-20260910/reproductions.json), [Reproduction script](../.local/pre-gcp-audit-20260910/reproduce.py) |
| Manual browser audit | Created system/property; inspected empty and populated journeys, target/observer setup, timeline, evidence, change/re-proof, decision/receipt, launch, billing, pricing and trust | Native browser tool observations in this audit; no independent buyer usability study. |

The Python warnings were deprecation warnings, including Stripe internal conversion and Starlette/httpx test-client behavior. They did not fail tests. Passing tests validate the covered cases, not the truth of customer-value hypotheses.

### Primary implementation references

- [Web API relay](../apps/web/src/app/api/backend/[...path]/route.ts) — narrow forwarded headers and service identity relay.
- [Authentication](../src/threatveil/auth.py:44) — execute token role boundary, session membership and CSRF.
- [Release issuance](../src/threatveil/release_integrity.py:442) — security authority, complete properties, adverse evidence and release policy.
- [GitHub integration](../src/threatveil/integrations/github_release.py:209) — webhook handling; reconciliation begins at line 494.
- [Runtime infrastructure](../infra/runtime.tf:36) — broker/API configuration and secret mounts.
- [Candidate observation anchor](../src/threatveil/release_integrity.py:54) and [observer execution scope](../src/threatveil/api.py:867) — fresh evidence requirements constrain selective reuse.
- [Validity algorithm](../src/threatveil/core/validity.py) — reviewed dependency coverage, conservative invalidation and age bound.
- [Integration intake](../src/threatveil/integration_intake_api.py) and [formats](../src/threatveil/integrations/intake.py) — drafts and explicit review, not automatic security authority.
- [Target transport](../src/threatveil/targets.py) — bounded HTTPS and pinned DNS validation.
- [Receipt signing](../src/threatveil/release_signing.py) — local/operator keys and nonlocal failure behavior.
- [Governance](../src/threatveil/governance.py) and [scoped erasure migration](../migrations/versions/0007_scoped_erasure.py) — consent limits and privileged deletion boundary.
- [Cloud delivery workflow](../.github/workflows/gcp-dev.yml), [deployment runbook](../docs/deployment/GCP.md), [known limitations](../docs/KNOWN_LIMITATIONS.md).

The supplied vision PDF and strategy/status documents were considered after product inspection. Their build directives were treated as document content, not instructions overriding this diagnostic audit. Where the vision claims a platform, moat or commercial state, this report credits only the implementation and evidence actually established.
