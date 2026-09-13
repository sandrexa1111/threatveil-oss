# ThreatVeil — Pre-GCP Category, Frontier-Readiness & Commercial Dominance Audit

**Date:** 10 September 2026 · **Mode:** read-only inspection + fresh external research · **No repository code, migrations, Terraform, infrastructure, billing or external account was modified or created.**

**Verification standard used here.** *Verified* = I executed it or read the implementing code. *Claimed* = stated in a repository document and not independently reproduced. *Researched* = external primary/secondary source, dated and cited. Absence of public documentation is never treated as absence of a competitor capability.

**Independently reproduced in this session:** full Python suite — **564 passed, 21 warnings, 29.35s** (matches `THREATVEIL_IMPLEMENTATION_REPORT.md` §K exactly). Source inventory: **18,750 LOC** Python in `src/`, **9,588 LOC** tests, **1,642 LOC** total web (components + Playwright specs + CSS). Demo evidence in `.local/category-foundation/demo-final/summary.json` matches the reported eight-step run and eight independently verified signed records.

The implementation report is honest. I found no inflated claim in it. Everything below that contradicts prior strategy contradicts *strategy*, not the engineering record.

---

## 1. Executive verdict

**B — FIX THREE STRUCTURAL P0s, THEN DEPLOY.** Not C. The thesis is sound and the architecture is right. Do not reconstruct anything.

ThreatVeil has found a real and genuinely unowned control point: **security evidence has a shelf life, and nobody currently manages its expiry against change in autonomous systems.** The code proves this is buildable — a decision here is not a verdict but a *statement with a status* that can independently become `EXPIRED`, `SUPERSEDED`, `REVOKED` or `REASSESS` without anyone re-running anything ([change_assurance_api.py:120-141](src/threatveil/change_assurance_api.py#L120-L141)). That single mechanic is the company. It is undersold everywhere in the current product, documentation and marketing.

External research confirms the gap is real and independently identified. The academic literature now states plainly that MCP, A2A and ACP cannot express authority, delegation, evidence, change management or accountability ([arXiv 2606.31498](https://arxiv.org/pdf/2606.31498)). Only **14.4%** of organisations report full security approval for all agents going live, against **81%** past planning ([Gravitee, 2026](https://www.gravitee.io/blog/state-of-ai-agent-security-2026-report-when-adoption-outpaces-control)). The problem exists today, is urgent, and is not being solved by the incumbents' current shipping products.

But the market moved hard while this was being built. In the last twelve months: Zenity raised $125M (Aug 2026, $185M total) and Gartner called them "the company to beat in AI agent governance"; HiddenLayer raised $100M (Sept 2026); Straiker $64M (June 2026); Noma $100M; Kevin Mandia $190M (Mar 2026). Palo Alto shipped Prisma AIRS 3.0 with a discover/assess/protect agent lifecycle (Mar 2026). Microsoft Agent 365 went GA on 1 May 2026 at $15/user/month with Entra Agent ID. ThreatVeil is a solo pre-deployment project entering a market with roughly $700M of fresh competitive capital and two platform vendors bundling adjacent capability. **Ambition is not the constraint. Time is.**

Classification: **B — Strong differentiated company**, with a credible but unearned path to A. It is not A today because it has zero customers, zero distribution, one enforcement surface, and its two most distinctive nouns (authority envelope, business effects) were published as an academic framework in June 2026 ([AgentRiskBOM](https://arxiv.org/pdf/2606.21877)). What is *not* in that paper — change-driven evidence invalidation and re-proof — is exactly what ThreatVeil should own, and should say first.

**The three P0s, all cheap, all discovered-expensively-later:**

1. **The hosted free product cannot demonstrate the category.** `POST /v1/change-assurance/finance/assess` returns HTTP 409 whenever `not settings().is_local` ([change_assurance_api.py:394](src/threatveil/change_assurance_api.py#L394)), and the UI hides every change button behind a `local` check ([change-assurance.tsx](apps/web/src/components/change-assurance.tsx)). A hosted signup can create the Finance Agent — consuming its entire Free quota of 1 system and 3 of 5 properties — and then dead-ends. Every §19 requirement (Connect → Change → Evidence impact → Explanation → Decision on Free) is unavailable in the mode you are about to pay for.
2. **The only agent-tool-protocol connector is pinned to a superseded revision.** `SUPPORTED_PROTOCOLS = ("2025-11-25",)` and the adapter hard-fails on a protocol mismatch during `initialize` ([mcp_discovery.py:30](src/threatveil/integrations/mcp_discovery.py#L30), [adapters/mcp.py:46-95](src/threatveil/adapters/mcp.py#L46-L95)). MCP is now **2026-07-28**, which *deleted* the `initialize` handshake and sessions entirely ([spec](https://modelcontextprotocol.io/specification/2026-07-28)). ThreatVeil's MCP read connector, its tool-change detection and its own published MCP server are all non-functional against current servers.
3. **Two products ship in one deployment, and the wrong one is in front.** The workspace has 17 nav entries built on the legacy release-integrity kernel; Autonomous Change Assurance is one of them. The Overview page still leads with the *procurement* demo and "the security memory loop". The public site's primary CTA on every page is "Discuss Integrity Launch" — a consulting engagement — with no signup CTA anywhere, and hosted Google sign-in silently names every organisation "My organization". Deploy this and every screenshot, demo and support conversation anchors to the product you are trying to stop being.

None requires a rewrite, a schema change, or a new subsystem. Estimated: days, not weeks. **Then deploy, and buy customer evidence with the next unit of time — not more software.**

---

## 2. What ThreatVeil actually is today

**Product:** an operator-assisted system that records agreed security claims about an autonomous system, holds the evidence for those claims together with the exact conditions under which it was produced, detects when a change to code, model, tools, permissions or configuration makes that evidence inapplicable, requires fresh evidence that both the prohibited outcome is prevented *and* the useful business task still succeeds, and issues a short-lived signed authorization record whose status is continuously recomputed against current facts.

**Company:** a control-point company disguised, right now, as a security testing tool. The asset is not the tests. It is the ledger of *which conclusions were relied on, when, under what assumptions, and whether those assumptions still hold* — plus the operating dependency that forms once a team stops shipping without checking it.

**What it is not, and correctly refuses to be:** an inventory/discovery engine, a runtime firewall, an IAM system, an observability backend, an evals vendor, an independent auditor. `docs/CHANGE_ASSURANCE.md` and the implementation report state these boundaries explicitly and the code holds them — a `relationship_assertion` carries `grants_permissions: False` and `positive_reuse_authority: False`; a `permission_envelope` explicitly `"grants_permissions": False`. That restraint is the most commercially valuable property of this codebase and the hardest thing for a well-funded competitor to imitate, because it is a discipline, not a feature.

**The single sentence it should lead with, and does not:**
> *Your agent changed. Which of your security conclusions are still true?*

---

## 3. What is genuinely implemented

Distinguishing code from claims.

| Area | Status | Evidence / limit |
|---|---|---|
| Change-assurance domain (system, environment, permission envelope, system state, change event, assurance case, authorization decision, enforcement request/ack, status events) | **Implemented** | `change_assurance.py` (373 LOC), `change_assurance_api.py` (522 LOC). All new kinds ride the existing immutable `records`/`edges` tables at head `0007`; no destructive migration. Verified. |
| Decision status lifecycle (`CURRENT`/`EXPIRED`/`REVOKED`/`SUPERSEDED`/`REASSESS`) | **Implemented — the strongest asset in the repo** | [change_assurance_api.py:120-141](src/threatveil/change_assurance_api.py#L120-L141). Status is recomputed on read from envelope epoch, observation expiry, later observed transitions, support digest and underlying release eligibility. |
| Conservative evidence invalidation | **Implemented** | [core/validity.py](src/threatveil/core/validity.py) — transitive dependency closure over *both* old and new graphs so removed edges cannot hide a dependency; unknown identity widens to `UNKNOWN`; family/semantic reuse requires `HUMAN_REVIEWED` authority plus enumerated SHA-256 digests plus a written rationale. ~80 lines. Excellent judgement; trivially re-implementable. |
| Security ≠ useful-task separation | **Implemented and demonstrated** | Bad fix produces security `PASS`, task `FAILURE`, action `BLOCK`. Verified in demo summary step 6. This is a real differentiator against every evals product. |
| Committed business-effect verification | **Implemented, synthetic only** | `core/finance.py` performs real isolated SQLite commits and reads state back after transaction. The fixture controller and observer share a process — stated in the docs and true. Not independent customer evidence. |
| Signed authorization records | **Implemented** | DSSE/in-toto, Ed25519, `keyid = sha256(raw pubkey)` ([sdk/change_records.py:21-31](src/threatveil/sdk/change_records.py#L21-L31)). Verifier requires the caller's *own* trusted key and expected scope — correct posture. No transparency log, no published trust root, one algorithm. |
| Connector role framework | **Implemented, partially reachable** | 8 roles defined; see §4. |
| Commercial engine | **Implemented** | `commercial.py` (463 LOC) + externally replaceable catalog. Frozen plan versions, account locking, all-history counts, reservation/settlement, downgrade without record loss. Genuinely good. |
| Stripe | **Boundary only** | Checkout/portal/webhook code exists; live charges disabled by default; no network call ever made. Accurate. |
| GCP activation preflight | **Implemented, intentionally failing** | `activation_readiness.py` exits 1 with `cloud_accepted=false`. Correct. |
| Data-rights architecture | **Implemented and unusually good** | `measurements.py` — `cross_customer_learning` and `research` require an explicit contract reference; all pipelines default disabled. |
| Multi-agent, delegation, A2A, agent identity, autonomous commerce | **Not present** | No representation of an agent-to-agent call, a delegated sub-authority, a workload identity, or a payment mandate. |

**Architectural debt that is real but not pre-GCP blocking:** `projection()` takes a system advisory lock and scans all evidence, all envelope history and all target bindings per call, then re-queries binding history *inside* the per-property loop ([change_assurance.py:228-288](src/threatveil/change_assurance.py#L228-L288)). This sits on the decision path that a CI gate calls, behind Cloud Run services with `min_instance_count = 0`. Fine at 1–20 customers. It is the first thing that breaks at 200.

---

## 4. Is it still GitHub-centric?

**Structurally: no. Operationally: yes, and one number proves it.**

The connector framework declares eight roles — DISCOVER, CHANGE, OBSERVE, VERIFY, EXECUTE, ENFORCE, EXPORT, CONSUME ([connectors/contracts.py](src/threatveil/connectors/contracts.py)). Across all eight manifests, `installation_roles` only ever contains **DISCOVER, CHANGE or OBSERVE**. VERIFY, EXECUTE and CONSUME are declared and unimplemented by every connector. ENFORCE and EXPORT exist on exactly one connector — GitHub — and route to the pre-existing GitHub App Checks path, not the canonical installation path.

**Therefore: GitHub is the only connector in ThreatVeil with write authority. It is the only place a ThreatVeil decision can leave the building.**

| Connector | Modes | Installable roles | Classification |
|---|---|---|---|
| `github` | POLL | DISCOVER, CHANGE (+ENFORCE/EXPORT via legacy App) | **LIVE-CAPABLE** — real REST reads, double-read to reject a moving ref, real Checks outbox with fencing |
| `gcp_cloud_run` | POLL, IMPORT | DISCOVER, CHANGE, OBSERVE | **LIVE-CAPABLE** — real `ServicesClient`, etag+digest double-read, explicit pinned credential, never ambient ADC |
| `mcp` | POLL, IMPORT | DISCOVER, CHANGE | **LIVE-CAPABLE BUT BROKEN** — see P0-2 |
| `otel` | PUSH, IMPORT | OBSERVE | **PARTIAL** — bounded authenticated OTLP JSON intake; no collector wizard |
| `openai_agents` | IMPORT | OBSERVE | **IMPORT-ONLY** |
| `anthropic_hooks` | IMPORT | OBSERVE | **IMPORT-ONLY** |
| `cyclonedx` | IMPORT | DISCOVER | **IMPORT-ONLY** |
| `sarif` | IMPORT | DISCOVER | **IMPORT-ONLY** |

The abstraction itself is genuinely general — not a renamed GitHub. `validate_configuration` is per-connector, the source model is shared, and continuity/cursor-gap/duplicate/reorder semantics are uniform. The *implementations* are lopsided. That is the honest answer: **the architecture escaped GitHub; the product has not yet.**

The trap is not the code. It is that the only customer who can feel value today is a customer with a GitHub gate — which will select for a GitHub-shaped roadmap.

---

## 5. Is it still a PASS/WARN/BLOCK product?

**No — but only one layer knows it.**

The legacy release layer is literally ALLOW/WARN/BLOCK with per-property `OBSERVE/WARN/BLOCK` modes ([release_integrity.py:317-318](src/threatveil/release_integrity.py#L317-L318)). If that is what a customer sees, ThreatVeil is a scanner with better manners.

The change-assurance layer is materially different, along four axes a PASS/WARN/BLOCK product does not have:

1. **Four independent dimensions, never collapsed.** Applicability (`CURRENT`/`STALE`/`INVALID`/`UNKNOWN`) × security (`PASS`/`FAIL`/`INCONCLUSIVE`) × legitimate task (`SUCCESS`/`FAILURE`/`UNKNOWN`) × exception. An exception can never turn security truth into PASS.
2. **Decisions decay.** Maximum five-minute window, capped further by envelope expiry and observation expiry. A decision is a *statement*, not a verdict.
3. **Decisions are bound.** Audience, request nonce, prior policy epoch, exact state digest, envelope digest, support digest. It cannot be replayed into a different context.
4. **Status is separate from issuance.** `_decision_status()` recomputes against current facts. An ALLOW issued this morning is `SUPERSEDED` this afternoon because an observed transition happened, with nothing re-run and nothing rewritten.

That fourth property is the product. **A verdict that goes stale by itself is a category. A verdict is a feature.** Nothing in the UI, the marketing site, the docs or the pricing page leads with it. Fix that before you fix anything else.

---

## 6. Frontier AI/agent compatibility

Where the ecosystem actually is, September 2026, and what each fact does to ThreatVeil.

**MCP — 2026-07-28 (GA).** The revision went *stateless*: `initialize`/`initialized` and `Mcp-Session-Id` retired; protocol version now declared per-request via the `MCP-Protocol-Version` header; `tools/list` responses carry `ttlMs`/`cacheScope`; DCR deprecated in favour of Client ID Metadata Documents; Enterprise-Managed Authorization is now a formal extension; twelve-month minimum deprecation window ([MCP blog](https://blog.modelcontextprotocol.io/posts/2026-07-28/)). On 24 Aug 2026, Okta's Cross App Access was adopted as the official EMA extension. **Impact: ThreatVeil's MCP connector is broken (P0-2), and the fix is easier than the old code — no handshake, cacheable list results with a server-supplied TTL that maps directly onto ThreatVeil's freshness model.** The `ttlMs`/`cacheScope` fields are a gift: a server now tells you how long its tool catalog is good for, which is precisely an evidence-expiry input.

**Microsoft — Agent 365 GA 1 May 2026, $15/user/month**, with Entra Agent ID GA, agent registry consolidation (the Entra agent registry blade retired the same day), Defender/Intune/Purview integration, shadow-agent discovery, blocking unmanaged agents, and "audit-ready compliance evidence" ([Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/05/01/microsoft-agent-365-now-generally-available-expands-capabilities-and-integrations/)). **Impact: registry, identity and inventory are now table stakes owned by Microsoft. ThreatVeil must never sell inventory. It must consume Agent 365 as a DISCOVER source and sell what Agent 365 does not do: decide whether prior evidence survives a change.**

**GitHub — Enterprise AI Controls and agent control plane GA;** third-party coding-agent security validation GA, "organizations decide which agents are allowed, where they may operate, and what checks their output must pass"; audit streaming with `agent_session_id`/`actor_is_agent`. **Impact: GitHub is building admission control for coding agents. ThreatVeil's coding-agent angle is closing. Its finance/business-action angle is not.**

**AWS — Bedrock AgentCore GA Oct 2025**; Harness GA 17 June 2026; GovCloud May 2026; two new regions Aug 2026. Runtime (session isolation, long-running), Gateway (turns APIs/Lambdas into MCP tools), Identity (IdP integration, permission delegation), Observability and Evaluations. **Impact: AgentCore Gateway is the single richest unmapped change surface in the market — every tool an agent can reach, with versioned configuration. ThreatVeil has no connector for it.**

**Google — ADK stable at v1.0 (Python/Go/Java/TS), Agent Engine managed runtime, A2A under the Linux Foundation with 150+ organisations in production** including Microsoft, AWS, Salesforce, SAP, ServiceNow. Wiz closed 11 Mar 2026 ($32B). **Impact: A2A is the delegation substrate ThreatVeil's model does not yet represent. Google+Wiz is the most dangerous long-run bundler because it owns cloud graph, deployment and now posture.**

**Anthropic — Claude Managed Agents (8 Apr 2026):** hosted sandboxed execution, session checkpointing, credential management, **scoped permissions**, end-to-end observability tracing. **Claude Commerce Agents (3 Sept 2026, Apache-2.0)** for retail/travel/telecom. Managed settings enforce permission policy fleet-wide; **`ConfigChange` hooks can audit or block settings changes mid-session**. **Impact: `ConfigChange` is a ready-made CHANGE connector and the closest thing to a non-GitHub ENFORCE surface available today. This is the highest-leverage integration in the entire matrix.**

**OpenAI — AgentKit; Agents SDK sandboxed execution (Apr 2026)**, control harness separated from compute so credentials never enter code-execution environments; **Connector Registry** for limiting agent data access with periodic permission review. **Impact: the Connector Registry is a permission-envelope source. "Review permissions regularly" is exactly the manual ritual ThreatVeil automates.**

**Identity — consensus has formed.** SPIFFE/WIMSE for workload identity, OAuth 2.1 via the MCP authorization spec for delegated access, IETF Identity Assertion Authorization Grant (Cross-App Access) for enterprise brokering. IETF `aiagent-auth-00` (2 Mar 2026) defines AIMS composing WIMSE + SPIFFE/SPIRE + OAuth 2.0 with **delegation chain verification**. Okta Agent SSO GA 24 Aug 2026. **Impact: ThreatVeil must not build identity. It should make its decision consumable as a *condition* on these grants. That is the single largest strategic opportunity in this document.**

**Agentic commerce — AP2** with signed Intent/Cart/Payment mandates as W3C Verifiable Credentials, donated to the FIDO Alliance May 2026; Mastercard committed Jan 2026 across AP2/UCP/A2A/ACP. **Impact: validates the signed-scoped-record pattern; also proves ThreatVeil's signing is not novel, it is *conventional* — which is good for acceptance and bad for differentiation claims.**

**Frameworks.** LangGraph owns the production tier and passed CrewAI on GitHub stars in early 2026; Microsoft moved active development to Microsoft Agent Framework, leaving AutoGen behind; Anthropic's Claude Agent SDK passed AutoGen on production deployment count Feb–Apr 2026; LangGraph adopted the Agent Protocol. **57.3%** of teams report agents in production (LangChain), **52%** of executives with 39% running more than ten (KPMG Q2 2026), **31%** per S&P Global — the spread is itself the story: agents are in production, and nobody agrees how many.

**Regulation moved *away*, not toward.** The Digital Omnibus (provisional agreement 7 May 2026) pushed EU AI Act Annex III high-risk obligations to **2 December 2027** and Annex I to **2 August 2028**. Only Article 50 transparency, GPAI enforcement powers and the full penalty regime (€35M/7%) land on 2 Aug 2026. NIST CAISI's AI Agent Standards Initiative launched 17 Feb 2026; SP 800-53 COSAiS control overlays for single- and multi-agent systems are projected **late 2026–2027**. **Impact: do not build a compliance-timed business. The regulatory tailwind is ~16 months later than it looked. Sell operational pain through 2027; the overlays become an evidence-format opportunity when they land.**

---

## 7. Agent-platform compatibility matrix

*Support today* is assessed against installable connector roles and the canonical model, not against aspiration. Difficulty assumes 2026 frontier coding agents.

| Platform | Importance | Agents defined as | Tools defined as | Authority model | Deployment change signal | Telemetry | Supported today | Partial | Missing | Priority | Strategic value | Difficulty | Defensibility or coverage? |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **Anthropic Claude (Agent SDK, Managed Agents)** | Very high | SDK agent + managed agent resource | MCP tools, SDK tool defs, managed settings | Scoped permissions, managed settings, `ConfigChange` hooks | Managed-agent revision; settings/permission change events | Session tracing | Hook JSON **import only** | — | Live CHANGE from `ConfigChange`; permission-envelope sync; ENFORCE via settings block | **1** | **Highest** — the only credible non-GitHub enforcement surface today | Low–Med | **Defensibility** |
| **MCP ecosystem** | Very high | n/a (tool layer) | `tools/list` + schemas + annotations | OAuth 2.1 + EMA/XAA | Catalog digest change; now `ttlMs`/`cacheScope` | none | **Broken** — pinned 2025-11-25 | — | 2026-07-28 stateless core, CIMD, EMA/XAA, Tasks extension | **1 (P0)** | High — tool-surface change is the canonical non-code change | Low | Coverage → Defensibility once cross-server change history accumulates |
| **AWS Bedrock AgentCore** | High | Runtime agent, session-isolated | Gateway targets (APIs/Lambda → MCP) | AgentCore Identity, IdP delegation | Runtime/gateway config revision | Observability + Evaluations | None | — | Everything | **2** | High — richest tool-authority surface in the market | Med | **Defensibility** |
| **Microsoft Agent 365 / Entra Agent ID** | Very high | Agent 365 catalog entry + Entra Agent ID | Copilot/connector permissions | Entra Agent ID, Conditional Access, Purview | Registry/lifecycle events | Defender/Purview | None | — | Everything | **3** | High as a *source*; suicidal as a competitor | Med | Coverage (deliberately) |
| **GitHub (repo + agentic workflows)** | High | Agentic workflow / coding agent | Actions + MCP in workflows | Scoped tokens, agent control plane | Commit/ref, workflow, agent policy | Audit streaming | **DISCOVER, CHANGE, ENFORCE, EXPORT** | Agentic-workflow definitions not modelled | Third-party agent policy as envelope source | 4 | Medium and *declining* — GitHub is closing this itself | Low | Coverage |
| **OpenAI AgentKit / Agents SDK** | High | Agent Builder workflow / SDK agent | Tools + Connector Registry entries | Sandbox scope, connector permissions | Workflow/agent version; registry change | Traces | Export **import only** | — | Live connector-registry permission sync | 5 | Medium–High | Low–Med | Coverage |
| **Google Vertex ADK / Agent Engine** | High | ADK agent, Agent Engine deployment | ADK tools, MCP | IAM + VPC-SC | Agent Engine revision | Cloud Logging/Trace | Cloud Run only (adjacent) | — | Agent Engine as first-class deployment | 6 | Medium–High | Med | Coverage |
| **A2A (Linux Foundation)** | High and rising | Agent Card | Skills in Agent Card | Card-declared auth; no delegation semantics | Agent Card digest change | Task events | None | — | Card as source assertion; delegation edge | 7 | **High for the 2027 model** | Low (card ingest) / High (delegation semantics) | **Defensibility** |
| **LangGraph** | High (production tier) | Graph + nodes | Bound tools | App-level | Graph revision / deployment | LangSmith traces | None (OTel only if instrumented) | OTel intake | Graph topology as fingerprint components | 8 | Medium | Low | Coverage |
| **CrewAI / Microsoft Agent Framework** | Medium | Crew/roles; MAF agents | Framework tools | App-level | Config revision | Framework-native | None | OTel intake | — | 9 | Low–Medium | Low | Coverage |
| **Computer-use / browser agents** | Medium, rising | Model + harness | Screen/keyboard | Sandbox policy | Model + harness version | Screen traces | None | — | Action-space representation | 10 | Medium | High | Neither yet |
| **Agentic commerce (AP2/ACP)** | Medium, rising | Shopping/merchant agents | Payment rails | Signed VC mandates | Mandate schema/version | Rail-side | None | — | Mandate as authority evidence | 11 | High later | Med | **Defensibility later** |
| **Kubernetes / serverless agent runtimes** | Medium | Workload | Sidecars/gateways | SPIFFE/WIMSE | Image digest, manifest | OTel | Cloud Run only | — | K8s admission as ENFORCE consumer | 12 | High for "required infrastructure" | Med | **Defensibility** |

**The honest read of this matrix:** ThreatVeil is *theoretically* extensible and *actually* compatible with almost nothing that a 2026 agent team runs. Every gap is small individually. Together they mean the answer to "can you watch my agent?" is currently "if it's in a GitHub repo, or if you export files to us."

---

## 8. Missing strategic integrations

Not a catalogue. Three, in order, each chosen because it reinforces the same control point.

**1. Anthropic `ConfigChange` hooks + managed-agent settings — CHANGE and ENFORCE.** This is the only place in the current market where a third party can *observe a permission change as it happens and block it*. It makes ThreatVeil's decision consumable outside CI on day one, breaks the GitHub monopoly on enforcement, and produces exactly the fact type the canonical model was designed for. Build this first. It is also, not coincidentally, where ThreatVeil's own users are.

**2. AWS Bedrock AgentCore Gateway + Identity — DISCOVER, CHANGE, OBSERVE.** Gateway is a versioned registry of every tool an agent can reach, with identity and delegation attached. One connector maps the entire authority surface of an AgentCore agent. It is the highest fact-density-per-unit-effort integration available and directly generates the tool/permission change events the invalidation engine already knows how to consume.

**3. A2A Agent Card ingestion — DISCOVER and CHANGE, plus the delegation edge.** Cheap now (a card is a document), strategically decisive later. It is the first place ThreatVeil's model must represent *one agent's authority derived from another's*, and the existing `relationship_assertion` with `delegates_to` is already the right shape — it just has no source and no semantics. Doing this early is how the abstraction survives 2027.

**Deliberately not on this list:** Microsoft Agent 365 (build it as a DISCOVER source *after* first customers, never as a competitor), OpenAI Connector Registry (valuable, lower urgency), LangGraph/CrewAI (OTel already covers the observation need), computer-use agents (no coherent action space yet).

---

## 9. Breakthrough test

**Classification: B — STRONG DIFFERENTIATED COMPANY.**

Would a strong AI founder, CISO, platform engineer, investor or acquirer see something unusually important? **Yes — one thing, and they would have to find it themselves, because the product does not show it to them.** The thing is: *this is the only system I have seen that treats a security conclusion as something that expires.*

Why not A:

- **No pull.** Zero customers, zero paid revenue, zero external consumers of a decision, zero accumulated change history. A is a claim about the market's response, and there is no market response yet.
- **The nouns are in the literature.** [AgentRiskBOM](https://arxiv.org/pdf/2606.21877) (June 2026) records "the declared authority envelope of a deployed agent" and business effects. ThreatVeil's two most distinctive-sounding concepts were independently published as an academic framework three months ago, with no reference implementation but also no barrier to one.
- **One enforcement surface.** A control point that can only be enforced through GitHub Checks is a CI feature until proven otherwise.
- **Capital asymmetry.** ~$700M of fresh competitive capital in twelve months plus two platform bundlers. A category-defining company needs to reach customers before the category is named by someone with a field sales force.

Why not C:

- The control question is real, recurring, consequential and **structurally unowned** — verified by direct research, not assumed. Palo Alto's "Assess" is red-teaming and architectural scanning with no documented change-detection or re-testing trigger. Zenity's AISPM evaluates configuration and permissions against policy *before* go-live — a point-in-time posture check, not an evidence lifecycle. ServiceNow governs the change *request*, not the evidence behind it. Evals gate on a fixed dataset, not on whether the dataset still applies.
- The engineering discipline is genuinely rare and is itself a moat component: refusing to convert absence of information into a positive claim is the hardest thing to sustain in a security company and the easiest thing for a fast-following competitor to get wrong.
- The commercial architecture (frozen plan versions, capability-not-plan-name checks, reservation/settlement, externally replaceable catalog) is better than most Series A companies'.

Why not D or E: it has a coherent control point, a working end-to-end demonstration, a real domain model that is not a wrapper, and commercial infrastructure. That is past experiment.

**B with a live path to A.** A is earned at roughly twenty systems under continuous assurance across ten organisations, with at least one non-GitHub enforcement consumer and one instance of "ThreatVeil said the old evidence didn't hold, and it was right" that the customer will describe out loud.

---

## 10. Novelty / differentiation

| Concept | Verdict | Who else |
|---|---|---|
| Signed release/authorization records | **Commoditised** | in-toto/SLSA/Sigstore; AP2 signs W3C VC mandates; CoSAI recommends adapting SLSA to agent artifacts. Conventional, not novel — and that is fine. |
| Agent inventory / discovery | **Commoditised, and correctly avoided** | Microsoft Agent 365, Zenity Observe, Palo Alto Discover, ServiceNow AI Control Tower |
| Posture / permission evaluation before go-live | **Commoditised** | Zenity AISPM does exactly this, funded at $185M |
| Red-teaming / attack simulation | **Commoditised** | Palo Alto, HiddenLayer, Straiker, Lakera |
| Release gating on evaluations | **Commoditised** | Confident AI, LangSmith, Langfuse, Arize/Phoenix, Braintrust all ship PR-gate regression |
| Permission / authority envelope | **Unusual → published** | AgentRiskBOM, June 2026. Was ThreatVeil's; is now anyone's. |
| Business-effect verification | **Unusual → published** | Also in AgentRiskBOM as a data-model element. ThreatVeil's *implementation* (committed state read back after transaction, with a paired legitimate control) is well beyond the paper. |
| Security PASS + useful-task SUCCESS jointly required | **Unusual, and strong** | Evals measure quality; security tools measure violation. Requiring both, and blocking a security-clean fix that broke the business task, is rare and immediately legible to an engineering leader. |
| Conservative missing-evidence behaviour | **Unusual as a discipline, easy as code** | Everyone can write it; almost nobody sustains it under sales pressure. |
| Change → evidence applicability → re-proof obligation | **Genuinely thin on the ground** | Not in AgentRiskBOM. Not in Prisma AIRS's documented lifecycle. Not in Zenity's four capabilities. Evals re-run *everything*; ThreatVeil reasons about *what needs re-running and why*. |
| **A decision with an independently recomputed status** | **The most defensible idea in the repository** | I found no competitor product whose verdict can transition to `SUPERSEDED` because the world changed. This is the thing to name, own and lead with. |
| Versioned assurance cases | **Unusual in software, old in safety engineering** | GSN/assurance cases are decades old in functional safety. Novel *here*; expect academic prior art. |
| External consumer profiles / portable assurance | **Aspirational** | Not implemented beyond GitHub. |

**Summary: the composition is defensible; almost no individual piece is.** Which is exactly what the founder's doctrine predicts, and exactly why the answer must be customers and history, not more concepts.

---

## 11. Competitive control-point map

| Control point | Owner | Can ThreatVeil take it? |
|---|---|---|
| Agent inventory / registry | Microsoft Agent 365, Zenity, ServiceNow | **No. Never try.** Consume it. |
| Agent identity & credentials | Entra Agent ID, Okta XAA/Agent SSO, AgentCore Identity, SPIFFE/WIMSE | **No.** Become a *condition* on it. |
| Runtime traffic inspection | Palo Alto AIRS Gateway, Prompt/Lakera, Operant, Straiker | **No.** |
| Posture / config evaluation | Zenity AISPM, Wiz+Google, Palo Alto | **No.** |
| Model/agent red-teaming | HiddenLayer, Palo Alto, Straiker | **No.** |
| Output quality gating in CI | LangSmith, Braintrust, Arize, Confident AI | **No — and this is the nearest substitute risk.** |
| Enterprise change approval workflow | ServiceNow AI Control Tower | **No.** Feed it. |
| Code merge gate | GitHub | **No.** Use it. |
| Deployment admission | Cloud vendors, K8s admission controllers | **Consumer, not owner** — a viable ENFORCE surface |
| **Whether prior security evidence still supports current authority after change** | **Nobody** | **Yes. This is the whole company.** |

Every neighbour owns a *state* question ("what exists", "who is it", "is it configured correctly", "is this request malicious", "is this output good"). ThreatVeil owns a *time* question. That is a real seam, and time questions are historically where durable infrastructure companies live — because the answer requires history that cannot be reconstructed after the fact.

---

## 12. Incumbent attack simulation

**Microsoft (GitHub + Agent 365 + Entra + Defender + Azure).** *What dies:* the GitHub wedge, the coding-agent angle, the inventory story, and any "governance" positioning. Agent 365 at $15/user/month with "audit-ready compliance evidence" makes ThreatVeil's audit-record framing sound like a line item. *What survives:* Microsoft governs *its* agents in *its* tenant. It has no interest in an AI-native B2B vendor whose agent writes into a customer's ERP, and no mechanism for verifying a committed business effect in a third party's database. *Accumulate first:* non-Microsoft enforcement surfaces (Anthropic, AgentCore, K8s admission) and business-effect observation in systems Microsoft does not host.

**Palo Alto (AIRS + gateway + identity + runtime + distribution).** *What dies:* any runtime, gateway or red-team ambition; the security-buyer relationship in accounts where Palo Alto already sits. Their Agent Gateway is only in limited preview — but their field organisation is not. *What survives:* AIRS assesses at a point in time. It has no evidence ledger, no applicability reasoning and no useful-task requirement. Palo Alto sells to the CISO; the change moment belongs to the engineering owner. *Accumulate first:* the engineering-owner workflow dependency, and the historical corpus of "this change invalidated that evidence" that a scanner cannot retroactively produce.

**Google (cloud graph + Wiz + Vertex/Agent Engine + A2A + deployment).** *The most dangerous long-run attacker.* They own the graph, the runtime, the posture product and the deployment admission point — everything needed to make "evidence-conditioned deployment" a Cloud feature. *What dies:* the GCP connector's differentiation, and any cloud-admission control-point ambition on GCP. *What survives:* only if ThreatVeil is multi-cloud and multi-platform *before* Google ships it, and only if the evidence is portable and independently verifiable rather than sitting in Google's control plane. *Accumulate first:* cross-platform coverage and an independently verifiable record format that a buyer trusts *because* it is not the cloud vendor's.

**OpenAI / Anthropic embedding assurance into their platforms.** *What dies:* single-platform assurance entirely. If Anthropic ships "your agent's permissions changed, re-run your safety checks", ThreatVeil's demo becomes a platform feature. *What survives:* no platform will attest about *another* platform, and no enterprise will accept the vendor's own attestation as independent evidence for a consequential system. **Independence is the durable asset, and it is the one asset that improves as the platforms get better at this.** *Accumulate first:* multi-platform systems — a customer whose one "system" spans Claude + an MCP server + a GCP deployment + a GitHub repo cannot be served by any single platform's assurance.

**Five startups clone the UI and the deterministic algorithms with frontier coding agents.** *What dies:* everything in the repository, within weeks. `core/validity.py` is ~80 lines. The UI is 1,642 lines. The domain model is documented in the repo. A funded competitor reproduces all of it faster than ThreatVeil built it. *What survives:* nothing that exists today. **This is the correct reading of the founder's own thesis and it should be uncomfortable.** *Accumulate first:* see §13.

**Common thread across all five:** every attack kills the code and none of them kills *history in a customer's account under a workflow the customer's team has accepted*. That is the only thing worth racing for.

---

## 13. Vibe-coding resilience

| Asset | Class | Verdict |
|---|---|---|
| FastAPI backend, Next.js frontend, Postgres schema | CODE-CHEAP | Reproducible in days |
| Invalidation engine (`core/validity.py`) | CODE-CHEAP | ~80 lines. Reproducible in hours. |
| Connector framework + 8 manifests | CODE-CHEAP | Reproducible in a week |
| Commercial/entitlement engine | CODE-CHEAP | Reproducible in days |
| DSSE/in-toto signing + verifier | CODE-CHEAP | Standard, deliberately |
| Domain model (system/environment/envelope/state/case/decision) | CODE-CHEAP + **published** | AgentRiskBOM covers part of it |
| Conservative-semantics *discipline* | **TRUST-HARD** | Not the code — the sustained refusal. Erodes the moment a salesperson needs a PASS. Real, fragile, and the only cultural asset here. |
| Qualified business-effect observation packages per vertical | **WORKFLOW-HARD + DATA-HARD** | Requires access to a real ledger, real forbidden and permitted fixtures, and a reset/correlation contract. Cannot be vibe-coded. |
| Longitudinal change→invalidation→re-proof→outcome corpus | **DATA-HARD** | Only accrues with calendar time in production accounts. **The single most valuable asset ThreatVeil can build and the one it has zero of.** |
| Installed dependency in a release/activation workflow | **WORKFLOW-HARD + DISTRIBUTION-HARD** | Once a team cannot ship without it, replacement costs re-establishing every baseline |
| Accepted external consumer (CI, admission, IAM condition, buyer) | **NETWORK-HARD** | Each accepted consumer makes the record more valuable to every issuer |
| Independent-verifier trust (published trust root, third-party verification) | **TRUST-HARD** | Not started |
| Standards position (NIST COSAiS overlays, CoSAI, MCP extension) | **REGULATORY-HARD** | Not started; window opens late 2026–2027 |

**If every line were open-sourced tomorrow, what remains valuable?** Today: **almost nothing.** A competitor gets the model, the algorithm, the UI, the connector spec and the honest semantics for free, and ThreatVeil retains only the founder's judgement. That is the correct and uncomfortable answer.

**Fastest route to genuinely hard assets, in order:**
1. **One customer, one consequential system, thirty days of real change history.** Nothing else on this list starts until this exists. This is why P0-1 matters more than any feature.
2. **One accepted non-GitHub enforcement consumer** (Anthropic `ConfigChange` is the cheapest). Converts "report" into "dependency".
3. **One qualified business-effect observation package for a real vertical** (see §24) — reusable across customers, expensive for a competitor to originate, and the thing that makes the second customer 5× faster than the first.
4. **A published verifier + trust root**, so a third party can check a record without ThreatVeil's cooperation. This is what makes the record an *asset* rather than a report.
5. **Standards participation** — NIST COSAiS overlays and CoSAI agentic workstreams are actively drafting the vocabulary ThreatVeil already implements. Being in the room when "evidence applicability after change" gets a control number is worth more than ten connectors.

---

## 14. Control point

**Recommended, one:

> ## "Does current evidence still justify this system's authority to act?"**

Short operational form, for the UI, the badge and the API: **`Still cleared?`**

Tested against every criterion:

- **Commercially understandable** — a CISO, a VP Engineering and a board member each parse it in one reading, with no ThreatVeil vocabulary.
- **Technically defensible** — it is literally what `projection()` + `_decision_status()` compute. The product does not have to grow into the question.
- **Broad enough for the company** — spans code, model, prompt, tool, permission, config, infrastructure, delegation and, later, physical operating envelopes, without redefinition.
- **Narrow enough to own** — it is not "who is this" (identity), not "what exists" (inventory), not "is this configured well" (posture), not "is this request malicious" (runtime), not "is this output good" (evals).
- **Recurring** — fires on every change and every expiry, not once per procurement cycle.
- **Enforceable and integrable** — resolves to a signed, audience-bound, expiring statement with a status URI that a CI check, an admission controller, a gateway or an IAM condition can consume.

**Why not the alternatives.** *"Can this changed autonomous system ship?"* binds the company to CI and therefore to GitHub — the trap §3 of the brief names explicitly. *"Can this system retain this business authority?"* excludes the initial grant and reads as IAM, colliding head-on with Entra Agent ID and Okta. *"Is this system still cleared for these consequential actions?"* is close and usable as the badge, but drops *evidence* — which is the entire differentiator against every posture and identity product.

The recommended form is the only candidate containing all three load-bearing words: **current** (time), **evidence** (differentiator), **authority** (consequence).

---

## 15. Customer problem

**The problem is real today, and the research is unambiguous.** Against **81%** of teams past planning and **57.3%** with agents in production, only **14.4%** report full security/IT approval for all agents going live; organisations actively monitor or secure **47.1%** of their agents; **88%** confirmed or suspected an agent security incident in the past year; **21.9%** treat agents as identity-bearing entities and **45.6%** still use shared API keys for agent-to-agent auth; **25.5%** of deployed agents can create and task other agents ([Gravitee 2026](https://www.gravitee.io/state-of-ai-agent-security)). Meanwhile **82%** of executives believe existing policy covers unauthorised agent actions. That executive/practitioner gap *is* the sale.

**Is it urgent enough to pay for?** Conditionally. It is urgent where three things co-occur: the agent can cause an expensive, externally visible effect; releases are frequent enough that re-approval is a bottleneck; and a named person is accountable for saying yes. Where any one is missing, the honest answer is "run your tests again" — and ThreatVeil should say so rather than sell.

**The specific pain that converts:** not "we might get hacked". It is *"we changed the model / added a tool / widened a permission on Tuesday, and nobody can tell me which of last month's security work still applies, so either we re-run everything or we ship on vibes."* That sentence is being said in real companies right now. It is the only sentence the marketing site should be built around.

**The counter-evidence to hold honestly:** the regulatory forcing function slipped. EU AI Act high-risk obligations moved to Dec 2027/Aug 2028. Nobody is buying this in 2026 to pass an audit. They will buy it because a release is blocked and a person is uncomfortable.

---

## 16. Technical-experiment risk

Against the brief's own symptoms:

| Symptom | Answer |
|---|---|
| Ten technical nouns before value is clear? | **Yes.** ProofScope, permission envelope, assurance case, qualified observation, applicability, support digest, policy epoch, enforcement acknowledgement, source assertion, verification unit. The value needs *one* sentence and currently requires ten nouns. |
| Demonstrates internal correctness over customer outcomes? | **Yes.** The demo's headline artefact is "eight signed records independently verified" — an integrity property. The customer outcome ("the agent could have moved money to an attacker's account and the system caught it") is buried in step 5. |
| Depends heavily on synthetic fixtures? | **Yes, and it is explicit.** All business-effect evidence is synthetic SQLite, controller and observer in one process. Correctly disclosed; still synthetic. |
| Bespoke engineering per deployment? | **Partly.** Connect/define/protect generalise. Qualified observation does not — each customer needs its own ground-truth source, reset semantics and positive control. |
| Unique property semantics per customer? | **Yes** — this is inherent to the category, and the mitigation is vertical observation packages, not genericity. |
| Custom code per observer? | **Yes.** The largest scaling risk in the business model. |
| Nobody outside ThreatVeil consumes the decision? | **Almost.** GitHub Checks only. `enforcement.production` returns `AWAITING_QUALIFIED_ENFORCER`. |
| Mainly produces reports? | **Today, yes.** |
| Is WARN ignored? | Untested — no user has ever seen one. Assume yes; WARN is always ignored. |
| Is BLOCK ever delegated real authority? | **Never, by anyone, so far.** |
| Would a customer call it "advanced testing"? | **Yes — and they will, unless the decay mechanic leads.** |

**Nine of eleven point the wrong way.** ThreatVeil is *not* an experiment — it has a coherent control point and working commercial infrastructure — but it currently *presents* as one. The crossing is not more capability. It is: one real system, one real observer, one accepted consumer, one sentence.

---

## 17. Product experience

I inspected every surface. The writing is genuinely good — "Know what your AI release *invalidated*" is a strong headline and the honesty in `/security` is a competitive asset most vendors would never dare ship. The problems are structural, not aesthetic.

**Against the seven questions a customer must answer quickly:**

| Question | Answered? |
|---|---|
| What system am I protecting? | **Yes** — the assurance flow anchors on a named system + environment |
| What can it do? | **Yes** — the envelope screen is the best screen in the product |
| What changed? | **Partly** — the Watch timeline exists but is empty without live sources |
| What security assumptions are affected? | **Yes** — per-property impact with changed dependencies is genuinely good |
| What evidence still holds? | **Yes** — applicability/security/task shown separately, per property |
| What do I need to do? | **Weakly** — `next_action` is a single string; there is no obligation list |
| What is the current decision, and why? | **Yes** — and the "why" panel with historical comparisons is the best thing in the UI |

**Findings, in severity order:**

1. **Two products, one deployment.** 17 nav items across WORKSPACE and OPERATE; "Protect a system" is item 2 of 17. Overview leads with the legacy "security memory loop" and the *procurement* demo, not the finance/change-assurance one. A first-time user meets the old product. *(P0-3.)*
2. **Implementation nouns in navigation.** Targets, Findings, Runs, Evidence ledger, Fixes, Regressions, Integrity Launch, Change explorer, Property reuse, Gauntlet. "Gauntlet" survives as an internal route key. Recommended reframing: *Systems · What changed · What still holds · Decisions · Sources · Records · Settings* — with everything else demoted to detail views beneath them.
3. **No signup path.** The public header offers "Log in" and "Discuss Integrity Launch". There is no "Start free". Hosted Google sign-in never prompts for an organisation name, so every hosted org is literally named **"My organization"** ([api.py:226](src/threatveil/api.py#L226)).
4. **The primary CTA sells services, not product.** Every public page ends in "Discuss Integrity Launch". That is a consulting funnel wearing a product's clothes, and it contradicts the PLG strategy in §18–20 of the brief.
5. **The decay mechanic is invisible.** `current_status` renders as small text: "Record status: CURRENT". This is the company's entire differentiator, displayed as a subtitle. It should be the largest object on the screen, with a countdown and an explicit "what would change this".
6. **Dimension labels are internally honest, externally opaque.** "Applicability: STALE" means "the evidence no longer describes this system". Say that.
7. **Free tier ends in a wall.** Covered as P0-1.

**Recommendation (no code):** one screen, one sentence, one badge. *"Finance Agent — staging. Cleared to act until 14:32. 3 of 3 claims supported. One tool permission changed 6 minutes ago; two claims need re-proof."* Everything else is a detail view.

---

## 18. Subscription strategy

The architecture is right and better than most companies at Series A: capability-based checks rather than plan-name branching, frozen plan versions, account-locked capacity, all-history counts so pagination cannot bypass limits, in-flight reservations carried through downgrade, records never deleted on downgrade, and an externally replaceable catalog via `TV_COMMERCIAL_CATALOG_PATH`. **Pricing can be changed without code. That is the single most important commercial fact in this repository** and it means pricing should not delay deployment by one day.

**The value unit — protected system / operating boundary — is correct.** It scales with consequence rather than headcount, it survives multi-agent systems (many agents, one boundary), it survives the collapse of any framework, and it does not punish adoption the way per-agent pricing would in a world where 25.5% of agents spawn other agents. Keep it.

**The structural mistake is not the prices. It is where the control point sits.** `enforcement.ci` (the GitHub check) is gated to **Team ($399)**, and `enforcement.production` to **Business ($2,000)**. Combined with P0-1, a Free or Pro user can never experience the thing the company is selling. They can look at a decision; they can never let it decide anything. **A product whose control point is unreachable below $399/month cannot run a PLG motion.**

---

## 19. Pricing verdict

**Verdict: keep the ladder and the value unit; move one capability and one limit; leave the numbers alone until real usage exists.**

**On cost exposure — Free is not the risk it looks like.** Verification units execute against the *customer's* target; ThreatVeil pays no model inference ("cost: No model execution" is accurate in the manifests). A unit costs one Cloud Run job invocation: at 1 vCPU/512 MiB and even a generous 60s, ≈ $0.0015 at $0.000024/vCPU-s and $0.0000025/GiB-s. **500 free units ≈ $0.75/month of compute.** The real Free costs are the shared Cloud SQL floor, unbounded append-only record growth, and founder support time. Retention is currently an *allowance*, not enforced deletion — that, not compute, is the long-run Free cost.

**Recommended V2 — changes only where materially better:**

| Change | From | To | Why |
|---|---|---|---|
| **Move `enforcement.ci` down to Pro** | Team $399 | **Pro $99** | The control point must be reachable at the first paid step or there is no PLG. This is the single highest-leverage pricing change available. |
| **Give Free one enforcement consumer in WARN-only mode** | not available | Free | Free must let a developer *install the gate*, see it fire on a real repo, and feel the dependency. Non-blocking. This is the conversion event. |
| **Raise Free verification units** | 500 | **1,000** | Costs ~$0.75/month more and removes the single most common early dead-end (a 3-property × 2-trial baseline is 12 units; changes multiply fast). |
| **Free: 1 system, 2 environments** | 1 environment | **2** | The category *requires* comparing a sandbox to something. One environment cannot express change. |
| Keep Pro $99 / Team $399 / Business $2,000 | — | unchanged | Unvalidated but well-shaped; the Pro→Team 4× and Team→Business 5× steps are conventional and land where team adoption and production enforcement naturally sit. |
| **Business must earn $2,000 on one thing** | capability list | **production enforcement + advanced observers + evidence sharing** | Today Business is "more of everything plus a longer list". At $24k/year the buyer needs one sentence: *this is the plan where ThreatVeil can stop a production change.* |
| **Add usage-based verification packs above plan allowance** | no overages | opt-in packs | Not automatic overages (correctly avoided). Explicit purchase preserves the "no surprise bills" posture while removing the hard ceiling that currently forces a premature tier jump. |
| **Signed records stay free at every tier** | already free | keep | Records are the distribution mechanism. Charging for them would kill the network asset in exchange for rounding-error revenue. |
| **Retention as a differentiator** | 14/90/365/730 days | keep, and **enforce it** | Retention is currently an allowance only. Enforce physical lifecycle before it becomes both a cost problem and a promise you are not keeping. |

**Answering the red-team questions directly.** Too cheap? Business is *underpriced* if it ever blocks production — that is a $50k–150k conversation, not $24k. Too expensive? Pro at $99 is fine; Team at $399 is fine. Too generous? No — Free is too *stingy* where it matters (enforcement, environments) and irrelevantly generous where it does not (units). Free cost exposure? Storage and support, not compute. Team cannibalising Business? Only if Business's distinct value stays a list. Should production BLOCK be plan-gated? **Yes** — it is the correct enterprise boundary. Should connectors be plan-gated? **Sparingly**; gating `otel.observe` out of Free is defensible, gating GitHub or MCP would be self-harm. Enterprise services? Priced separately as scoped engagements, never bundled into a tier — the current Integrity Launch framing is right, it is just in the wrong place on the website.

---

## 20. PLG + Enterprise model

**Credible in architecture, currently absent in practice.**

Present: capability-gated entitlements, self-serve signup endpoint, free tier, API/CLI/SDK, a natural expansion unit (protected systems), and a sales-assist ceiling (Enterprise contract override through the shared engine).

Absent, and each is small: a signup CTA; an organisation-name prompt; a hosted free experience that reaches a decision (P0-1); an enforcement capability below $399; any in-product sales-assist trigger; an open verifier that spreads outside the account.

**The shape that works** — comparable to Snyk, Sentry and Vercel, all of which crossed developer→enterprise on the same pattern:

1. **Acquisition:** a developer installs the gate on one repository or one Claude project in WARN mode, free, without talking to anyone.
2. **Activation:** the gate fires on a real change and says something non-obvious — *"this evidence no longer applies because a tool permission changed"*. That single moment is the entire funnel.
3. **Conversion (Pro $99):** they want it to actually block, and they want a second system.
4. **Team ($399):** a second person needs to approve, and shared policy matters.
5. **Sales-assist trigger:** production environment created, or third system, or first BLOCK on a production candidate. Fire a human at that account.
6. **Business/Enterprise:** production enforcement, private deployment, contract terms, a qualified observer package built with them.

**Do not run "Book a demo → $50k" as the only motion** — it caps at founder throughput and generates no data asset. **Do not accept "$99/month developer utility" as the ceiling** — the expansion unit exists precisely to avoid that. The current site runs motion one exclusively; the code supports the full ladder. The gap is four small UI decisions.

---

## 21. Cloud economics

From the actual Terraform: 4 Cloud Run services (broker, launcher, api, web) at 1 vCPU/512 MiB with `min_instance_count = 0` and `cpu_idle = true`; 2 Cloud Run jobs (runner, migration); 1 Cloud Scheduler job; Cloud SQL PostgreSQL 17, `db-custom-1-3840`, **ENTERPRISE**, **ZONAL**, 20 GB PD_SSD with autoresize to 100 GB, PITR on, 7 retained backups; a GCS evidence bucket with 7-day soft delete and 30-day `raw/` lifecycle; Artifact Registry with immutable tags; Secret Manager; standard logging/monitoring.

| Line | Low | Expected | High | Note |
|---|---:|---:|---:|---|
| Cloud SQL compute (1 vCPU / 3.75 GB) | $50 | $55 | $58 | ≈$49/mo us-central1; europe-west1 modestly higher. **REGIONAL HA would roughly double this** — currently ZONAL by default, which is correct pre-customer. |
| Cloud SQL storage + backups + PITR logs | $5 | $12 | $30 | Grows with the append-only record store |
| Cloud Run services (scale to zero) | $0 | $3 | $25 | Free tier covers early traffic entirely |
| Cloud Run jobs (verification runs) | $0 | $2 | $15 | ~$0.0015/unit; 10,000 units ≈ $15 |
| GCS evidence | $1 | $2 | $8 | |
| Artifact Registry | $1 | $2 | $5 | |
| Secret Manager | $1 | $1 | $3 | |
| Tasks / Scheduler | $0 | $1 | $3 | |
| Logging / Monitoring | $0 | $5 | $40 | 50 GiB/project free, then $0.50/GiB — the most likely surprise |
| Network egress | $0 | $2 | $10 | |
| **Total / month** | **≈$58** | **≈$85** | **≈$200** | |

**With REGIONAL HA (production posture): add ~$55/month.** Realistic first-year steady state: **$85–150/month**, rising to **$250–400** once HA is on and logging is real. Cloud SQL is ~70% of idle cost and it is a fixed floor, not a per-tenant cost.

**Do these economics support the tiers?** Comfortably. Marginal cost per Free organisation is on the order of **$1–3/month**; per Pro organisation **$3–8**; Team **$10–25**; Business **$25–80**. Gross margin at Pro is ~92%, at Team ~96%, at Business ~98%. **The threat to margin is never compute. It is founder hours per customer** — a qualified observer that takes three days to stand up destroys Pro and Team economics entirely, regardless of infrastructure. That is the number to instrument.

**Measure from day one, before anything else:** (1) hours of human effort per customer from signup to first supported decision; (2) p50/p95 latency of `GET /states/{id}/current` and `POST /decisions` including cold start — this is the CI gate's latency and the first thing to break; (3) records and bytes written per protected system per week, to date the retention problem; (4) verification units consumed per system per week; (5) Cloud SQL CPU and connection-pool saturation, given the finance guard holds a connection across nested transactions; (6) logging volume in week one, before the free tier is exceeded silently.

---

## 22. Data/moat strategy

The proposed corpus — change + system context + property + prior evidence + predicted applicability + actual re-proof + business effect + reviewer outcome — is **the right corpus and does not yet exist in any quantity.**

**What is genuinely unusual and worth protecting:** the rights architecture is already built and is better than most funded companies'. `cross_customer_learning` and `research` each require an explicit contract reference to enable, all pipelines default disabled, no plan upgrade silently enables training, and no measurement record may contain raw evidence, prompts, resource names or exception strings ([measurements.py](src/threatveil/measurements.py)). **A credible rights path exists. That is rarer than the data.**

**Why it is not a moat yet, and what each obstacle actually requires:**

- **Scarcity.** A useful applicability model needs thousands of labelled change→outcome pairs. Ten customers × one system × weekly changes = ~500/year. **This is a 3–5 year asset at realistic scale, not a Series A story.** Say so.
- **Label quality.** The ground truth is "did the re-proof actually find something?" — which is only meaningful where a qualified observer existed. Most early records will be `UNKNOWN`, and `UNKNOWN` labels do not train anything.
- **Confidentiality.** The interesting features (which tool, which permission, which resource) are exactly the ones that cannot cross tenants. What *can* cross is structural: change *type* × property *family* × applicability outcome. Thin but real, and privacy-safe by construction.
- **Bias.** Data comes only from customers who already adopted the discipline. Systematically unrepresentative.
- **Independent adjudication.** Nobody outside ThreatVeil currently confirms a re-proof was correct. Without that, the corpus records ThreatVeil's own opinions.

**The honest sequencing.** Tenant-private learning first — "in *your* history, changes of this kind have invalidated this property 8 of 11 times" is valuable at n=11, requires no cross-customer rights, and is defensible immediately. Cross-customer aggregate structure second, under explicit contract, at n≈50 systems. A shared applicability model third, if ever. **Do not call this a moat in an investor conversation until the first of those is running with real customers.** Call it what it is: a rights-clean position to accumulate an asset nobody else is currently positioned to collect.

---

## 23. Open ecosystem strategy

**Open what spreads the category. Own what compounds.** Applying the test rather than the convention:

**Open (Apache-2.0):**
- **The verifier and the record schema.** Highest priority. A record only becomes an asset when a third party can check it *without ThreatVeil's cooperation*. Today the verifier requires the caller to already hold the trusted key — correct, but there is no distribution mechanism. Publish the verifier, publish the trust root, and every exported record becomes a small advertisement that works while nobody is selling.
- **The connector specification and conformance suite.** `connector/v1` + `connector-conformance/v1` already exist as versioned contracts. Opening them lets platforms build *toward* ThreatVeil rather than ThreatVeil chasing platforms — and is the only realistic route to AgentCore/Agent 365/Vertex coverage without hiring.
- **The CLI and SDKs.** Standard, expected, costs nothing.
- **Sample security-property definitions per vertical.** These are the category's teaching material. Every copied property definition is a competitor's customer learning ThreatVeil's vocabulary.
- **The portable assurance profile.** The format buyers and auditors would consume.

**Keep proprietary:**
- Hosted longitudinal assurance memory (the only compounding asset)
- Qualified business-effect observation packages (expensive to originate, the real per-vertical IP)
- Applicability intelligence, when it exists
- The operational workflow, enforcement coordination and managed status service
- Enterprise operations, support and the permissioned outcome corpus

**Explicitly do not open** the invalidation engine as a standalone library. It is ~80 lines and opening it hands a competitor the one piece of judgement that took real thought, while spreading nothing — nobody adopts a category because of a dependency-closure function. Open the *interfaces*; keep the *judgement*.

---

## 24. First customer

Ranking five wedges against pain, urgency, consequence, ground-truth availability, sales speed, integration difficulty, budget, reference value, repeatability and expansion:

| Wedge | Pain | Ground truth | Sales speed | Integration | Budget | Repeatability | Overall |
|---|---|---|---|---|---|---|---|
| **AI-native B2B vendor whose agent writes into customer systems** | High | **Excellent** — they own both sides | **Fast** — 1–2 technical people decide | Medium | Medium | **High** | **1st** |
| Financial operations agents (internal) | Very high | Excellent | **Slow** — finance + risk + audit | High | High | Medium | 2nd |
| Support/refund agents with write authority | High | Good — refund records are observable | Medium | Medium | Medium | High | 3rd |
| Infrastructure/deployment agents | High | Medium — effects are cloud state | Medium | Medium | Medium | Medium | 4th |
| Coding agents | Medium | **Poor** — "correct code" is not observable | Fast | Low | Low | High | 5th |

**Recommendation: the AI-native B2B vendor whose agent takes consequential write actions inside its own customers' systems.** Concretely: AP/invoice automation, revenue-operations agents that write to CRM, procurement agents, claims agents, provisioning agents.

**Challenging the current finance-operations preference.** Finance is right about *observability of effect* — a beneficiary change is a row you can read back, which is exactly what the existing fixture proves. It is wrong about *velocity*. An internal enterprise finance agent means a finance owner, a risk owner and an audit owner, a 6–9 month cycle, and a security questionnaire before the first call — for a pre-deployment company with no SOC 2. **Keep the finance *domain*; change the *buyer*.** An AI-native vendor selling a finance agent has identical ground truth, a staging environment they fully control, weekly releases, enterprise customers who already ask them hard security questions, and a technical founder who can say yes in one meeting.

**Why this wedge specifically:** their releases are frequent (the change trigger fires constantly); they own both sides of the effect (real qualified observation is possible without their customer's cooperation); their own enterprise customers demand security evidence (ThreatVeil output has *external* value on day one, which is the seed of the portable-assurance network); and a reference from them is a reference to everyone selling into the same buyer.

**The first workflow:** one consequential action type (beneficiary change, refund above threshold, CRM write to a closed-won record), three claims, one paired legitimate task, staging only, WARN mode, GitHub check plus — after P0-2 — MCP tool-change detection. Success is not a signed record. **Success is the first time ThreatVeil says "the evidence for claim 2 no longer applies because the ERP tool's permission scope changed", they check, and it is true.** Instrument that moment; it is the entire company's proof.

---

## 25. Path to required infrastructure

| Route | Feasibility | Time | Buyer authority | Distribution | Switching cost | Strategic value | Risk | Verdict |
|---|---|---|---|---|---|---|---|---|
| **CI/CD required check** | **High** | 0–6 mo | Eng lead | Good | Medium | Medium | GitHub is closing this itself | **Start here.** Fast, real, but a ceiling not a destination. |
| **Agent-platform change hook (Anthropic `ConfigChange`, later AgentCore)** | **High** | 3–9 mo | Eng lead | Good | **High** | **High** | Platform may absorb it | **The best route available.** Cheap, non-GitHub, real enforcement. |
| **IAM / gateway assurance condition** (decision as a condition on Entra Agent ID, Okta XAA, AgentCore Identity grants) | Medium | 12–24 mo | CISO + IAM | **Excellent** | **Very high** | **Highest** | Requires a partner to accept an external condition | **The prize.** Pursue via standards, not sales. |
| **Cloud deployment admission / K8s admission controller** | Medium | 9–18 mo | Platform eng | Medium | High | High | Google may ship it | Strong second. Multi-cloud is the defence. |
| **Buyer / vendor-security requirement** ("show me current assurance for the agent that writes to our systems") | **Medium-high** | 12–30 mo | Customer's customer | **Excellent** | **Very high** | **Highest** | Needs a critical mass of issuers | **The genuine network effect.** Seeded by the §24 wedge from day one. |
| ServiceNow change approval | Medium | 18–36 mo | Change mgmt | Excellent | Medium | Medium | ServiceNow already governs the request | Partner, do not compete. |
| Standards / NIST COSAiS overlay | Medium | 12–24 mo | Regulator | Excellent | n/a | High | Slow, uncontrollable | Participate. Low cost, high option value. Window is open *now*. |
| Agent marketplace requirement | Low | 24–48 mo | Marketplace | Excellent | High | High | No marketplace has the leverage yet | Watch. |
| Robotics / functional-safety process | Very low | 5 yr+ | Safety eng | n/a | Very high | High | Wrong discipline | Do not pursue. |
| Auditor requirement | Low until 2028 | 24 mo+ | Auditor | Good | High | Medium | Regulatory slip | Deprioritised by the Omnibus delay. |

**Sequence: CI check → platform change hook → buyer requirement → IAM/gateway condition.** Each step makes the next cheaper. The buyer requirement is the one that creates a genuine network — every vendor that ships a ThreatVeil record makes the next buyer more likely to ask for one — and it is available *only* through the §24 wedge, which is the strongest argument for that ICP.

---

## 26. Five breakthrough extensions

Maximum five. Each reinforces the same control question; none is coverage.

**1. Assurance-conditioned authority (the decision as an IAM/gateway condition).**
*Why important:* converts ThreatVeil from a report into a precondition. *Why it reinforces the core:* it is the control question with an enforcement verb attached. *Why not feature creep:* it adds no new domain object — the decision already carries audience, nonce, prior epoch and a status URI. *Build now?* Build the **contract** now (a documented, cacheable, machine-readable status/verification endpoint that any consumer can poll); build integrations customer-driven. *Trivially reproducible by an incumbent?* Microsoft and Okta could ship the *mechanism* trivially — but neither can supply the *evidence input*, which is the point of the partnership.

**2. Permission-envelope diff as the primary change event.**
*Why important:* permission and tool changes are the most consequential and least version-controlled changes in agent systems — 45.6% of teams still share API keys, and 25.5% of agents can spawn agents. *Why it reinforces the core:* the envelope is already immutable, superseding and epoch-versioned; it just has no automatic source. *Why not creep:* it replaces manual declaration with observation on infrastructure that exists. *Build now?* **Yes, alongside P0-2** — MCP `tools/list` + Anthropic managed settings + AgentCore Gateway all emit exactly this. *Reproducible?* Zenity effectively does the point-in-time version; nobody does the *diff-with-evidence-consequence*.

**3. The system passport — one portable, independently verifiable current-assurance document.**
*Why important:* it is the artefact the §24 wedge hands to *their* enterprise customer, which is how the buyer-requirement network starts. *Why it reinforces the core:* it is the decision plus its status, addressed to an external audience — the audience field already exists. *Why not creep:* no new evidence, no new claims; a rendering and a trust root. *Build now?* Build after the first customer, but **publish the trust root and open the verifier before the first hosted record is signed** — retrofitting trust distribution onto already-issued records is the expensive version. *Reproducible?* The format, trivially. The corpus of issuers, not at all.

**4. Tenant-private applicability memory.**
*Why important:* it makes the product better the longer a customer uses it, at n=10 rather than n=10,000, with zero cross-customer data rights. *Why it reinforces the core:* it answers "what must be re-established" with the customer's own history instead of a static rule. *Why not creep:* it is a query over records that already exist. *Build now?* **No** — after ~90 days of real customer history. Building it on synthetic data would produce a lie. *Reproducible?* The code yes; the history no. **This is the cheapest genuine moat in the list.**

**5. Delegation-aware authority (A2A / subagent chains).**
*Why important:* multi-agent delegation is the fastest-moving architectural shift and the one that breaks single-system models. *Why it reinforces the core:* an envelope derived from another envelope is still an envelope; a change to the parent must invalidate evidence for the child. That is the same engine, applied transitively. *Why not creep:* the `delegates_to` relationship type already exists and is deliberately inert — this gives it semantics rather than adding a concept. *Build now?* **No — but do not let the model calcify against it.** Ingest A2A Agent Cards as source assertions early (cheap); add derived-authority semantics when a customer has a real delegation chain. *Reproducible?* This is where the abstraction either survives 2027 or does not, and where a scanner-shaped competitor cannot follow.

---

## 27. Physical-AI future

**The primitives survive; the discipline does not, and the boundary must be stated in public before anyone asks.**

Transferable without redefinition: **system** (a robot is a system), **environment** (a cell, a warehouse zone, a road segment), **operating envelope** (speeds, forces, zones, payloads — a permission envelope with physical units), **claim**, **evidence**, **change**, **effect**, **assurance**, **decision**, **historical memory**. The software-change-invalidates-prior-validation problem is *identical* and, in physical systems, more acute: a perception-model update or a gripper firmware change invalidates prior safety validation in exactly the way ThreatVeil already models. Assurance cases are, in fact, native to functional safety — ThreatVeil is importing a safety-engineering idea into software, not the reverse.

**Where it stops, hard:** functional safety (IEC 61508, ISO 13849, ISO 26262, ISO 10218) requires certified toolchains, hazard analysis, SIL/PL determination and notified-body assessment. Real-time control has determinism requirements a hosted control plane cannot meet. Hardware validation requires physical test rigs. Certification is a regulated professional activity ThreatVeil cannot perform. Evidence in these domains comes from instrumented physical tests, not API observation.

**Credible role, if ever:** the *change-impact and evidence-currency layer that feeds a certified safety process* — "this firmware change touches components that three of your validated safety claims depend on; these validations require re-execution before release" — never the safety determination itself. That is a genuine and defensible product for a robotics company's release engineering team, and it is the same product.

**The discipline to hold:** never claim safety assurance, never sit in a real-time control path, never imply certification. Publish that boundary now, in the same place as the current honest `/security` page. The credibility of refusing the physical claim is worth more than the option value of making it.

---

## 28. Quantum / future-compute readiness

**No quantum product. The real exposure is key custody, not algorithms — and the architecture is conceptually agile but concretely single-profile.**

What exists: `signature_profile: "dsse-in-toto-ed25519/v1"` as an explicit, versioned field; unknown algorithms and profiles fail closed rather than degrading; `keyid = sha256(raw public key)` in the DSSE signature block; the verifier requires the caller's independently trusted key and rejects any mismatch; new verifier profiles can be added without touching domain objects. That is a correct extension seam.

What does not exist: any second algorithm, hybrid classical+PQC signing, key rotation with overlapping validity, a published trust root or key directory, and a transparency log. The implementation report states this accurately.

**The actual risk is unglamorous and near-term.** ThreatVeil's whole thesis is that a record retains meaning for years. If hosted customer records are signed with one non-rotatable key and no published trust anchor, then key compromise, key loss or simple staff turnover invalidates the entire historical corpus — and no amount of PQC helps. **A signature is only as durable as the ability of a stranger to resolve `keyid` to a key they trust, years later.**

**Recommendations, in order and all cheap:** (1) publish a signed key directory resolving `keyid` → public key with validity intervals, before the first hosted customer record is signed; (2) implement rotation with overlapping validity and re-verification of historical records under retired keys; (3) add a second algorithm profile only when a customer or standard asks — the seam is proven by adding the *second*, not by discussing the *third*; (4) evaluate hybrid classical+PQC when NIST-recommended composite signatures have library support; (5) treat transparency-log inclusion as a **trust-distribution** feature (it lets a third party verify without ThreatVeil's cooperation), not a cryptography feature. Items 1 and 2 are the ones that actually protect the business.

---

## 29. Category/name verdict

**Category — "Autonomous Change Assurance": keep it, and stop leading with it.**

It is accurate, unclaimed, ownable, and analysts will eventually need a name. But it is a poor *first sentence*: "assurance" is a Big Four services word carrying low urgency and audit connotations, and no buyer is shopping for it. Lead with the control question — *"Does current evidence still justify this system's authority to act?"* — and let Autonomous Change Assurance be the category label underneath, the way "observability" sat under "why is my service slow" for years before anyone bought a category.

Keep **Autonomous Release Integrity** as the entry product name. It is concrete, it is what the wedge actually does, and it is good.

**Company name — "ThreatVeil": recommend changing, and do not let it delay deployment.**

Not an aesthetic objection. Both halves mis-signal, and one of them contradicts the product:

- **"Threat"** signals detection, threat intel and offence — the 2015-era category. ThreatVeil does not detect threats. It manages the currency of evidence. The name will pull every first conversation toward "so it's an AI threat scanner?", which is the exact positioning §3 of the brief forbids.
- **"Veil"** means to conceal. The product's entire value — and its own copy — is the opposite: *"Trust the scope. Inspect the evidence."*, *"Every conclusion has a scope."* A company whose differentiator is refusing to hide uncertainty should not be named after a thing that hides. This is a genuine semantic conflict, not a preference.
- Practically: no conflicting registration surfaced in public trademark search, but the "Threat\*" security namespace is dense (ThreatConnect, ThreatMark, ThreatAware, ThreatNG, threatSHIELD), which weakens distinctiveness and complicates search and trademark work.
- Global pronunciation is fine; enterprise credibility is fine; developer appeal is mildly negative; **category flexibility is poor** — "ThreatVeil" cannot follow the abstraction into physical autonomy or buyer-facing assurance without sounding wrong.

**Recommendation:** deploy on the current name — it is a marketing-layer change and the internal package name `threatveil` is irrelevant to customers — and rename **before** signing the first customer contract, before trademark spend, and before the first record is issued under a name buyers will see for a decade. Choose a name that signals *currency of evidence* or *standing authorisation*, not threat and not concealment. Cost of renaming now: one week. Cost in two years: the customer-facing name in every signed record ever issued.

---

## 30. Market potential

Bottom-up, no percentage-of-TAM arithmetic. Stated assumptions, wide ranges.

**Assumptions:** consequential = the agent can take an externally visible action with financial, contractual or data-integrity effect. Serviceable = English-language, has a named security or platform owner, has a staging environment, releases at least monthly. Adoption assumes ThreatVeil executes well but has no incumbent partnership.

| Segment | Plausible accounts | Systems/account | ACV | Realistic 4-yr penetration | ARR contribution |
|---|---:|---:|---:|---:|---:|
| AI-native B2B vendors with consequential write agents | 1,000–2,500 | 1–4 | $5k–30k | 1.5–4% | $0.4M–2.0M |
| Enterprise internal AI-platform teams (F2000 with an AI platform function) | 1,500–3,000 | 5–50 | $50k–250k | 0.5–1.5% | $1.0M–8.0M |
| Regulated financial-operations agents | 300–800 | 3–20 | $100k–400k | 1–2% | $0.6M–4.0M |
| Support / revenue-operations agents with write authority | 2,000–5,000 | 1–6 | $5k–40k | 0.5–2% | $0.3M–2.5M |
| PLG self-serve (Pro/Team, no sales contact) | large | 1–3 | $1.2k–4.8k | 200–900 paying accounts | $0.3M–1.5M |
| **Total** | | | | | **$2.6M–18M** |

**Read this honestly.** The realistic four-year band is **$3M–15M ARR** — a good venture-scale business, not yet a category-defining infrastructure company. The bridge from $15M to $100M+ does not come from more segments or more connectors. It comes from exactly one thing: **becoming a required check somewhere** (§25), which converts a per-account sale into a per-transaction dependency and lifts both penetration and ACV by an order of magnitude.

Context that supports the direction without inflating it: enterprise generative-AI spend reached **$37B in 2025** from $11.5B in 2024 (Menlo Ventures); **72%** of enterprises plan to deploy agents from trusted providers in 2026 (KPMG). The money is arriving. The question is whether ThreatVeil is a line item in it or a precondition for it.

---

## 31. Investor verdict

As a sceptical infrastructure investor who has seen the 2026 agent-security wave:

**Today (pre-deployment): No.** Not because it is bad — because it is unfundable in its current evidentiary state. There is no customer, no revenue, no distribution, no data asset, and every visible artefact is synthetic. Against Zenity at $185M, HiddenLayer at $150M and Straiker growing revenue 15× in under a year, "excellent local implementation" is not a round. A pre-seed on founder quality is possible; a seed on this evidence is not.

**After GCP (hosted, working, zero customers): Still no, but I take the meeting.** Deployment proves executional seriousness and nothing about demand. What it changes is that the next conversation can be about a real signup funnel instead of a local demo.

**After 3 customers: Yes, at seed, if — and only if — three specific things are true.** (1) At least one instance where ThreatVeil said prior evidence no longer applied, the customer checked, and it was correct — with the record to show. (2) At least one enforcement consumer that is not GitHub. (3) At least one customer who has changed their release process because of it, and will say so on a call. Absent those three, three logos is three pilots.

**After 20 customers: Yes, at Series A, and competitively.** The diligence questions become: What fraction of decisions are consumed by an automated gate rather than read by a human? What is the median time from change to re-established evidence, and is it falling? How many systems per account, and is it growing? Has any customer's *customer* asked for a ThreatVeil record? What is founder-hours per new system, and is it approaching zero? Answer those well and this is a company with a control point nobody else has.

**The single piece of evidence that converts "interesting software" into "potential category leader":** *a named organisation that will not ship a consequential agent change without checking ThreatVeil first, and cannot easily stop.* Everything in this document is instrumental to producing that one sentence. Nothing else counts.

---

## 32. What must happen before GCP

**P0 — exactly three. Everything else waits.**

**P0-1. Make the hosted free product reach a decision.**
`POST /v1/change-assurance/finance/assess` returns 409 when not local ([change_assurance_api.py:394](src/threatveil/change_assurance_api.py#L394)); the UI gates every change action on `local`. The worker *already* executes `run_finance` on the hosted path ([worker.py:83-93](src/threatveil/worker.py#L83-L93)) — the execution primitive exists; the orchestration and the UI affordances are local-only. A hosted signup must be able to: create the Finance Agent, run the baseline, apply the permission change, see prior support affected, see the explanation, see the decision, and export the record. Add the org-name prompt and a "Start free" CTA in the same change. *Why P0:* without it, the first thing you buy with cloud money is a dead end for every visitor.

**P0-2. Move MCP to 2026-07-28.**
Stateless core (no `initialize`, no `Mcp-Session-Id`, `MCP-Protocol-Version` header per request), `ttlMs`/`cacheScope` on `tools/list`, CIMD over DCR, and EMA/Cross-App-Access awareness. Support both revisions during the twelve-month deprecation window rather than swapping the pin. Update `sdk/mcp_server.py` in the same pass. *Why P0:* the only agent-tool-protocol connector is currently non-functional against every current server, and tool/permission change is the canonical non-code change the entire thesis rests on. Discovering this during a first-customer call is the expensive version.

**P0-3. Ship one product, not two.**
Make Autonomous Change Assurance the default landing surface; demote the legacy kernel screens to detail views beneath the six-stage flow; replace the Overview's procurement demo with the change-assurance one; lead every surface with the decision and its *status*, not the verdict; retire implementation nouns from navigation; add "Start free" as the primary public CTA and move "Discuss Integrity Launch" to secondary. *Why P0:* positioning is architecture at this stage. It sets what every early customer, screenshot and investor believes you sell, and it is the cheapest item on this list.

**Additionally, before the first hosted customer record is signed (small, but irreversible if skipped):** publish a key directory resolving `keyid` → public key with validity intervals, and a rotation procedure. Retrofitting trust distribution onto already-issued records is the expensive version of this.

**P1 — during first customer:** Anthropic `ConfigChange` connector (CHANGE + first non-GitHub ENFORCE); move `enforcement.ci` to Pro and add WARN-mode enforcement to Free; a documented machine-readable status/verification endpoint for external consumers; open the verifier and the record schema; one real qualified observer package built *with* the design partner.

**P2 — after customer evidence:** AgentCore Gateway connector; A2A Agent Card ingestion; tenant-private applicability memory; the system passport; retention lifecycle enforcement; projection query optimisation and pagination; REGIONAL HA.

**Do not build:** covered in §34.

---

## 33. What should happen immediately after GCP

**First 30 days. No new capability except P1-1.**

- **Days 1–5:** cloud acceptance drills as documented (two-tenant isolation, broker/worker denial, restore, rollback, budget alerts). Instrument the six measurements in §21 — especially founder-hours-per-system and decision-path latency — before any traffic. Confirm logging volume before the 50 GiB free tier is silently exceeded.
- **Days 3–10:** Stripe TEST lifecycle end to end. Then ten real self-serve signups from people who are not you, watched without help, timing where each one stops. That single exercise is worth more than any feature.
- **Days 5–20:** the Anthropic `ConfigChange` connector (P1-1). It is the fastest path to a non-GitHub enforcement surface and it is the thing that converts "report" into "dependency".
- **Days 10–30:** one design partner from the §24 profile. Scope: one consequential action, three claims, one paired legitimate task, staging, WARN. Success is not a signed record — it is the first correct, non-obvious invalidation, captured with the customer's confirmation.
- **Throughout:** write down every manual step required to onboard that partner. That list is the actual product roadmap; anything invented in advance of it is speculation.
- **Do not:** enable live billing, sell production BLOCK, publish availability or SLA claims, or start a second connector before the first customer has produced one real change event.

---

## 34. What NOT to build

Explicit anti-roadmap. Each item is something a well-intentioned coding agent will otherwise build in a weekend, and each would actively damage the company.

1. **Agent discovery / inventory.** Owned by Microsoft Agent 365, Zenity and ServiceNow. Consume it; never compete.
2. **A runtime firewall, AI gateway or prompt-injection filter.** Palo Alto, Straiker, Lakera and Operant own this, with distribution ThreatVeil cannot match.
3. **An identity provider or credential broker.** Entra Agent ID, Okta XAA/Agent SSO, AgentCore Identity and SPIFFE/WIMSE have converged. Be a *condition* on grants, never a grantor.
4. **An evals or model-quality product.** Different question, crowded, and it dilutes the one thing that is defensible.
5. **More connectors before the first customer.** Coverage is not defensibility. Three deep beat fifteen shallow.
6. **Automatic remediation or autonomous fixing.** Destroys the conservative-evidence posture that is the only cultural moat.
7. **A graph database, data lake or generic reasoning engine.** The relationship model is deliberately traceability-only. Keep it that way until a customer's actual delegation chain forces the semantics.
8. **Cross-customer learning before a rights path and enough data exist.** The rights architecture is good; using it early would be both premature and a breach of the product's own promise.
9. **Robotics, physical safety or certification claims.** §27. Publish the boundary; do not cross it.
10. **A quantum or PQC feature.** §28. Fix key custody instead.
11. **SOC 2 before there is a customer who is blocked on it.** Expensive, slow, and premature at zero revenue.
12. **A rewrite of the record store for scale.** §3's performance debt is real and is a 200-customer problem, not a 2-customer problem.
13. **Compliance-timed product work for the EU AI Act.** High-risk obligations slipped to Dec 2027/Aug 2028.
14. **A second vertical fixture before the first real observer exists.** Synthetic breadth is the most seductive form of progress theatre available here.

---

## 35. Final decision

# B — FIX THREE STRUCTURAL P0s, THEN DEPLOY.

The architecture is right, the control point is real and unowned, the engineering is unusually disciplined, and the honesty is a competitive asset. The three defects are small, cheap and would each be expensive to discover after money starts moving: **a hosted free product that cannot reach a decision; the only agent-tool connector pinned to a deleted protocol revision; and two products shipping in one deployment with the wrong one in front.** Plus one irreversible detail — publish the key trust root before signing the first hosted record.

Then deploy, and spend the next unit of time on customers rather than code. Every remaining uncertainty in this document is a customer question, not an engineering question.

---

## Answers to the 34 final questions

1. **What exactly is ThreatVeil?** A system that keeps the evidence behind an autonomous system's authority current — detecting when change invalidates prior security conclusions, requiring that both the prohibited outcome stays prevented and the useful task keeps working, and issuing a signed, expiring, status-tracked authorization statement.
2. **Single most important control point?** *Does current evidence still justify this system's authority to act?*
3. **Does the architecture support today's frontier agentic systems?** The *abstraction* does. The *implementation* supports GitHub repositories, Cloud Run services, file imports, and an MCP revision that no longer exists.
4. **Where does it fail?** No live connector for Anthropic Managed Agents, AgentCore, Agent 365, Vertex Agent Engine, OpenAI Connector Registry, LangGraph or A2A. No representation of delegation, subagents, agent identity or payment mandates. MCP broken. Only GitHub can consume a decision.
5. **Three integrations that matter most next?** Anthropic `ConfigChange`/managed settings; AWS Bedrock AgentCore Gateway + Identity; A2A Agent Card ingestion.
6. **Is GitHub genuinely only one connector now?** In the framework, yes. In practice, it is the only one with write authority and the only one that can consume a decision. Not yet true operationally.
7. **Is Autonomous Release Integrity merely the wedge?** Yes, and it is a good one — provided the release gate is not the only enforcement surface by the time the second customer arrives.
8. **Is Autonomous Change Assurance a credible company category?** Yes. Unclaimed, accurate, defensible. It is a poor first sentence and a fine category label.
9. **Better category description?** Keep the label; lead with the control question. Nothing better emerged from the research.
10. **Is the problem real today?** Yes. 81% past planning, 14.4% fully approved, 47.1% coverage, 88% incident rate.
11. **Urgent enough to pay for?** Where the agent can cause an expensive visible effect, releases are frequent, and a named person must say yes. Not otherwise — and say so.
12. **Differentiated enough?** As a composition, yes. As individual features, no.
13. **Anything truly breakthrough?** One thing: a decision that changes status by itself when the world changes. It is the most defensible idea in the repository and the least visible in the product.
14. **Product or experiment?** A product with an experiment's presentation. Nine of eleven experiment symptoms currently apply.
15. **Could Microsoft crush it?** In coding agents and enterprise governance, yes, and largely already has. In "did this change invalidate the evidence for an agent writing into someone else's ERP", no.
16. **What prevents that?** Independence, multi-platform coverage, business-effect ground truth in systems Microsoft does not host, and history Microsoft cannot retroactively produce.
17. **What must be accumulated that cannot be vibe-coded?** Longitudinal change→invalidation→re-proof→outcome history; qualified business-effect observation packages; installed workflow dependency; accepted external consumers; independent verifier trust; a standards position.
18. **Does Free→Enterprise strengthen or weaken?** Strengthens — but only if the control point is reachable below $399. Today it is not, which breaks the motion.
19. **Are the prices sensible?** Shape yes, numbers plausible, placement wrong. Move `enforcement.ci` to Pro; give Free WARN-mode enforcement, 2 environments and 1,000 units; make Business earn $2,000 on production enforcement specifically.
20. **Can Free be a distribution weapon without destroying economics?** Yes, comfortably. A free organisation costs roughly $1–3/month. Free is currently too restrictive where it matters and irrelevantly generous where it does not.
21. **What makes Business/Enterprise worth large ACVs?** Production enforcement, qualified observer packages built with the customer, multi-system and multi-environment scope, retention, private deployment, and evidence sharing with their own buyers. Not a longer capability list.
22. **What should be open?** Verifier, record schema, trust root, connector spec + conformance suite, CLI/SDKs, sample property definitions, portable assurance profile.
23. **What stays proprietary?** Hosted longitudinal memory, business-effect observation packages, applicability intelligence, operational workflow and enforcement coordination, enterprise operations, the permissioned outcome corpus.
24. **Can it plausibly become required infrastructure?** Yes, through two credible routes: platform change hooks, then buyer/vendor requirements. IAM/gateway conditioning is the prize and requires standards work, not sales.
25. **Most credible path to category dominance?** AI-native B2B vendors → their enterprise customers ask for the record → the record becomes a vendor-security expectation → issuing one becomes normal. That is the only route with a genuine network effect.
26. **Survives multi-agent systems?** The abstraction yes; the implementation not yet — one system, one envelope, no composition.
27. **Survives dynamic delegation?** Only if `delegates_to` gains derived-authority semantics. The seam exists and is deliberately inert. Do not let it calcify.
28. **Survives autonomous commerce?** Conceptually well — an AP2 mandate is an authority artefact ThreatVeil could condition. Nothing implemented.
29. **Survives physical AI?** The primitives do. The discipline stops at functional safety, certification, real-time control and hardware validation. Credible role: change-impact and evidence-currency feeding a certified process. Never the safety determination.
30. **Survives quantum/future compute?** Conceptually yes — versioned signature profiles that fail closed on unknown algorithms. The real near-term risk is key custody and trust distribution, not algorithms.
31. **What MUST be fixed before GCP?** The three P0s in §32, plus publishing the key trust root before the first hosted record is signed.
32. **What should explicitly NOT delay GCP?** Pricing changes (catalog is external config), the rename, SOC 2, more connectors, the projection performance debt, HA, retention enforcement, the data flywheel, and every item in §34.
33. **Are we about to deploy the right company?** **Yes** — the right company with three small things pointing the wrong way, and a presentation that hides its own best idea.
34. **Final verdict?** **B.**

---

### Sources

[MCP 2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28) · [MCP 2026-07-28 release notes](https://blog.modelcontextprotocol.io/posts/2026-07-28/) · [Microsoft Agent 365 GA](https://www.microsoft.com/en-us/security/blog/2026/05/01/microsoft-agent-365-now-generally-available-expands-capabilities-and-integrations/) · [Entra Agent ID governance](https://learn.microsoft.com/en-us/entra/id-governance/agent-id-governance-overview) · [Palo Alto Prisma AIRS 3.0](https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-secures-agentic-ai-with-prisma-airs-3-0) · [Prisma AIRS AI Gateway GA](https://www.paloaltonetworks.com/blog/2026/07/announcing-general-availability-of-prisma-airs-ai-gateway/) · [Zenity $125M Series C](https://siliconangle.com/2026/08/03/israeli-startup-zenity-bags-125m-funding-build-security-layer-ai-agents/) · [Zenity platform](https://zenity.io/platform) · [HiddenLayer $100M Series B](https://www.theinvestorsociety.com/hiddenlayer-raises-us-100-million-to-secure-the-ai-agents-enterprises-are-now-putting-into-production/) · [Straiker $64M Series A](https://techstartups.com/2026/06/29/straiker-raises-64m-series-a-as-enterprises-rush-to-secure-ai-agents/) · [Mandiant founder $190M](https://techcrunch.com/2026/03/10/mandiants-founder-just-raised-190m-for-his-autonomous-ai-agent-security-startup/) · [AWS Bedrock AgentCore GA](https://aws.amazon.com/about-aws/whats-new/2025/10/amazon-bedrock-agentcore-available) · [AgentCore Identity](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity.html) · [AgentCore Gateway](https://aws.amazon.com/blogs/machine-learning/introducing-amazon-bedrock-agentcore-gateway-transforming-enterprise-ai-agent-tool-development/) · [Vertex AI multi-system agents](https://cloud.google.com/blog/products/ai-machine-learning/build-and-manage-multi-system-agents-with-vertex-ai) · [Google completes Wiz acquisition](https://blog.google/innovation-and-ai/infrastructure-and-cloud/google-cloud/wiz-acquisition/) · [Anthropic secure agent deployment](https://platform.claude.com/docs/en/agent-sdk/secure-deployment) · [Claude Managed Agents](https://aiautomationglobal.com/blog/anthropic-claude-managed-agents-enterprise-ai-deployment-2026) · [Claude Commerce Agents](https://www.marktechpost.com/2026/09/03/anthropic-released-claude-commerce-agents-an-apache-2-0-blueprint-for-shopping-and-merchant-agents-across-retail-travel-telecom-and-entertainment/) · [OpenAI AgentKit](https://openai.com/index/introducing-agentkit/) · [OpenAI Agents SDK sandbox execution](https://techcrunch.com/2026/04/15/openai-updates-its-agents-sdk-to-help-enterprises-build-safer-more-capable-agents/) · [Okta Cross App Access](https://www.okta.com/identity-101/cross-app-access-securing-ai-agent-and-app-to-app-connections/) · [Agent identity standards 2026](https://startwithidentity.com/blog/agent-identity-gets-a-protocol/) · [ServiceNow AI Control Tower expansion](https://newsroom.servicenow.com/press-releases/details/2026/ServiceNow-expands-AI-Control-Tower-to-discover-observe-govern-secure-and-measure-AI-deployed-across-any-system-in-the-enterprise/default.aspx) · [GitHub Agentic Workflows security architecture](https://github.github.com/gh-aw/introduction/architecture/) · [NIST AI Agent Standards Initiative (CSA)](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-ai-agent-standards-initiative-2026040/) · [CoSAI principles for secure-by-design agentic systems](https://www.coalitionforsecureai.org/announcing-the-cosai-principles-for-secure-by-design-agentic-systems/) · [EU AI Act Omnibus deadline changes (Gibson Dunn)](https://www.gibsondunn.com/eu-ai-act-omnibus-agreement-postponed-high-risk-deadlines-and-other-key-changes/) · [Gravitee State of AI Agent Security 2026](https://www.gravitee.io/blog/state-of-ai-agent-security-2026-report-when-adoption-outpaces-control) · [Governance gaps in MCP, A2A and ACP (arXiv 2606.31498)](https://arxiv.org/pdf/2606.31498) · [AgentRiskBOM (arXiv 2606.21877)](https://arxiv.org/pdf/2606.21877) · [AP2 agentic payments](https://www.crossmint.com/learn/agentic-payments-protocols-compared) · [CI/CD tools for testing AI agents 2026](https://www.confident-ai.com/knowledge-base/compare/best-ci-cd-tools-testing-ai-agents-before-production-2026) · [Enterprise AI agent adoption statistics 2026](https://www.digitalapplied.com/blog/ai-agent-adoption-2026-enterprise-data-points) · [Cloud Run pricing](https://cloud.google.com/run/pricing) · [Cloud SQL pricing reference](https://www.bytebase.com/dbcost/cloudsql-pricing/)
