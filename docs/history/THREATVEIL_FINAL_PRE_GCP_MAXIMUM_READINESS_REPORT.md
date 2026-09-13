# ThreatVeil — final pre-GCP maximum readiness report

**Date:** 2026-09-12 · **Wave:** final pre-GCP commercialization, self-service and launch readiness
**Status at completion:** `READY_FOR_PRIVATE_GCP`, `cloud_accepted = false`, `configuration_ready = false`
**Next action:** private GCP activation. No further local product expansion.

---

## A. Verdict and stop condition

This wave did what could responsibly be finished without a customer and without the cloud: it
made ThreatVeil **measurable, self-serviceable and domain-neutral**, and it closed two real
privacy and hygiene gaps found by reviewing its own surfaces adversarially.

| Dimension | Before this wave | After |
|---|---|---|
| Can a stranger get a true answer about their own agent without us? | No. Onboarding assumed a finance fixture and a guided setup | Yes: import a declared agent definition, declare one claim, approve one mapping, ask what a change would break — in minutes |
| Can we tell whether the product is working? | Partly. Activation counted a system-side event; synthetic and real activity blurred at the edges | Yes: provenance separation, customer confirmation, a determinate-answer activation definition, precision with denominators, and a weekly North Star |
| Would a shared passport leak internal data? | **Yes** — identifiers and resource names were inside the signed document | No: disclosure profiles, a reviewed preview, explicit confirmation |
| Could a customer leave with their data? | Partly — 44 of 103 record kinds | Yes: every kind except one deliberate secret-bearing exclusion, enforced by a test |
| Is the business measurable by the founder without touching tenant data? | No | Yes: an operator-only store the product API cannot reach |

**Stop condition reached.** The limiting resource is not code. It is one customer with a real
agent, a real system of record and a real change.

## B. What was built, in business terms

1. **"What would this change break?"** — a dry run against the customer's own proposed
   configuration, as a non-blocking pull-request check. This is the fastest honest path to value
   and needs no natural change to occur.
2. **Declared change impact** — a customer can state what must be true in minutes and
   immediately learn which changes touch it, with `NOT_YET_VERIFIED` never presented as proof.
3. **A business-effect observer contract** — what an observer must declare, a ten-scenario
   qualification harness, and a read-only PostgreSQL observer that refuses to guess.
4. **Truthful measurement** — provenance, confirm/dispute, activation on a determinate answer,
   precision with numerators, and Relied-upon Protected Systems weekly.
5. **An operator-only business view** — staff time, classification, prospects, offers, pricing
   experiments, and an investor-ready export where zero is a valid answer.
6. **Self-service scaffolding** — a claim builder with ten reviewed patterns, neutral starter
   actions, deterministic mapping suggestions, four DRAFT assurance packs, and an example
   gallery with exactly one runnable (synthetic) card.
7. **Bounded frontier foundations** — agent-definition parsing for six formats, configuration
   history replay, automatic re-proof that can only repeat an approved verification, and AI
   seams that can only propose.

## C. Implementation matrix: what the plan said, what happened

| Area | Matrix call | Delivered |
|---|---|---|
| Truthful business measurement | BUILD NOW | Yes — `business_measurement.py`, `operator_store.py`, migration `0008` |
| Domain-neutral product | BUILD NOW | Yes — hero, login, onboarding, gallery, templates, neutral actions |
| Proposed-change assurance | BUILD NOW | Yes — API, CLI, SDK, GitHub Action; the App PR webhook stays PREPARE ONLY |
| Declared change-impact mode | BUILD NOW | Yes — declared dependencies, the four-level ladder, consequence integration |
| Claim builder and templates | BUILD NOW | Yes — 10 patterns, 13 neutral actions, draft endpoint, workspace UI |
| Dependency-mapping UX | BUILD NOW | Yes — suggestions with reasons, proposal/review queue, overview |
| AI seams | BUILD NOW (off) | Yes — proposal-only, mock-tested, budget-gated, usage-accounted |
| Observer platform | BUILD NOW | Yes — contract, five qualification states, harness, SQL observer |
| Bounded auto re-proof | BUILD NOW | Yes — policy, planner, sandbox dispatch, no remediation path |
| Agent-definition intelligence | BUILD NOW | Yes — six formats, deterministic, history replay |
| Assurance packs | BUILD NOW | Yes — format plus four DRAFT packs and the gallery |
| Launch offer and kit | BUILD NOW | Yes — `docs/ASSURANCE_LAUNCH_KIT.md`, offer records in the operator store |
| Pricing readiness | BUILD NOW | Yes — `availability: contact` for Business and Enterprise |
| Brand seam | BUILD NOW | Yes — issuer behind config, `BRAND_RENAME_IMPACT.md`; nothing renamed |
| Passport privacy | BUILD NOW | Yes — disclosure profiles, preview, confirmation |
| Security hardening | BUILD NOW | Yes — six findings fixed, adversarial suite added |
| Supply chain | BUILD NOW | Yes — scan, SBOM, advisories, build provenance, accepted revision |
| Export, quickstart, failure UX, API examples, cost, analytics | BUILD NOW | Yes — all documented and implemented |
| AgentCore, Entra, Okta, Vertex, OpenAI/Anthropic platforms, Salesforce, ServiceNow, K8s, A2A | PREPARE ONLY | Unchanged: the connector contract and observer contract are the seams |
| Chatbot, remediation, cross-customer ML, marketplace, trust score, connector sprawl, second vertical | DO NOT BUILD | Not built |

---

## D. Truthful measurement: provenance

Every consequence carries exactly one provenance: `LIVE`, `IMPORTED`, `CUSTOMER`, `PROPOSED`,
`REPLAYED`, `SYNTHETIC`. Synthetic dominates every other origin; replayed history is shown and
never counted. The demonstration track reports its whole journey with `activated` permanently
false and a separate `demonstration_complete` flag.

`/v1/measurements/business` reports counts per provenance plus `counted` and the explicit
`never_counted: ["SYNTHETIC", "REPLAYED"]`.

**Test:** `test_synthetic_consequences_are_shown_and_never_counted` — a confirmed consequence on
the demonstration system leaves activation false, precision denominators zero and RPS zero.

## E. Confirm and dispute ("WAS THIS RIGHT?")

`CORRECT`, `PARTIALLY_CORRECT`, `INCORRECT`, `NOT_SURE`, optional 500-character comment.
Append-only, bound to a digest of the consequence as shown, tenant-isolated, idempotent per key,
and structurally incapable of changing the consequence (`effect_on_assurance: NONE`).

**Test:** `test_feedback_is_append_only_isolated_and_changes_no_conclusion` — the change view and
the gate are identical after a dispute; a database `UPDATE` on the record fails; another tenant
gets 404 on read and write; oversized comments and unknown verdicts are 422.

## F. Activation: `FIRST_CONFIRMED_CONSEQUENCE`

Business activation requires a **determinate claim-level answer** (`INVALIDATION` or
`NO_IMPACT`) about a real change on a non-synthetic system, confirmed by a member or acted on
through re-proof within seven days. "No baseline", "no claims" and "no change" are recorded and
are not claim-level answers. `claim_basis` distinguishes `EVIDENCED` from `DECLARED`, and
`activation.qualified` is the strict reading.

`FIRST_MEANINGFUL_ASSURANCE_EVENT` remains the system-side event. A new
`FIRST_PROPOSED_CONSEQUENCE` milestone measures time to wow.

**Test:** `test_declared_claim_consequence_confirmed_on_a_real_system_is_activation`.

## G. Precision metrics

Six rates, each `{numerator, denominator, value}` with `value: null` at zero denominator:
confirmed, fully-correct, dispute, false-invalidation, no-impact-confirmation, and the
mapped/unmapped change ratio. Plus four counts: confirmed and disputed invalidations, confirmed
and disputed no-impact answers — because **a precise no-impact answer is value**, not an absence
of value.

`NOT_SURE` never counts as agreement. Synthetic and replayed feedback is reported as excluded.

## H. North Star: Relied-upon Protected Systems

Weekly, three conditions: watched (a live source within 7 days), maintained (clearance current,
or lost within 14 days and being re-established), relied upon (a machine gate check, a CI check
or an external passport check within 7 days). `WATCHED` and `MAINTAINED` are reported beside it
so a zero is diagnosable. Gate checks are hourly-deduplicated per consumer, so polling cannot
inflate it.

**Current value: 0.** Correct, and it will stay zero until a customer connects a live source and
something reads the gate.

## I. Founder business dashboard and the operator store

Migration `0008` adds `operator_records`: no row-security policy for the runtime role, every
non-owner grant revoked, append-only, and erased with its organization. Operator reads use the
migration identity; the only cross-tenant read is the organization listing, after which each
organization is measured **inside its own tenant context**. Every report run appends an
`operator_access` record.

`threatveil operator business-report` reports: organizations by classification, activation per
organization with seconds-to-activation, weekly RPS summed across external organizations,
aggregated precision, consequences by provenance, staff hours by category and stage, hours per
activated organization, the commercial funnel with pricing experiments, contracted value, and an
explicit `vanity_metrics_excluded` list. `investor-export` emits the same numbers with
definitions, numerators and denominators, as CSV or JSON.

**Tests:** the runtime role is denied on `operator_records` and sees no cross-tenant rows even
with the GUC set; the product API exposes no operator route; operator records are append-only
even for the operator.

## J. Staff-time logging

Per organization, system, observer, stage and support event, in nine categories. This is the
number that decides product versus consultancy: **hours per activated organization, trending
down**. Internal and test organizations' hours are excluded and reported separately.

---

## K. Domain-neutral product audit

| Surface | Was | Now |
|---|---|---|
| Landing eyebrow | `AUTONOMOUS RELEASE INTEGRITY` | `CHANGE ASSURANCE FOR AI AGENTS` |
| Hero | "Your agent changed…" | "Your AI agent changed. Which security conclusions are still true?" (kept, sharpened) |
| Hero visualization | payment authorization, beneficiary change, "Procurement agent" | "A consequential change must never commit without a recorded approval", "Any agent with consequential tools"; timeline reads CLEARED → CHANGED → RE-ESTABLISHED |
| Secondary CTA | "Discuss an Integrity Launch" | "Apply for an Assurance Launch" |
| Workspace eyebrow | `AUTONOMOUS CHANGE ASSURANCE` / `AUTONOMOUS RELEASE INTEGRITY` | `CHANGE ASSURANCE FOR AI AGENTS` / `RELEASE INTEGRITY KERNEL` |
| Login caption | "The security gate for AI releases" | "Change assurance for AI agents", plus the two-choice next step |
| Empty workspace | "Nothing is protected yet… or follow the Finance example" | Two-choice onboarding plus the example gallery |
| Claim examples | finance placeholders in one form | ten reviewed patterns, thirteen neutral actions, any custom action |
| Release-integrity kernel | front of house | retained beneath, under Advanced |

The Finance fixture is unchanged and still labelled synthetic: it is the regression fixture and
the one runnable example.

## L. Onboarding and the example gallery

Primary **Connect my own agent**; secondary **Explore an example**. Five cards: four DRAFT packs
labelled `TEMPLATE · NOT RUNNABLE · NOT VERIFIED FOR YOUR SYSTEM`, and one
`RUNNABLE · SYNTHETIC DATA ONLY` Finance card with `counts_as_customer_activity: false`.

## M. Proposed-change assurance

`POST /v1/systems/{id}/proposed-changes` parses the proposal with the same deterministic parser a
real import uses, compares it against the last observation, and answers with the same semantics.
Read-only for clearance: the only write is one append-only assessment labelled
`PROPOSED · NON-ACTIVE · NOT CURRENT STATE`. Bounded, rate-limited, idempotent, tenant-scoped.

**Test:** `test_proposed_change_answers_what_would_break_without_touching_clearance` — the gate
is byte-identical afterwards and only the assessment, its audit entry and service metrics grew.

## N. The GitHub check

`integrations/github-change-assurance` publishes **THREATVEIL — CHANGE ASSURANCE** as a job
summary with `success` for no impact and `neutral` otherwise. It never publishes `failure` and
never fails the build unless `fail-on` is set. Outputs `effect`, `conclusion`, `assessment-id`.
One deterministic idempotency key per commit and file, so a re-run reads the same answer.

## O. Time-to-wow instrumentation

`seconds_to_first_proposed_consequence` and `seconds_to_first_confirmed_consequence`, per
organization, from signup. `NO_BASELINE`, `NO_CHANGE` and `NO_CLAIMS` do not count as a wow.

## P. Declared change-impact mode

`DECLARED` → `NOT_YET_VERIFIED` → `QUALIFIED` → `CURRENT`, never collapsed, with counts, meaning
and next step per claim. A declared claim never enters the gate, never appears as supported, and
produces no passport conclusion. A declared claim with dependencies **does** get the answer the
customer wants: which changes reach it, with "now prove it" as the next step.

**Tests:** the ladder counts stay `{DECLARED: 0, NOT_YET_VERIFIED: 1, QUALIFIED: 0, CURRENT: 0}`
with evidence currency reporting `SUPPORTED: 0`.

## Q. Claim builder and template library

Ten patterns, every one labelled `STARTER TEMPLATE / NOT VERIFIED FOR YOUR SYSTEM`; thirteen
neutral starter actions; a draft endpoint that records nothing. No model involved.

## R. Dependency-mapping UX

Deterministic suggestions with six reasons and three confidence **categories** (never a
percentage), each citing the source record that reported the fact. A proposal/review queue where
only approval creates a mapping; the overview shows mapped facts with approver, time and source
record, and unmapped facts with the consequence spelled out.

**Test:** `test_a_mapping_proposal_changes_nothing_until_a_person_approves_it` — the change is
unscoped before approval and scoped after; a second review is 409; a dependency no claim declares
is refused.

## S. AI seams, flags and invariants

Off by default (`TV_AI_PROVIDER=disabled`, both feature flags false). Proposal-only, minimal
context (names, never payloads or secrets), must cite its inputs, cannot invent a subject, human
approval required, `ai_usage` recorded per call, and a paid provider refuses to run without a
configured budget. A deterministic mock provider is what the tests exercise.

**Invariants asserted:** no model output changes an assurance status; the declared claim is still
`NOT_YET_VERIFIED` after every AI call; with the flags off the endpoints are 409 and no provider
is constructed.

## T. Observer platform

A contract with nine mandatory declarations; five qualification states bound to a contract digest
with expiry; a ten-scenario harness where six scenarios require the observer to **refuse**; a
read-only PostgreSQL observer with no arbitrary SQL, cross-tenant correlation-collision
detection and window checks; and an effect summary where a compensation never erases a commit and
missing evidence is never "no effect".

**Tests:** the SQL observer answers all ten scenarios correctly against a real temporary schema;
an unqualified observer's facts are recorded and never become evidence; a forged qualification for
a different contract is 409; a partially passing harness leaves it `QUALIFICATION_PENDING`.

## U. Bounded auto re-proof

A policy requires an approved claim, an approved target, a `QUALIFIED` observer, one environment,
a recorded authority scope, a bounded budget and an explicit `confirm_no_remediation`. The planner
refuses with a named reason rather than improvising, and checks the observer and the authority
boundary **before** the budget. Dispatch works only in the labelled synthetic sandbox; anywhere
else it reports `NO_QUALIFIED_DISPATCHER`. There is no remediation code path.

**Test:** `test_auto_reproof_repeats_one_verification_and_can_never_widen_scope` — eligible only
after assurance is lost; budget exhaustion; a superseded envelope ends the permission; a revoked
observer ends it; a non-sandbox policy is refused by the flag.

## V. Agent-definition intelligence

Six formats parsed deterministically (ThreatVeil manifest, Claude Code settings, `.mcp.json`,
subagent markdown, `langgraph.json`, CrewAI), with the OpenAI Agents SDK refused with a clear
message. Secrets never retained. YAML anchors refused. The authority vocabulary now covers scope
lists, denial lists, grant flags and ordered permission modes; everything else stays
`UNKNOWN_IMPACT`. History replay is labelled `REPLAYED` and never counts as activation.

## W. Assurance packs

Pack format with ID, version, archetype, claims, dependency proposals, observer requirements,
limitations, compatibility, author and status. Four packs, all `DRAFT`. Applying one declares
claims and queues proposals, approves nothing, and creates no observer.

## X. The Assurance Launch offer and kit

$12,000–15,000, four weeks, one workflow, one staging environment, three claims, one live source,
one qualified observer, the gate in WARN, one passport, one confirmed consequence, one restoration
cycle. The kit carries a qualification checklist, eight disqualifiers, a mutual action plan, six
success criteria, responsibilities, a week-by-week plan, the time-logging template, the observer
checklist, the claim workshop, the mapping review and the conversion review. Pricing experiments
at $10K/$15K/$20K are recorded with outcomes and reasons.

## Y. Pricing readiness

The ladder is unchanged. Business and Enterprise now carry `availability: contact`, render as
**Contact us**, and are excluded from self-service upgrade prompts. The entitlement mechanics are
untouched, so nothing about security truth or allowances changed.

## Z. Website and front-of-house

Change assurance is front of house; release integrity is the kernel beneath it. The Assurance
Launch replaces the Integrity Launch in public copy. CTAs: **Start free** (→ connect my own agent
or explore an example) and **Apply for an Assurance Launch**.

## AA. Brand and rename readiness

`BRAND_RENAME_IMPACT.md` classifies every binding as CONFIGURABLE, MIGRATABLE or HARD BINDING,
with the migration path for each and the order a rename must happen in. The passport issuer moved
behind `TV_TRUST_ISSUER` and the schema no longer pins the literal issuer name. **Nothing was
renamed and no name is proposed.**

## AB. Security hardening and adversarial review

Six findings found and fixed (passport over-disclosure, unconfirmed sharing, control characters,
path-looking reference ids, AI endpoint ordering, export coverage). Twenty-three boundaries
re-verified with the test that covers each. Seven accepted risks stated with what would change
them. Full detail: `docs/SECURITY_HARDENING_PRE_GCP.md`.

## AC. Passport privacy

Disclosure profiles at issuance (a signature covers exactly what it signs): `STANDARD` withholds
organization, system, environment and state identifiers, the decision id, resource names and
interface names, and carries a stable pseudonymous `system.reference` instead. Sharing requires
reviewing a preview and confirming it. Status recomputation reads identifiers from the record,
not the document. Old passports keep what they were signed with.

## AD. Supply chain, SBOM and build provenance

| Check | Tool | Result |
|---|---|---|
| Secrets, committable files only | gitleaks 8.30.1 | **0 findings** across 472 files |
| SBOM | syft 1.51.1 | 315 components (105 PyPI, 187 npm), CycloneDX 1.7 |
| Advisories | osv-scanner | **0 known vulnerabilities** across 276 locked packages |

**Accepted revision:** `ddd14f778941eb97912f75cd29c966ef98de1b4c` — the first commit in this
repository's history, 473 files, created after every gate in §AK was green. The repository has
**no remote and nothing has been pushed**; adding a remote is a founder decision.

`scripts/supply_chain.sh` reproduces all three. `/v1/build-info` reports source revision, image
digest, build time, migration head, applied schema, catalog version, claim-template version and
pack versions, with `UNKNOWN` where the deployment bound nothing. `Dockerfile.python` takes
`SOURCE_REVISION` and `BUILD_TIME`; Terraform passes the digest-pinned image as
`TV_IMAGE_DIGEST`. Reproducibility limits are stated honestly in `docs/SUPPLY_CHAIN.md`: the
dependency set and source are reproducible, image layers are not bit-for-bit, and signed build
provenance is not implemented.

## AE. Cloud cost instrumentation

Three standing labels plus a `component` label on every billable resource (web, api, broker,
launcher, runner, migration, data, evidence, images, secrets). A billing-export plan with three
standing queries, the unit-economics formula keyed to RPS rather than signups, four budget
dimensions, and what is deliberately not instrumented. `docs/COST_ATTRIBUTION.md`.

## AF. AI cost control

`ai_usage` records provider, model, feature, organization, system, tokens, latency, estimated
cost, result count and approval outcome. `/v1/measurements/ai-usage` reports per-feature totals,
the configured budget and month-to-date spend. A paid provider refuses to run without a budget
and stops at it. Zero is the normal answer.

## AG. Analytics privacy

Server-side, metadata only, per tenant, on request. No browser tracker, no third-party analytics,
no cross-customer aggregation, no prompts or tool output retained, no secret values from agent
definitions, hourly-bucketed reliance counters with bounded dimensions.
`docs/ANALYTICS_PRIVACY.md`.

## AH. Customer export and portability

Every tenant record kind is exportable — 103 kinds — with one documented exclusion
(`credential`, which names a secret-manager version). A source-scanning test fails if a new kind
is added without a decision. `docs/DATA_EXPORT.md`.

## AI. API, SDK and CLI experience

36 new endpoints. Python SDK gains propose-change, history replay, claims, guidance, templates,
feedback, observed effects, business measurement, disclosure preview and build info. The CLI gains
`propose-change`, `replay-config-history` (reading local git) and five operator commands.
`docs/API_EXAMPLES.md` shows curl, Python, TypeScript and CLI for every important path, with the
error and idempotency contract.

## AJ. Quickstart and failure UX

`docs/QUICKSTART.md` takes a stranger to a real answer about their own system in under fifteen
minutes, with the honest statement of what they have and do not have at the end. Nine named
failure states (`docs/FAILURE_STATES.md`) each say what ThreatVeil refuses to claim and the next
step, rendered in the workspace and available at `/v1/systems/{id}/guidance`.

---

## AK. Acceptance results

| Gate | Result |
|---|---|
| Python test suite | **693 passed, 0 failed, 0 errors, 0 skipped** (50.0 s) — 39 new tests this wave |
| Ruff | clean across `src`, `tests`, `scripts` |
| Strict TypeScript (`tsc --noEmit`) | clean |
| Terraform `validate` + `test` | **10 passed, 0 failed** |
| Container: web production build | passed |
| Container: TypeScript SDK | passed |
| Container: browser suite | **14 passed** (35.1 s), including the reviewed-disclosure share flow, the feedback control, the claim ladder, the mapping review and the proposed-change view |
| Container: canonical demonstration | completed: cleared → changed → consequence → re-proof → restored → gate → passport verified by an outsider before and after the change (`CURRENT` → `SUPERSEDED`, `authentic_after_change: true`) |
| Activation preflight | `configuration_ready=false`, `cloud_accepted=false`; database PASS; 11 external activation checks FAIL as expected |
| Supply chain | 0 secrets, 315-component SBOM, 0 advisories |
| Migration head | `0008` (applied and verified) |

**Normal Node toolchain: still unavailable on this machine.** There is no Node, pnpm or
Terraform on `PATH`. Strict TypeScript runs through the Node binary bundled with another
application; the production build, the browser suite, the SDK tests and the canonical
demonstration run inside Colima containers via `scripts/container_acceptance.sh`; Terraform runs
via its official container. This is a local environment limitation, reported rather than worked
around, and it is why the container harness is the acceptance gate of record.

### Specific acceptance tests the mandate required

| Required invariant | Test |
|---|---|
| Synthetic activity never counts as activation | `test_synthetic_consequences_are_shown_and_never_counted` |
| Confirm/dispute is append-only and tenant-isolated | `test_feedback_is_append_only_isolated_and_changes_no_conclusion` |
| A proposed change does not modify clearance | `test_proposed_change_answers_what_would_break_without_touching_clearance` |
| A declared claim is never supported without evidence | `test_templates_are_neutral_and_a_draft_is_never_a_claim` |
| Proposals do not influence assurance until approved | `test_a_mapping_proposal_changes_nothing_until_a_person_approves_it`, `test_ai_assistance_is_off_by_default_and_can_only_propose` |
| An unqualified observer cannot produce qualified evidence | `test_an_unqualified_observer_can_never_produce_qualified_evidence`, `test_an_unqualified_observer_cannot_be_made_to_speak` |
| Auto re-proof cannot widen scope | `test_auto_reproof_repeats_one_verification_and_can_never_widen_scope` |

## AL. Performance of the new hot paths

In-process against real PostgreSQL on the Finance fixture, 12 samples each:

| Path | p50 (ms) | p95 (ms) |
|---|---|---|
| `GET /systems/{id}/assurance/current` (gate) | 24.3 | 28.0 |
| `GET /systems/{id}/guidance` | 23.6 | 24.2 |
| `GET /systems/{id}/claims` (ladder) | 22.2 | 23.3 |
| `GET /systems/{id}/changes` | 24.2 | 25.2 |
| `GET /systems/{id}/consequence-feedback` | 2.5 | 6.5 |
| `GET /systems/{id}/mappings-overview` | 23.1 | 27.1 |
| `GET /systems/{id}/mapping-suggestions` | 22.5 | 23.0 |
| `GET /measurements/business` | 24.3 | 25.7 |
| `GET /measurements/activation` | 33.0 | 69.6 |
| `GET /measurements/ai-usage` | 2.9 | 5.1 |
| `GET /example-gallery` | 2.6 | 5.3 |
| `GET /claim-templates` | 2.5 | 3.9 |
| `POST /systems/{id}/proposed-changes` | 38.2 | 47.2 |
| `POST /systems/{id}/consequences/{id}/feedback` | 31.5 | 42.1 |

Reproduce with `uv run python scripts/performance_check.py`. Limitations: one tenant with a small
record set, in-process (no network or TLS), developer hardware. The measurement endpoints iterate
per system and per environment and are bounded at 50 systems and 5 environments; large-tenant
latency is not validated.

## AM. Prepared only, and deliberately not built

**Prepared only** (the seams exist; no integration was written): AWS AgentCore, Microsoft Agent
365 / Entra Agent ID, Google Vertex / ADK, the OpenAI platform, Anthropic managed settings, Okta,
a Salesforce observer, ServiceNow, Kubernetes admission, A2A, and delegation execution. Each
would arrive as a connector (`docs/CONNECTOR_CONTRACT.md`) or an observer
(`docs/BUSINESS_EFFECT_OBSERVER.md`), and neither contract needed to change to accommodate them.

**Deliberately not built:** a generic chatbot, an agent inventory product, firewalls, DLP, SIEM,
a SOC, red-teaming, model evaluations, GRC workflow, a trust score, a marketplace, automatic
remediation, cross-customer machine learning, twenty connectors, and a second vertical nobody has
validated.

---

## AN. The first thirty days after deployment — plan only

**Not executed.** This is the plan for after private GCP activation.

### Week 1 — activation and proof that it is real

| Day | Action | Done when |
|---|---|---|
| 1 | Apply Terraform to the private project; no public DNS | plan reviewed and applied; every resource carries its `component` label |
| 1 | Provision the operator signing key and publish the trust directory | `/v1/trust/keys` serves an operator-managed directory, not a derived one |
| 2 | Bind build provenance: `TV_SOURCE_REVISION`, `TV_BUILD_TIME`, `TV_IMAGE_DIGEST` | `/v1/build-info` reports no `UNKNOWN` |
| 2 | Run the activation preflight against the deployed configuration | `configuration_ready = true`; `cloud_accepted` still false until the external checks are demonstrated |
| 3 | Run the container acceptance suite against the deployed image | browser suite and canonical demonstration pass in the cloud |
| 3 | Demonstrate the external checks: delivered alert, budget alert, restore, rollback | each recorded with the artefact that proves it; only then `cloud_accepted = true` |
| 4 | Run the canonical demonstration end to end as an outside reviewer would | a passport verified from a machine with no account |
| 5 | Classify every existing organization; set the AI and auto-re-proof flags explicitly | `business-report` shows a clean classification split |

**Week 1 done when:** the deployment can say exactly what is running, an outside party can
verify a passport, and the founder's report runs against real data and reports zeros honestly.

### Week 2 — be the first customer

| Action | Why |
|---|---|
| Connect ThreatVeil's **own** repository and agent configuration as a protected system | dogfooding is the only free source of real changes |
| Declare three claims about our own agent tooling, approve the mappings | exercises the self-service path as a stranger would |
| Qualify one observer against our own PostgreSQL | the first qualified observer outside a test |
| Install the change-assurance check on our own pull requests in WARN | the first CI reliance, and the first `RELIED_UPON` week |
| Log every hour it takes, honestly | the first real onboarding-hours number |

**Week 2 done when:** ThreatVeil has one protected system that is watched, maintained and relied
upon — RPS = 1 — and we know how long it took.

### Week 3 — one design partner

| Action | Target |
|---|---|
| Qualify five prospects against the checklist, record every disqualification reason | 5 recorded, at least 2 disqualified on purpose |
| Make the Assurance Launch offer at $15,000 to the two best-qualified | 2 offers recorded with price and outcome |
| Run the claim workshop with whoever says yes | three claims in their business language |
| Get them to the proposed-change dry run on **their** configuration in the first session | their first real consequence, inside week 3 |

**Week 3 done when:** one signed Assurance Launch, or three recorded rejections with reasons
specific enough to change the offer.

### Week 4 — first confirmed consequence, then stop and read the numbers

| Action | Target |
|---|---|
| Connect their live source; qualify their observer | `NO_LIVE_SOURCE` and `NO_QUALIFIED_OBSERVER` cleared from guidance |
| Evaluate their first real change; get the answer confirmed | `FIRST_CONFIRMED_CONSEQUENCE` with `claim_basis: EVIDENCED` |
| Lose and restore clearance once | one completed cycle with a recorded restore time |
| Run the conversion review and the founder business report | hours, precision and RPS on real data |

**Day 30 decision gate — read these five numbers and nothing else:**

1. **RPS** — is it ≥ 1 and does it include someone other than us?
2. **Confirmed consequences** — how many, and what is `confirmed_rate` with its denominator?
3. **Onboarding hours** per activated organization — and is the trend down?
4. **Offers made / accepted, with reasons** — is the price the objection, or is it the value?
5. **Disputed consequences** — what did we get wrong, and is it a semantics bug or a contract bug?

**Then choose one, explicitly:** deepen the archetype that worked, fix the precision problem the
disputes revealed, or change the offer. Not all three.

### What must not happen in the first thirty days

- No new connectors, no second vertical, no new surface area before a customer asks twice.
- No enabling AI assistance or auto re-proof outside a sandbox.
- No marketing claim that outruns the evidence: no "validated archetype" without a
  `CUSTOMER_VALIDATED` pack, no certification language, no trust score.
- No synthetic number in any investor or customer material. Zero is a valid answer.

---

## Final strategic test

**"Has this wave made ThreatVeil more likely to become a scalable company, or merely larger
software?"**

Honestly: **both, and the split is knowable.**

The parts that make it more likely to be a **company**:

- It can now be adopted without us. A stranger can import a definition, declare a claim, and get
  a true answer about their own agent in minutes. That is the difference between a product and an
  engagement.
- It can now tell the truth about itself. Provenance separation, confirm/dispute, a determinate
  activation definition, precision with denominators, RPS, and staff hours per activated
  organization mean the next decision is a reading rather than a feeling. A company that cannot
  measure whether it is working cannot scale, however good the software is.
- The commercial loop is instrumented end to end — qualification, offer, price, reason,
  contract, kickoff, first confirmed consequence, hours, conversion — without a CRM and without
  fabricating anything.
- The fastest path to value no longer depends on waiting for a change or building a test harness:
  the proposed-change dry run makes the customer's own pending change the demonstration.

The parts that are **merely larger software** until a customer touches them:

- Four DRAFT assurance packs. One archetype hypothesis, zero validation.
- The auto re-proof foundation, which can only run in a sandbox because no qualified dispatcher
  exists.
- The AI seams, off by default and proposal-only.
- The read-only PostgreSQL observer, exercised against a test schema rather than a customer's
  ledger.

Those four are gated, labelled and cheap to carry, which is the point of having built them this
way. But they add no probability of success on their own.

**The decisive fact is unchanged.** Zero customers. Zero confirmed consequences on a real system.
RPS = 0. Every number in this report that matters commercially is zero, and the product now says
so instead of flattering itself.

So: this wave raised the ceiling and made the floor visible. It raises the probability of
becoming a scalable company **only if the next action is deployment and one design partner**. If
the next action is more building, this wave will have been the moment ThreatVeil chose to become
larger software instead.

**The next action is private GCP activation. Stop building.**
