# ThreatVeil — Product experience compression report

**Wave:** convert the category-complete assurance platform into a simple, contemporary
B2B SaaS product without weakening any assurance semantics.

**Classification on entry:** `READY_FOR_PRIVATE_GCP`
**Classification on exit:** `READY_FOR_PRIVATE_GCP`, `cloud_accepted = false`

---

## A. Executive result

The product now presents five verbs — **connect, watch, review, restore, share** — over
the same backend. Primary navigation went from **eleven product links plus a seventeen-item
Advanced group** to **four product destinations** (Home, Systems, Changes, Integrations)
and three utility links.

The internal ontology is no longer the navigation. System map, authority, claims, evidence
currency, re-establishment, clearance and the Passport are all still present, all still
exact, but each now lives on the object it describes: the protected system. The Assurance
Gate is contextual to a system rather than a destination. Re-establishment is a call to
action, not a section. The six-stage protection journey is one disclosure inside a
five-step setup checklist rather than a customer's first contact with the product.

Nothing was deleted. Every advanced route still resolves, and every retired product route
redirects to its canonical replacement.

**No backend assurance semantics changed.** One read-only, tenant-scoped aggregation
endpoint was added (`GET /v1/home`) because the alternative was one HTTP request per
protected system to render one screen. It concludes nothing new: it composes the same
per-system projections the system workspace already renders.

**One real defect was found and fixed during the wave**: a system with no baseline was
being filed under "current". It is now always an attention item, because ThreatVeil has
established nothing about it. That is a semantics *tightening*, not a loosening.

| Suite | Before | After |
|---|---|---|
| Python tests | 693 passed | **696 passed** (3 new Home tests) |
| Browser tests | 14 passed | **19 passed** (5 new, 1 superseded) |
| Strict TypeScript | clean | clean |
| Web production build | passing | passing (container) |
| TypeScript SDK | passing | passing (container) |
| Terraform validate + tests | 10 passed | **10 passed** |
| Canonical demonstration | passing | passing (container) |
| `ruff check src tests migrations scripts` | clean | clean |

---

## B. UX problems found

1. **The navigation was the domain model.** Eleven primary links named internal concepts
   (*System map*, *What it can do*, *What still holds*, *Re-establish*, *Clearance*,
   *Passport*, *Sources*). A customer had to learn the ontology before getting an answer.
2. **No operating centre.** `/app` showed one system's summary — chosen implicitly as the
   first in the list. With more than one system there was no way to see which one needed
   attention without opening each in turn.
3. **Onboarding appeared in at least four places**: `Onboarding` in the intelligence
   module, `NoSystems` + `SandboxCard` in change assurance, the `demo-banner` on the
   overview, and the six-stage journey banner. A new customer met four different framings
   of the same product.
4. **The six-stage workflow was the first mental model.** *System & source → Authority →
   Claims → Baseline → Watch → Decide* is internally coherent and cognitively expensive as
   a first contact.
5. **Global pages needed an implicit system.** Every intelligence view carried its own
   "Protected system" dropdown, repeated on eleven pages, with no shared selection.
   Switching system on one page did not switch it on the next.
6. **Status was scattered.** Clearance had its own destination; the status of a system was
   not visible from the list of systems.
7. **Re-establishment was a place, not an action.** The customer had to know to browse to
   it.
8. **A seventeen-item Advanced group** sat in ordinary product navigation, including
   internal and demonstration surfaces.
9. **Terminology leaked**: *Approved properties*, *Verification units*, *Evidence
   Currency*, *Re-establish*, raw canonical enum values rendered as badges.
10. **Equal visual weight everywhere.** Most screens offered four to six equally weighted
    actions and no dominant one.
11. **The proposed-change form exposed an internal payload shape.** For an
    agent-definition source it required a `{format, document}` envelope the customer had no
    way to know about; pasting the actual file produced an error.

---

## C. Old information architecture

```
Workspace
├── SYSTEM
│   ├── Systems                /app
│   ├── System map             /app/map
│   └── What it can do         /app/authority
├── ASSURANCE
│   ├── Claims                 /app/claims
│   ├── What changed           /app/changes
│   ├── What would break       /app/propose
│   ├── What still holds       /app/holds
│   ├── Re-establish           /app/reestablish
│   └── Clearance              /app/decisions
├── EVIDENCE
│   ├── Passport               /app/passport
│   ├── Sources                /app/sources
│   ├── Dependency mapping     /app/mappings
│   └── Records                /app/records
├── ▸ Advanced (17 items)
│   Protection journey · Releases · System register · Security properties ·
│   Authorized targets · Findings · Execution history · Evidence ledger ·
│   Verified fixes · Regressions · Procurement demonstration · Integrity Launch ·
│   Integrations · Reports · Change explorer · Schedules · Property reuse
└── Plan & usage · Settings · Documentation
```

**28 links in ordinary product navigation.**

---

## D. New information architecture

```
THREATVEIL
├── Home                       /app
├── Systems                    /app/systems
├── Changes                    /app/changes
├── Integrations               /app/integrations
├──────────────────────────────
├── Usage & billing            /app/billing
├── Settings                   /app/settings   (+ Developer tools)
└── Documentation              /docs
```

**4 core product destinations. 7 links in total.**

The protected system is the core product object, with one canonical layout:

```
/app/systems/{id}                 Overview      ← status, reason, one next action
/app/systems/{id}/capabilities    Capabilities  (was: What it can do)
/app/systems/{id}/claims          Security claims
/app/systems/{id}/evidence        Evidence      (was: What still holds + Sources + mapping)
/app/systems/{id}/activity        Activity      (was: What changed + Clearance lifecycle)
/app/systems/{id}/share           Share         (was: Passport)

contextual, reached from a call to action, never a tab:
/app/systems/{id}/map             System map
/app/systems/{id}/restore         Restore assurance
/app/systems/{id}/setup           Verified assurance setup
```

---

## E. Route migration map

Every former product route redirects on load, resolving the intended system from the URL,
then the selected system, then the first system. Covered by **Journey F**.

| Former route | Now | Disposition |
|---|---|---|
| `/app/overview` | `/app` | redirect |
| `/app/map`, `/app/map/{id}` | `/app/systems/{id}/map` | redirect |
| `/app/authority` | `/app/systems/{id}/capabilities` | redirect |
| `/app/claims` | `/app/systems/{id}/claims` | redirect |
| `/app/holds` | `/app/systems/{id}/evidence` | redirect |
| `/app/mappings` | `/app/systems/{id}/evidence` → Dependency mapping | redirect |
| `/app/reestablish`, `/app/reestablish/{id}` | `/app/systems/{id}/restore` | redirect |
| `/app/decisions`, `/app/decisions/{id}` | `/app/systems/{id}` | redirect |
| `/app/passport`, `/app/passport/{id}` | `/app/systems/{id}/share` | redirect |
| `/app/assurance`, `/app/assurance/{id}` | `/app/systems/{id}/setup` | redirect |
| `/app/sources` | `/app/integrations` | redirect |
| `/app/propose` | `/app/changes/propose` | redirect |
| `/app/changes` | `/app/changes` | **rebuilt** as the global workflow |
| `/app/systems` | `/app/systems` | **rebuilt** as the customer inventory |
| `/app/records` | unchanged | kept; reached from Share and Developer tools |
| every other Advanced route | unchanged | kept; reached from Settings → Developer tools |
| `/passport/{token}` (public) | unchanged | untouched |

When no system exists, a system-scoped legacy route redirects to `/app/systems` rather
than 404.

---

## F. Home

`/app` is a prioritized work queue, not a dashboard. It answers **what needs my
attention?** and works for zero, one and many systems.

- **Attention summary** — `1 system needs attention · 2 claims need fresh evidence ·
  1 dependency mapping awaiting review`.
- **Needs attention** — one card per system, each answering *system / what happened / why
  it matters / next action*, with the clearance status as a pill and the change headline
  as the reason. The next action is a single dominant button.
- **Current systems** — a quiet list: name, last-current timestamp, status.
- **Recent activity** — meaningful events only: change detected, assurance restored,
  assurance not established, Passport issued. Chronological, tinted by outcome.
- **Quick actions** — *Check a proposed change*, *Connect a system*.

A system enters **Needs attention** when its clearance is `NEEDS_REASSESSMENT`,
`NOT_CLEARED` or `REVOKED`, when it has an open change, when a claim needs fresh evidence
or failed, **or when it has no baseline at all**. It is never filed as current on the
strength of an absence.

Data comes from one request: `GET /v1/home`.

## G. Systems

A clean inventory. Each row carries name, environment and purpose, status pill, claim
counts (`4 current · 1 needs fresh evidence`), the last meaningful change with its
timestamp, live source coverage, and the next action. One primary action at the top:
**Connect system**. No template gallery once real systems exist.

**Empty state:** *"No systems connected."* → **Connect your first system**.

## H. System detail

One canonical layout. A named region (`System status`) carries:

- system name and a large status pill (`Cleared`, `Needs attention`, `Not cleared`,
  `Revoked`, `Not set up yet`), with the canonical clearance state in its `title`;
- environment, purpose, synthetic label, and the decision status (`Current`, `Superseded
  by a later change`, `Expired`, …);
- the plain-language reason, taken from the same projection the backend computes;
- the system switcher (only when more than one system exists);
- **one** contextual primary action.

The primary action is chosen in priority order and never points at the tab you are already
reading, so the change review offers **Restore assurance** rather than pointing at itself:

```
no decision            → Set up assurance
open change            → Review change → Restore assurance → Review required evidence
attention              → Restore assurance → Review required evidence
claims need evidence   → Review required evidence → Restore assurance
otherwise              → Share current assurance
```

Six tabs, one snapshot: the whole system workspace loads `GET /v1/systems/{id}/intelligence`
once and distributes it, so no tab can disagree with the header.

## I. Capabilities

*"What this system is currently able to do and the authority behind it."*

The existing Authority Map and Authority Diff, unchanged in substance: action, resources,
principal/identity, environment, tool/interface, conditions, governing claims, source
epoch, review freshness, and each authority's current assurance status. Declared,
connected, observed and verified stay distinct. A tool a source reports is still never
treated as a granted permission. Interfaces outside the declared boundary are still called
out. The Authority Diff sits directly beneath, with before → after per subject and the
expansion/contraction/equivalent/unknown classification preserved exactly.

## J. Security claims

Customer-facing title **Security claims**, subtitled *"The conditions that must remain true
for this system to stay assured."* The word "guarantees" is not used anywhere.

The canonical four-level progression is translated for display only:

| Canonical | Shown as |
|---|---|
| `DECLARED` | Defined |
| `NOT_YET_VERIFIED` | Needs evidence |
| `QUALIFIED` | Ready to verify |
| `CURRENT` | Current |

Every count tile and every claim badge carries `title="Canonical status: …"`, and the
principle line still prints the canonical names verbatim: *"DECLARED, NOT_YET_VERIFIED,
QUALIFIED and CURRENT are different states and are never merged."* The claim builder is
unchanged.

**Empty state:** *"No claims defined."* → start from a reviewed pattern.

## K. Evidence

Combines evidence currency, sources and observers, and dependency mapping.

- **Evidence status** (was *Evidence Currency*) — current / needs fresh evidence / failed
  verification / not yet supported, each tile carrying its canonical statuses in `title`.
- **Claim by claim** — *"What still holds, and why."* Per claim: what it governs, what it
  depends on, the forbidden outcome, the work that must keep succeeding, the last
  verification, when its evidence was produced and whether that was for this state, and
  which change affected it. "Why ThreatVeil concluded this" stays an expandable detail.
- **Sources and observers** — *"A connection is not an observation."* Each source with its
  status, freshness, whether it is live, and its coverage limitations.
- **Dependency mapping** behind a disclosure, mounted only when opened.

**Empty state:** *"No evidence established."* → **Establish verified assurance**.

## L. Activity

The system's chronological record: every change with its consequence (what moved, where it
came from, which way authority moved, which claims are affected, which still hold, what
must be re-established), the fixed-template narrative, the "was this right?" feedback
control, the clearance lifecycle, and historical assurance memory.

The Assurance Gate block is **not** repeated here — Overview owns machine use — so the two
tabs no longer show the same object twice.

**Empty state:** *"No changes detected yet."* → **Check a proposed change**.

## M. Share / Passport

*"Share current assurance"* — a signed statement about the system that exists today, and a
separate check of whether it is still true.

Issue, preview disclosure, confirm, share, download signed JSON, and verify authenticity in
the browser — all unchanged. **The disclosure preview and its explicit confirmation are
untouched**: sharing still requires reviewing exactly what leaves the organization, and the
withheld fields are still listed. Signed records, the scoped report exports and the
published trust root sit behind a secondary disclosure.

**Empty state:** *"No current Passport."* — and the issue form is only offered when a
system state exists to describe.

## N. Changes

One global workflow with two views.

- **Detected** — observed changes across every protected system, newest first, each with
  its system, the authority movement, the canonical effect, how many claims are affected
  and how many still hold, and **Review change**. A checkbox includes changes already
  covered by later verification.
- **Proposed checks** — the check itself plus every earlier evaluation, each labelled
  *"None of them is current state."*

Primary action at the top of both: **Check a proposed change**.

## O. Proposed-change experience

The screen answers *can I ship this?*

```
PROPOSED · NON-ACTIVE · NOT CURRENT STATE
<headline>
[effect] [authority movement] check <conclusion> · WARN · not blocking

✓ Unchanged — this change has not been activated. Current assurance is CLEARED.
  If it were shipped and nothing else changed, it would become NEEDS_REASSESSMENT.

Potential impact
  AFFECTED CLAIMS | UNAFFECTED CLAIMS | EVIDENCE THAT WOULD NEED RE-ESTABLISHING
  DECLARED CLAIMS REACHED (needs evidence — ThreatVeil holds none for it yet)

IF SHIPPED
  numbered explanation · the check body a CI step would publish · limitations
```

The dry run still mutates nothing. The unchanged-assurance statement is asserted by
Journey A.

**One substantive fix:** the form is now connector-aware. For an agent-definition source it
offers the definition format and wraps the pasted file itself, so a customer pastes the
file they are about to ship rather than an internal envelope.

## P. Contextual restore-assurance flow

`Restore assurance` has no global link. It is reached from:

- a Home attention item's primary action;
- the system header's primary action;
- the change review (the header falls through to it);
- the demonstration panel.

It renders the existing re-establishment plan unchanged: what must be re-established, the
latest verification outcome, the ordered steps, and the re-proof controls. The engine, the
rule that clearance returns only when the forbidden outcome is prevented *and* the
legitimate task still succeeds, and the statement that ThreatVeil never changes your system
or proposes a remediation to it, are all unchanged.

## Q. Integrations

Built from the connector catalogue, so only connectors that are actually implemented
appear, each with the modes it really supports:

| Category | Connectors |
|---|---|
| Code & configuration | GitHub · Agent definition import · CycloneDX import · SARIF import |
| Agent protocols | Bounded MCP · OpenAI Agents import · Anthropic hooks import |
| Cloud | GCP Cloud Run |
| Evidence & system of record | OpenTelemetry |
| CI & enforcement consumers | Assurance Gate · GitHub checks |

States are derived from real installation health: **Connected** / **Imported** /
**No observation yet** / **Needs attention** / **Expired** / **Revoked**, or **Available**
when nothing is installed. Each card states plainly whether ThreatVeil reads the source
itself or the customer sends a snapshot, what facts it supplies, and its coverage
limitations. There are no placeholder connectors and no future seams presented as
available.

**Empty state:** *"Nothing is watching your systems yet."*

## R. Onboarding

One onboarding experience, on Home, and nowhere else.

```
Find out what an AI-agent change would affect.

Connect your AI system. ThreatVeil watches what changes, tells you which security
claims are affected, helps you restore current assurance, and lets your pipeline or
customer verify the result.

[Connect my system]   [Explore an example]

1. Connect your AI system.
2. Define what must stay true.
3. Check a proposed change.
```

The three steps are a real path, asserted end to end by Journey A: connect a system with a
pasted `settings.json` → land on Security claims → build and save one claim → check a
proposed change and get a claim-level answer. **Journey A also asserts that the onboarding
headline does not appear on `/app/changes`, `/app/integrations` or `/app/billing`.**

*Explore an example* reveals the gallery: the Finance Agent card labelled
`RUNNABLE · SYNTHETIC DATA ONLY` alongside the four DRAFT packs labelled
`TEMPLATE · NOT RUNNABLE · NOT VERIFIED FOR YOUR SYSTEM`. Only the Finance card runs.

Verified assurance is a separate, later flow (§22): a five-step checklist scoped to one
system — connect an evidence source, define what must stay true, qualify an observer,
establish a baseline, watch and restore — with the full six-stage workflow behind
*Advanced setup*, mounted only when opened so it always reads current records.

## S. Advanced / developer tools disposition

The Advanced group is gone from ordinary navigation. Every route is retained at its
existing URL and indexed under **Settings → Developer tools**.

| Former Advanced route | Classification | Disposition |
|---|---|---|
| `/app/assurance` — Protection journey | C. duplicate | → `/app/systems/{id}/setup`, and the workflow itself is the Advanced setup disclosure |
| `/app/systems` — System register | C. duplicate | superseded by the customer inventory at the same URL |
| `/app/properties` — Security properties | A. developer | Developer tools → Verification |
| `/app/targets` — Authorized targets | A. developer | Developer tools → Verification |
| `/app/runs`, `/app/runs/{id}` — Execution history | A. developer | Developer tools → Verification; run deep links unchanged |
| `/app/evidence` — Evidence ledger | A. developer | Developer tools → Verification |
| `/app/schedules` — Schedules | A. developer | Developer tools → Verification |
| `/app/findings` — Findings | A. developer | Developer tools → Security memory |
| `/app/fixes` — Verified fixes | A. developer | Developer tools → Security memory |
| `/app/regressions` — Regressions | A. developer | Developer tools → Security memory |
| `/app/propagation` — Property reuse | D. customer-useful | Developer tools → Security memory |
| `/app/impact` — Change explorer | A. developer | Developer tools → Release integrity |
| `/app/releases` — Releases | A. developer | Developer tools → Release integrity |
| `/app/records` — Records | D. customer-useful | Developer tools → Release integrity, **and** linked from Share |
| `/app/reports` — Reports | D. customer-useful | Developer tools → Release integrity, **and** exported from Share |
| `/app/gauntlet` — Integrity Launch | D. customer-useful | Developer tools → Engagements |
| `/app/demo` — Procurement demonstration | B. internal/demo | Developer tools → Engagements |
| `/app/integrations` — old panel | C. duplicate (split) | customer-facing part → new Integrations page; API tokens, qualified observation sources, GitHub workflow bindings and the CLI snippet → Settings |

**Regression found and fixed during the wave:** replacing `/app/integrations` initially
orphaned the API token manager and the observer manager. They are now rendered on Settings
as `DeveloperAccess`, and `tests/commercial-loop.spec.ts` exercises the token
issue/revoke and observer registration path there.

## T. Terminology changes

| Was | Now | Canonical value |
|---|---|---|
| Evidence Currency | Evidence status | unchanged |
| Approved properties | Security claims | `property` records unchanged |
| Verification units | Monthly verification capacity | units still the accounting unit, explained in place and in a tooltip |
| Re-establish | Restore assurance / Re-verify | `RE_ESTABLISH` obligation unchanged |
| Claims | Security claims | unchanged |
| What it can do | Capabilities | authority model unchanged |
| What still holds | Evidence → "What still holds, and why." | unchanged |
| Clearance (destination) | a status shown everywhere | `CLEARED` / `NEEDS_REASSESSMENT` / `NOT_CLEARED` / `REVOKED` / `NOT_ESTABLISHED` unchanged |
| `DECLARED` / `NOT_YET_VERIFIED` / `QUALIFIED` / `CURRENT` | Defined / Needs evidence / Ready to verify / Current | unchanged, shown in `title` |
| `SUPPORTED` / `NEEDS_FRESH_EVIDENCE` / `FAILED` / `UNKNOWN` | Current / Needs fresh evidence / Failed / Not yet supported | unchanged, shown in `title` |

No API field, record kind, enum value or record payload was renamed. This is UI
translation only.

## U. Pricing-page copy changes

Prices, plan names, entitlements and entitlement logic are **unchanged**. Business and
Enterprise remain *Contact us*. No plan-name conditionals were introduced.

- "5 approved properties" → "5 security claims"
- "1,000 monthly verification units" → "1,000 monthly verification capacity", with
  `title="Verification units: one unit per planned trial in a bounded execution."`
- Usage meters: "Approved properties" → "Security claims"; "Verification units" → "Monthly
  verification capacity"
- The accounting note now defines the unit in plain language before using it.
- "Real value from Free" now names checking a proposed change, which is what Free actually
  delivers first.

## V. Empty and failure states

Every canonical surface has a purposeful empty state with one action and no internal
vocabulary: Systems, Changes (detected), Security claims, Evidence, Share, Integrations,
Home, and the proposed-change form when no system or no source exists.

Failure states use the existing guidance semantics unchanged. Each one names what it means,
**what ThreatVeil will not claim while it holds**, and the next step, with severity shown
as a pill carrying the canonical code:

| Code | Severity | ThreatVeil will not claim |
|---|---|---|
| `NO_LIVE_SOURCE` | limits scope | that it is watching this system |
| `SOURCE_OUTAGE` | limits scope | that a gap means nothing changed |
| `BASELINE_MISSING` | blocking | anything a change could invalidate |
| `UNMAPPED_CHANGE` | limits scope | that an unnamed fact is harmless |
| `NO_QUALIFIED_OBSERVER` | blocking | that missing evidence means no effect |
| `CLAIM_NOT_EXECUTABLE` | limits scope | that a declared claim is supported |
| `EVIDENCE_STALE` | blocking | that a historical pass is a current pass |
| `CLEARANCE_EXPIRED` | blocking | that an expired clearance speaks for now |
| `PASSPORT_AUTHENTIC_BUT_SUPERSEDED` | informational | that authenticity is current status |

The security-passed / useful-task-failed case still reads *"Security held, but useful work
broke: not cleared."* and is asserted by two browser tests.

## W. Accessibility

`tests/accessibility.spec.ts` audits twelve canonical surfaces and asserts, on each:

- every visible interactive control has an accessible name;
- no heading level is skipped;
- exactly one `main` landmark;
- every `nav` landmark is named when more than one is present;
- every status element carries text, so status is never conveyed by colour alone.

Plus: the skip link is the first tab stop and reaches `#main`; system tabs are links, so
they are focusable and activated with Enter; the system switcher opens with Enter, exposes
`role="listbox"` with `aria-selected`, and closes with Escape.

Improvements made:

- the system header is a named `region` (`System status`), so a screen reader can land on
  the status directly;
- status pills pair a shape (icon) and a word with the colour, and carry the canonical
  value in `title` plus an `sr-only` span;
- `aria-current="page"` on the active primary nav item and the active system tab;
- checklist steps announce "Complete" / "Not complete" to screen readers rather than
  relying on the tick;
- `aria-label` on the attention summary, the system-at-a-glance grid, quick actions,
  integration summary and each nav landmark;
- a real `.sr-only` utility was added to `globals.css`;
- focus outlines, the skip link and the existing keyboard behaviour are unchanged.

## X. Browser acceptance

19 browser tests, all passing.

| Journey | Test |
|---|---|
| **A — new user** | `product-experience.spec.ts` — four primary links and no retired ones; one onboarding experience with three steps; the headline appears on no other route; connect with a pasted `settings.json`; define one claim (stays *Needs evidence*); check a proposed change; affected/unaffected/re-establishment groups and the unchanged-assurance statement |
| **B — existing current system** | `product-experience.spec.ts` — Home shows it current; header shows `Cleared` with its reason; `3 of 3`; all five tabs open, keep system context and set `aria-current`; the system map is reached from Overview |
| **C — system needs attention** | `assurance-intelligence.spec.ts` — a gateway change; Home shows the attention item with the change headline; **Review change** opens the review; affected claim, two still supported, `NEEDS FRESH EVIDENCE`; authority expansion on Capabilities; **Restore assurance**; security failure → broken useful work → restored; back to `Cleared` |
| **D — Passport** | `assurance-intelligence.spec.ts` — issue, preview disclosure, confirm, share; an outside browser verifies authenticity and reads *Still current*; the system changes again; the passport stays authentic and reads *Superseded by a later change* |
| **E — multiple systems** | `product-experience.spec.ts` — `1 system needs attention`; the system with no baseline is the attention item and the cleared one is not; its next action opens setup; the switcher moves context and keeps the tab; a reload keeps the URL |
| **F — legacy URL** | `product-experience.spec.ts` — 14 legacy routes land on their canonical replacement; Settings → Developer tools → Execution history |
| Accessibility | `accessibility.spec.ts` |
| Assurance semantics | `change-assurance.spec.ts` — BLOCK on security failure, no activation offered when the useful task fails, acknowledged sandbox activation, signed DSSE export; trust root |
| Commercial & release | `commercial-loop.spec.ts` (7), `commercial-platform.spec.ts` (2), `release-integrity.spec.ts` (2) |

Mobile: every journey ends by asserting `document.documentElement.scrollWidth <=
innerWidth + 1` at 390 × 844.

## Y. Full regression

| Suite | Command | Result |
|---|---|---|
| Python | `TV_ENV=test uv run pytest` | **696 passed** |
| Lint | `ruff check src tests migrations scripts` | clean |
| TypeScript | `pnpm typecheck` (strict) | clean |
| Browser | `pnpm --filter @threatveil/web test` | **19 passed** |
| Terraform | `terraform validate` + `terraform test` | valid, **10 passed** |
| Web production build | container acceptance | passed |
| TypeScript SDK | container acceptance | passed |
| Canonical demonstration | container acceptance | passed |
| Performance | `scripts/performance_check.py` | see below |

Container acceptance (`scripts/container_acceptance.sh`) runs the production web build, the
SDK, the whole browser suite and the canonical demonstration against a real PostgreSQL 17
with a non-superuser `NOBYPASSRLS` runtime role, in isolated containers.

### Performance

Measured in-process against real PostgreSQL, one tenant with the synthetic Finance system
(three claims, evidence, one change), 12 samples:

| Path | p50 | p95 |
|---|---|---|
| `GET /v1/home` (the attention queue) | 22.9 ms | 25.2 ms |
| `GET /v1/systems/{id}/intelligence` (system workspace) | 25.2 ms | 29.6 ms |
| `GET /v1/systems/{id}/assurance/current` (gate) | 21.1 ms | 22.3 ms |

Home is one read for the whole organization; the system workspace is one read for every
tab. Both are in line with the endpoints that already existed. `/v1/home` loads at most 25
systems per request and reports `truncated` when more exist. As with the rest of this
harness, latency grows with history and these are a regression signal on one developer
machine, not a capacity model.

## Z. Route inventory of the finished canonical experience

Screenshots captured at 1440 × 1000 against the running application:

| Route | Screenshot |
|---|---|
| `/app` (zero state) | `ux-home-zero.png` |
| `/app` (all current) | `ux-home-current.png` |
| `/app` (needs attention) | `ux-home-attention.png`, `canonical-attention.png` |
| `/app/systems` | inventory with status, claims, last change, source coverage |
| `/app/systems/new` | connect: name, purpose, environment, boundary, access/actions, definition import |
| `/app/systems/{id}` | `ux-system-overview.png`, `canonical-cleared.png` |
| `/app/systems/{id}/capabilities` | `canonical-authority-diff.png` |
| `/app/systems/{id}/claims` | four levels, canonical names retained, claim builder |
| `/app/systems/{id}/evidence` | evidence status, claim by claim, sources, dependency mapping |
| `/app/systems/{id}/activity` | `canonical-change-review.png` |
| `/app/systems/{id}/share` | `canonical-disclosure.png`, `canonical-passport-superseded.png` |
| `/app/systems/{id}/map` | secondary visualization |
| `/app/systems/{id}/restore` | contextual restore plan |
| `/app/systems/{id}/setup` | five-step checklist + advanced disclosure |
| `/app/changes` | detected changes across systems |
| `/app/changes/propose` | `ux-proposed-change.png` |
| `/app/integrations` | five categories over the real connector catalogue |
| `/app/billing` | plan, capacity meters, history |
| `/app/settings` | organization, members, Developer tools index, machine access |
| `/passport/{token}` | public verification, unchanged |
| `/`, `/product`, `/pricing`, `/security`, `/docs`, `/contact` | public site; `/docs` rewritten to the three-step model |

Screenshots are written to `.local/browser-tests/` by the acceptance suite.

## AA. What was deliberately not changed

- **No backend assurance semantics.** No change to clearance computation, evidence
  applicability, authority classification, observer qualification, decision recomputation,
  state binding, the Gate contract, Passport disclosure or revocation, or
  proposed-change non-mutation.
- **No security or privacy invariant.** Tenant isolation, FORCE RLS, append-only history,
  `UNKNOWN` semantics, billing/security separation, sandbox isolation and the AI
  proposal-only boundary are untouched. The Passport disclosure confirmation step is
  intact.
- **No pricing.** No price, plan name, entitlement value or entitlement mechanism changed.
- **No new capability.** No connector, observer, AI feature, trust score, analytics
  product, remediation capability or security feature was added.
- **No deletion of mature functionality.** Every Advanced surface still exists at its URL.
  The one component removed is the duplicate design-partner claim form under Capabilities;
  claim definition is unchanged and lives in the claim builder on Security claims, which
  posts to the same `POST /v1/systems/{id}/claim-definitions` endpoint.
- **The brand.** The restrained ThreatVeil palette, type and tone are unchanged; only
  hierarchy, density and status prominence moved.
- **The six-stage workflow.** Retained in full as the advanced setup.
- **The public marketing site**, apart from the `/docs` steps.
- **`release-integrity.spec.ts`** needed no change: those routes were already developer
  surfaces and kept their URLs.

## AB. Remaining UX debt

1. **The Settings page is long.** Organization, members, invitation, Developer tools index
   and machine access are stacked on one route. A future wave could split machine access
   onto `/app/settings/developer`.
2. **The capability → claim bridge is a link, not a prefill.** Defining a claim from
   Capabilities now sends the customer to the claim builder rather than prefilling the
   action they were looking at. Carrying the action across would be a small, clear win.
3. **The system map is a five-column grid.** It is horizontally scrollable and legible on a
   laptop, but it is dense at tablet width and was not redesigned in this wave.
4. **Home caps at 25 systems** and reports `truncated`. There is no paging in the UI yet —
   correct for a design-partner scale, not for hundreds of systems.
5. **Activity has no filter.** It shows every recorded change for the system with one
   "include covered changes" toggle; a large history would want filtering by source or
   claim.
6. **The proposed-change form takes pasted JSON.** A file picker and a GitHub PR picker
   would both be better, and both are out of scope here (no new connector work).
7. **`workspace-parts.tsx` and `intelligence.tsx` remain dense single-line-style files.**
   They were refactored where the wave touched them, not rewritten.
8. **No dedicated tablet layout.** Desktop and laptop are the design targets; the sidebar
   collapses and tabs scroll below 900px, and no page scrolls horizontally at 390px, but
   the tablet range was not specifically tuned.

## AC. Final status

```
READY_FOR_PRIVATE_GCP
cloud_accepted = false
```

Nothing was deployed. No cloud resource was created, no provider was called, and no
external system was contacted. The next action is unchanged:

**PRIVATE GCP ACTIVATION.**

---

### Verification

```sh
TV_ENV=test uv run pytest                    # 696 passed
uv run ruff check src tests migrations scripts
pnpm typecheck                               # strict, clean
pnpm --filter @threatveil/web test           # 19 passed
(cd infra && terraform validate && terraform test)   # 10 passed
bash scripts/container_acceptance.sh         # build + SDK + browser + canonical demo
uv run python scripts/performance_check.py
```
