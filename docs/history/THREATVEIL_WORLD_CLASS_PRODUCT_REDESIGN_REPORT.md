# ThreatVeil — World-class product redesign report

**Date:** 2026-09-13
**Classification on entry:** `READY_FOR_PRIVATE_GCP`, `cloud_accepted = false`
**Scope:** product experience only. No assurance semantics, connectors, observers, pricing or AI capability were added or changed.

The one backend addition is `POST /v1/connectors/definition-preview`: a read-only, non-persisting call to the parser the import path already uses, so onboarding can show what a definition declares before anything is created (§P).

---

## A. Actual-browser audit

The running build was treated as the source of truth (mandate §0). A production web build and the API were run against PostgreSQL 17 in containers, and a scripted Playwright walk captured **51 full-page screenshots** across every customer route and state: marketing, login, Home (zero / one system / current), Systems, onboarding, every System tab (fresh, cleared, attention), setup, restore, map, Changes (detected, proposed form, proposed result), Integrations, Billing, Settings, six developer surfaces, and mobile. They are kept in `.local/redesign/before/` (git-ignored), with per-screen DOM measurements in `notes.md`.

What the browser actually showed:

| Surface | Measured | What a customer met |
|---|---|---|
| Home — zero state | 1000px | A marketing hero inside the product: uppercase eyebrow, 38px headline, explanatory paragraph, three decorative numbered cards. |
| Home — with systems | 1000px | **Good.** An attention summary, an attention row with what / why / action, a timeline. The closest surface to the target. |
| System — Overview (not set up) | **2021px** | Five fact tiles, three of them reading `0`, `0 of 3` or `—`; three large "limitations" cards with red **BLOCKING VALUE** badges; a six-card "canonical demonstration" grid; a machine-use card; an upsell panel. |
| System — Overview (**cleared**) | **2021px** | The header said **CLEARED** while a red **BLOCKING VALUE** card sat directly below it, followed by two stacked "See Pro" upsell rows. It failed the five-second test: is this system fine or not? |
| System — Claims | 1326px | Raw enum names as body copy ("DECLARED, NOT_YET_VERIFIED, QUALIFIED and CURRENT are different states and are never merged."), four count tiles (three zero), run-on claim lines with `permissions:finance-approval` inline. |
| System — Evidence | 1851px, 7 card blocks, 6 eyebrows | Four count tiles, raw `INCONCLUSIVE` / `UNKNOWN` enums, identifier chips at the second level of the hierarchy. |
| System — Activity | 1530px | The answer ("No open change.") was one line inside the first card; below it, **seven "Not yet" lifecycle cards**, four zero-memory tiles and a table of zeros. |
| Changes — proposed check | 1014px form, **1906px** with result | A five-field form with a JSON textarea stayed open above the answer. The before→after of the moved field appeared only as sentence 2 of a numbered list near the bottom. |
| Onboarding | 1201px | Six manual fields first — name, purpose, environment, boundary, access, actions — with **"Import a definition file now (recommended)" collapsed below them**. |
| Settings | **3933px**, 19 card blocks, 9 eyebrows | The longest screen in the product. |
| Mobile — System | **3683px** | The desktop stack, linearised. |

Design-system measurements on entry: the whole product was set in **Arial**; the CSS carried 12 distinct border radii (3–20px), dozens of near-identical literal greens and greys as border colours, and 44 distinct font sizes from 7px to 75px. Workspace chrome text ran at 7–11px (the environment badge was 7px uppercase).

## B. Differences between the previous report and the actual UI

The previous wave (`THREATVEIL_PRODUCT_EXPERIENCE_COMPRESSION_REPORT.md`) is accurate about what it changed and optimistic about what that achieved.

| Previous report | Browser reality |
|---|---|
| Primary navigation reduced to Home / Systems / Changes / Integrations; retired links gone. | **True.** The sidebar matched §16 on entry. The mandate's premise that the release-integrity sidebar was still visible did not hold. |
| Developer tools moved behind Settings. | **True.** |
| Home rebuilt as "what needs my attention?". | **Largely true** once a system exists. The zero state still marketed ThreatVeil. |
| "System detail: status, reason, one next action." | The **header** did this. The body beneath it did not: it was the densest, longest, most enum-heavy surface in the product, and on a cleared system it contradicted the header. |
| "One onboarding experience… connect with a pasted settings.json." | One *place* for onboarding — but the flow itself was manual-form-first, with import hidden. |
| Proposed-change experience rebuilt. | Rebuilt as a form with a result appended beneath it. No diff was rendered, although the API returns one. |
| Density, hierarchy and status prominence "moved". | Hierarchy moved in the header and on Home. Density did not: zero tiles, stacked cards and 2000px screens remained. No design-system or typography work had been done. |

The earlier wave compressed the **information architecture**. It did not reach the **object** (the System body), the **hero workflow** (the proposed-change review), the **import flow**, or the **design system**. This wave was aimed at exactly those.

## C. Competitive / reference product study

Each reference product was studied through its own published documentation, looking for interaction principles rather than layout or branding. Nothing below copies a proprietary layout, visual asset or brand treatment.

| Product | What its documentation establishes | Question it answered for ThreatVeil |
|---|---|---|
| **Linear** | **Peek** previews an issue "without opening" it, from any list or board: Space opens it, "↑ and ↓ move through adjacent issues … while updating the preview", Esc closes it. Triage and Inbox are keyboard-reachable (`G` then `T`, `G` then `I`), and the command menu previews items as you move. | How do you inspect one object without leaving the work? |
| **Vercel** | A project's dashboard shows "an overview of the production deployment and any active pre-production deployments". Deployments are a manageable history "regardless of environment, status, or branch". Work happens inside a selected team, and there is universal search "in the top right corner of every page". The redesign's stated aim: "the most crucial project elements easily accessible". | What is the central object, and what does its overview answer first? |
| **Sentry** | An issue groups similar events by fingerprint. The Issue Details header carries the problem, "total counts", affected users, and the actions (assign, resolve, share, archive). Evidence follows in a fixed order from diagnosis to context: highlights, stack trace, suspect commits, breadcrumbs, then deeper data. | How does a technical signal become one actionable problem, with evidence beneath it? |
| **Ramp** | Policy Agent sorts expenses into "approval recommended", "requires review" and "rejection recommended", shows its "rationale and cited policy text", and by default "only recommends actions"; "reviewers always have final authority". Violation logs record the resolution status. | How do you present a machine judgement that a human must own? |
| **GitHub** | A pull request separates **Files changed** (the diff, unified or split), **Checks** (which validations ran and why they passed or failed), and a merge status that "highlights blockers" in the header. A review is submitted explicitly as comment, approval or change request. | What does a serious review of a proposed change look like? |
| **Cloudflare** | An account "contains one or more users and zones". Account-level products appear in the sidebar before a zone is chosen; inside a zone, the sidebar shows that zone's products. Zone-level settings "only affect … that zone". | How do global and object scope coexist without confusing each other? |

Sources: [Linear — Peek](https://linear.app/docs/peek), [Linear — Triage](https://linear.app/docs/triage), [Linear — Inbox](https://linear.app/docs/inbox), [Vercel — Projects overview](https://vercel.com/docs/projects/project-dashboard), [Vercel — Managing deployments](https://vercel.com/docs/deployments/managing-deployments), [Vercel — Dashboard redesign](https://vercel.com/blog/dashboard-redesign), [Vercel — Universal search](https://vercel.com/changelog/dashboard-universal-search), [Sentry — Issue details](https://docs.sentry.io/product/issues/issue-details/), [Sentry — Issue grouping](https://docs.sentry.io/concepts/data-management/event-grouping/), [Ramp — Policy Agent for approvals](https://support.ramp.com/hc/en-us/articles/47618318137875-Use-Policy-Agent-for-approvals), [Ramp — Policy violations](https://ramp.com/answers/policy-enforcement/transaction-violates-a-policy-rule), [GitHub — Reviewing proposed changes](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/reviewing-proposed-changes-in-a-pull-request), [GitHub — Status checks](https://docs.github.com/en/pull-requests/reference/status-checks), [Cloudflare — Accounts, zones and profiles](https://developers.cloudflare.com/fundamentals/concepts/accounts-and-zones/).

## D. Principles borrowed from Linear

- **Inspect without leaving the list** (Peek). A claim opens in a right-side drawer over the Claims list. ↑/↓ move to the adjacent claim while the panel stays open, Esc closes it and returns focus to the row, and the open claim is a deep link (`?claim=`) (§W).
- **The keyboard is the fast path** (command menu, `G` shortcuts). ⌘K / Ctrl-K reaches every destination, both main actions and every system by name, with ↑↓ / ↵ / esc.
- **Complexity can be calm.** Neutral page ground, white surfaces, one line colour in three weights; colour is reserved for state.
- **Rows, not cards.** Capabilities and claims render as 44px rows inside one bordered list.
- **Short headings.** "What must stay true", "Latest change", "Recent activity".

## E. Principles borrowed from Vercel

- **The protected system is the project.** Its overview answers the most crucial thing first: whether it is cleared, and the change that matters. Tabs follow.
- **Change history is a list of objects.** Detected changes and proposed checks share one reviewable shape (`ChangeObject`), the way deployments share one shape across environments and branches.
- **Search in the chrome, on every page.** The ⌘K trigger lives in the topbar of every workspace screen.
- **Scope is always visible.** The organization sits at the top of the sidebar; the system name, status and tabs sit at the top of every system screen.

## F. Principles borrowed from Sentry

- **The header carries the problem, the count and the action.** An open change leads the Overview with its headline, its status and authority move, **Review change**, and **Restore assurance** as the resolution beside it.
- **Evidence follows in a fixed order, from diagnosis to context:** what moved (the diff), which claims it reached, what still holds, then the reasoning, limits and raw check body behind one disclosure.
- **Attention is ordered.** Home keeps its attention queue; the zero state no longer competes with it.

## G. Principles borrowed from Ramp

- **A machine judgement is a recommendation with its rationale beside it.** The proposed check states its explanation and limits and never presents itself as a decision. Current assurance is shown as "Unchanged by this check". This matches ThreatVeil's existing proposal-only rules, which were not changed.
- **Items needing review are grouped separately from those that don't.** A cleared system's limits collapse to one line; a system that is not cleared shows them open, because then they are the reason.
- **Plain operational language.** "Still current", "If shipped", "Confirm what ThreatVeil cannot read".
- **No commercial prompts on the work surface.** Upgrade moments left the System Overview; they remain in Usage & billing.

## H. Principles borrowed from GitHub

- **Files changed → the diff is rendered as a diff.** `AuthorityDiff` shows subject, field and `before → after` for every moved authority dimension, for example `beneficiary.update approval_required true → false`. The direction appears as a coloured rule and in the values themselves.
- **Checks → the claims split.** Which claims the change would reach (Affected) and which still hold (Still current) take the role of which checks failed and which passed.
- **Merge status in the header → the two states.** "Current system — Cleared" beside "If shipped — Needs attention" is the blocker summary a reviewer reads before anything else.
- **A result is bound to its revision.** The check shows its reference (`pull request #482`), when it ran, a link to the source, a copyable result, and the CI check body under one disclosure.

## I. Principles deliberately not copied

- **Sentry's issue inbox or Linear's Triage as the root of the IA.** ThreatVeil's owned object is the system, and "is it cleared right now?" needs a permanent home. Triage belongs on Home.
- **GitHub's review submission** (approve / request changes) on the proposed check. A ThreatVeil check reads only; adding an approval would change Gate semantics, which this wave must not touch (§28).
- **Ramp's auto-approval by an agent.** ThreatVeil's AI stays proposal-only.
- **Vercel's deployment screenshots and status favicon.** There is no visual artefact of an agent's authority to screenshot, and a status favicon was out of scope.
- **Cloudflare's product breadth.** Only its scoping model applied, and the four-destination sidebar already had it.
- **Linear's near-invisible status colour.** Assurance status must be unmistakable, so it keeps a shape, a word and a colour.
- **Anything resembling a posture dashboard.** No scores, charts, radar, sparklines or AI sparkle (§20).

## J. Three design directions

**A — Infrastructure minimalism (Vercel × Linear).** Four-link sidebar; System as the project; Overview plus tabs; neutral palette; compact typography; deployment-like change history.
*Strengths:* calmest; best density; strongest "one product" feel; least new machinery.
*Weaknesses:* attention across many systems is implicit; changes are a tab, not a first-class review object.

**B — Operations console (Sentry × Ramp).** An "Attention" inbox becomes destination one; Systems become secondary; issues open full-page; onboarding becomes a queue task.
*Strengths:* scales to many systems; strongest triage.
*Weaknesses:* demotes the object customers own; buries "is my system cleared?"; risks reintroducing the console feel the mandate rejects.

**C — Change review platform (GitHub PR × Linear).** Changes become destination one; systems are filters on the change stream; the proposed check is the hero with approve and restore actions.
*Strengths:* the best possible proposed-change review; matches the question that sells the product.
*Weaknesses:* a quiet system has no home; Passport and Share become homeless.

Wireframe concepts, drawn before implementation. Each covers navigation, Home, System Overview, the proposed-change review and onboarding.

**Direction A — Infrastructure minimalism**

```
┌ Sidebar ─────┐┌──────────────────────────────────────────────────────────────┐
│ ▣ Northwind  ││ Finance Agent   ● Needs attention          [Review change]   │
│ Home         ││ staging · synthetic   Refund authority changed.              │
│ Systems      ││ Overview  Claims  Evidence  Activity  Share                  │
│ Changes      │├──────────────────────────────────────────────────────────────┤
│ Integrations ││ 2 of 3 claims current · 2 capabilities · last cleared 18m    │
│              ││ LATEST CHANGE  beneficiary.update approval_required t → f    │
│ Usage        ││   Affected: Beneficiary approval   Still current: Tenant…    │
│ Settings     ││ CAPABILITIES   Beneficiary update ─ observed                 │
└──────────────┘│ RECENT ACTIVITY  12m  Authority expanded                     │
                └──────────────────────────────────────────────────────────────┘
Home: one status line, then a systems table.   Proposed: a page with a diff and a claims list.
Onboarding: one screen — upload/paste, detected facts inline, confirm name.
```

**Direction B — Operations console**

```
┌ Sidebar ─────┐┌ Attention (3) ─────────── filter: [all systems ▾] [severity ▾] ┐
│ Attention  3 ││ ▲ Finance Agent   Authority expanded · 1 claim stale  12m [→]│
│ Systems      ││ ▲ Infra Agent     Live source offline 47m             47m [→]│
│ Changes      ││ ○ Support Agent   Setup incomplete · no baseline       2d [→]│
│ Integrations ││────────────────────────────────────────────────────────────── │
│              ││ Issue: Authority expanded                   [Resolve ▾]       │
└──────────────┘│ system Finance Agent · evidence 1 stale · events ▸             │
                └──────────────────────────────────────────────────────────────┘
Home = the queue.  System = a filter on the queue.  Proposed check = one issue type.
Onboarding = a queue item: "Finish setting up Finance Agent".
```

**Direction C — Change review platform**

```
┌ Sidebar ─────┐┌ Changes ─────────────────── [Detected] [Proposed] [+ Check] ┐
│ Changes      ││ #482 refund-policy  Finance Agent   ● would need review  12m │
│ Systems      ││ #479 add MCP server Support Agent   ✓ no claim affected   2h │
│ Integrations │├ #482 ────────────────────────────────────────────────────────┤
│              ││ Files  beneficiary.update  approval_required  true → false   │
│              ││ Checks  ▲ Beneficiary approval   ✓ Tenant   ✓ Invoice auth    │
│              ││ Current ● Cleared  →  If shipped ● Needs review  [Approve…]  │
└──────────────┘└──────────────────────────────────────────────────────────────┘
Home = changes awaiting review.  System = a facet.  Share/Passport has no natural home.
Onboarding = "open your first check" against an imported definition.
```

The implemented hybrid appears in §AB.

## K. Selected direction

**A as the frame, C for the change object, B's triage on Home only** — the recommended hybrid in §22 of the mandate, validated against the repository:

- The API already models the *system* as the aggregate (`/systems/{id}/intelligence` returns status, claims, evidence, changes, authority and gate in one snapshot), so a Vercel-style project frame fits the data without new endpoints.
- The API already returns structured authority dimensions on both detected changes and proposed checks, so a GitHub-style change object needed no backend work.
- Home already had a sound attention queue, so B contributes ordering there and nothing else.

## L. Before / after information architecture

Global navigation is unchanged from the previous wave, by design (§16 was already met).

```
Before (browser)                              After
─────────────────                             ─────
Home                                          Home
  zero: marketing hero + 3 cards                zero: "Protect your first AI system" + Import / Example
Systems → System                              Systems → System
  Overview: 5 tiles · 3 limit cards ·           Overview: fact line · change object with diff ·
    6-card demo grid · machine card ·             capabilities rows · timeline · [limits] [machine use]
    upsell panel                                  [synthetic controls]
  Claims: 4 tiles · enum prose · run-on list    Claims: count line · 44px rows → claim drawer (?claim=)
  Evidence: 4 tiles · cards                     Evidence: count line · claim detail
  Activity: feed · 7 lifecycle cards ·          Activity: changes · lifecycle and history only once
    4 memory tiles · table of zeros               something has happened
  Share                                         Share
Changes                                       Changes
  Proposed: form, result appended below         Proposed: review (diff · claims · two states); form folds
Integrations: category card grids,            Integrations: category heading + one row per connector
  consumer cards                                (state, supplies, connect, limitations); consumers as objects
Settings → Developer tools: 15 tiles          Settings → Developer tools: grouped 44px rows
Systems → New: 6 manual fields,               Systems → New: 1 choose & read → 2 detected →
  import collapsed                              3 confirm what ThreatVeil cannot read; manual behind Advanced
—                                             ⌘K command menu, available everywhere
```

## M. Home redesign

- **Zero state** (`home.tsx`): the eyebrow, marketing headline, explanatory paragraph and three decorative cards were replaced by **"Protect your first AI system"**, one sentence, **Import a definition** and **Explore an example**, then one line naming the next two steps. 24px heading instead of up to 38px.
- **With systems:** the attention queue, current systems and quick actions were kept. The timeline became one line per event (system · readable status, with the canonical status in a tooltip) and uses relative time ("12m ago") with the exact time on hover.

## N. System redesign

`system.tsx` — the largest change in this wave.

- **Fact line** (`role="group"`, "System at a glance") replaces the five tiles. Any count that is zero and diagnoses nothing is omitted, so an unconfigured system no longer renders a wall of `0`.
- **The change leads.** When a change is open, "1 change awaiting review" shows a `ChangeObject`: headline, time, **Needs review** and the authority move, the `AuthorityDiff`, the **Affected / Still current** split, **Review change**, and a secondary **Restore assurance** link. Before this, a real (non-synthetic) system had no route to Restore from its Overview at all; the only such link lived in the synthetic demonstration grid. When nothing is open, the latest change shows as settled history with a positive tone; it no longer lists re-established claims under a warning.
- **Capabilities** as four 44px rows with their basis (`verified`, `observed`) and a link to all.
- **Recent activity** as a compact timeline.
- **Level 4, folded:** limits on what ThreatVeil will say (open when the system is not cleared, collapsed when it is), machine use, and the synthetic example's controls each sit behind one quiet disclosure. The canonical `FailureState` content is unchanged inside them.
- **Removed from the Overview:** the six-card demonstration grid (now inside "Synthetic example controls"), and upgrade prompts (still in Usage & billing).
- **Claims tab** (`intelligence.tsx`): enum prose and zero tiles replaced by a count line whose canonical level stays in each item's `title`. Each claim is one row that opens the **claim drawer** (§W).
- **Evidence tab:** the four tiles and the "We proved this once…" banner became one count line.
- **Activity tab:** the seven-stage lifecycle and the history block render only once a stage has been reached or a change observed. Marketing headings ("What changed, and which conclusions it touched.", "A clearance is a statement with a lifetime.") became plain ones.

## O. Proposed-change redesign

`changes.tsx` → `ProposedResult`.

1. **Header:** `Proposed` status, the reference (`pull request #482`), an **Open source** link when a URL was given, when it was checked; the headline; the authority move; and, in plain words, *"This check reads only. It has not changed current assurance."*
2. **What would change:** the `AuthorityDiff`.
3. **Consequence:** "1 security claim would need fresh evidence", split into **Affected** (with `current → would need fresh evidence`) and **Still current**. The third column in the old layout duplicated the first and was removed; declared-but-unverified claims keep their own group.
4. **Two states side by side** (`region` "Assurance before and after"): **Current system — Cleared — Unchanged by this check** → **If shipped — Needs attention — If nothing else changed.** This replaces a banner whose inline status pill broke mid-sentence.
5. **One disclosure** for the explanation lines, limitations, the check's conclusion and mode, **Copy result**, and the CI check body.
6. **The form folds** into "Check another change" once a result exists; before that it is an open, plainly titled region ("What would this change break?").
7. **Earlier checks** show a readable effect ("claims would need fresh evidence") with the canonical value in the tooltip.

## P. Onboarding redesign

`systems.tsx` → `ConnectSystem`, plus `POST /v1/connectors/definition-preview`.

1. **How is your system defined?** Format, **Upload the file** or paste it, **Read this definition**. **Advanced manual setup** is a text button beside it.
2. **Detected.** What ThreatVeil can establish deterministically — format, tools, MCP servers, agents — each group stating "none declared" when empty, plus any unreviewed fields and the adapter's limitation: *"An agent definition is declared configuration; it does not prove the running agent uses it."*
3. **Confirm what ThreatVeil cannot read.** Name, environment, operating environment, useful work, operating boundary. Access and actions appear only in manual mode, where there is no definition to derive them from. A name is suggested only when the file declares an agent; an MCP server or tool name is never guessed as the name of a workflow.

**Connect system** then performs exactly the calls the old form did — create the system, the environment and the definition source, and import the file as a first observation — so what gets persisted is unchanged.

**The preview endpoint** (`connector_api.py`) requires any organization member (`require(a)`, weaker than creating a system), calls `agent_definitions.snapshot()`, writes nothing, records nothing, and returns bounded facts. Its errors are content-free: a parser `DefinitionError` passes through; any other failure returns a fixed message, so customer configuration is never echoed. Covered by `tests/integration/test_definition_preview.py` (declared facts; nothing created; secret never echoed; unknown format rejected; session required).

## Q. Navigation

- The four primary destinations and the utility group are unchanged (already §16-compliant).
- The sidebar was tightened: 48px brand row, 30px items at 12.5px (previously 11px), a neutral selected state instead of a green wash, a solid organization mark, and the account row pinned to the bottom.
- The topbar is 48px and sticky, and carries **Jump to… ⌘K**.
- The system switcher stays in the system header (from the previous wave) and is also reachable through ⌘K.

## R. Developer mode

Unchanged from the previous wave, and verified in the browser: Properties, Targets, Runs, Evidence ledger, Records, Releases, Findings, Fixes and Regressions have no sidebar link, remain reachable from **Settings → Developer tools**, and keep their URLs. No developer surface was removed or redesigned.

## S. Forms

- **Connect** became a three-step flow (§P).
- **Proposed check** folds away once a result exists (§O).
- **Inputs:** 7px × 10px padding (was 11 × 13), 13px text, one border token, and a focus state with a 3px tint ring alongside the existing focus-visible outline. Labels are 12px medium in muted ink instead of 12px bold.
- **Buttons:** 34px default and 30px small (were 46 and 36), 12.5px medium, no hover lift.

## T. Design system

Tokens on `:root` (`globals.css`):

| Group | Tokens |
|---|---|
| Surfaces | `--cream` page ground, `--paper` surface, `--inset` |
| Lines | `--line`, `--line-strong`, `--line-soft` |
| Text | `--ink`, `--muted`, `--soft` |
| Status | `--ok/-bg/-line`, `--amber/-bg/-line`, `--red/-bg/-line` |
| Radius | `--r-sm` 4, `--r-md` 6, `--r-lg` 8, `--r-xl` 12 |
| Spacing / density | `--s-1…--s-6`, `--row` 44px |
| Type | `--font-sans`, `--font-mono` |
| Elevation | `--shadow-pop` (drawer and command menu only) |

New shared primitives in `product.tsx`: `AuthorityDiff`, `ChangeObject` (in `system.tsx`), `Drawer`, `Facts`, `When` / `ago`. New layout classes: `.factLine`, `.block`, `.rows`/`.row`, `.quiet`, `.changeObject`, `.claimSplit`, `.review`, `.states`, `.step`, `.detected`, `.drawer`, `.cmd`.

**Card audit** (mandate §3). Every card family on a customer surface was classified, then kept, converted or removed:

| Card family | Where | Class | Outcome |
|---|---|---|---|
| Fact tiles (five, mostly zero) | System Overview | Decorative | Replaced by one fact line; zero values omitted |
| "Limitations" cards | System Overview | Structural, level 4 | Kept intact inside one disclosure — open when not cleared, folded when cleared |
| Six-step demonstration grid | System Overview | Unnecessary on Overview | Moved inside "Synthetic example controls" |
| Upgrade / "See Pro" panel | System Overview | Unnecessary on a work surface | Removed from Overview; remains in Usage & billing |
| Machine-use card | System Overview | Structural, level 4 | Same content, quiet disclosure |
| Level count tiles | Claims, Evidence | Decorative | One count line; canonical level in `title` |
| Seven lifecycle boxes, four memory tiles | Activity | Decorative until something happens | Rendered only once a stage is reached or a change observed |
| Three numbered step cards | Home zero state | Decorative | Removed; one action-led sentence |
| Affected / Unaffected / Re-establish groups | Proposed check | Structural; third duplicated the first | Two-column split; duplicate removed |
| Connector cards | Integrations | Structural list | One row per connector |
| Consumer cards (Gate, GitHub) | Integrations | Actionable | Kept as bordered objects matching the Overview change object |
| Developer tool tiles | Settings | Navigation | Grouped rows |
| Plan cards | Usage & billing | **Actionable** (each selects a plan) | **Kept** — cards are the right control for a side-by-side choice |
| Setup checklist | System setup | Structural | Kept (already a joined row list) |
| Change object, drawer, detected step | New | Actionable / structural | Introduced with one shared surface treatment |

**Migration of existing product stylesheets** (`intelligence`, `change-assurance`, `commercial`, `product` modules): 40 literal neutral border colours → line tokens, 59 literal radii → the four radius tokens, 40 font sizes → one scale (11 · 11.5 · 12 · 12.5 · 13 · 14 · 15 · 17 · 19 · 24, plus display sizes). Status reds and ambers were deliberately left literal. What remains is listed honestly in §AC.

## U. Typography

- **Arial → a modern UI stack** (`ui-sans-serif, -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', 'Roboto', …`), with optical smoothing and legibility rendering. This is the largest single perceived-quality change, with no network dependency.
- **Body** 13px / 1.5 (was 14px / 1.65 mixed with 9–11px chrome). **Headings** weight 550 at −0.021em tracking (was 500 at −0.045em — too tight at small sizes).
- **Minimum text 11px in the signed-in product.** 69 workspace rules that ran at 7–10.5px were raised: sidebar account and organization captions (8–9px), status badges and eyebrows (10px), record tables, detail grids, JSON disclosures, billing plan labels, integration and developer-tool text. Still below 11px, and recorded as debt (§AC): the public marketing site and login page, and legacy developer-mode panels — the release event timeline, record-table toolbars and search, and the procurement demo version list.
- **Uppercase eyebrows** were removed from the System body, Claims, Evidence, Activity, the proposed check, onboarding and the Home zero state. The token remains, demoted to 10px, 600 weight and soft ink.

## V. Color

- The page ground moved from a green-tinted cream (`#f7f6ef` / `#f5f7f2`) to a neutral off-white (`#f6f7f5`). The sidebar and topbar are white.
- The selected nav item is a neutral raised state, not a green wash.
- ThreatVeil green is kept for the brand mark, positive state and focus.
- Status keeps three hues — ok, attention, stop — each paired with an icon and a word (`StatusPill`); the diff pairs its coloured rule with an arrow and before/after values. Colour is never the only signal.

## W. Interaction patterns

- **Claim drawer** (`Drawer`, `ClaimDrawer`). A modal right-side panel. Escape or the scrim closes it; focus moves in on open and returns on close. It shows the claim, verification level and evidence status, currency, next step, the changes that reached it, governs / forbidden / must-keep-working / depends-on / last verification / evidence, the reasons, and identifiers under **Advanced**. The open claim is in the URL (`?claim=`), survives a reload, and is cleared on close. While the drawer is open, ↑/↓ (or k/j) walk to the adjacent claim and move the deep link with it; keys typed into a form field are ignored.
- **Command menu** (`command-menu.tsx`). ⌘K / Ctrl-K toggles it from anywhere, with a visible topbar trigger. It is a combobox with a listbox, grouped Go to / Actions / Systems, ↑↓ / ↵ / esc, and `aria-activedescendant`. It only navigates; it never runs anything. On a narrow screen the trigger is an icon button, since a shortcut hint means nothing without a keyboard.
- **Relative timestamps with an exact tooltip** in timelines.
- **Progressive disclosure.** Level 4 detail (limits, machine use, reasoning, CI body, identifiers) sits behind one consistent quiet disclosure.
- **Copy result** on the proposed check (copy command already existed on machine use).
- **Deliberately not built:** optimistic UI, since every mutation here is an assurance write and must show its real result; and loading skeletons, recorded as debt in §AC.

## X. Responsive behavior

At 390px: the topbar never widens the page — the breadcrumb drops its root crumb and truncates the object name, and the command-menu trigger becomes a 30px icon button (an overflow probe found this row 2px too wide once the trigger was added, and the fix was verified in the final capture, §AB); the header wraps (title, status, action), tabs scroll inside their own container, the fact line wraps, the diff stacks subject over values, the claims split becomes one column, the two-state comparison stacks, the drawer takes the full width, and the command-menu trigger collapses to its icon. No screen scrolls horizontally in any capture. The two mobile System captures are not a like-for-like comparison and are not presented as one: the audit captured a system that was not yet set up (3683px); the final capture shows a system needing attention, with an open change and its limits expanded (§AB).

## Y. Accessibility

- Status is always shape + word + colour, with the canonical value in the accessible name (`StatusPill`, unchanged).
- The drawer and command menu are `role="dialog"` with `aria-modal`, a labelled title or name, and focus management; the command menu uses combobox/listbox/option semantics.
- New landmarks and labels: "System at a glance", "Assurance before and after", "Latest change", "Capabilities", "Recent activity".
- Text is 11px or larger across the signed-in product's customer surfaces (exceptions in §U); focus-visible outlines are retained on every control; the drawer animation respects `prefers-reduced-motion`.
- The existing `accessibility.spec.ts` still runs, updated to reach the manual form through **Advanced manual setup**.

## Z. Browser acceptance

The full Playwright suite (seven spec files, 20 tests: accessibility, the canonical demonstration, the finance change-assurance journey, commercial loop and platform, product experience, release integrity) ran against the production build and real PostgreSQL. It was run until green, not once: each run's failures were diagnosed from the browser and the API request log before anything was changed.

**Found and fixed during acceptance**

| Run | Failure | Diagnosis | Resolution |
|---|---|---|---|
| 1 | JOURNEY A — strict-mode violation on `mcp__payments__refund_issue` | The new "Detected" chip and the pasted definition in the textarea both contain the tool name | Test: exact match, which selects the detected chip |
| 1 | Finance journey — horizontal overflow at 390px | Overflow probe: the topbar's refresh button sat 2px past the viewport once the command-menu trigger was added; the tabs were contained by their own scroller | **Product:** on narrow screens the breadcrumb truncates and drops its root crumb, and the trigger becomes a 30px icon button |
| 1 | Canonical demonstration — "Relax beneficiary approval" never found | The synthetic controls had moved behind the "Synthetic example controls" disclosure on Overview | Test: asserts the controls are hidden, opens the disclosure, then acts — so it now also verifies the disclosure |
| 2 | Canonical demonstration — "Restore assurance" link never found on Overview | API request log showed the test reached Home, Activity, Capabilities and the map, then waited on Overview; that link had only existed inside the demonstration grid | **Product:** an open change now offers **Restore assurance** beside **Review change** (§N) |
| — | Capture metric reported raw enums on most screens | It counted screen-reader-only canonical status text and code snippets | Metric counts visible text only; the canonical values remain for assistive technology |

**New acceptance coverage added this wave**
- **JOURNEY A** (rewritten for import-first onboarding): the definition is read and its tools shown before any system exists; the proposed check shows the two states and folds the form away.
- **JOURNEY G** (new): a claim opens in the drawer; identifiers sit under Advanced; ↓/↑ walk adjacent claims and move the deep link; the link survives a reload; Esc clears it; ⌘K/Ctrl-K reaches a system by name.
- **Definition preview API** (`test_definition_preview.py`, Python): declared facts returned; nothing created; customer configuration never echoed; unknown format rejected; session required.

**Final result on the final build: 20 passed, 0 failed** (`npx playwright test`, unfiltered — the same command `scripts/container_acceptance.sh` runs), against the production `next build` output and real PostgreSQL 17:

1. accessibility — the canonical surfaces are keyboard reachable and correctly labelled
2. assurance-intelligence — canonical demonstration: change, consequence, restore, gate and an externally verified passport
3. change-assurance — finance journey retains failures, useful work and exact acknowledged activation
4. change-assurance — signed records and the published trust root stay available to a third party
5. commercial-loop — a customer proves failure, verifies a useful fix, and blocks historical regression
6. commercial-loop — public pages work on a narrow screen without horizontal overflow
7. commercial-loop — an owner issues and revokes access, schedules approved verification, and reuses a property as a draft
8. commercial-loop — contact request records explicit consent without claiming configured CRM delivery
9. commercial-loop — older approved properties remain accessible beyond the recent record window
10. commercial-loop — external capture evidence supports a scoped canary and selection audit
11. commercial-loop — a reviewed tool contract installs six drafts without approving or executing them
12. commercial-platform — Free to Pro commercial lifecycle preserves limits and explains billing honestly
13. commercial-platform — versioned public pricing exposes all five plans on mobile
14. product-experience — JOURNEY A: a new organization meets one onboarding experience and reaches a real answer
15. product-experience — JOURNEY B: a current system reads as current from Home, and every tab opens
16. product-experience — JOURNEY G: a claim is inspected in place, deep-linked, and the command menu reaches any system
17. product-experience — JOURNEY E: several systems: Home prioritises attention and context never crosses over
18. product-experience — JOURNEY F: old bookmarks still land on the canonical surface
19. release-integrity — candidate change voids prior proof, re-proof blocks regression, and a useful fix allows a signed release
20. release-integrity — Integrity Launch preserves scope, records actual effort, and keeps unverified installation and payment explicit

After that run, the new journey's title was changed from a duplicate "JOURNEY F" to "JOURNEY G" (title only); `product-experience.spec.ts` was re-run on the same build and passed 5 of 5 under the final titles.

## AA. Full regression

| Check | Result |
|---|---|
| TypeScript (`tsc --noEmit`) | pass |
| Production web build (`next build`) | pass |
| Python suite (`pytest -p no:cacheprovider --junitxml`, real PostgreSQL 17, non-superuser `NOBYPASSRLS` runtime role) | **700 tests · 0 failures · 0 errors · 0 skipped** (JUnit), 54s — the previous 696 plus the 4 in `test_definition_preview.py` |
| Browser suite (`npx playwright test`, unfiltered, as `scripts/container_acceptance.sh` runs it) | **20 passed · 0 failed** on the final production build (§Z) |
| Backend change scope (§28) | `git diff HEAD -- src/ migrations/`: `connector_api.py` gains one read-only endpoint (+40 lines, 0 removed). `assurance_api.py` and `assurance_intelligence.py` also differ from HEAD, but those changes were already in the working tree before this wave began (present in the opening `git status`) and were not edited. No migration, RLS policy, Gate, Passport, evidence-applicability or authority-classification code changed. |

## AB. Screenshot contact sheet

Reproducible with `apps/web/redesign-capture/` (its own Playwright config, kept out of the acceptance suite so `playwright test` never runs a twenty-screen capture): `final-capture.spec.ts` drives a fresh organization through every §25 state and records per-screen metrics; `contact-sheet.spec.ts` lays any screenshot directory out at one scale.

**Artifacts** (git-ignored `.local/redesign/`): `contact-before.png` — 15 screens from the actual-browser audit; `contact-after.png` — 20 screens from the final build; `final/` — each full-page screenshot with `metrics.json`; `before/` — the 51 audit screenshots and `notes.md`.

**Measured on the final build** (fresh organization, synthetic Finance example; eyebrows and raw enums counted only where a sighted user can see them — screen-reader-only canonical values and code snippets excluded):

| Screen | Before height | After height | Before eyebrows | After eyebrows | After: visible raw enums | After: horizontal scroll |
|---|---|---|---|---|---|---|
| Home — zero state | 1000px | 1000px | 1 | 0 | 0 | no |
| Onboarding — detected | 1201px | 1386px | 1 | 0 | 0 | no |
| Home — all current | 1000px | 1000px | 0 | 0 | 0 | no |
| System — current | 2021px | 1133px | 2 | 0 | 0 | no |
| Systems list | 1000px | 1000px | 0 | 0 | 0 | no |
| System — claims | 1326px | 1079px | 2 | 0 | 0 | no |
| System — evidence | 1851px | 1771px | 6 | 3 | 0 | no |
| Passport / Share | 1000px | 1000px | 0 | 1 | 0 | no |
| Changes | 1000px | 1000px | 0 | 0 | 0 | no |
| Integrations | 2116px | 1995px | 0 | 0 | 1 | no |
| Usage & billing | 2230px | 2207px | 8 | 8 | 0 | no |
| Settings | 3933px | 3787px | 9 | 5 | 0 | no |

States with no like-for-like audit capture (the audit did not reach them): Proposed-change review 1044px, Home — attention 1000px, System — attention 1810px, Claim drawer 1079px, System — activity 1818px, Command menu 1809px, Mobile — home 992px, Mobile — system 2482px.
Page errors during the final capture: 0.

Reading the table honestly:
- **System Overview** is the largest change: 2021px → 1133px for a cleared system, with no uppercase eyebrows, no zero tiles and no contradiction between header and body.
- **Onboarding is not like-for-like.** The audit captured the empty manual form; the final capture shows the definition read, its detected facts, and the confirm step. It is longer because it shows more of the answer.
- **Share is not like-for-like.** The audit's Share screen belonged to a system with no baseline, so it had no passport controls; the one eyebrow is on the passport block.
- **The one visible "raw enum" on Integrations** is `$THREATVEIL_TOKEN` inside the Assurance Gate's copyable curl command, which is correct there.
- **Usage & billing and Settings** barely changed in length (§AC, items 1–2).

**Does it look like one product?** Viewed without reading: Home, onboarding, every System tab, the proposed-change review, the claim drawer, Changes, Integrations and the command menu now share one ground, one line weight, one row rhythm and one status treatment, and the mobile screens keep the same header and hierarchy. Two surfaces still read as the older product: **Usage & billing** (plan cards and eight eyebrows) and, to a lesser degree, the long **Settings** stack. The dense per-claim blocks on **Evidence** and **Activity** are the next most visible inconsistency.

**Five-second test** (§26), applied to each final screenshot — where am I, what object, is anything wrong, what next:

| Screen | Where / object | Anything wrong? | Next action |
|---|---|---|---|
| Home — zero | Home; no systems | Nothing to be wrong yet | **Import a definition** |
| Home — attention | Home; Finance Agent | "1 system needs attention" + amber row | **Review change** |
| System — current | Finance Agent Overview | **Cleared**; fact line agrees | **Share current assurance** |
| System — attention | Finance Agent Overview | **Needs attention**; open change leads with its diff | **Review change**, **Restore assurance** |
| Proposed-change review | Changes; `pull request #482` | "1 security claim would need fresh evidence"; Current **Cleared** → If shipped **Needs attention** | Reasoning disclosure; **Check another change** |
| Claim drawer | One claim over the Claims list | Status pill in the subtitle | ↑↓ next claim; Esc |
| Usage & billing | Billing | Plan and usage meters | Choose a plan — **passes, but slower to read** |
| Settings | Settings | — | **Slow**: the page must be scrolled to find a section |

## AC. Remaining design debt

Stated plainly; none of these was hidden by the screenshots.

**Surfaces not yet brought to the new standard**
1. **Settings is still long** (≈3,800px). Developer tools became rows, but the organization, members, invitation, API token, observation-source, GitHub binding and CLI panels are still stacked cards written as dense one-line JSX in `workspace-parts.tsx`. Each is structural; the page wants a left-hand section index or tabs.
2. **Usage & billing keeps its eyebrows and plan cards** (≈2,200px). The plan cards are actionable and were kept on purpose (§T); the eight uppercase labels and the commercial history block were not reworked, because the billing specs assert exact commercial wording.
3. **Evidence and Activity keep their legacy detail blocks** once a system has history. The zero tiles and marketing headings are gone, but per-claim evidence articles still show identifier chips at the second level, and the Activity change feed plus lifecycle strip is dense. The claim drawer shows the better pattern; these blocks should adopt it.
4. **Legacy developer-mode surfaces** (runs, records, releases, findings, schedules, change explorer, Integrity Launch) were deliberately left unchanged, and still use the old card system and some 8–10px text (§U).
5. **The marketing site and login page** were out of scope and keep their own styles and sub-11px captions.

**Mandate items only partly delivered**
6. **Onboarding step 1 offers upload, paste and manual setup, not "Connect GitHub" or "Connect MCP" tiles** (§8). Live GitHub, MCP and Cloud Run sources exist, but they are connected from a system's Evidence tab, because a live source needs a system and environment to attach to. Offering them in step 1 means creating the system first, which was not attempted in this wave.
7. **The starter security claim is chosen on the Claims tab after connecting**, not inline as onboarding step 3. Connect lands directly on that tab.
8. **The proposed check still takes pasted JSON.** The review is new; the input is not. A file picker, and a pull-request picker bound to a GitHub source, remain to do.
9. **Interaction patterns not built:** recent systems; ↑/↓ list navigation outside the claim drawer (Systems list, Changes, Home queue); loading skeletons, where the product still shows a single "Loading…" line; a change preview drawer to match the claim drawer.

**Design system**
10. **`globals.css` is still the minified legacy sheet.** Tokens now drive the shell and every product module, but it still holds about 60 distinct literal border colours, mostly on public and developer surfaces. Status reds and ambers are deliberately literal.
11. **Type is a system UI stack, not a self-hosted typeface.** A self-hosted Inter or Geist via `next/font` would give identical rendering across platforms, but needs build-time network access, which the private build environment was not assumed to have.

_Items found by the final capture are appended in §AB._

## AD. READY_FOR_PRIVATE_GCP result

**`READY_FOR_PRIVATE_GCP` — unchanged. `cloud_accepted = false`.**

Why the classification holds:
- **No assurance truth changed** (§28). The only backend change is a read-only, non-persisting preview endpoint that reuses the existing import parser and writes nothing. Tenant isolation, RLS, append-only history, evidence applicability, authority classification, observer qualification, proposed-change non-mutation, Gate and Passport semantics, UNKNOWN, billing/security separation and AI proposal-only rules were not touched, and their suites pass.
- **No product breadth was added** (§29): no connector, observer, assistant, pricing or assurance semantic.
- **Verified on this wave's final build:** strict TypeScript (host and container), production `next build`, **700 / 700** Python tests, **20 / 20** browser tests, a 20-screen capture with zero page errors and no horizontal overflow at 1440px or 390px.

Not re-run in this wave, and therefore not claimed: the end-to-end `scripts/container_acceptance.sh` as a single script (in particular its TypeScript SDK tests and `scripts/canonical_demo.py`), and the Terraform tests. Neither the SDK, the demo script nor `infra/` changed in this wave, so their previous results stand, but they were not re-executed here.

**Against the final standard** (§31): a first-time user now meets an object with a status, the change that matters shown as a diff, and one next action — "ThreatVeil watches my AI system, tells me what a change affects, and helps keep its security claims current" is readable from the System Overview and the proposed-change review without documentation. The depth is still there, one disclosure or one drawer away. The work is not finished everywhere: Usage & billing, Settings, and the Evidence and Activity detail blocks still carry the older design (§AC). The next action for the business remains private GCP activation and a design partner, not another UI wave.
