# ThreatVeil — Pre-GCP product completion report

**Date:** 2026-09-13
**Classification on entry:** `READY_FOR_PRIVATE_GCP`, `cloud_accepted = false`
**Scope:** product completion and product expression. No assurance, Gate, Passport, pricing, entitlement or connector semantics changed. No connector, observer, assistant, vertical or cloud resource was added.

Backend changes are read-only projections only: format detection on the existing definition-preview endpoint, and `stack`, `reliance`, evidence-record fields and change `connector` on existing snapshots (§AO).

---

## A. Executive verdict

The product now shows the whole ThreatVeil loop without documentation — connect, understand, define, check, prove, watch, restore, share — and it does so through four objects that exist nowhere else: the **Assurance Chain**, the **Change Impact** transition, the **Assurance Gate** answer and the **Passport** with authenticity and currency kept apart. Connection starts from how a customer's agent actually lives (GitHub, MCP, an uploaded definition), the format is detected rather than chosen, and every ecosystem identity carries a label that says exactly what the relationship is.

The wave also closed every item of the previous report's §AC that was in scope: Settings is five sections, Usage & billing is on the design system, Evidence and Activity are rebuilt, proposed-change input takes files, and the change preview, recent systems, list keyboard navigation and loading skeletons exist.

**Verdict: `READY_FOR_PRIVATE_GCP` — unchanged. `cloud_accepted = false`.** Regression results are in §AQ.

## B. Previous remaining debt

Items from `THREATVEIL_WORLD_CLASS_PRODUCT_REDESIGN_REPORT.md` §AC and their outcome:

| # | Debt | Outcome |
|---|---|---|
| 1 | Settings ≈3,800px stack | **Closed.** General · Members · Security · Developer · Data & export, each its own route (§AI). |
| 2 | Usage & billing eyebrows and cards | **Closed.** Account line, compact meters, one plan comparison table; prices, limits and commercial wording unchanged (§AJ). |
| 3 | Evidence / Activity legacy blocks | **Closed.** Evidence status + per-claim rows + drawer (§T–U); Activity as assurance history with filters, change records on Change Impact (§V). |
| 4 | Legacy developer-mode surfaces | **Not changed, by design.** Still reachable from Settings → Developer at their URLs. |
| 5 | Marketing site and login styles | Out of scope; unchanged. |
| 6 | No GitHub / MCP tiles in onboarding | **Closed truthfully** (§I, §L, §M). |
| 7 | Starter claim chosen after connecting | Unchanged: connect still lands on Security claims; the setup progression now says so. |
| 8 | Proposed check takes pasted JSON | **Closed.** Upload, paste or GitHub pull-request reference, all auto-detected (§W). |
| 9 | Recent systems, list keys, skeletons, change preview | **Closed** (§Z, §AK, §AL). |
| 10–11 | Legacy literal colours in `globals.css`; system font stack | Unchanged; recorded again in §AT. |

## C. Browser audit

The running build was the source of truth. The previous wave's final 20-screen capture was taken on this exact build (the container's tree matched the working tree by checksum), so it serves as the before state; it is kept in `.local/completion/before/` with its metrics. What the browser showed, against this mandate:

| Surface | Before (measured) | Problem |
|---|---|---|
| Home zero state | 1000px, clean | Sparse: no product loop, no ecosystem presence, "Follow the synthetic Finance example" framing on Connect. |
| Connect | 1386px | A format dropdown first; no GitHub or MCP method; nothing about models or permissions. |
| System Overview | 1133–1810px | Change object good, but no stack, no chain, no setup maturity; Gate hidden in a disclosure, Passport absent. |
| Evidence | 1771px, 3 eyebrows | Legacy cards: raw identifier chips, `NEEDS FRESH EVIDENCE` badges, a full article per claim. |
| Activity | 1818px | Legacy change cards plus a lifecycle strip; no chronology of assurance. |
| Integrations | 1995px | Every connector "AVAILABLE"; "Bounded MCP" described as both *ThreatVeil reads it on a schedule* and *you upload a snapshot* in one sentence; **every "Connect for a system" link landed on the Evidence tab, which had no connect form — a dead end.** |
| Usage & billing | 2207px, 8 eyebrows | Older card design. |
| Settings | 3787px, 5 eyebrows | One long stack. |

Current experience → problem → proposed completion → build / do not build, for each surface, is the body of §G–§AK.

## D. Product-expression audit

Before this wave the only distinctive elements were the brand mark, the green accent and the before→after diff row. Everything else — status pills, rows, cards, drawers — was well-made generic SaaS. The four signature objects in §R, §S, §AD and §AE are the answer: each encodes a ThreatVeil-specific idea (a chain that breaks where assurance stops holding; a transition whose colour is the direction of authority; a read-only machine answer; two independent facts about one signed document).

## E. Ecosystem identity strategy

Identity appears where it answers a question a customer actually has — *does this work with my stack?* (Home, Connect), *what is this system made of?* (System Stack), *where did this change come from?* (Change Impact, Activity, Changes), *how is it connected?* (Integrations). It never appears as decoration: no logo wall, no identities on pricing, none in the synthetic example beyond MCP, which the fixture really is.

## F. Brand-asset truthfulness

- **No proprietary logo is reproduced.** Official asset files were not available to this build, several vendors' mark-usage terms are unclear, and redrawing a mark from memory would be an altered mark. Every third-party identity is a neutral monogram tile plus the product name in text (`SourceMark`), which is nominative reference. `SourceMark` is the single substitution point if approved assets are later licensed.
- **A mark always travels with its relationship label**: *live source*, *import*, *trace import*, *declared in definition*, *imported snapshot*, *consumer*, *advanced security import*.
- **No colour or trade dress** is borrowed; tiles are neutral.
- The Home copy was checked in the browser for *partner*, *official integration* and *certified*: none appear (§AQ).

## G. Home

Zero state keeps **Protect your first AI system**, **Import a definition** and **Explore an example** (the example gallery), and adds **Explore how ThreatVeil works**, which launches the guided example (§AG). One compact five-step strip — Connect · Define · Check · Verify · Keep current — states the loop in one line each. No hero, no carousel.

With systems: the attention and current-system lists move with ↑/↓, recent activity rows name their source and open the change preview, and loading is a structured skeleton.

## H. Home ecosystem presence

"Import or connect from": GitHub · *live source*, Claude Code · *import*, MCP · *connect or import*, LangGraph · *import*, CrewAI · *import*, OpenAI Agents SDK · *trace import*. The last is deliberately *trace import*: Agents SDK definitions are code, which ThreatVeil never parses, so the only real relationship is importing `Span.export()` records as evidence.

## I. System connection

**How do you want to connect your AI system?** — three primary methods, then **Paste definition** and **Advanced manual setup**:

- **GitHub · live source · Watch a repository.** Repository, numeric ID, branch reference and a registered read credential reference. It reads repository identity and the branch revision; it does not read file contents, so the screen invites the definition upload too. **With no credential reference registered it stops at CONFIGURATION REQUIRED** (verified in the browser in local mode). No OAuth, repository list or pull request is faked.
- **MCP · agent protocol · Import MCP configuration.** A `.mcp.json` or a `tools/list` catalog snapshot now; live MCP is stated as *configuration required* because it reads only a verified MCP target registered for an existing system.
- **Upload configuration · supported definitions.** Drop or choose a file; the format is detected.

Then **ThreatVeil found** and **Confirm what ThreatVeil cannot know**. Connect performs the same persisted calls as before (system, environment, installation, import), plus a GitHub installation and first collection only when a credential is present.

## J. Connection-method taxonomy

| Method | Relationship | Established by |
|---|---|---|
| GitHub | Live source (POLL, read credential) | connector `github` |
| MCP catalog / `.mcp.json` | Imported snapshot / declared servers | connectors `mcp` (IMPORT) / `agent_definition` |
| Upload / paste | Supported definition (IMPORT) | connector `agent_definition` |
| Advanced manual | Declared by the customer | `POST /v1/systems` |

## K. Format auto-detection

`agent_definitions.detect_format(document, filename)`, exposed as `format: "auto"` on the existing read-only preview:

- **Structure decides**, and every structural candidate must also **parse under its own adapter** — a stray `permissions` key that is not a valid Claude Code permissions block selects nothing.
- A **file name only settles a tie** between candidates that already fit; it never selects a format alone.
- **Ambiguous → ask**: the UI offers the candidates as buttons. **Unsupported → say so**, with specific guidance for an OpenAI Agents trace export or hook-event file.
- Manual choice lives under **Advanced: choose the format**.
- Nothing about the content is returned in a detection result, and errors stay content-free (tested with a planted secret).

Covered by `test_detection_is_structural_and_never_guesses` and three endpoint tests.

## L. GitHub onboarding

Implemented up to exactly what the product supports: the existing read connector (identity + branch revision with a credential reference) and the existing GitHub App check publication. Repository enumeration, OAuth and pull-request fetching do not exist, so they are not shown. In a workspace with no credential reference the flow says **Configuration required** and offers the definition upload.

## M. MCP onboarding

Import of a tool catalog (connector `mcp`, IMPORT) or a `.mcp.json` (definition import) with the same detection. The synthetic example's gateway is an IMPORT installation, and everywhere it appears it reads **MCP · imported snapshot** — never live. Live MCP is offered on Integrations only against a verified MCP target; without one it says configuration required.

## N. Definition / import ecosystem

The preview now returns, from the adapters' own output: advertised **models**, **permissions** (allow / deny / ask and default mode), agents that **inherit every parent tool**, **delegation**, **code execution**, tools that **require approval**, and the **ecosystem the format establishes**. A model string never establishes a vendor (`gpt-5` in a manifest yields no OpenAI identity; tested).

## O. Detected System Stack

`assurance_intelligence.stack(ctx)` returns one item per technology with its basis — `LIVE_SOURCE`, `INSTRUMENTED`, `IMPORTED` or `DECLARED` — from installations and their stored batch facts. Identities come only from a connector id or a definition format; duplicates collapse to the strongest relationship and keep the others as `also`. The header shows compact chips (*Claude Code · imported*, *MCP · declared*); a live dot appears only when the source is actually connected, and each chip links to the source list on Evidence.

Deliberately absent: PostgreSQL. The synthetic evidence record states its ground truth as *"Synthetic committed SQLite ledger"*, so no database brand is shown anywhere.

## P. Assurance setup progression

Six stages, grouped **Useful change impact** (system understood · security claims defined · proposed-change analysis ready) and **Verified current assurance** (verified evidence · live monitoring · machine or external reliance), each computed from the snapshot. The next missing stage carries one outline action; the header's primary action is unchanged, so a screen still has one dominant action. Onboarding shows the same progression from the first stage.

## Q. System Overview

Order: fact line → **Assurance Chain** → the latest change as **Change Impact** → **Assurance setup** → capabilities → **Who relies on this answer** (Gate and Passport primitives) → recent activity (linked, with source identity) → limits → synthetic controls. The machine-use curl moved to Integrations; the Overview shows the answer, last machine check and consumers, and links there.

## R. Assurance Chain

System → Authority → Security claim(s) → Evidence → Current assurance, on one track. Every link is read from the snapshot (authority count or the open change's classification and moved field; claims affected or current; evidence counts; clearance). The final link *is* the canonical clearance, so the chain cannot disagree with the header. When a link stops holding its node changes shape (diamond for changed/affected, ring for stale, square for not cleared) and every link after it is drawn dashed; the heading changes from *Why this answer holds* to *Where the answer stops holding*. Used on Overview only, plus the tour.

## S. Change Impact component

One component for detected changes, proposed checks, Activity records and the preview drawer: source identity and relationship; reference; headline; the **before → after transition** in large mono type with a directed rule coloured by authority direction; the authority effect; **Affected** and **Still current**; declared-not-verified claims; and two states (*Before this change → Current system* for a detected change from `prior_clearance`; *Current system → If shipped* for a proposed check from `clearance.current / if_applied`). Nothing is derived in the UI that the API already states.

## T. Evidence

**Evidence status** (proportional bar + legend: Current · Needs fresh evidence · Failed · Unknown), then **By security claim** rows — claim · status · why · last verified · observed by · Review — then sources with identity and relationship, then the dependency-mapping disclosure. *Why* names the change that moved after the evidence was produced.

## U. Evidence detail

A drawer (`?evidence=`, ↑/↓ between claims, Esc) with the explanation, what moved since, last verified, observed by (the record's own `ground_truth`), qualification and coverage, security and useful-task outcomes, system state used, reliance window, governs / forbidden / must keep working, reasons, limitations from the record, and next action. **Advanced**: claim ID, canonical status and applicability, evidence record, verification run, evidence digest, observer ID.

## V. Activity / assurance history

A chronology built from the snapshot: changes (with source identity and the moved field), *Previous assurance superseded* (once per superseded clearance, naming claims needing fresh evidence), verification decisions (*Security failed*, *Useful task failed*, *Verification passed*), *Assurance established* / *Assurance restored* (restored only after a loss), Passport issued, Gate read by a machine, Passport checked externally. Filters: All · Changes · Assurance · Verification · External use. Below it, **Changes in detail** on Change Impact with reasoning and feedback; the raw lifecycle and record history sit behind one disclosure. No zero-state lifecycle blocks. *Verification started* is not shown because no such record exists.

## W. Proposed-change input

**Check a change**: system, the source it is compared against, and where the candidate comes from — **GitHub pull request** (number, optional exact commit, optional https link, plus the candidate file), **Upload candidate config**, **Paste candidate definition**. The candidate is detected before anything is evaluated, and a format the chosen source cannot read is refused with a reason. The GitHub option states plainly that ThreatVeil does not fetch pull requests; the number, commit and link label the result exactly, using the existing `Reference` fields.

## X. Proposed-change review

Header (*Proposed*, checked time, the claim-level answer, *This check reads only*), then Change Impact with *Current system → If shipped*, then reasoning, limits and the CI check body behind one disclosure. A GitHub identity appears only when the customer-supplied link's host is `github.com`, labelled *reference · not fetched*.

## Y. Source-aware changes

Every change shows where it came from: connector identity plus acquisition (*imported snapshot*, *live source*, *sends observations*) on Overview, Activity, Changes and Home; *Declared boundary* when the change is a reviewed authority declaration with no connector. `connector` was added to Home change rows and activity (read-only).

## Z. Change preview

A right-side drawer from Home, Changes, Systems and Activity (`?change=`, plus `?system=` outside a system), matching the claim drawer: Change Impact, the consequence in one sentence, **Restore assurance** when open, and **Open full review** (the Activity record anchor).

## AA. Integrations

Recommended (GitHub, MCP, definition upload) → Code & configuration → Agent protocols → Agent platforms → Infrastructure → Evidence & observability → Use ThreatVeil's answer. Each row: identity, name, relationship type, real state, one sentence, one real action, *Coverage and limitations*. Rows appear only for connectors in the catalog.

## AB. Integration semantics

States are computed from installations, health and configuration: *Connected · last seen X ago* (only when health says connected), *Needs attention*, *Imported · N snapshots*, *Import available*, *Not connected*, *Configuration required* (no credential reference, or no verified MCP target), *Needs system*, *Not configured* (OpenTelemetry). Actions open one drawer that uses only the existing connector API: create installation → collect (live), create a push intake (OpenTelemetry), or import a file with detection. The dead-end "Connect for a system" link is gone.

## AC. Integration branding

Neutral monogram tiles with names and relationship labels (§F). *OpenAI Agents SDK · trace import*, *Claude Agent SDK hooks · trace import*, *Claude Code · import*, *GitHub · live source*, *GitHub Checks · consumer*, *Cloud Run · live source*. No row implies a partnership.

## AD. Assurance Gate visual primitive

A dark answer line — `GET …/assurance/current → Cleared` — with a proprietary two-post glyph (no lock, no shield), a *Read-only* badge, last machine check, consumers and reliance window, and the sentence *It answers assurance and never grants permission.* Last machine check and consumers come from minimized server records written once per consumer per hour; the UI says so.

## AE. Passport visual primitive

Two facts side by side — **Authenticity: signed · verifiable offline** and **Current status** (Current / Superseded / …) — so an authentic Passport that is no longer current reads exactly that way. A document-with-status-ring glyph, *Not issued* with *Nothing is ever published automatically* when none exists. Disclosure preview and confirmation are unchanged.

## AF. Custom ThreatVeil glyphs

Five, 16px grid, monochrome: **Assurance** (a chain ending in a filled node), **Authority** (a boundary crossed by an arrow), **Evidence continuity** (observations on a timeline), **Assurance Gate** (two posts and an answer), **Passport** (a document and a separate status ring). Ordinary actions keep standard icons.

## AG. Guided example

**Explore how ThreatVeil works** starts an 11-step guided mode over the real product: *Step X of N*, plain description, *Back / Next / Exit tour*, *Synthetic demonstration* badge, the real object outlined on the real screen. Preparation requires the same explicit synthetic-scope confirmation as the example. Each action button calls the fixture's existing controls — the same `finance/setup`, `simulate-change` and `assess` endpoints the synthetic controls use — then asks the open view to re-read. Steps: example system → current → permission changes → what moved → one claim needs fresh evidence → others remain current → verification fails → bad fix rejected → proper fix restores → machines read the answer → Passport verification.

## AH. Finance fixture treatment

Home says *Explore an example* and *Explore how ThreatVeil works*; Connect says *Use the synthetic example instead*. Inside the example the fixture is named honestly, labelled synthetic everywhere, shown with its one real ecosystem identity (MCP, imported), and never counted as customer activity.

## AI. Settings

Five routes under `/app/settings/…` with a left section nav (a scrolling tab row on narrow screens): **General** (workspace, role, sign-in; IDs under details), **Members** (members, invitation; enforcement stays in the API), **Security** (authentication, GitHub workflow bindings, credential references — restricted text for non-security roles), **Developer** (API tokens, CLI workflow, qualified observers, schedules, all developer tools, integration status JSON), **Data & export** (memory export, retention allowance, scoped reports). `/app/settings` opens General.

## AJ. Usage & billing

Account line, **Usage** meters, **Compare plans** as one table (systems, environments, security claims, verification capacity, retention, scoped evidence; actions on the last row; Business/Enterprise *Talk to us*), local sandbox and commercial history behind quiet disclosures. No uppercase eyebrows. Prices, limits, entitlements, plan definitions and the wording the billing specs assert are unchanged. No ecosystem identities.

## AK. Loading / polish

Structured skeletons replace "Loading…" on the workspace shell, Home, Systems, the System snapshot, Changes, Integrations, the change preview and Settings panels. Topbar: the *Local* badge shows only in local/development mode; *Talk to the founder* is now `NEXT_PUBLIC_TV_CONTACT_LABEL` (defaults to the current launch wording; set empty to remove); refresh kept.

## AL. Keyboard interaction

↑/↓ move focus between rows of the Home attention and current lists, the Systems list and the Changes list (`useListKeys`, opt-in `data-row-link`, ignored inside fields). ↑/↓ also walk claims in the evidence drawer. ⌘K gains a **Recent** group (last five systems visited, stored locally).

## AM. Accessibility

Every new status pairs shape, word and colour; `[data-tone]` elements always carry text (non-text bars use `data-status`). New regions are labelled (*Assurance chain*, *Assurance setup*, *Assurance Gate*, *External assurance*, *Assurance history*, *Evidence status*, *ThreatVeil found*, *Assurance before and after*). Drawers keep dialog semantics and focus return; filters are `aria-pressed` buttons; file inputs are labelled. The existing accessibility audit passes on the new build (§AQ).

## AN. Responsive behavior

At 390px the chain becomes a vertical track, the transition stacks, states stack, primitives stack, evidence rows collapse to two lines, integration rows wrap, settings navigation becomes a horizontal scroller, the plan table scrolls inside its own container, and the tour panel fits the viewport. Checked for horizontal overflow on Home, System, Evidence, Activity, Integrations, Settings, Changes and Billing (§AQ).

## AO. Security invariants

- **Backend changes are read-only projections**: detection on the existing non-persisting preview (still `require(a)`, still content-free errors); `stack` and `reliance` on the intelligence snapshot; evidence-record fields (`ground_truth`, `observer_id`, `qualified`, `coverage_complete`, `synthetic`, `expires_at`, `run_id`, `evidence_digest`, `limitations`) on `evidence_currency`; `id` and `connector` on Home rows. No migration, RLS policy, write path, Gate, Passport, applicability or classification code changed.
- Every UI write goes through existing endpoints with existing role checks. The tour calls only the synthetic fixture's existing endpoints, after explicit confirmation.
- Uploaded files are bounded (256 KiB client-side, existing server bounds) and never echoed in errors.

## AP. Marketing-truth invariants

- An import is never shown as connected; a live dot requires health `connected`.
- No identity is inferred from a model string, host, tool name or URL — except the explicitly labelled *GitHub · reference · not fetched* for a customer-supplied `github.com` link.
- No partnership, certification, endorsement, customer logo, testimonial or score.
- No unsupported method is offered: no OAuth, repository picker, PR fetch, OpenAI definition import or live MCP without a verified target.

## AQ. Full regression

Run on this wave's final tree. Evidence is in git-ignored `.local/completion/`.

| Check | Result |
|---|---|
| Python suite (`pytest -p no:cacheprovider --junitxml`, real PostgreSQL 17) — includes MCP, Assurance Gate, Passport, trust directory, commercial and security tests | **710 tests · 0 failures · 0 errors · 0 skipped** (JUnit, 51s). That is the previous 700 plus 10 new tests in `test_product_completion.py`. |
| Ruff (`ruff check src tests scripts`) | All checks passed |
| Strict TypeScript (`tsc --noEmit`) | Pass (exit 0) on the final tree |
| Production web build (`next build`, container) | Pass |
| TypeScript SDK (`pnpm test:sdk`) | **5 passed · 0 failed** |
| Canonical demo (`scripts/canonical_demo.py` against the live API) | `completed: true`. The change outside code is read as `AUTHORITY_EXPANDED` from the imported MCP gateway (1 claim affected, 1 evidence stale, 2 still hold). The Passport moves `CURRENT → SUPERSEDED` and stays authentic after the change. |
| Terraform validate + tests (hashicorp/terraform 1.16.1) | **Configuration valid · 10 passed · 0 failed** |
| Full Playwright suite (`npx playwright test`, unfiltered, production build, real PostgreSQL 17) | **22 passed · 0 failed** on the final build: the previous 20 plus 2 new tests in `product-completion.spec.ts` |

How these were run, stated plainly:
- **Container DNS was down** during this wave, although host DNS worked. `scripts/container_acceptance.sh` needs DNS, because it downloads uv and the pnpm packages, so it could not run as one script. Its steps ran individually instead, in the long-lived `tv-live-run` container against `tv-live-pg`: the production build, the full browser suite, the SDK tests and the canonical demo. The API was launched from the project virtualenv. Terraform needed `--dns 1.1.1.1` to download its provider.
- **The first Terraform attempt failed** on a DNS timeout while downloading the provider. That was a network failure, not a configuration result; the retry above is the result.
- **Two browser runs produced no result**, for infrastructure reasons now fixed: one ran with the API down (`uv run` could not resolve packages), and one collected macOS AppleDouble `._*.spec.ts` files. Neither is counted.
- **Found and fixed during acceptance** (earlier run on the final build: 19 passed, 3 failed):
  - **Billing overflowed at 390px.** A product bug: the plan table's grid parent lacked `min-width: 0`. Fixed in CSS.
  - **JOURNEY G's command-menu locator matched two options.** Intended: the new *Recent* group lists the visited system too. The test now takes the first.
  - **Settings showed a duplicate "Members" heading while loading.** A product bug, found by the new spec. Fixed.
  - **The billing overflow survived the first fix.** A probe at 390px found the real cause: screen-reader text inside the plan table is absolutely positioned, so it escaped the scroll container and widened the page. Giving the table container `position: relative` fixed it, and the next full run passed 22 / 22.
- **Fixed after the visual review of the contact sheet**, then verified by one more full run (22 / 22) and a full recapture:
  - The detection bar and *ThreatVeil found* said "Claude Code" twice.
  - The Recommended "upload any definition" card used the Claude Code identity for a generic upload. It now uses the neutral *Agent definition* identity.
  - On Evidence, the *Needs fresh evidence* pill overflowed its column into *Why*.

**Backend change scope** (`git diff --stat HEAD -- src/ migrations/ infra/`): 4 files, +451 / −1, nothing in `migrations/` or `infra/`. The diff includes earlier uncommitted waves (the redesign's preview endpoint, and prior edits to `assurance_api.py` / `assurance_intelligence.py`). This wave's part is additive: `detect_format` / `parse_text`, the auto branch of the preview, `stack`, `reliance`, the evidence-record fields, and `id` / `connector` on Home rows. The one removed line is a Home row literal that was extended.

## AR. Screenshot contact sheet

Reproducible with `apps/web/redesign-capture/completion-capture.spec.ts`, then `contact-sheet.spec.ts`. Artifacts are in git-ignored `.local/completion/`: `contact-after.png` (27 screens at one scale), each full-page screenshot in `after/` with `metrics.json`, and the before state in `before/`.

Measured on the final build. The capture uses a fresh organization, a definition upload, and the synthetic example driven by the guided tour and its controls. **Page errors: 0. Horizontal scroll: none**, at 1440px or 390px.

| Screen | Height | Visible eyebrows | Notes |
|---|---|---|---|
| Home — zero state and ecosystem presence | 1000 | 0 | |
| Connect — methods / GitHub configuration required / definition detected | 1081 / 1108 / 1851 | 0 | GitHub stops at *Configuration required* |
| Guided example — step 2 | 1830 | 0 | Tour panel over the real Overview |
| System — current (stack + chain) | 1833 | 0 | |
| Check a change — input / GitHub PR reference result | 1029 / 1157 | 0 | *GitHub · reference · not fetched* |
| System — attention (MCP-origin Change Impact) | 3034 | 0 | Limits and synthetic controls open (§AT 2) |
| Home — attention / Systems | 1000 / 1000 | 0 | |
| Capabilities | 2230 | 3 | Legacy panels (§AT 1) |
| Security claims | 1112 | 0 | |
| Evidence / Evidence detail | 1000 / 1000 | 3* | |
| Activity — assurance history / change preview | 1650 / 1650 | 0 | |
| Changes — detected | 1000 | 0 | |
| Share — Passport | 2580 | 2 | Legacy issuance and document cards (§AT 1) |
| System — Gate and Passport primitives | 1862 | 0 | |
| Integrations | 2274 | 0 | One visible raw token: `$THREATVEIL_TOKEN` in the copyable curl, which is correct there |
| Settings — General / Members / Developer | 1000 / 1000 / 2671 | 0 / 0 / 2 | Developer keeps the legacy token and observer panels |
| Usage & billing | 1202 | 0 | Was 2207px with 8 eyebrows |
| Mobile — home / system | 1139 / 3028 | 0 | |

\* The metric counts `.eyebrow` elements in the closed dependency-mapping disclosure. None is visible on the Evidence screen itself.

Before → after for the surfaces the previous wave left behind: **Settings** 3787px with 5 eyebrows → General 1000px with 0, as five routes. **Usage & billing** 2207px with 8 eyebrows → 1202px with 0. **Evidence** 1771px with legacy cards → 1000px with status and rows. **Activity** 1818px → 1650px as an assurance history.

**Does the product now show the full ThreatVeil story?** Yes, without documentation. The loop is on Home, the chain and change impact are on Overview, what must be re-proved is on Evidence, restoration is in Activity and the tour, and machine and external reliance are on Overview, Integrations and Share.

**Does it look uniquely like ThreatVeil?** The recognisable objects are ThreatVeil's own: the broken-chain track, the directed before → after transition, the dark Gate answer line and the two-fact Passport. Remove the logo and colour, and those remain. Rows, pills, drawers and tables stay deliberately generic.

**Does it clearly belong in the AI-agent ecosystem?** Yes. GitHub, Claude Code, MCP, LangGraph, CrewAI, OpenAI Agents SDK, Claude Agent SDK, Cloud Run and OpenTelemetry appear where they answer a question: connecting, the stack, change sources, and integrations.

**Are all ecosystem claims truthful?** Yes, and they are asserted in the browser. Each identity carries its relationship; no import reads as connected; GitHub and live MCP say *Configuration required* when they are; nothing implies a partnership; the synthetic example shows only MCP, imported.

**Visual consistency.** Viewed without reading, Integrations, System Overview, Settings, Billing and Evidence share one ground, one line weight, the same row rhythm, the same state treatment and the same source tiles. The remaining visual inconsistencies are the legacy panels listed in §AT 1.

## AS. Deliberately not built

GitHub OAuth, repository enumeration, pull-request fetching; live MCP without a verified target; OpenAI Agents definition import (definitions are code); official vendor logos (§F); a PostgreSQL identity (not established); *Verification started* events (not recorded); approve/reject on proposed checks (would change Gate semantics); an AI assistant; new connectors or observers; a trust score or shield; pricing or entitlement changes.

## AT. Remaining post-deployment UX debt

Stated plainly, from the final contact sheet and full-resolution review:

1. **Legacy panels inside new surfaces.** Capabilities (authority rows and the authority diff), the Passport issuance and document cards on Share, the API-token and qualified-observer panels in Settings → Developer, and the synthetic-controls card still use the older card design with uppercase eyebrows (3 on Capabilities, 2 on Share, 2 on Developer in the capture metrics). The consequence-feedback prompt keeps its *WAS THIS RIGHT?* overline.
2. **System Overview is long when it has something to say.** 3,034px with an open change, its limits expanded and the synthetic controls opened; the same at 390px. The order is right; the limits could fold once the change is reviewed.
3. **A backend headline still carries an enum.** A recorded state transition reads *"Configuration changed: … re-proof decision ALLOW"* in Activity. It is the canonical headline and was not rewritten in the UI.
4. **Brand assets.** Identities are neutral monograms until official marks are licensed and approved (§F). This is a deliberate truth-over-polish choice.
5. **Integrations actions are per system**, through a system selector. There is no organisation-wide bulk connect.
6. **Carried over:** literal legacy colours in `globals.css`, the system font stack, marketing and login styles (§B items 10–11, 5), and legacy developer-mode surfaces.
7. **Tooling.** `redesign-capture/final-capture.spec.ts` targets the previous wave's UI and is superseded by `completion-capture.spec.ts`. `scripts/container_acceptance.sh` should be re-run end-to-end once container DNS is available (§AQ).

## AU. READY_FOR_PRIVATE_GCP verdict

**`READY_FOR_PRIVATE_GCP` — unchanged. `cloud_accepted = false`.**

- **No assurance truth changed.** The backend additions are read-only projections, covered by 10 new tests. Tenant isolation, RLS, append-only history, evidence applicability, authority classification, proposed-change non-mutation, Gate and Passport semantics, UNKNOWN handling, billing/security separation and AI proposal-only rules were not touched, and their suites pass (§AQ).
- **No product breadth was added.** No connector, observer, assistant, pricing, vertical or cloud resource. Nothing was deployed, applied or charged, and nobody was contacted.
- **The marketing-truth invariants hold** (§AP) and are asserted in the browser. No import is shown as connected, no unsupported method is offered, and there is no partnership language.
- **The stop condition in the mandate (§73) is met.** Connection is modern and truthful; the stack is factual; the loop is visible end to end in the product and in the guided example; Evidence and Activity are on the new standard; Integrations operate; Settings is organised; proposed-change input matches its result; source identity is clear; Gate and Passport are discoverable and distinctive; the Assurance Chain and Change Impact exist and agree with canonical status; and the regression passes.

This is the last local product-experience wave.

## AV. Exact private-GCP next action

**Private GCP activation, per the accepted Terraform in `infra/`.** Nothing further to build locally first.

1. Commit the working tree: this wave plus the two earlier uncommitted UI waves. Then re-run `scripts/container_acceptance.sh` end-to-end on a machine with working container DNS, and keep its output with the release.
2. Set `NEXT_PUBLIC_TV_CONTACT_LABEL` for the hosted build: the launch wording, or empty to hide the topbar link.
3. Register a read-only GitHub credential reference in the private deployment, so the GitHub live source and onboarding method leave *Configuration required* with a real repository.
4. Proceed with the private GCP activation steps and a design partner. `cloud_accepted` changes only after the cloud acceptance run, not before.
