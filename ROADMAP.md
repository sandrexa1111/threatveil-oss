# Roadmap

These are the directions that would turn ThreatVeil's model into something that works beyond its
synthetic demonstration. **None of it is a promise**: there is no company, schedule or funding
behind it. The roadmap exists so contributors and researchers can see where the real gaps are and
pick one up.

Each item links to evidence in [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md) and to the
[product reality and gap audit](docs/history/THREATVEIL_PRODUCT_REALITY_AND_GAP_AUDIT.md). Gap IDs
such as G1 refer to its §AL. Anything that changes what ThreatVeil reports as verified or current
follows the [assurance-semantics rule](CONTRIBUTING.md#the-assurance-semantics-rule).

## P0: Generic assurance loop

Make "reach, lose and regain verified assurance" work on a system that is not the fixture.

- **Generic restoration (G1).** After a source-observed change, restore assurance when a qualified
  observer re-observes the changed fact's after-state, or when the mapped claims are re-verified on
  the new state. Today this requires exact internal digests that only `finance-v1` supplies.
- **Observer unification (G2).** One observer concept that yields evidence. The Business Effect
  Observer Contract becomes the abstraction and signed collectors become its implementation.
- **Generic verify-and-decide (G7).** Productize run → plan → release → state → decision, which is
  composed only for the fixture today.
- **Truth fixes (G4).** Operator surfaces must never be more optimistic than the Gate. A declared-only
  state stays in attention, a Passport requires at least one supported claim, and setup stages are
  computed in the backend.

## P1: Continuous watching

Make "watching" true.

- **Source scheduling (G3).** Collect connected sources on a schedule instead of only on request.
- **Source freshness.** Freshness should degrade *watching*, not unsupport every claim at once.
- **Source health and loss notifications (G11).** Email and signed webhooks when assurance is lost.

## P2: System intelligence

Understand more of what a system can actually do.

- **Code-defined agents (G22).** Export or analysis for LangGraph and OpenAI Agents SDK, where tools
  live in code.
- **Effective permissions and tool constraints (G8).** Numeric limits, schema bounds and MCP
  annotations, which are `UNKNOWN_IMPACT` today.
- **Deployment binding (G15).** Tie evidence to what is deployed (Cloud Run, Kubernetes and others),
  and define production-environment semantics beyond the current 24-hour, staging-only bound.
- **Mappings in force (G16) and a mapping UX (G10).** Judge history by the mappings that applied at
  the time, and make mappings survive reinstallation.

## P3: Ecosystem

- **Framework and platform adapters:** additional agent-definition formats, GitHub contents
  collection at the pull-request head with a Checks API result (G9), and identity-provider and
  data-scope sources (G23).
- **Observer packages:** reference SQL and HTTP business-effect observers, and a collector SDK that
  signs, fingerprints dependencies and runs trials (G5).
- **Gate consumers:** examples for CI systems, policy engines and admission controllers that
  consume the Gate without treating it as authorization.
- **Trust distribution (G18):** operator key rotation, KMS custody and transparency logs.

## P4: Research

- **Evidence applicability:** can we measure false-ALLOW and false-VOID rates of scope decisions,
  and replace or assist the human-reviewed compatibility allowlist?
- **Authority graphs:** composing authority across agents, tools and delegated identities.
- **Change-effect learning:** predicting which claims a class of change tends to reach, without
  letting predictions become evidence.
- **Portable assurance:** a vendor-neutral, verifiable format for "this conclusion still applies"
  that other tools could issue and consume.
- **Statistical independence** of repeated trials under customer-managed resets.
- **Formal semantics** of evidence validity and invalidation.

## Out of scope

Runtime firewalls, identity providers, SIEMs, universal trust scores, remediation agents, and
production enforcement without a qualified enforcement partner are out of scope. ThreatVeil should
consume or export to those systems, not become them.

## How to help

Open an issue that names the item, propose the smallest step that moves it, and include the negative
test that shows it cannot overstate assurance. Issues labelled `good first issue`, `help wanted` and
`research` are the easiest entry points.
