# Declared change impact, and the claim builder

A customer can state what must be true about their agent in minutes. Proving it takes
longer. ThreatVeil refuses to blur the two, and it refuses to be useless in between.

## The four verification levels, never merged

`GET /v1/systems/{id}/claims`

| Level | What it means | What ThreatVeil will say |
|---|---|---|
| `DECLARED` | Stated in business language. No dependencies declared | Nothing about changes; it is a statement on the record |
| `NOT_YET_VERIFIED` | Declared **with** dependencies | Which changes reach it — and never that it is supported |
| `QUALIFIED` | An approved executable claim with a qualified observer exists | Evidence can support it; whether it currently does is a separate question |
| `CURRENT` | Supported by evidence produced for the system as it is now | It holds, for this exact state |

A declared claim is **never** reported as supported, never counted as evidence, and never
enters the Assurance Gate's `claims` list. The ladder is reported with counts per level and
the next step for each claim, and `claim_ladder` carries the principle in the payload so an
integrator cannot accidentally collapse it.

## What a declared claim buys you immediately

Once a claim declares its dependencies and one mapping is approved, ThreatVeil can answer the
question the customer actually has:

- on an observed change: `declared_effect: DECLARED_CLAIMS_AFFECTED` with the claims named, and
  the narrative line *"It reaches N declared claims not yet verified … prove it to make this
  consequence evidenced"*;
- on a proposed change: the same answer before shipping
  (`docs/PROPOSED_CHANGE_ASSURANCE.md`);
- in measurement: a confirmed declared-claim consequence activates with
  `claim_basis: DECLARED`, and the strict `qualified` reading stays `false` until evidence
  exists.

This is the Free-tier job: *tell me which of my stated rules this change touches*. It is real
value and it is honestly labelled, which is why the next step is always visible: **now prove
it.**

## The claim builder

`GET /v1/claim-templates` → ten reviewed patterns, every one labelled
`STARTER TEMPLATE / NOT VERIFIED FOR YOUR SYSTEM`:

`APPROVAL REQUIRED`, `TENANT ISOLATION`, `MAXIMUM TRANSACTION LIMIT`, `READ-ONLY BOUNDARY`,
`PRODUCTION DEPLOY REQUIRES APPROVAL`, `REFUND LIMIT`, `EXTERNAL MESSAGE APPROVAL`,
`PRIVILEGED ACTION REQUIRES HUMAN CONFIRMATION`, `NO CROSS-TENANT WRITE`, `TOOL ALLOWLIST`.

Plus thirteen domain-neutral starter actions: `read`, `create`, `update`, `delete`, `send`,
`refund`, `pay`, `provision`, `deploy`, `approve`, `grant`, `revoke`, `execute` — and any
action you type yourself. Nothing in the builder assumes finance, support or infrastructure.

`POST /v1/claim-templates/draft` fills a pattern in for your resource and returns a **draft**:
nothing is recorded, `establishes_evidence` is `false`, and the next steps say plainly that it
stays `NOT_YET_VERIFIED` until an approved executable check with a qualified observer is bound
to it.

No model is involved in any of this.

## The fields a claim carries

| Field | Purpose |
|---|---|
| `claim` | The sentence a business owner would recognise |
| `action` | The governed consequential action |
| `resource` | What it governs |
| `permitted_outcome` | What the agent is allowed to do |
| `forbidden_outcome` | The outcome that must never commit — stated precisely, because this is what gets tested |
| `legitimate_task` | The useful work that must keep succeeding. Blocking useful work is not a fix |
| `ground_truth_source` | What could observe the effect independently of the agent |
| `expected_conditions` | The conditions that must hold |
| `declared_dependencies` | What the claim relies on, so changes can be scoped to it |
| `template_id` | Which pattern it started from, if any |

## From declared to current

1. Declare the claim and its dependencies (minutes).
2. Approve the mappings that connect your source's facts to those dependencies
   (`docs/DEPENDENCY_MAPPING.md`).
3. Bind an approved executable claim — the check that attempts the forbidden outcome and
   confirms the legitimate task still works.
4. Declare and qualify a business-effect observer
   (`docs/BUSINESS_EFFECT_OBSERVER.md`).
5. Establish a baseline. Now the claim can be `CURRENT`, and a change can take it away again.

Steps 1–2 are self-service. Steps 3–4 need evidence production, which today requires
expert setup (see `docs/KNOWN_LIMITATIONS.md`).
