# Bounded automatic re-proof

Re-proof is the expensive part of change assurance: a change invalidates a claim, and somebody
has to run the check again. Automating that is valuable and dangerous, so ThreatVeil automates
exactly one thing and refuses everything else.

**What it does:** repeat one already-approved verification when its clearance has been lost.

**What it never does:** change a claim, pick a different target, widen scope, run in an
environment it was not approved for, or remediate anything. There is no remediation code path
in this subsystem at all.

## A policy is a standing, explicit permission

`POST /v1/systems/{id}/auto-reproof-policies` requires every precondition to be approved
already:

| Requirement | Enforced as |
|---|---|
| An approved executable claim | the property must exist and be `approved` |
| An approved target | scoped to this system |
| A `QUALIFIED` business-effect observer | qualification checked at approval **and** at every plan |
| One environment | scoped to this system |
| One authority scope | the envelope id and the digest the baseline was anchored to are recorded on the policy |
| A bounded budget | `max_runs_per_window` (1–24) in `window_hours` (1–168), `trial_count` 1–3 |
| A stated reason | 40 characters minimum |
| `confirm_no_remediation: true` | a literal `true`; anything else is a 422 |

The policy records `level: LEVEL_2_3_ONLY` and `remediation: NONE`.

## The planner refuses rather than improvises

`GET /v1/auto-reproof-policies/{id}/plan` returns a decision and the reason, in this order:

| Reason | When |
|---|---|
| `POLICY_DISABLED` | the policy is not enabled |
| `FLAG_DISABLED_OUTSIDE_SANDBOX` | the environment is not a sandbox and `TV_AUTO_REPROOF_ENABLED` is false |
| `CLAIM_NOT_APPROVED` | the claim is no longer an approved executable claim |
| `OBSERVER_NOT_QUALIFIED` | the observer is not `QUALIFIED` any more (expired, revoked, or its contract changed) |
| `AUTHORITY_SCOPE_CHANGED` | the reviewed authority boundary moved after approval |
| `TARGET_CHANGED` | the approved target is not the one the policy was approved for |
| `BUDGET_EXHAUSTED` | the bounded run budget for this window is used up |
| `NOTHING_TO_REPROVE` | clearance is current — so there is nothing to do |
| `ELIGIBLE` | every approved precondition still holds |

Every decision carries the scope it would run in, with `widened: false`, and every execution is
recorded append-only with that scope. A plan is also shown on the policy itself, so the answer
is visible without running anything.

Note the order: a changed authority boundary or a lost observer ends the standing permission
**before** the budget is even consulted. Re-proof under a boundary nobody reviewed is not
re-proof.

## Dispatch

`POST /v1/auto-reproof-policies/{id}/run`:

- if the plan is not `ELIGIBLE`, it records a `SKIPPED` execution with the reason and stops;
- if eligible in a **labelled synthetic sandbox** (the Finance fixture), it dispatches through
  the ordinary verification path a person would use, records `DISPATCHED`, then records
  `COMPLETED` with the decision the verification reached;
- otherwise it records `SKIPPED · NO_QUALIFIED_DISPATCHER` and says so plainly: the plan is
  eligible, and this deployment has no qualified automatic dispatcher for that environment.

That last case is the honest state for a customer environment today. ThreatVeil will not invent
a dispatcher it has not built.

## Outside a sandbox

`TV_AUTO_REPROOF_ENABLED` defaults to `false`. With it false, any non-sandbox policy plans to
`FLAG_DISABLED_OUTSIDE_SANDBOX`, whatever else is approved. Turning it on is a deliberate
deployment decision, and it still cannot widen scope or remediate — the planner's refusals are
not conditional on the flag.

## What would have to be true to widen this

1. A qualified dispatcher for the customer's environment, with its own contract and harness.
2. A cost model the customer sees before it runs (verification budget is already metered).
3. Evidence from at least one design partner that automatic re-proof reduced their restore time
   without surprising them.

Until those exist, this is a foundation with a sandbox demonstration, and it is labelled as one.
