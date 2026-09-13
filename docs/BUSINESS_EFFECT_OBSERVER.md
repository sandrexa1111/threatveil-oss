# The Business Effect Observer Contract

An observer answers one question: **did the business effect commit in the system of record?**
That answer is worth exactly as much as the contract behind it, so ThreatVeil makes the
contract explicit, earns qualification through a fixed harness, and lets it go stale.

Two invariants hold everywhere in this subsystem:

1. **Missing evidence is never evidence of no effect.**
2. **A compensation never erases a commit that happened.**

---

## 1. What a contract must declare

`POST /v1/systems/{id}/observer-definitions`

| Field | Why it is mandatory |
|---|---|
| `system_of_record` | Which system durably holds the effect. Not the agent, not the gateway |
| `resource` | What is being watched |
| `observed_effects` | Which of `ATTEMPTED`, `AUTHORIZED`, `DISPATCHED`, `COMMITTED`, `DENIED`, `COMPENSATED`, `UNKNOWN` this observer can actually see |
| `actions` | The consequential actions it covers |
| `correlation` | How an attempt is tied to a record: `CORRELATION_ID`, `IDEMPOTENCY_KEY`, `RESOURCE_VERSION` or `TIME_WINDOW` — and a note. A time-window correlation must state what it cannot distinguish |
| `read_method` | `READ_ONLY_SQL`, `HTTP_READ`, `LOG_READ` or `MANUAL_EXPORT`. `writes` is structurally `false` |
| `commit_semantics` | What "committed" means there: `COMMITTED_TRANSACTION`, `APPEND_ONLY_LOG`, `EVENTUALLY_CONSISTENT` or `UNKNOWN` |
| `observation_window_seconds` | How long after an attempt a record may still appear (≤ 24 h) |
| `coverage_limits` | At least one. What this observer cannot see |
| `failure_semantics` | On unreachable: `UNKNOWN`, always. On ambiguous: `UNKNOWN`, always. On a missing record: `UNKNOWN`, or `DENIED` **only** if the contract covers commits and says why |
| `requalify_days` | When qualification goes stale (default 90) |

An observer that does not see `COMMITTED` may never read absence as `DENIED`. That is refused
at the API boundary, not left to discipline.

## 2. Qualification states

| State | Meaning |
|---|---|
`UNQUALIFIED` | No attempt yet. Facts are recorded; they are not evidence |
`QUALIFICATION_PENDING` | An attempt exists but did not pass every scenario |
`QUALIFIED` | Passed **every** scenario for this exact contract, and a person reviewed it |
`REVOKED` | Withdrawn. History stands; new facts are not evidence |
`STALE` | Expired, or the contract changed after qualification was granted |

Qualification is bound to a digest of the contract. Submitting a harness result for a
different digest is a 409. Facts carry the qualification state **at the time they were
recorded**, so an earlier unqualified fact never becomes evidence retroactively.

## 3. The qualification harness: ten scenarios, one required answer each

| Scenario | Required answer |
|---|---|
| `POSITIVE_COMMIT` | `COMMITTED` |
| `DENIED` | `DENIED` |
| `NO_EFFECT` (no record, observer covers commits) | `DENIED` |
| `COMPENSATED` | `COMPENSATED` |
| `MISSING_CORRELATION` | `UNKNOWN` |
| `STALE` (candidate outside the window) | `UNKNOWN` |
| `MULTIPLE_MATCHES` | `UNKNOWN` |
| `OUTAGE` | `UNKNOWN` |
| `WRONG_TENANT` | `UNKNOWN` |
| `INSUFFICIENT_COVERAGE` | `UNKNOWN` |

One deviation fails qualification. An observer that raises instead of answering fails that
scenario. Six of the ten require the observer to **refuse to answer**, which is the point:
most of an observer's value is knowing when it does not know.

```python
from threatveil.observer_platform import run_harness
result = run_harness(lambda scenario: my_observer(scenario))   # {"outcome": "PASSED"|"FAILED", ...}
```

Then record it with the contract digest, the harness version, an evidence reference and a
human review note. `PASSED` plus review is the only path to `QUALIFIED`.

## 4. The read-only PostgreSQL observer

`threatveil.observer_sql` is a generic observer for any system of record that keeps its
effects in PostgreSQL. It has **no arbitrary SQL**:

- the operator configures a schema, a table and the columns carrying correlation, state,
  time, resource and tenant;
- identifiers are validated against `^[a-z_][a-z0-9_]{0,62}$` and composed with
  `psycopg.sql.Identifier`;
- the statement runs in a `READ ONLY` transaction with `SET LOCAL statement_timeout` and a row
  limit, and the connection is rolled back;
- the connection string is never stored in a record: it comes from an operator-provisioned
  environment variable named by a slug (`TV_OBSERVER_DSN_<SLUG>`);
- source states map to the observer vocabulary through a bounded, reviewed `state_map`. An
  unmapped state is `UNKNOWN`, never a guess.

Its refusals are deliberate:

| Situation | Answer |
|---|---|
| Two indistinguishable matching rows | `UNKNOWN` |
| A row with this correlation value in another tenant | `UNKNOWN` — correlation collision detected |
| The only candidate is outside the observation window | `UNKNOWN` |
| Unreachable, timed out, or any database error | `UNKNOWN` |
| No record anywhere, and the contract covers commits | `DENIED` |

## 5. What a set of facts establishes

`GET /v1/observer-definitions/{id}/effects?correlation_value=…`

| Result | Meaning |
|---|---|
| `COMMITTED` | The system of record durably holds it |
| `COMMITTED_THEN_COMPENSATED` | It committed and was reversed. `committed` stays `true` |
| `DENIED` | A control refused it before any effect could commit |
| `NO_EFFECT_OBSERVED` | Commit coverage plus no record inside the window |
| `UNKNOWN` | Anything else, including "no facts at all" |

Only facts recorded while the observer was `QUALIFIED` count toward the conclusion;
unqualified facts are reported separately and never upgrade it.

## 6. Writing your own observer

An observer is anything that can answer the ten scenarios and then report facts:

```bash
curl -X POST "$TV_API_URL/v1/observer-definitions/$ID/observations" \
  -H "Authorization: Bearer $TV_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"correlation_value": "refund-9", "effect": "COMMITTED", "action": "refund.issue",
       "resource_reference": "refund/9", "observed_at": "2026-09-12T10:04:11+00:00",
       "record_digest": "…", "idempotency_key": "obs-refund-9-commit"}'
```

Rules the API enforces: the effect must be inside the declared contract (or `UNKNOWN`), facts
are idempotent per key, a revoked observer cannot record new facts, and the observation time
must carry a timezone.

## 7. Known limitations

- ThreatVeil cannot verify that the system you named is the real system of record. That is a
  human review, recorded in the qualification note.
- Coverage limits are declarations. A wrong declaration produces a confident wrong answer, and
  that is exactly what the harness and the review exist to catch.
- An observer is not an enforcer. It witnesses effects; it never prevents them.
