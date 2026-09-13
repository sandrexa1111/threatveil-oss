# Truthful business measurement

A security product that flatters itself cannot be trusted to tell a customer the truth
either. These are the numbers ThreatVeil keeps, what each one means exactly, and what is
deliberately excluded.

Two endpoints serve the tenant (`/v1/measurements/business`, `/v1/measurements/activation`).
The founder's own view is not an endpoint at all: it lives in an operator-only store that the
product API cannot reach (§6).

---

## 1. Provenance: where a consequence came from

Every consequence carries exactly one provenance.

| Provenance | Meaning | Counts? |
|---|---|---|
| `LIVE` | observed from a source ThreatVeil reads itself | yes |
| `IMPORTED` | the customer sent a real snapshot | yes |
| `CUSTOMER` | a customer-recorded state transition or authority declaration | yes |
| `PROPOSED` | a dry run of a change the customer is considering | yes |
| `REPLAYED` | reconstructed history, judged by today's claims | **never** |
| `SYNTHETIC` | a labelled demonstration system | **never** |

Synthetic dominates: any consequence on a demonstration system is `SYNTHETIC`, whatever its
source. The demonstration track shows the whole journey and its `activated` field is
permanently `false`.

## 2. "Was this right?": confirm and dispute

Each consequence carries a customer judgement: `CORRECT`, `PARTIALLY_CORRECT`, `INCORRECT`
or `NOT_SURE`, with an optional 500-character comment.

- It is a separate append-only record bound to a digest of the consequence as it was shown.
- It never edits, re-scores, hides or re-opens the consequence. `effect_on_assurance` is
  `NONE`, and the tests assert the gate and the change view are byte-identical afterwards.
- Later answers are recorded too; the newest verdict per consequence is the one metrics use,
  and the earlier ones remain readable.

## 3. Activation: `FIRST_CONFIRMED_CONSEQUENCE`

Business activation requires, on one **non-synthetic** system:

1. a **determinate claim-level** consequence — it named claims that need fresh evidence
   (`INVALIDATION`) or said none are affected (`NO_IMPACT`); and
2. a real provenance (`LIVE`, `IMPORTED`, `CUSTOMER` or `PROPOSED`); and
3. either a member confirming it `CORRECT`/`PARTIALLY_CORRECT`, or the customer **acting** on
   it — clearance re-established within 7 days of losing it to that change.

"No baseline yet", "no claims defined" and "no change" are recorded and are **not** claim-level
answers, so confirming one of those is not activation.

Each activation carries a `claim_basis`:

- `EVIDENCED` — the answer rested on evidence-backed claims;
- `DECLARED` — it rested on declared, not-yet-verified claims (the Free-tier path).

`activation.qualified` is the strict reading: `EVIDENCED` **and** a `LIVE`/`PROPOSED` change.
Both numbers are reported; neither is hidden behind the other.

`FIRST_MEANINGFUL_ASSURANCE_EVENT` remains the system-side event: ThreatVeil established a
consequence, whether or not anyone read it.

## 4. Precision, with numerator and denominator

Every rate is `{numerator, denominator, value}`, and `value` is `null` when the denominator is
zero. Nothing is ever reported as a bare percentage.

| Metric | Numerator | Denominator |
|---|---|---|
| `confirmed_rate` | `CORRECT` + `PARTIALLY_CORRECT` | decided verdicts (`NOT_SURE` excluded) |
| `fully_correct_rate` | `CORRECT` | decided verdicts |
| `dispute_rate` | `INCORRECT` | decided verdicts |
| `false_invalidation_rate` | `INCORRECT` on an `INVALIDATION` | decided verdicts on invalidations |
| `no_impact_confirmation_rate` | confirmations of `NO_IMPACT` | decided verdicts on no-impact answers |
| `mapped_change_ratio` | fully mapped observed source changes | observed source changes (excluding first observations) |

`value` also reports the four counts that matter commercially: confirmed and disputed
invalidations, confirmed and disputed no-impact answers. **A precise no-impact answer is
value**: for a team that re-tests everything after any change, "this touches nothing" is the
result that saves the week.

`NOT_SURE` is never counted as agreement. Synthetic and replayed feedback is reported as
`excluded_synthetic_or_replayed` and never enters a rate.

## 5. North Star: Relied-upon Protected Systems (RPS), weekly

A non-synthetic system counts in a week when all three hold:

1. **Watched** — a live source reported within 7 days. An import is not a live source.
2. **Maintained** — clearance is current, or was lost within the previous 14 days and is being
   re-established. For the current week, present clearance expiry is applied too.
3. **Relied upon** — at least one reliance event in 7 days: a machine Assurance Gate check, a
   CI check, or an external passport status check.

`WATCHED` and `MAINTAINED` are reported beside it, so a low RPS is diagnosable rather than
mysterious. Gate checks are deduplicated hourly per consumer, so polling cannot inflate it.

**RPS will be zero for a while. That is the correct reading, not a measurement bug.**

## 6. The founder's view is operator-only

Internal commercial measurement lives in `operator_records`, a table the runtime database
role cannot read at all (privileges revoked, row security with no policy for that role). The
product API exposes no route that touches it, and a test asserts that.

Reading it requires the migration identity (`TV_ADMIN_DATABASE_URL`) through the CLI:

```bash
threatveil operator classify <org> --classification CUSTOMER --reason "Signed Assurance Launch"
threatveil operator time <org> --minutes 90 --category CLAIM_AUTHORING --stage MODELING --note "Claim workshop"
threatveil operator prospect acme-support --archetype "Support/refund agent" --source FOUNDER_NETWORK
threatveil operator proof acme-support --event OFFER_REJECTED --offer ASSURANCE_LAUNCH --price-usd 15000 \
  --reason "Wants a live source connected first"
threatveil operator business-report --weeks 12
threatveil operator investor-export --format csv
```

Cross-tenant reading is narrow by construction: the operator session reads the organization
list with an explicitly switched-on GUC, then measures **each organization inside its own
tenant context**, exactly as a tenant request would. Every report run appends an
`operator_access` record.

### Organization classification

`CUSTOMER`, `DESIGN_PARTNER`, `INTERNAL`, `TEST`, or `UNREVIEWED` by default (a real
self-service signup nobody has classified). Local-identity organizations default to
`INTERNAL`. `INTERNAL` and `TEST` organizations are excluded from every business metric, and
the count of what was excluded is reported.

### Staff time

Logged per organization, system, observer, stage and support event, in one of nine
categories: `SYSTEM_MODELING`, `CLAIM_AUTHORING`, `OBSERVER_SETUP`, `DEPENDENCY_MAPPING`,
`BASELINE`, `DEBUGGING`, `SUPPORT`, `CUSTOM_INTEGRATION`, `OTHER`. This is the number that
decides whether ThreatVeil is a product or a consultancy: hours per activated organization,
trending down, or it is not a product yet.

### Commercial proof

Prospect (a pseudonymous handle, never a name or email), qualified, pain confirmed, offer,
price, accepted or rejected with the reason, contract value, kickoff, gate installed, passport
checked, conversion — plus the derived facts for a linked organization (first confirmed
consequence, staff hours). Pricing experiments are grouped by offer and price so acceptance
rates per price point are visible with their denominators.

## 7. What is deliberately excluded

`vanity_metrics_excluded` is part of the report: signups, page views, sessions, synthetic
demonstration runs, API calls, and passports issued without an external check. None of them
measures whether anyone relies on ThreatVeil.

Also excluded, deliberately:

- no cross-customer aggregation of security data anywhere;
- no revenue ThreatVeil has not been told about by the operator (`contracted_value_usd` comes
  from entered contracts and provider-confirmed paid plans, and zero is a valid answer);
- no inferred intent: a prospect is qualified when the operator says so, not when a heuristic
  decides.
