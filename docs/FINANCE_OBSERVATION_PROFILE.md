# Finance observation profile

The `synthetic-finance-v1` package is an isolated SQL demonstration of three approved claims: beneficiary approval, tenant-bound writes and authorized invoice mutation. It is a qualification aid, not independent customer observation. The controller and observer share one process; no live money, provider or customer resource is involved.

Each trial resets a SQLite database containing the synthetic beneficiary and tenant A/B invoice rows. The capsule's initial-state digest covers those rows. Authorization behavior changes independently of repository history. The observer commits changes and reads state back, retaining before/after values, tenant/resource identity, action phase, correlation and sequence. The positive control is an authorized tenant A invoice update to `reviewed`.

`finance-finality-v1` augments the established `deterministic-v1` evaluator for this package only. Historical evaluator meaning and stored observations are not rewritten. The finance profile requires all four probes (unapproved beneficiary, cross-tenant invoice, unauthorized invoice and legitimate invoice), terminal business-state outcomes and required before/after values. A denial flag contradicting a changed row is inconclusive. Missing ground truth cannot establish a verified failure or success.

The bounded negative modes retain phase distinctions:

| Scenario | Established result |
|---|---|
| Attempt without terminal outcome | Security INCONCLUSIVE even when the separate legitimate invoice succeeds |
| Dispatched operation still pending | Security INCONCLUSIVE; no absence-of-commit PASS |
| Intermediate invoice state committed as `pending_review` | INCONCLUSIVE; legitimate task UNKNOWN |
| Known forbidden beneficiary commit plus pending work | FAIL is retained despite incomplete coverage |
| Forbidden commit later compensated by a committed restore | Original FAIL is retained with both receipts |
| Bad fix denies useful invoice updates | Security may PASS; legitimate task FAILURE prevents supported ALLOW |
| Proper fix with final observed state | Bounded security PASS and legitimate task SUCCESS |
| Missing witness, missing ground truth or omitted adverse probe | INCONCLUSIVE; no supported ALLOW |

Qualification runs eight generated SQL scenarios covering fixed/regressed/bad-fix/missing-witness plus attempt, pending, partial and compensated effects. Dedicated negative tests additionally remove ground truth, omit a tenant probe and contradict a denial with observed mutation. The result's trial verdicts, aggregate outcome, confidence inputs, evidence evaluator version and coverage use the finance profile. Original recorded observations remain intact.

Source changes are a separate input. An explicit finance fixture in a SANDBOX environment can discharge a one-shot imported hint with a fresh full finance assessment; the source remains IMPORTED and unqualified. Real external facts cannot disappear because another test ran later. Their component identities must enter approved dependency coverage, and qualified observed state must match the relevant after-values. Gaps, configuration changes and unmapped facts remain review obligations. No deployment attestation or selective re-use authority is created by this fixture.

Validation lives in `tests/core/test_finance_finality.py`, `tests/core/test_source_reconciliation.py`, `tests/integration/test_connectors.py` and the canonical change-assurance suites. Customer deployment, independent observers, effective IAM, asynchronous finality windows and real business semantics require separate acceptance.
