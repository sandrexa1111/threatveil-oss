# Re-proof

POST /v1/proof-plans records the candidate, complete fingerprint, optional previous fingerprint, active approved properties, invalidations, reused evidence and one bounded obligation for every property lacking sufficient applicable proof. Callers cannot omit a property by supplying a subset. Trial/variant requirements are part of each obligation.

POST /v1/proof-plans/{id}/execute accepts exactly one run per obligation, matching system, candidate, fingerprint and coverage. Qualification controls cannot discharge release obligations. Existing target authorization, budgets, idempotency and worker isolation apply. Each accepted run retains its durable idempotency key and a proof_execution association.

Execution is a multi-run orchestration, not a cross-run transaction. If an individual request is rejected, the response records ACCEPTED, PARTIAL or REJECTED plus per-property failures and accepted runs. Accepted runs continue; a rejected obligation supplies no evidence. Retry with stable run idempotency keys after resolving the failure. Release creation always reevaluates all properties and does not treat successful dispatch as a passing result.

The local demo executes an actual obligation against the synthetic regressed configuration, then records BLOCK. It restores the tested fixed configuration and records ALLOW. Automated patch generation, customer code modification and unattended re-proof from a GitHub push are not implemented.
