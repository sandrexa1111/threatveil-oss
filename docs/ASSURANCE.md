# Candidate canaries and selection audits

These APIs assess existing, explicitly identified execution evidence. They do not launch trials, consume execution allowance, approve production deployment, or inspect opaque provider internals. Historical snapshots are immutable; current assessments are recomputed on detail reads.

## Canary contract

`POST /v1/canaries` accepts:

```json
{
  "system_id": "SYSTEM_UUID",
  "candidate": {
    "type": "application_version",
    "id": "SYSTEM_UUID",
    "version": "release-version",
    "digest": "EXPECTED_SHA256_CONTENT_DIGEST"
  },
  "pairs": [
    {
      "baseline_id": "BASELINE_UUID",
      "candidate_run_id": "EXISTING_RUN_UUID"
    }
  ]
}
```

The request contains 1–25 pairs, with one immutable property counted once. A pair can omit its candidate run to record a coverage gap. Application/model candidates require a 64-character lowercase SHA-256 digest. Git candidates use an identical version/digest containing the 40- or 64-character commit identifier, and their execution must have the existing verified workflow binding. A version label alone does not establish exact candidate identity.

Baseline, run, system, property, target, and organization relationships must match. Foreign relationship pairs are rejected. A normal canary can only preserve a property when the candidate is actively qualified, observed, complete, useful, and compatible with the historical baseline. A synthetic or self-reported PASS is insufficient.

| Classification | Meaning |
|---|---|
| `PRESERVED` | The exact candidate has a compatible, qualified useful execution for this property |
| `REGRESSED` | Compatible historical comparison confirms recurrence/degradation |
| `STALE` | Target/observer authorization is no longer active, or candidate evidence is outside the time window |
| `INCOMPATIBLE` | Candidate identity or comparison design does not match |
| `UNKNOWN` | Required evidence, observation qualification, coverage, or useful behavior is missing |

Confirmed failures always block. An inconclusive or mismatched row never becomes `ALLOW`; non-passing rows follow the property's blocking/warning policy. `ALLOW` covers the explicitly requested pairs, not every property of an organization or a replacement GitHub release authorization.

The current assessment also checks retained adverse history. A successful retry cannot clear a confirmed failure for the same system, immutable property, target, reviewed observation binding, signed candidate content, and observed configuration. Changing the caller's candidate label, challenge payload, sample count, fingerprint ordering, or provenance labels does not erase that memory. Qualification controls are excluded. A new observed artifact or configuration can be verified against the original challenge; changing collector scope still requires compatible qualified replay.

The selected sample can remain `PASS` while release is blocked. A canary reports `UNKNOWN` with `adverse_memory` references when another run contradicts its selected passing evidence; it does not invent a compatible historical regression from a differently scoped challenge. A selection audit reports `FAILED` when its candidate has a retained, qualified failure, including when the supplied run was a passing retry. An unresolved legacy failure with unavailable exact observation remains blocking without being asserted as a newly proven regression.

The guard reads server-persisted capture provenance and configuration, including a failure captured before a later timeout or transport error. Raw observation expiry after 30 days does not clear the retained decision evidence. The guard has no date or latest-N cutoff. This is scoped customer memory, not a claim that a digest reveals hidden model-provider internals. Historical saved snapshots remain unchanged; current reads and fix eligibility must respect later contradictory evidence.

The initial freshness policy is **24 hours from candidate run creation**, including on rechecks. It is returned as `max_evidence_age_hours: 24`. Baselines represent historical memory; they do not become current candidate proof by being selected. A current assessment describes recent evidence and current authorization, not a live assertion that an unchanged deployment is still serving traffic.

## Selection audit contract

`POST /v1/selection-audits` accepts `impact_id`, the same typed `candidate`, and `candidate_run_ids` containing zero to 500 existing run IDs. Runs must uniquely map to properties in the impact's selected/excluded partition. Empty or partial input records missing coverage; it does not prove the absence of selection misses.

The audit verifies that the immutable impact covers the entire approved property scope that existed when it was created. It requires the observed candidate's complete fingerprint configuration to match the impact's expected configuration. Declared expected values do not excuse unobserved actual components. If new properties have since been approved, the historical snapshot stays intact but the current full-suite assessment becomes incomplete and blocking.

`missed_failure_property_ids` identifies properties the selector excluded despite qualified observed failures. `selected_failure_property_ids` identifies failures that the selector included. Such rows use `FAILED`, not `REGRESSED`: an audit does not invent a historical baseline comparison. Missing, stale, incompatible, or unqualified runs keep the audit incomplete.

## Reads and workflow

`GET /v1/canaries/{id}` and `GET /v1/selection-audits/{id}` return the frozen `snapshot`, its digest, and a recomputed `current` assessment. Both assessments contain rows, counts, `complete`, `release_action`, `checked_at`, and limitations. A current read can become stale or blocking without rewriting the original snapshot.

The list endpoints accept optional `system_id` and `limit` from 1 to 50. They return saved snapshots with `history_only=true`; a list item is not a current assurance decision. Fetch detail to reassess. Tenant readers may read their authorized records; creating assessments requires a mutating role. These assessments do not grant extra execution or billing permissions.

Use the workflow: execute an approved, budgeted candidate suite → create canary or selection audit → review coverage and evidence → use the independently configured release gate. Fix source/target qualification or collect missing evidence instead of treating missing observations as success.

Verification is in `tests/integration/test_assurance.py`, using actual tenant persistence and signed observations from the controlled procurement sink over simulated HTTP. This does not constitute validation against a live customer's deployment or proof of provider-internal behavior.
