# Assurance Gate — consumer contract

The Assurance Gate is the machine-consumable answer to one question:

> **Is this system still cleared to act?**

It is the single contract every future consumer (CI, GitLab, Kubernetes admission, a deployment pipeline, an agent runtime or gateway, an IAM workflow, ServiceNow, an enterprise buyer's system) reads, so no integration has to redefine ThreatVeil. ThreatVeil supplies assurance truth. **The consumer decides its own availability policy.** No response ever grants a permission.

## Request

```
GET /v1/systems/{system_id}/assurance/current
    ?environment_id=<uuid>                 optional; defaults to the environment with the latest state
    &action=<consequential action>          optional; adds a scoped answer for one authority
    &expected_state_digest=<sha256 hex>     optional; the state the consumer believes is current
Authorization: Bearer tvk_…                 a read-only API token is sufficient
X-ThreatVeil-Consumer: ci-gate              optional bounded label [a-z0-9][a-z0-9_.-]{0,39}
```

Tenant isolation is enforced by PostgreSQL FORCE RLS: another tenant's system returns 404. Clients: `ThreatVeilClient.current_assurance()` (Python), `ThreatVeilClient.currentAssurance()` (TypeScript), `threatveil assurance-current SYSTEM --require-cleared` (CLI, exit 2 unless cleared). Schema: [`schemas/assurance-gate-v1.schema.json`](../schemas/assurance-gate-v1.schema.json).

## Response (abridged)

```json
{
  "schema_version": "threatveil-assurance-gate/v1",
  "status": "SUPERSEDED",
  "action": "ALLOW",
  "cleared": false,
  "authorizes": false,
  "system": {"id": "…", "name": "Finance Agent"},
  "environment": {"id": "…", "name": "Finance sandbox", "purpose": "SANDBOX"},
  "state": {"id": "…", "digest": "…", "envelope_digest": "…"},
  "authority": {"envelope_digest": "…", "policy_epoch": 1, "reviewed_until": "…"},
  "decision": {"id": "…", "action": "ALLOW", "issued_at": "…", "signed_statement_expires_at": "…",
               "signed_statement_live": false, "status_uri": "…", "record_uri": "…"},
  "claims": {"total": 3, "supported": 2, "affected": [{"title": "Beneficiary changes require finance approval", "status": "NEEDS_FRESH_EVIDENCE"}]},
  "scope": {"action": "invoice.update", "declared": true, "status": "SUPPORTED", "cleared": false},
  "obligations": [{"kind": "RE_VERIFY", "subject": "…", "reason": "…"}],
  "reasons": ["The system changed after this clearance was issued."],
  "freshness": {"evaluated_at": "…", "max_age_seconds": 60, "valid_until": "…"},
  "consumer_contract": {"UNKNOWN": "…", "cleared": "…", "cache": "…", "availability": "…", "offline": "…"}
}
```

Raw domain objects (ProofScopes, evidence bodies, support digests, internal reasons) are deliberately not exposed.

## Status semantics

| Status | Meaning | `cleared` |
|---|---|---|
| `CURRENT` | The latest clearance for this exact state still holds. | only if `action` is `ALLOW` |
| `SUPERSEDED` | The system was **observed** to change after issuance: a later observed state, an observed source change that moved the clearance's support, or a state digest that differs from the consumer's `expected_state_digest`. | false |
| `REASSESS` | Support moved **without** an observed change: evidence, source continuity (for example a live source outage) or release eligibility. | false |
| `EXPIRED` | The reviewed authority boundary or the exact-state observation the clearance relied on has lapsed. | false |
| `REVOKED` | Someone withdrew the clearance explicitly. | false |
| `UNKNOWN` | ThreatVeil cannot establish clearance (no environment, no state, no decision). **Never treat UNKNOWN as authorization.** | false |

`cleared` is true only when `status == CURRENT` and `action == ALLOW`. The helper `is_cleared()` / `isCleared()` also requires the answer to be within `freshness.valid_until`, and therefore fails closed.

### The scoped answer

With `?action=`, `scope.status` reports whether the claims governing that one authority are supported: `SUPPORTED`, `NEEDS_FRESH_EVIDENCE`, `FAILED`, `UNGOVERNED` (declared, but no approved claim governs it) or `UNDECLARED` (outside the reviewed authority boundary). `scope.cleared` additionally requires the system-level clearance. A consumer may therefore see that `invoice.update` is still supported while the system clearance is `SUPERSEDED` because of a beneficiary change. How to act on that is the consumer's policy, not ThreatVeil's.

## Freshness and caching

- An answer is valid until `freshness.valid_until`: at most 60 seconds, and never beyond the authority review or observation expiry.
- HTTP responses carry `Cache-Control: no-store` because they contain tenant data. Consumers may keep a private copy until `valid_until`.
- The signed decision (`decision.record_uri`) has its own five-minute statement lifetime. `signed_statement_live=false` does **not** mean the clearance lapsed. The gate's `status` is recomputed on every request, and that recomputed status is what the lifetime field refers to.

## Offline authenticity vs online current state

| Question | How |
|---|---|
| Did ThreatVeil issue this exact decision at that time? | Verify the DSSE record offline (`verify_change_record_with_directory`) against `/v1/trust/keys`. |
| Is it still current? | Call the gate (online). Offline verification never establishes current status. |

## Availability

If ThreatVeil is unreachable, the consumer applies its own fail-open or fail-closed policy. ThreatVeil does not impose one. For consequential write authority, fail-closed with a human override is the conservative default.

## Consumption as operational dependency

Each consumer label is recorded at most once per hour as a minimized `service_metric` (`assurance_gate.checked`, with the label and whether a machine token or a person asked). That makes "machines check ThreatVeil" a measurable retention signal without logging request bodies.
