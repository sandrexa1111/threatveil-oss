# Taking your data with you

A security memory you cannot leave with is a hostage, not an asset. `GET /v1/memory/export`
streams your organization's whole record set as newline-delimited JSON.

```bash
curl -sS "$TV_API_URL/v1/memory/export" -H "Authorization: Bearer $TV_API_TOKEN" > memory.ndjson
wc -l memory.ndjson
jq -r 'select(.type=="record") | .kind' memory.ndjson | sort | uniq -c | sort -rn
```

The export requires the SECURITY role set (owner, admin or security): it is the whole tenant's
memory, so it is not a developer-level read.

## What the stream contains

| Line type | Meaning |
|---|---|
| `manifest` | schema version, organization, generated-at, and the cutoff the export was taken at |
| `record` | one immutable record: `id`, `kind`, `created_at`, and the full payload |
| `edge` | one relationship between records (`source_id`, `target_id`, `relation`) |

Records are streamed in `(created_at, id)` order and paginated internally, so a large tenant
exports without loading into memory. Re-running the export after the cutoff returns the same
history plus anything newer.

## Coverage

**103 record kinds** are exportable — every kind ThreatVeil writes for a tenant, including the
whole change-assurance set: systems, environments, authority boundaries, states, observed
changes, source batches and assertions, source health, connector installations, dependency
mappings with their proposals and reviews, claim definitions, assurance cases, authorization
decisions, enforcement requests and acknowledgements, status events, passports with their
shares and revocations, consequence feedback, proposed-change assessments, observer definitions
and business-effect observations, auto-re-proof policies and executions, AI usage, and the audit
trail.

A test (`tests/core/test_export_coverage.py`) reads the source, finds every record kind the code
writes, and fails if one is neither exportable nor explicitly excluded. Coverage cannot silently
regress as the product grows.

## The one deliberate exclusion

`credential` records are never exported. A credential record names a **secret-manager version**
for a credential you own: it is deployment secret material, not portable customer memory.
Exporting it would copy a pointer to a secret into a file that then travels. Organization
erasure still removes these records.

Everything else is yours, including records ThreatVeil wrote about its own behaviour toward you:
service metrics, AI usage, commercial interest, entitlements and billing events.

## Evidence objects

The export carries records and relationships. **Raw evidence objects** (captured artefacts
referenced by `trial_capture` records) are stored separately and retained per your plan's
retention allowance; the records name them by key and digest. Request raw objects through the
governance path if you need the bytes as well.

## Erasure

Export and erasure are separate, deliberate operations. Erasure is owner-requested, recorded,
and scoped to one organization; it removes tenant rows (including `operator_records` attached to
that organization) under an explicitly scoped identity. Export before erasing: afterwards there
is nothing left to export, which is the point.

## Reading the export elsewhere

Every record carries its `schema_version`, so a consumer can branch on the version rather than
guess. The published JSON Schemas for the signed artefacts (`schemas/`) describe the passport,
gate and receipt documents you may have shared externally; those remain verifiable offline with
the trust directory, independently of this export and independently of ThreatVeil.
