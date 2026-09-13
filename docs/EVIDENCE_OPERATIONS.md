# Evidence and memory operations

Implemented locally on 7 September2026. GCP calls have contract tests with a fake storage client; real bucket/IAM/lifecycle acceptance awaits access.

## Capture and finalization

Every active HTTP/MCP/model-adapter trial has a server-derived correlation tied to run, variant and index. The broker consumes a signed run lease for `/v1/observe`; local execution takes the same run-state lock and capture path. A slot can be retried with identical evidence; different evidence cannot replace it. The frozen approved observer and separate ground-truth signatures must verify before the evaluator can trust customer receipts.

Raw normalized observation JSON is stored as `raw/{organization UUID}/{run UUID}/{SHA256}.json`. Local objects are exclusive-created with mode0600. GCS writes use `if_generation_match=0`; references pin the returned generation. No worker receives Storage permissions. Reads validate the authorized tenant/run namespace, recorded generation, byte length and SHA256 before decoding.

PostgreSQL retains immutable capture metadata, observation digest, evaluator output, server evaluation time and raw-object reference. Completed external results contain capture IDs and compact per-trial evaluations. Finalization reconstructs the verdict from durable captures; it never trusts a submitted aggregate PASS. Stored server acquisition times preserve the original freshness decision during a longer experiment.

A confirmed prohibited outcome remains FAIL/BLOCK even if a later trial errors, the evidence budget is exhausted, the worker expires or target authorization is revoked. Incomplete execution cannot verify a fix. A run that is still executing exposes a captured FAIL immediately. Reconciliation finishes durable completion receipts exactly once and never automatically replays expired claimed work.

## Bounds and retention

The adapter response limit is1MiB; normalized stored objects are capped at2MiB. Aggregate raw capture budget is16MiB per run. Before starting another trial, the runner requires room for the maximum next capture. This deliberately may stop before all16MiB are consumed. Reduce sample count or collector payload if the experiment exceeds this budget; incomplete coverage is visible.

New external raw captures expire after30days. The scoped capture endpoint returns410 on recorded expiry or missing local raw evidence. Evaluation summaries, hashes, fingerprints, fixes, baselines and release history remain. GCP lifecycle deletes the `raw/` namespace after30days and retains a separately configured7day soft-delete recovery window. Local reconciliation removes expired files only from ThreatVeil's UUID/digest raw namespace. This is not a promise of immediate physical deletion.

User-authored findings, approved properties, replay stimuli/fixtures and imported frozen trace inputs are intentional durable memory, not automatically subject to the raw capture timer. Synthetic fixture observations may remain inline in synthetic results. Do not put live credentials in these fields. Customer-specific deletion/retention agreements and managed database backup retention must be resolved before production onboarding; there is no self-service irreversible organization erasure endpoint in v1.

## Inspection and export

- `GET /v1/runs/{run}/evidence`: finalized compact result, scope, statistics, digest and limitations.
- `GET /v1/runs/{run}/captures/{capture}`: authorized retained observation plus evaluation/reference; expired raw objects are explicit.
- `GET /v1/memory/export`: organization-bound NDJSON manifest, all exported immutable records and their included edges, then a required `complete` trailer. Export is available to owner/admin/security roles. Credentials, auth material and pending outbound messages are excluded. Retrieve raw capture bodies separately before expiry.
- System JSON/escaped-HTML reports state their recent-detail limit; their summary counts cover the system's full history. Workspace lists support bounded keyset pages and exact totals.

Hashes detect accidental corruption and inconsistent object references. They do not make an administrator-controlled database cryptographically tamper-proof or certify a customer's collector. Source qualification is scoped evidence of successful reviewed controls, never an assertion that the collector cannot be compromised.

## Failure handling and telemetry

Unexpected HTTP errors are intercepted before framework traceback logging can expose exception text or SQL parameters. Structured operational events contain allowlisted opaque IDs, statuses, duration and exception type. Request bodies, query strings, tokens and raw observations are excluded. Sentry disables local-variable capture and removes request/exception text and user context. Debug logging of provider SDKs is not part of the supported production profile.

The release gate remains blocked by evidence/storage failure where complete evidence is required. Use the request/run ID to inspect authorized records; never paste raw customer evidence into operational logs or outbound support systems.

## Retained semantic relationships

New qualified captures retain the tool, operation, action phase, source/version, violation/control labels and before/after state digests for relevant security receipts. Principal, tenant and resource identifiers become stable organization-bound references; arbitrary before/after values are not copied into those facts. The references are pseudonymous, not anonymous. The observed fingerprint and server-derived qualification provenance also remain, allowing a known failure to continue blocking an unchanged artifact after raw expiry.

`POST /v1/memory/query` accepts optional `tool`, `operation`, `principal_id`, `resource_id`, `resource_type`, `limit` and cursor filters. It is a read operation with cookie CSRF protection; a POST body keeps queried identities out of URL logs. Results contain scoped capture/run references and matching confirmed-violation facts. Deliberately prohibited observer qualification controls are excluded. The Python/TypeScript SDKs expose this operation. Older unindexed records are still exportable; an empty search is not proof that no failure ever occurred.
