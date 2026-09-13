# Canonical source connectors

Implemented profile: `connector/v1`. Mapping and conformance versions are retained on records, so a later parser does not reinterpret historical facts. The enduring subject is a system operating in an environment. Connector installations are sources attached to that subject; neither a repository nor a tool catalog defines it.

The contract is openly inspectable through authenticated `GET /v1/connectors/catalog`. Every supported role declares product/protocol versions, exact read/write permissions, supported facts, qualification assumptions, freshness, continuity, pagination, failure semantics, classification, retention, request/time/cost bounds and conformance version. The role vocabulary is DISCOVER, CHANGE, OBSERVE, VERIFY, EXECUTE, ENFORCE, EXPORT and CONSUME. A vocabulary entry is not an implemented integration.

## Implemented surfaces and limits

| Source | Implemented canonical installation | Versions and bounds | What the source establishes |
|---|---|---|---|
| GitHub | POLL; DISCOVER + CHANGE | REST `2022-11-28`; one numeric repository identity and exact branch; three read calls; fixed API origin; bounded response streams; repeated ref read detects movement | Repository identity and branch revision as reported by GitHub. No deployment or running-code evidence. Intermediate changes between polls may be missed. |
| MCP | POLL or IMPORT; DISCOVER + CHANGE | Version-aware: `2026-07-28` stateless Streamable HTTP preferred, `2025-11-25` handshake retained for its deprecation window; verified target; at most three tools/list pages, 1,000 tools and 4 MiB | Tool declarations, catalog changes, negotiated protocol revision and server cache freshness. No tool execution, effective permission proof or behavioral verification. An unimplemented protocol revision cannot claim a complete catalog. |
| OpenTelemetry | PUSH or IMPORT; OBSERVE | OTLP JSON v1 and the frozen `integration-intake-v1` GenAI subset; 5,000 spans and 4 MiB; source schema revision may remain unknown | Authenticated ingestion establishes who submitted the batch. Invocation phase, opaque model label, configuration hashes and unverified trace relationships remain instrumentation. Sampling and missing events prevent completeness claims. |
| GCP Cloud Run | POLL or IMPORT; DISCOVER + CHANGE + OBSERVE | Admin API v2; one exact service resource; Google Cloud Run Python SDK; two service and two service-IAM reads; ten-second request timeouts; no retries; etag and snapshot comparisons | Desired configuration, service IAM digest and control-plane readiness/routing. Mixed revisions remain represented. It never establishes exact running system state or effective inherited permissions. |
| OpenAI Agents / Anthropic hooks | IMPORT; OBSERVE | Existing frozen bounded export/hook parser subsets; SDK revision remains unknown where absent | Minimized invocation and advertised model metadata. No live provider connection or exact model behavioral revision. |
| CycloneDX / SARIF | IMPORT; DISCOVER | CycloneDX 1.5/1.6 and SARIF 2.1.0; existing bounded parsers | Declared composition/dependencies or unverified finding references. Detailed finding review still uses the existing integration-intake workflow. |

The existing GitHub App check publisher is separately described as ENFORCE/EXPORT in the manifest, with `checks:write`, exact-SHA checks, installation approval, publication outbox and reconciliation. A canonical read installation cannot enable those roles or acquire its credentials. Check publication is still distinct from a required gate actually preventing an external deployment.

No provider, GCP or customer connection was made to validate this implementation. Mocked transport/SDK conformance establishes local behavior, not effective remote IAM, actual publication, cloud availability or customer acceptance.

## MCP protocol revisions

Two eras are implemented. `2026-07-28` is stateless: every request carries `io.modelcontextprotocol/protocolVersion`, `clientInfo` and `clientCapabilities` in `_meta`, mirrored into the `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers. `2025-11-25` and earlier establish a session with an `initialize` handshake.

The era is established by an observed response, never assumed. ThreatVeil probes `server/discover` at the current revision first. A recognized specification error (`-32020` HeaderMismatch, `-32021` MissingRequiredClientCapability, `-32022` UnsupportedProtocolVersion) identifies a modern server, and `-32022` carries the versions it does support, from which a mutually supported revision is selected and retried once. Any other response — including the JSON-RPC error a handshake-era server returns for an unknown method — identifies a legacy server and the handshake is used. There is no silent downgrade and no silent upgrade: a revision this adapter does not implement fails closed.

Declared coverage is enumerated in `threatveil.integrations.mcp_protocol.FEATURE_SUPPORT` as SUPPORTED, PARTIAL, IGNORED, UNKNOWN or UNSUPPORTED. Multi round-trip requests, subscriptions, the Tasks and MCP Apps extensions, stdio transport, elicitation and sampling are **not** implemented; an interim `input_required` result is refused rather than interpreted. A request-scoped SSE response is parsed for its final response only, which is why streaming is declared PARTIAL. Enterprise-Managed Authorization and Client ID Metadata Documents are UNKNOWN: ThreatVeil neither implements nor claims them.

`tools/list` cache hints are recorded as freshness beside the catalog and are deliberately excluded from the catalog identity digest, so a changed TTL is never mistaken for a changed tool contract. Across paginated pages the least fresh `ttlMs` bounds the joined catalog and a conflicting `cacheScope` aborts the collection. A server hint bounds when ThreatVeil should re-read; it never extends the validity of security evidence.

ThreatVeil's own MCP server serves both eras from one endpoint. A request carrying per-request metadata is served statelessly and its results carry `resultType` and, where the specification requires it, `ttlMs`/`cacheScope`; an `initialize` request selects the legacy revision. `server/discover` is implemented, as the specification requires.

## Authority and persistence

Creation requires a security-capable interactive actor, a tenant-owned system and a matching tenant-owned environment. A server-generated installation UUID assigns the source identity. An incoming payload cannot select another tenant, issuer, acquisition mode or qualification.

Records are appended through the existing tenant-safe `Record` / `Edge` persistence and PostgreSQL RLS. No domain rows or historical receipt formats are rewritten. New kinds are:

- `connector_installation`: fixed system/environment, connector profile, enabled roles and acquisition mode.
- `connector_configuration`: append-only scope, credential reference, expiration and revocation versions.
- `source_batch`: source and mapping versions, valid/recorded times, event identity, watermarks, privacy-minimized facts and component digest proposal.
- `source_assertion`: provenance and references to the captured batch. Authority remains UNREVIEWED.
- `source_change`: before/after references, changed component keys, observed transition, gap state and reassessment requirement.
- `source_health`: successful acquisition or typed failure history. Current health is a projection.

Source IDs are namespaced by installation. Component keys use stable type/external-identity pairs, for example `permissions:projects/.../services/finance-agent`; source provenance is retained separately. An opaque model's configuration hash is explicitly marked `ADVERTISED_CONFIGURATION` with an unknown behavioral revision.

Raw environment values, IAM members, prompts, tool arguments, model output and scanner messages are not retained by this source projection. Full configuration and unsupported fields contribute to conservative digests so that a change is not silently ignored. Minimized invocation phases and unverified trace edges remain available. Existing intake/evidence APIs retain their own explicit data handling and qualification policies. Source records are private customer data with no cross-customer use.

## Continuity and freshness

An installation row lock serializes source ingestion and configuration changes. Event IDs are unique within the installation at the service boundary: exact replay returns the original record and conflicting replay returns 409. Sequence and valid-time reordering preserves history without moving current watermarks backward. Missing sequence/cursor continuity produces CURSOR_GAP and remains unresolved across subsequent submitted batches.

A partial snapshot may add or change observed facts; it cannot remove missing components. A failed read appends a failure, not an empty successful inventory. Full server-side polling reconciles the current bounded snapshot and records SNAPSHOT_RECONCILED; that does not prove a complete event history between polls. Only server collectors may select API_OBSERVED or reconciliation. Imports remain IMPORTED, including when a complete catalog was supplied.

The initial freshness contract is 300 seconds. Configuration expiration/revocation is distinct from observation expiry. Reconfiguring credentials or source scope invalidates old source freshness and emits a reassessment event. Sources become stale when their observation window expires and unknown immediately on acquisition failure. No background polling daemon is installed by this change; an authorized operator or future scheduler must invoke collection, and stale sources stay visible when it does not.

`connected` means a recent authenticated acquisition succeeded. Partial instrumented telemetry can be connected while its coverage and applicability remain UNKNOWN. All imported sources have `connected=false`. Neither a connection nor a fresh source assertion is a qualified deployment anchor. `running_state_proven` is always false for these connectors.

The system projection consumes source health and all source-change history conservatively. A reported non-code permission/configuration change can require fresh evidence. Imports are unreviewed hints: the supported synthetic finance demonstration can discharge a one-shot hint by a fresh full assessment of its explicit fixture boundary, while the import stays unqualified. This does not prove that a customer MCP deployment has been reconciled. Unmapped relevant facts in real deployments require reviewed state/dependency coverage; these connectors never replace the existing qualified execution anchor or establish selective evidence reuse.

## Credentials and execution bounds

GitHub and Cloud Run POLL installations require an existing tenant credential-record UUID. That record points to a pinned organization-namespaced Secret Manager version outside local tests. There is no inline token field, ambient Google credential fallback, automatic token minting, credential distribution to arbitrary targets or write API in these collectors. Use narrowly scoped read credentials with the manifest's permissions. A remote token's actual permissions and expiration remain provider-enforced; authorization failures make source health unknown. Local secret provisioning uses the existing `.local/secrets/<credential-record-id>` convention.

Cloud Run invokes `get_service` and `get_iam_policy` only for the configured resource. The two reads of each object must agree; a moving etag or snapshot is PARTIAL. This is bounded reconciliation, not a distributed atomic snapshot. Parent IAM, deny policy, inherited grants, other business services and actual application behavior remain outside the source's coverage.

MCP requires an existing verified, unexpired target in the same system and an exact authorized POST path. Target authorization is rechecked before every request and after collection. Its transport allows initialize, initialized notification and tools/list only. `tools/call` cannot cross this read boundary even if an adapter is misused. Existing DNS pinning, HTTPS origin/path controls, header restrictions and body limits remain in force. No subprocess/stdio MCP server is launched.

Collection requests hold an installation lock for the bounded read sequence, use no automatic retries and are spaced at least ten seconds apart. This simple serialization consumes a database connection during collection; fleet-scale collection should move to a transactional job/lease boundary before broad rollout. Provider quotas and cloud costs still apply. No verification/model execution budget is consumed by read-only source polling.

## API examples

First create or select a system and environment using the canonical change-assurance API. Register a Cloud Run read installation with an existing credential reference:

```json
{
  "system_id": "<tenant system UUID>",
  "environment_id": "<matching environment UUID>",
  "connector_id": "gcp_cloud_run",
  "mode": "POLL",
  "roles": ["DISCOVER", "CHANGE", "OBSERVE"],
  "name": "Finance staging Cloud Run",
  "configuration": {
    "service": "projects/customer-project/locations/us-central1/services/finance-agent"
  },
  "credential_id": "<existing tenant credential-record UUID>",
  "expires_at": "<timezone-aware expiration within 90 days>"
}
```

Submit to `POST /v1/connectors`, then call `POST /v1/connectors/<id>/collect` with `{"event_id":"<unique request id>"}`. An acquisition failure returns an explicit failure status and `batch:null`; it does not return successful empty data. Successful replay returns the previous batch without another provider call. Get the installation and its projected health from `GET /v1/connectors/<id>`.

For MCP POLL, configuration is `{"target_id":"<verified target UUID>","path":"/mcp"}`; credentials come from that target's reviewed binding. IMPORT installations use `POST /v1/connectors/<id>/import`. OpenTelemetry PUSH uses `/telemetry` with tenant API/session authentication. The submitted envelope contains `event_id`, `payload`, `valid_at`, optional `sequence`, `cursor` and `previous_cursor`. There is no public endpoint accepting a prequalified `Snapshot`.

`GET /v1/connectors/<id>/history?kind=source_change` exposes bounded historical change records. The internal assurance projection reads all applicable source events rather than using this presentation cutoff. Commercial role capabilities are checked by the central entitlement service at installation and each acquisition; quota or plan denial never modifies existing security/source history. Export/read access remains available under the existing tenant authorization.

## Acceptance evidence and pending work

`tests/core/test_connector_contracts.py` covers role contracts, exact GitHub scope, Cloud Run SDK read bounds and moving etags, configuration/IAM/identity changes, mixed routing, sensitive-data minimization, MCP method bounds/rechecks, unsupported versions, and OTel false-success semantics. `tests/integration/test_connectors.py` exercises PostgreSQL tenancy, immutability by append, duplicates/reordering, cursor loss, partial snapshots, source outage/expiry/revocation, configuration invalidation, negative authority, entitlement denial, push ingestion and canonical finance reassessment.

Private cloud acceptance must still establish real read credential scope, service identity, provider rate limits, source health under real outages, rotation/revocation, database connection consumption, and deployment/recovery behavior. A customer must qualify independent running-state and business-effect observation separately. General cloud discovery, runtime enforcement, automatic provider installation, general telemetry storage, source-signature federation, token refresh automation, a universal connector marketplace and new-protocol compatibility are not implemented.

Primary API references checked for the implemented Cloud Run mapping: [service representation and reconciling/status semantics](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services), [service IAM read scope](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services/getIamPolicy), and [Python ServicesClient](https://docs.cloud.google.com/python/docs/reference/run/latest/google.cloud.run_v2.services.services.ServicesClient). The service control plane distinguishes desired configuration from observed reconciliation; this mapping deliberately stops short of a qualified running-state assertion.

## Structured MCP facts (category-complete wave)

MCP snapshots, both collected and imported, add these facts:

- `authorization`: a flattened, bounded path → scalar map; `None` when not captured; long or structured values kept as digests
- `catalog_parts`: digests of protocol version, server info, capabilities and catalog metadata
- `tool_components`: component key → tool name

Component identities and catalog digests are unchanged. These facts let a change be named exactly and classified by `authority-semantics/v1` ([system intelligence](SYSTEM_INTELLIGENCE.md)). They remain UNREVIEWED source declarations.
