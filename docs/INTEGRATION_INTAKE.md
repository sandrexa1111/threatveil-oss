# Integration intake

ThreatVeil imports observations, tool contracts, composition manifests and scanner findings into tenant-owned drafts. Imports strengthen change analysis and reproduction setup. They do not establish security PASS/FAIL, qualify a witness, activate a property, authorize a target, or update an existing release.

## Supported inputs

| Format | Input | Operational result | Scope |
|---|---|---|---|
| `otel_genai` | OTLP/JSON `ExportTraceServiceRequest` with `resourceSpans` | Instrumented tool/agent observations, trace-parent links, model/config/toolset fingerprint proposals | JSON traces only; no protobuf/gRPC receiver, logs or automatic collector deployment |
| `openai_agents` | `{"spans": [span.export(), ...]}` from Python Agents SDK | Function invocation, handoff, generation, response and MCP-name observations | Export shape checked against SDK 0.22.2; no API key or remote trace retrieval required |
| `anthropic_hooks` | `{"events": [hook_input, ...]}` | PreToolUse/PostToolUse/PostToolUseFailure and subagent observations | Claude Agent SDK hooks; no transcript-file reading or live session control |
| `mcp_tools` | Captured `tools/list` result or joined catalog wrapper | Tool/schema/description/metadata fingerprints and deterministic JSON-pointer differences | Network discovery is pinned to MCP 2025-11-25 JSON Streamable HTTP |
| `cyclonedx` | CycloneDX JSON 1.4–1.7 | Application/model/dependency graph proposals, explicit unresolved references | No external BOM fetching, signature verification or deployed-inventory claim |
| `sarif` | SARIF 2.1.0 | Draft findings with rule/scanner attribution, resolved message/location references and suppression provenance | No external property-file fetching or automatic finding dismissal |

Each parser rejects malformed input, unsupported document versions and ambiguous identities. Local parsing accepts at most 4 MiB, 32 levels and 100,000 JSON nodes. The hosted API retains its stricter 2,000,000-byte request limit. Maximums are 5,000 telemetry events/components/results, 1,000 MCP tools and 20 discovery pages. These bounds reject input rather than silently truncating security-relevant data.

## Local normalization

```python
import json
from pathlib import Path
from threatveil.integrations.intake import normalize_integration

payload = json.loads(Path("integrations/intake-examples/mcp-tools.json").read_text())
result = normalize_integration("mcp_tools", payload)
print(result.model_dump_json(indent=2))
```

The examples directory contains synthetic inputs for all six formats. `source_digest` identifies the original JSON content. Normalized tool-contract digests include descriptions, schemas, annotations, execution metadata and unfamiliar extensions. Catalog order is canonicalized. Unknown schema arrays retain their original order; the diff makes no backward-compatibility claim.

## Hosted import and review

Authenticated `owner`, `admin`, `security` and `developer` roles can call:

```text
POST /v1/integrations/intake/{format}
{
  "system_id": "<owned system UUID>",
  "idempotency_key": "<unique request key>",
  "context": {"source_id": "payments", "source_version": "1", "boundary": "staging"},
  "payload": { ...source document... }
}
```

Reusing the same key and request returns the original immutable intake. Reusing it for different content returns 409. Tenant ownership is checked before processing or returning the replay. An account lock serializes competing imports. One malformed result rolls back the entire import, including draft findings. Validation errors and operational logs do not echo the source document.

`GET /v1/integrations/intake?system_id=...&limit=25&cursor=...` returns bounded summaries. `GET /v1/integrations/intake/{id}` returns the normalized private record. Importing SARIF also creates ordinary draft finding records, linked to their intake and source/result digests. Those findings use the existing compiler and security-property approval workflow.

An `owner`, `admin` or `security` reviewer can explicitly accept fingerprint facts:

```text
POST /v1/integrations/intake/{id}/approve-fingerprint
{
  "source_digest": "<digest returned by import>",
  "candidate": {"type":"application_version", "id":"checkout", "version":"v2", "digest":"<SHA-256>"},
  "fingerprint": {"components": [ ...full reviewed candidate components... ]},
  "previous_fingerprint": {"components": [ ...previous candidate components... ]},
  "review_reason": "Verified this catalog and its bindings for checkout v2",
  "idempotency_key": "<unique review key>"
}
```

The full fingerprint must retain all imported component facts unchanged and bind the candidate version/content digest. UNKNOWN cannot be promoted by review. OBSERVED import provenance becomes DECLARED because accepting an upload is not deployment observation. Approval appends a `fingerprint_review` and `change_set`; it leaves the original draft, existing system and historical evidence unchanged. The reviewed full fingerprint can then be supplied to `POST /v1/proof-plans`.

## Observation authority

Every imported observation has an `INSTRUMENTED`, incomplete witness, `task_outcome: UNKNOWN`, and recorded-boundary limitations. It has no authoritative authorization decision, tenant identity assertion, durable before/after state or qualification ID. Even adding its source to a qualified-source allowlist does not promote its authority in the existing evaluator.

Pre-tool hooks establish a reported attempt. Completed function/tool spans establish reported dispatch, not commit. A tool error is not proof of denial or absence of side effects. OpenAI handoffs retain their named endpoints as unverified trace edges; they do not grant delegated authority. Missing response model details, conflicting configurations, incomplete catalogs and unresolved dependency graphs remain UNKNOWN.

OTel span `gen_ai.provider.name` is preferred; legacy `gen_ai.system` is supported. The importer reads standard GenAI operation, tool, model/config, agent and tool-definition fields. Trace, span and parent identifiers remain available for joining to independently collected evidence. Prompt bodies, tool inputs and tool outputs are omitted from normalized telemetry.

## MCP discovery

```python
from threatveil.integrations.mcp_discovery import discover_mcp_tools, diff_mcp_tools

# adapter is an existing MCPAdapter prepared with an authorized staging target.
snapshot = await discover_mcp_tools(adapter, server_id="payments")
comparison = diff_mcp_tools(previous_snapshot, snapshot)
```

Discovery uses the adapter's already authorized transport, endpoint, protocol and credential scope. It negotiates the existing pinned protocol, records server information, follows bounded tools/list cursors and never invokes a listed tool. Wrong request IDs, JSON-RPC errors, duplicate JSON members/tools, repeated cursors and exhausted bounds abort capture.

An uploaded joined catalog must explicitly declare `complete: true`. A result with `nextCursor` cannot claim completeness. Incomplete comparisons report `NOT_OBSERVED` instead of asserting removal. Effective authorization is UNKNOWN unless separately supplied; server annotations remain untrusted declarations. New protocol revisions are retained as unvalidated/UNKNOWN instead of silently enabled.

## Data handling and validation status

Intake records are private customer data with cross-customer use disabled. The API stores normalized results, source hashes and provenance; it does not retain the original source document. Normalized findings and MCP schemas/metadata may still contain sensitive customer content and receive ordinary tenant isolation. Avoid placing credentials in those fields. There is no cross-customer pooling, provider upload, source-URL fetching, remote execution or model invocation in normalization.

Parser tests cover authority forgery, missing/dropped data, duplicate identities, timestamp/correlation validation, schema and description drift, pagination ambiguity, manifest dependency gaps, unknown extension ordering, and SARIF reference integrity. API acceptance tests run against real PostgreSQL and exercise tenant isolation, RLS reads, role/CSRF boundaries, idempotency, atomic malformed imports, source preservation and security-only review. Provider accounts, customer collectors and live remote MCP endpoints have not been exercised by these local tests.

## Primary specifications checked

- [OpenTelemetry GenAI span conventions](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-spans.md) and [agent/tool conventions](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md). These conventions are under development; the importer accepts the documented subset above.
- [OpenAI Agents integrations and observability](https://developers.openai.com/api/docs/guides/agents/integrations-observability). The published Python SDK 0.22.2 tracing export source was inspected for the concrete serialization shape.
- [Claude Agent SDK hooks](https://code.claude.com/docs/en/agent-sdk/hooks).
- [MCP 2025-11-25 tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).
- [CycloneDX 1.7 JSON schema](https://github.com/CycloneDX/specification/blob/master/schema/bom-1.7.schema.json).
- [OASIS SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html).
