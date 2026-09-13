# ThreatVeil SDK and adapter integration

`Trace` records explicit action/resource/identity phases. SDK receipts start as
`INSTRUMENTED`; calling `observation(complete=True)` does not establish source
authority or qualify the collector. Qualification is a separate, reviewed,
source/version/boundary-specific process with permitted, prohibited and missing
observation challenges.

```python
from threatveil.sdk import ThreatVeilClient

# The API token is a revocable, organization-bound read/execute credential from the control plane.
with ThreatVeilClient("https://your-threatveil.example", token=token) as client:
    run = client.create_run(
        system_id=system_id,
        property_id=property_id,
        target_id=target_id,
        version="candidate-build-42",
        observer_id=qualified_observer_id,
        candidate=exact_candidate_reference,
        stimulus={"path": "/threatveil/test", "payload": reviewed_stimulus},
        idempotency_key=stable_ci_submission_id,
    )
    completed = client.wait_run(run["id"], timeout_seconds=300)
    # A completed execution is not necessarily a passing security/release decision.
    assert completed["release_action"] == "ALLOW"
```

For cookie-authenticated local integration tests, pass a pre-authenticated
`httpx.Client` as `http_client` and the session's CSRF value as `csrf_token`.
Clients do not automatically retry execution mutations or follow redirects.

Complete machine release issuance uses a separate short-lived exact-plan `tvrel_`
authorization approved by a security session. Call
`client.decide_authorized_release(binding)` with that credential; TypeScript uses
`client.decideAuthorizedRelease(binding)`. Ordinary execute tokens continue to
run approved tests without gaining policy/admin authority. See the
[release authorization contract](../../../docs/P0_ACCEPTANCE_2026-09-10.md)
for binding fields, revocation, expiry, replay and CLI usage.

## Safe transport bridge

Remote adapters never construct HTTP clients. The control plane supplies a
transport that has already bound the registered origin, paths, methods, expiry,
DNS/IP pinning, response/streaming limits, deadline, and credential reference to
the claimed run. A bridge must preserve these controls on *every* request:

```python
from threatveil.adapters import HTTPAgentAdapter, AdapterContext, Stimulus, TransportResponse


class RunTransport:
    def __init__(self, scoped_transport):
        self.scoped_transport = scoped_transport

    async def request(self, method, url, *, body=None, headers=None):
        response = await self.scoped_transport.request(method, url, body=body, headers=headers)
        return TransportResponse(response.status_code, response.body, response.headers)


adapter = HTTPAgentAdapter(RunTransport(run_scoped_transport))
await adapter.prepare(AdapterContext(authorized_endpoint, "DIGITAL_STAGING", correlation_id))
try:
    await adapter.stimulate(
        Stimulus(type="structured_input", correlation_id=correlation_id, payload=approved_stimulus)
    )
    observation = await adapter.observe()
finally:
    await adapter.cleanup()
```

The HTTP endpoint accepts `{schema_version, correlation_id, input}` and returns
the `Observation` JSON schema from `threatveil.core.contracts`. The receiving
control plane must verify independently approved witness bindings before passing
`qualified_witnesses` to `evaluate_trace`; target JSON cannot approve itself.

The structured-trace adapter only evaluates recorded observations. The protected
live boundary remains untested. The OpenAI-compatible adapter is a bounded chat
completion adapter; model output does not prove a tool action and generated tool
calls are never executed. Use the HTTP/instrumentation adapter around the actual
agent for consequential workflow assurance.

The remote MCP adapter supports a bounded JSON-response subset of Streamable HTTP
with protocol `2025-11-25`, initialization and session correlation. SSE-only
responses, newer protocol revisions, client sampling, elicitation, resource
fetches and stdio/process servers are not enabled. Tool names must come from the
server-reviewed digital binding, never a model-generated allowlist. Reference:
[MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle).

No adapter enables physical, hardware-in-the-loop or simulator execution.
