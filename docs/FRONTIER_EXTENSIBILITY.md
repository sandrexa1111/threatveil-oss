# Frontier agentic extensibility

The canonical model is SYSTEM · COMPONENT · STATE · AUTHORITY · RELATIONSHIP · CHANGE · EFFECT · EVIDENCE · DECISION. New frameworks become **sources** and **consumers** of that model. They never redefine it. Nothing in this table is implemented as a provider integration unless it says so.

| Pattern / platform | Maps onto | Status |
|---|---|---|
| MCP servers and tools | TOOL / MCP_SERVER components; declared authorization facts; interface diffs | **Implemented** (bounded collection and import, 2026-07-28 plus legacy 2025-11-25) |
| GitHub | CODE component (exact ref SHA); CI consumer of decisions and checks | **Implemented** |
| GCP Cloud Run | DEPLOYMENT / PERMISSION / IDENTITY digests | **Implemented** (read-only) |
| OTel, OpenAI Agents export, Anthropic hooks | observations and advertised models (IMPORTED / INSTRUMENTED, unreviewed) | **Implemented** as intake |
| Anthropic ConfigChange / managed agent configuration | configuration change source → CHANGE on PROMPT / TOOL / PERMISSION components | Not implemented; fits the connector contract |
| OpenAI Connector Registry | tool-catalog source, analogous to MCP | Not implemented |
| AWS AgentCore (Gateway, Identity) | gateway tool authority → TOOL + authority facts; AgentCore Identity → IDENTITY source | Not implemented |
| Microsoft Agent 365 / Entra Agent ID | agent registry and identity source; IDENTITY node; consumer of the gate | Not implemented |
| Google Vertex Agent Engine / ADK | deployment and tool configuration source | Not implemented |
| A2A | agent-to-agent delegation → `delegates_to` relationship | Seam only (inert) |
| Browser / computer-use agents | actions on business resources; effects need a qualified observer of the target system | Model fits; no adapter |
| Autonomous commerce / signed payment or intent mandates | a mandate is a declared authority fact (amount, merchant, expiry); a payment is a BUSINESS_EFFECT to observe | Model fits; no adapter |

## Delegation seam

`relationship_assertion` with `delegates_to` is recorded, shown in the System Map as a SUBAGENT with `inert: true` and `grants_permissions: false`, and derives nothing.

Qualified delegation semantics, when a real customer needs them, would have to state four things:

1. the bounded authority passed (a sub-envelope contained in the delegator's envelope; containment is checked with the same authority lattice)
2. how a change to the delegate propagates (a delegate component change is a CHANGE that reaches the delegator's claims through reviewed dependencies)
3. which claims depend on the delegate
4. when the delegate's evidence applies to the delegator's state

Until then, nothing is inferred.

## Identity boundary

ThreatVeil is not an identity provider. Entra Agent ID, Okta, SPIFFE, AgentCore Identity and cloud workload identity are future **sources** of IDENTITY facts and **consumers** of the gate. ThreatVeil's question stays:

> **Does current assurance support the authority associated with this identity?**

It never asks "who is this identity?"

## Open ecosystem

These artifacts are distributable without the hosted service: the verifier (`sdk/change_records.py`, `sdk/passports.py`, `sdk/trust_directory.py`), the schemas (`schemas/`), the gate contract ([ASSURANCE_GATE.md](ASSURANCE_GATE.md)), the connector contract, and the SDK and CLI.

Proprietary value compounds elsewhere: hosted assurance memory, customer-specific dependency mappings, qualified observation methods, business-effect packages, and operational coordination.
