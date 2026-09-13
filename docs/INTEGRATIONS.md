# Integrations — verified boundary

Canonical source connectors now coexist with legacy adapters: GitHub, bounded MCP, OTel and GCP Cloud Run enter the same system/environment contracts. Supported role declarations never imply qualification or deployed-state proof. See [contract and conformance](CONNECTOR_CONTRACT.md).

| Integration | Implemented local surface | External acceptance still required |
|---|---|---|
| GitHub App | Verified installation contracts, HMAC change/lifecycle intake, exact-SHA Checks, durable fenced retries and refresh | Real App/install/webhook, branch protection, deployed scheduler |
| GitHub OIDC Action | Trusted workflow binding and exact-candidate qualified gate | Real customer workflow and deployment witness |
| OpenAI Agents / OTel GenAI | Span normalization, declared fingerprint and incomplete observation intake | Real instrumentation and independently qualified collector |
| Anthropic hooks | Hook-event normalization and explicit unknown outcome | Real customer hook/collector integration |
| MCP | Bounded tools/list discovery and catalog fingerprint; existing authorized execution adapter; read-only ThreatVeil stdio server | Real server authorization, deployed agent and collector qualification |
| CycloneDX / SARIF | Supported composition versions, draft findings, reviewed fingerprint updates | Real repository export and customer review |
| Python / TypeScript SDK / CLI | Authenticated release, evidence, plan and intake access; portable receipt verification | Customer installation and workflow acceptance |
| Stripe | Explicit scoped offers, checkout/portal, current payment reconciliation | Configured prices/allowances, real checkout and paid invoice |
| Email / CRM | Existing consented durable delivery routes, disabled by default | Verified sender/provider configuration and authorized delivery |
| GCP | Infrastructure and operations source | Applied private environment and live drills |

See INTEGRATION_INTAKE.md for supported formats and provenance limits, RELEASE_GATE.md for GitHub, and ASSURANCE_RECEIPTS.md for verification. Passing mocked provider contracts does not establish a working customer installation.
