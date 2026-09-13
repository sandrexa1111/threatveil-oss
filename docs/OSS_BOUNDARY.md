# Open-source and hosted boundary

The category foundation publishes readable JSON input schemas under `schemas/change-assurance/`, connector/conformance documentation, sample finance property contracts and independent scoped DSSE verification in `sdk/change_records.py`. These are interoperability assets, not a claim that package publication or license review is complete. Hosted maintained cases, qualification and operations remain the commercial service; customer export is preserved.

Portable contracts, property templates, observation/fingerprint schemas, receipt verification, clients and a read-only MCP stdio interface form the developer surface. The repository contains these implementations and schema artifacts. The repository is licensed under Apache-2.0 (see LICENSE and THIRD_PARTY_NOTICES.md). No Python or npm package and no container image is published.

Run `uv run threatveil mcp-serve --help` for the local MCP command. Public templates/schemas need no tenant credentials. Tenant history tools use the configured authenticated HTTP client and fixed API origin; tool arguments cannot override origins or paths. The server cannot execute tests, approve properties, alter evidence or issue releases. JSON framing, message limits and protocol initialization are tested.

Hosted authority includes qualified historical evidence, customer permissions, reviewed ProofScopes, release policy, signed issuance, recurring history, tenant governance and commercial operations. A local schema or verifier cannot grant hosted authorization or fabricate a trusted deployment observation. Private customer traces are not an OSS data contribution and are not pooled by default.

The Python and TypeScript clients retain existing functions while adding release-integrity and intake methods. Public receipt trust requires a separately obtained public key and expected candidate/organization binding; an envelope's embedded key is informational only.
