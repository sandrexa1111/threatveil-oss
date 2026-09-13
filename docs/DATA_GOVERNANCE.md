# Data governance

GET /v1/governance/policy reports three classes: PRIVATE_CUSTOMER traces/code/prompts/identities/evidence; CUSTOMER_DERIVED_ABSTRACT permission-gated abstractions; GLOBAL_PUBLIC specifications and templates. Abstract-feature and model-training consent default off. Any opt-in requires an explicit contract reference and owner review. Consent records do not activate a cross-customer processing or model-training pipeline; neither pipeline exists.

POST /v1/governance/policy appends policy history. Raw capture retention is 1–30 days locally, applies to new captures, and is enforced by reference expiry and local cleanup. Existing immutable expiry remains visible. Nonlocal shorter retention is rejected until the cloud lifecycle has been provisioned and accepted. Derived security history is retained independently of raw payload expiry.

An owner requests deletion through POST /v1/governance/deletion-requests using the exact organization name and export acknowledgement. The request freezes new mutations and execution, revokes targets/leases/tokens, and disables schedules/bindings. Read/export remains available subject to normal authentication. Cancellation records an event; it does not restore revoked authorization.

For a newly scoped local organization, `uv run python scripts/erase_local_organization.py --organization UUID --request REQUEST_UUID --confirm-organization UUID` uses the separate threatveil_admin migration connection. It refuses paid/provider billing, GitHub bindings/publications, attempted outbound provider delivery and nonlocal credentials/storage until reconciled. It deletes only the matching primary records and exact raw/credential namespace. Runtime roles cannot enable this exception.

Private HMAC-authenticated v2 manifests in .local/deletion-receipts support recovery after database commit and before file cleanup. They bind exact organization/request IDs, configured roots and typed object identities. Descriptor-relative filesystem traversal rejects symlinks. Keep the manifest key and receipts protected; unsigned/altered recovery metadata requires operator reconciliation.

Tests erase only freshly generated synthetic organizations, prove other tenant objects survive, reject runtime deletion bypass and symlinked storage, and resume an injected cleanup crash. This is not a complete account erasure: shared user profiles, unscoped abuse/provider event records, logs, backups, provider objects and downloaded exports require separate retention and deletion procedures. No cloud/provider/backups erasure is claimed.
