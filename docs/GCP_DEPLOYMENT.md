# GCP deployment status

The deployment source and operator runbook are in deployment/GCP.md and infra/. Terraform models Cloud Run services/Jobs, Cloud SQL, Storage, Secret Manager, Tasks/Scheduler, Artifact Registry and separate service identities. Local Terraform format, validation and ten mocked infrastructure tests pass. They validate configuration structure and stated boundaries, not deployed IAM behavior. The [P0 acceptance record](P0_ACCEPTANCE_2026-09-10.md) describes the repaired GitHub relay/publisher wiring, narrow machine issuer and explicit activation preflight.

No GCP project, region, billing/spend ceiling or authenticated deployment identity was supplied for this execution. No resources were applied, domain exposed, customer data uploaded or bill incurred. A private deployment is BLOCKED_EXTERNAL until those inputs are available. Existing project resources must be inventoried before applying infrastructure.

Before customer acceptance: provision reviewed secrets and managed identity; apply migrations through the dedicated admin path; prove the runtime is non-owner with FORCE RLS; verify worker grants and private broker invocation; establish DNS/TLS and scheduled reconciliation; run actual failure/timeout/lease and egress checks; perform backup restore and targeted deletion drills; rebuild and scan current images; measure cost and latency against agreed limits.

Receipt signing outside local/test requires an operator-provisioned Ed25519 private key through the secret boundary. Key distribution, rotation, archival public-key trust and incident revocation must be operationally owned. This implementation does not claim live Sigstore keyless signing or transparency-log inclusion.
