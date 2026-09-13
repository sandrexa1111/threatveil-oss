# Engineering status — 2026-09-10

This file is supplemented by the [category foundation implementation report](history/THREATVEIL_IMPLEMENTATION_REPORT.md), which records the latest integrated acceptance. New system/environment/authority and connector projections, the Finance Agent journey, configurable Free–Enterprise plans, mock billing, narrow machine authority and activation preflight are implemented locally. Hosted customer observation, actual enforcement and Stripe provider acceptance remain externally pending; no local acceptance closes them.

The current wedge is Autonomous Release Integrity. This status supersedes the September 7 implementation status; prior build/security reports remain historical records. No cloud or commercial acceptance is implied by local tests.

## DONE

Implemented, integrated and locally tested:

- Immutable ProofScopes, evidence ledger, deterministic invalidation, complete property selection, bounded re-proof execution and exact-candidate release decisions.
- Standard DSSE/in-toto Ed25519 receipts, independent offline verification and current applicability separate from immutable history.
- Candidate/source authority, synthetic-to-Git rejection, version-alias adverse-history protection, expiry, role/source revocation, two-person scoped exceptions and append-only tenant RLS.
- GitHub App provider implementation and real-database/mocked-provider lifecycle: installation review, authenticated push/lifecycle events, exact-SHA Checks, fenced retry, ambiguous-create recovery and latest-decision refresh.
- OTel GenAI/OpenAI Agents/Anthropic/MCP/CycloneDX/SARIF normalization, review-required intake and explicit fingerprint approval. Imports do not qualify evidence.
- Release timeline, change explorer, ProofScope/evidence inspector, receipt export, current-vs-historical status, Integrity Launch scope/effort/milestones and configured commercial offers.
- Python/TypeScript/CLI release/intake access and read-only MCP stdio server.
- Default-off data-use consent, owner deletion requests, execution freeze, local retention and migration-role scoped erasure with authenticated crash recovery.
- Documentation and reproducible real local HTTP→PostgreSQL→SQLite release demonstration.

## PARTIAL

- Cloud deployment source is validated locally; current images and all live GCP acceptance remain unverified.
- GitHub, collector/provider instrumentation, Stripe and commercial delivery have implementation/contract tests, not live customer acceptance.
- Receipt key custody/distribution/rotation is operator-configured; no live managed key lifecycle or keyless Sigstore profile.
- Local primary-data erasure is tested; cloud, shared account, provider, logs, backup and exported-copy deletion are distinct unfinished acceptance scopes.
- Event-level release/launch/run data exists; complete commercial cohort, economics and false-warning dashboards need real measured inputs.
- Historical reads prioritize correctness; large-ledger load, customer-specific budgets and operational SLOs are unvalidated.
- SDK/developer surfaces exist in the workspace; public package publication/license review is not completed.

## BLOCKED_EXTERNAL

- GCP project/region, spend ceiling, deployment identity and private-environment configuration.
- Real prepared customer system, allowed actions, exact staging target, reset semantics and independent collector keys/ground truth.
- GitHub App registration/installation, trusted workflow, webhook endpoint and branch-protection acceptance.
- Managed authentication, configured receipt key/public-key distribution, Stripe prices/allowances and real payment testing.
- Provider/compiler credentials and authorized email/CRM delivery configuration where used.
- Customer onboarding/repeat-release/second-system and paid-conversion evidence.

## NOT_STARTED

- Sigstore keyless certificate and transparency-log verification profile.
- Automatic source-code repair/promotion; unattended execution triggered by imported changes.
- Learned causal invalidation, fleet/insurance products, physical execution and pooled customer training.

## Verification

| Check | Result |
|---|---|
| Full Python suite | 469 passed; 15 upstream deprecation warnings |
| Browser | 9 passed; 2 affected release/launch cases rerun after receipt-link fix |
| TypeScript SDK | 4 passed |
| Web typecheck and production build | Passed |
| Terraform fmt/validate/tests | Passed; 7 tests; no apply |
| Ruff and actionlint | Passed |
| Semgrep selected Python/JavaScript security rules | 0 findings, 34 rules, 115 targets |
| OSV locked Python/JS dependencies | 0 issues; 89 Python and 187 JS packages |
| Gitleaks Python source tree | No leaks found; redacted source scan |
| Real local release demonstration | ALLOW → VOID/re-proof BLOCK → restored ALLOW; 3 receipts verified |

Exact commands, limitations and local evidence paths are in BUILD_REPORT_2026-09-10.md. September 7 container-image findings are historical and do not attest to today's source.
