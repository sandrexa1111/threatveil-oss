# Implementation decisions

## 2026-09-07 — Canonical application and compatibility

The founding-CTO execution mandate authorizes implementation. The older build pack stays reference-only: its unauthenticated development hooks, incomplete runner fetch and illustrative schema are not copied into the commercial boundary. Build a canonical modular application at the repository root, retaining V3 plans unchanged as historical strategy.

Use typed autonomous-system contracts: actions/phases, typed resources, witness coverage, extensible fingerprint components and typed release candidates. Physical execution classes can be represented but are rejected by launch execution policy. No robotics adapters, actuation or safety certification are included.

Use actual local PostgreSQL and non-owner RLS roles for integration acceptance. A SQLite simulation cannot validate tenancy. Managed identity is production authentication; explicit loopback development identity is local-only and never represents live customer authentication. Credential-dependent acceptance remains separately recorded.

Use a fixed proprietary procurement fixture and security evaluator for the first authoritative side-effect loop. Existing open regression tools were assessed in V3; reuse telemetry/transport/SDK libraries rather than duplicate generic attack discovery. The fixture/evaluator exercise ThreatVeil's qualified semantics, which existing generic replay does not substitute for automatically.

## 2026-09-07 — Shared execution and durable observations

Use the founder-selected shared job with a single-use five-minute bootstrap capability plus verified service identity. Claims bind an ephemeral worker public key, nonce and run; short leases require signatures, fences, expiry and fresh authorization. Ordinary runners have no database, Secret Manager or Storage access. The trusted broker resolves exact credentials and evidence assignments.

Two separately controlled collector signatures plus three assigned permitted/prohibited/missing-observation controls qualify an external source only for its declared boundary/version. The expected observed candidate component and initial-state digest are frozen. Imported traces and model prose cannot promote themselves to authoritative evidence. Actual collector independence remains a reviewed customer integration obligation.

Stream each trial into immutable capture metadata plus content-addressed raw storage before advancing. Reconstruct completion server-side from captures. Preserve confirmed failures through later errors. Bound raw evidence to 16 MiB per experiment; keep compact conclusions/lineage after 30-day raw expiry. Use PostgreSQL relationships and portable NDJSON export, not a graph database or customer data lock-in.

## 2026-09-07 — Comparison and revenue semantics

Deterministic prohibited outcomes immediately FAIL. External trials do not automatically establish statistical independence; their intervals are descriptive and cannot assert stochastic degradation without qualified independence. Baseline comparison requires compatible property, evaluator, attack stimuli, source binding and experiment/capsule. A changed stimulus cannot verify the original fix, and an incompatible historical baseline cannot ALLOW release.

Approved-property allowances count immutable approval families: Starter 20, Growth 100, Pro 500; drafts and retained versions do not consume extra slots. Approval and billing changes serialize on the account. A destination-system adoption creates a new family and requires local binding/review. Existing history remains available after a downgrade.

Stripe reconciles current provider state and actual successful, positive live payment evidence; webhook arrival order, test payments and manual pilots cannot manufacture revenue. Email delivery is an idempotent durable outbox with a retry window shorter than Resend's retention. CRM gets consented allowlisted routing fields, never the security finding or free-text intake. Provider acceptance is distinct from inbox delivery and customer conversion.

## 2026-09-07 — Failed retries consume bounded allocations

An interrupted run previously refunded its whole reservation even when it had already produced a confirmed failure. That allowed repeated work without consuming the organization's execution allowance. Once execution reaches RUNNING, its reserved execution units are consumed on settlement, including ERROR/TIMEOUT. Only work that never started receives its reservation back. This conservative allocation policy bounds ambiguous external work; it is not a claim to measure provider tokens or charge new monetary overages. The frozen plan and final usage record state the policy. Actual provider cost remains separately unmeasured.

## 2026-09-07 — Adverse history cannot be rerolled away

A later sampled PASS cannot authorize the same artifact after a confirmed qualified failure of the same system/property/target and observed configuration. Exact artifact history ignores a caller's candidate-ID alias and component ordering. New signed configuration evidence can establish a changed system; changing only a label or stimulus cannot erase failure memory. Captures and finalization serialize within the artifact scope. Run, fix, canary and release reads reassess retained adverse evidence and current authorization while preserving immutable historical decisions and the sampled PASS/FAIL distinction.


## 2026-09-10 — Release integrity execution wave

**Decision:** Extend the existing modular control plane and immutable Record/Edge ledger with ProofScope, invalidation, re-proof and signed release objects. Alternative: replace the substantial prior implementation or add microservices. Reason: preserve tested tenant and execution boundaries while making the release path explicit. Consequence: migrations stay small; high-volume historical reads need later performance work.

**Decision:** Default to full-fingerprint proof scope; permit selective scope only with explicit human review and declared dependency preservation. Alternative: let AI infer irrelevant changes. Reason: false reuse is more damaging than additional proof cost. Consequence: some safe changes still require re-proof.

**Decision:** Use exact positive candidate authority and broader content identity for adverse memory. Alternative: trust caller labels or submitted expected fingerprints. Reason: version aliases and synthetic-to-Git substitution could otherwise create false ALLOW. Consequence: independent deployment anchoring is mandatory even when some property evidence is reusable.

**Decision:** Issue standard DSSE/in-toto Ed25519 receipts now with external public-key trust. Alternative: claim keyless Sigstore without available identity/transparency services. Reason: portable verifiable artifacts can be tested locally without inventing hosted trust. Consequence: hosted key custody, distribution and rotation remain explicit external acceptance.

**Decision:** Keep GitHub as an asynchronous outbox projection and recheck immediately before writes. Alternative: report queue acceptance as installed or claim distributed exactly-once writes. Reason: lost external responses and later revocation must be visible. Consequence: ambiguous writes require reconciliation; polling cannot supply atomic remote revocation.

**Decision:** Remove default public dollar anchors and expose only configured commercial scopes while preserving legacy paid contracts. Alternative: retain speculative list prices. Reason: scope and execution economics require actual measured customer work. Consequence: first offers need founder configuration and real payment validation.

**Decision:** Default customer-derived use/training rights off and implement only explicitly scoped local erasure with authenticated recovery. Alternative: automatically pool traces or claim universal deletion. Reason: consent, source privacy and backups/providers have distinct boundaries. Consequence: complete cloud/account/provider erasure remains an operator acceptance obligation.
