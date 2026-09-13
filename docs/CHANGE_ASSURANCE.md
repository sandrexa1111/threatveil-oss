# Autonomous Change Assurance — implemented foundation

Autonomous Release Integrity is the first commercial wedge. The enduring subject is an autonomous system operating within a reviewed environment and permission envelope. Code, tools, providers and repositories remain replaceable components. This additive foundation preserves the existing execution, observation qualification, ProofScope, evidence, complete-property release and signed-receipt kernel.

## Persisted domain and compatibility

The database remains PostgreSQL at migration `0007`. Existing tenant-scoped, immutable `records` and `edges` hold the new typed/versioned concepts; no table rewrite, historical backfill or receipt resigning occurs. JSON inputs reject unknown fields and all references are checked against organization, system and where appropriate environment. New kinds inherit FORCE RLS, append-only triggers and existing tenant/kind indexes.

| Domain concept | Implemented representation and authority |
|---|---|
| System | Existing `system`, independent of any connector or repository |
| Environment | `environment`: accountable owner, operating boundary and SANDBOX/STAGING/PRODUCTION purpose |
| PermissionEnvelope | Immutable `permission_envelope`, principals/actions/resources/constraints, expiry, supersession and monotonic policy epoch; describes authority, does not grant IAM |
| SystemState / ComponentRevision | `system_state` and existing canonical fingerprint components, exact candidate, environment, envelope digest, declared coverage, unresolved unknowns and evidence anchor |
| SourceAssertion / DeploymentObservation | `source_assertion`/`source_batch` with acquisition, valid/recorded times and provenance; GCP facts are configuration observations, not universal running-state identification |
| RelationshipAssertion | Reviewed typed `relationship_assertion` edges; currently traceability only, never a qualification or permission grant |
| SecurityPropertyVersion | Existing immutable approved `security_property` families and explicit fingerprint dependencies |
| EvidenceRecord / ApplicabilityAssessment | Existing qualified `evidence_record` and conservative applicability engine; new projection adds environment, authority, source health and full source history |
| ChangeEvent | `source_change` plus canonical `change_event`, before/after states, PROPOSED/OBSERVED, dependency impact and explicit no-prevention claim for observed changes |
| AssurancePlan / AssuranceCaseVersion | Existing `proof_plan` plus immutable `assurance_case` snapshot containing complete approved properties, release, support, assumptions and policy |
| AuthorizationDecision | `authorization_decision`, exact state/environment/envelope/policy/audience/nonce/epoch binding and short-lived signed DSSE envelope |
| EnforcementAcknowledgement | Separate `enforcement_request` and `enforcement_acknowledgement`; synthetic atomic registry only is implemented for acknowledgement |
| StatusEvent / ConsumerAcceptance | Immutable revocation/status events; separately recorded consumer acceptance is customer-reported, not independently attested |

A decision is a statement with a lifetime, not a permanent verdict, and the product surfaces that distinction as its primary object: a previously issued ALLOW may become EXPIRED, SUPERSEDED, REVOKED or REASSESS without the historical record being altered in any way. Only the current status is recomputed.

`change-assurance/v1` is a new profile. Existing `assurance-receipt/v1` history remains interpreted by its original verifier/evaluator. Component types and IDs are open identifiers; future cloud, identity, agent-delegation or physical-system facts need a connector/qualification contract rather than a new definition of System. Generic graph traversal and automated relationship inference are not implemented. Today's consequential impact follows reviewed property dependencies and conservative unknown-component handling.

## Positive support requires all of the following

An approved, complete property set; unexpired current authority; exact candidate and fingerprint; a qualified test destination bound to this environment before supporting evidence was produced; evidence generated after the reviewed envelope; successful legitimate work; no retained matching adverse result; no unresolved relevant source change, stale source, missing coverage or expired observation. An unobserved PRODUCTION deployment cannot borrow the synthetic or staging observation label.

Source assertions can remove support. They cannot mint qualified business-effect evidence. A fresh timestamp does not discharge an unreviewed imported permission/tool change. Reconciliation requires reviewed dependency coverage and observed exact after-values; only the explicitly labeled finance sandbox may discharge imported demonstration hints after fresh fixture execution. Imported records remain IMPORTED and UNREVIEWED afterward.

The current projection retains applicability CURRENT/STALE/INVALID/UNKNOWN, security PASS/FAIL/INCONCLUSIVE and legitimate task SUCCESS/FAILURE/UNKNOWN separately. It also derives `assurance_obligations`: a restatement of that same assessment as what the operator must do next — RE_ESTABLISH, RE_VERIFY, CONFIRM, RECONNECT_SOURCE, REVIEW or NONE. This is a projection of existing semantics for a human reader. It introduces no policy of its own, proposes no remediation to a customer system, and never converts an unknown into an action ThreatVeil has not established. Authorization also consults the complete original release assessment. Exceptions remain distinct and cannot turn the underlying security truth into PASS. Signing freezes the statement; status reads recheck expiry, revocation, superseding observed transitions, current support and underlying release eligibility.

## Decisions and enforcement

A decision has a maximum five-minute window, capped by authority/observation expiry. Its DSSE/in-toto profile identifies schema, algorithm, issuer, key ID, timestamps and a status URI. Ed25519 is the sole implemented algorithm. Unknown algorithms/profiles fail closed; new verifier profiles may be added without changing domain objects. This is an extension seam, not implemented post-quantum support or keyless signing.

`POST /v1/change-assurance/enforcement` compares organization, environment, state digest, audience, request nonce and prior operating epoch, verifies the signature and requires a current ALLOW. Synthetic compare-and-set records the applied epoch and acknowledgement atomically under a system lock. It changes only a local sandbox registry. External requests require the production-enforcement entitlement and remain `AWAITING_QUALIFIED_ENFORCER`: no external delivery or acknowledgement is fabricated.

`PROTECTED` requires complete current support, a CURRENT decision for the exact displayed state ID/digest and an acknowledgement naming the same digest. It means this bounded accepted workflow, not universal system safety or live cloud/customer acceptance. A historical acknowledged state can remain in history after a change, with its historical ALLOW unmodified and current status restrictive.

## Customer journey and APIs

Open `/app/assurance` for Connect → Define → Protect → Baseline → Watch → Decide. Register a system, review its environment and authority, inspect approved properties and the paired useful task, establish evidence, see non-code changes/source health, and export the signed scoped decision. GitHub, bounded MCP, OTel and Cloud Run appear as sources with separate coverage and freshness.

The complete self-contained path is the opt-in Finance Agent example on Free, and it is hosted-capable. Verification always goes through the ordinary run path, so a deployed API process never executes a fixture itself: the isolated worker does. Because that worker is asynchronous, `POST /v1/change-assurance/finance/assess` is resumable rather than one-click — it returns `202` with `status: "RUNNING"` and the dispatched run identifiers until every run has settled with a persisted result, then returns `201` with the completed assessment. Calling it again with the same idempotency key is how the caller waits; an unfinished run establishes no security conclusion and no state, decision or assurance case exists until it settles. Only local development, which has no separate worker process, executes runs inline.

The demonstration boundary is structurally isolated from any customer system: a SANDBOX environment, a `finance-v1` fixture profile on both system and target, a `synthetic_procurement` adapter and a fresh in-memory SQLite instance per trial. Fixture-manipulation controls operate that labelled sandbox and nothing else; synthetic enforcement refuses any environment that is not that sandbox. The customer-target path remains assisted: use existing property, target, observer qualification and run interfaces, then bind and assess the canonical environment/state through the API.

The finance fixture executes real isolated SQLite writes: beneficiary approval, cross-tenant writes and authorized invoice updates. Security attacks and a useful invoice update have committed before/after observations with tenant/resource/correlation and qualified synthetic scope. Regressed approval creates a committed forbidden beneficiary update. The bad fix disables useful work and remains BLOCK. Missing or nonfinal observations remain inconclusive. The fixture controller and observer share a process and are not independent customer evidence.

Local assessment retries preserve a durable exact-state checkpoint across signing failure and do not recharge completed runs. A separate same-system guard serializes this demo workflow. It retains a DB connection across nested run transactions; it is not a hosted high-concurrency orchestrator.

Primary API prefix: `/v1/change-assurance`. Resources: `environments`, `envelopes`, `target-bindings`, `states`, `transitions`, `relationships`, `decisions`, `enforcement`, `systems/{id}`, `finance/setup`, `finance/assess`. Live OpenAPI provides exact payloads. Readable input schemas are in `schemas/change-assurance/`. Independent verification is `threatveil.sdk.change_records.verify_change_record`; a caller supplies its independently trusted key and expected scope. `verify_change_record_with_directory` resolves the signing key from a published trust root instead, with rotation and revocation semantics specified in [trust distribution](TRUST_DISTRIBUTION.md). Offline verification is historical unless the caller supplies an evaluation time; it cannot establish current revocation status.

## Migration and deployment order

1. Preserve database and evidence backups and trusted historical signing keys. Use the existing normal `alembic upgrade head`; head stays `0007` for this additive release.
2. Deploy API and web together, retaining prior images for rollback. No data rewrite is required. Old clients continue to use their existing receipt/release APIs; an old UI will not expose new record kinds.
3. Configure a versioned catalog before new purchases. New organizations receive frozen Free contracts; existing accounts retain their prior interpretation. Plan changes do not delete historical evidence.
4. Run full local acceptance and the read-only activation preflight. Set real managed identity, images, narrow credentials, budgets, alerts, retention, rollback and restore configuration for private GCP.
5. Perform authorized private-cloud acceptance before activating customer enforcement or Stripe TEST mode. Live billing and customer mutation remain separate approvals.

See [connector specification](CONNECTOR_CONTRACT.md), [commercial platform](COMMERCIAL_PLATFORM.md), [P0 gates](P0_ACCEPTANCE_2026-09-10.md) and the [implementation report](history/THREATVEIL_IMPLEMENTATION_REPORT.md).

## Category-complete additions (11 September 2026)

- **Precise change scoping.** Collected MCP catalogs retain bounded structured facts: a flattened authorization block, catalog-part digests and tool names. Reviewed `dependency_mapping` records (SECURITY role, or the labelled `SYNTHETIC_PACKAGE`) state which named source facts control which reviewed claim dependencies. When every named subject of a later, unreconciled source change is mapped, the projection limits its impact to the claims whose dependencies it reaches. One unmapped subject, a gap or a reconfiguration keeps the conservative meaning. Mappings never discharge a change, qualify a source or grant permission. Each affected row now records `affected_by`.
- **Status refinement.** `clearance_status()` separates whether a clearance still speaks for the system from the signed statement's five-minute lifetime. `_decision_status()` still returns EXPIRED first. An *observed* source change that moves support now yields SUPERSEDED rather than REASSESS; REASSESS remains for support that moved without an observed change. Authority or observation expiry yields EXPIRED. Every one of these is non-current.
- **Obligations.** An IMPORTED source no longer produces a "reconnect" obligation; it never claimed to be live.
- **Finance sandbox.** Setup connects a labelled synthetic MCP tool gateway (IMPORT) with package-reviewed mappings. `POST /finance/simulate-change` accepts only four enumerated gateway changes and operates only the finance SANDBOX.
- **New surfaces.** System map, authority map and diff, change consequences, evidence currency, lifecycle, re-establishment, memory, the Assurance Gate and the Current Assurance Passport. See [system intelligence](SYSTEM_INTELLIGENCE.md), [Assurance Gate](ASSURANCE_GATE.md) and [Passport](ASSURANCE_PASSPORT.md). The database head stays `0007`: new kinds use the existing record store, RLS and append-only triggers.
