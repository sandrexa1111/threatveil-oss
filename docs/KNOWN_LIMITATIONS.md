# Known limitations

Last reviewed **2026-09-13**, at open-source release. This is meant to be the most
trustworthy file in the repository. If something below is wrong or missing, that is a bug:
please open an issue.

Most items were verified empirically by the
[product reality and gap audit](history/THREATVEIL_PRODUCT_REALITY_AND_GAP_AUDIT.md) on
2026-09-13, not only by reading code. Gap IDs (G1…) refer to its §AL and to
[ROADMAP.md](../ROADMAP.md).

## In one paragraph

The assurance kernel is implemented and heavily tested, and it is conservative: the
Assurance Gate did not report a false clearance in any audited scenario. Declared change
impact ("what would this configuration change break?") works on real configuration files.
The complete loop, however, works end to end **only on the labelled synthetic Finance Agent
fixture**: reach verified assurance, lose it when the system changes, regain it. No
production deployment, customer system, cloud environment or real payment has ever been
accepted. Treat ThreatVeil as a research prototype.

## 1. Restoring assurance outside the fixture (G1)

- A non-synthetic system *can* reach CLEARED through the generic signed-collector path.
- After a source-observed change (for example an imported Claude Code settings file), two
  complete, passing re-verifications still leave the Gate not cleared. Source changes are
  reconciled only against exact observed digests, and only `finance-v1` is discharged without
  them (`src/threatveil/change_assurance.py`, `source_change_reconciled`).
- The flagship lose → restore loop is therefore demonstration-only.

## 2. Two observer mechanisms (G2)

- The Business Effect Observer Contract (`src/threatveil/observer_platform.py`) accepts
  self-reported harness results, and no assurance projection reads its facts. It produces
  **no evidence**. Its consumers are guidance, automatic re-proof and export.
- Evidence comes only from the older `/v1/observers` mechanism. It needs two Ed25519
  collector keys, a public HTTPS target serving a challenge file, three qualification runs,
  at least two trials per claim and a signed fingerprint listing every claim dependency.
- The setup checklist computes "Qualify an observer" from the first mechanism and links to
  the second.

## 3. "Live" sources are not watched (G3)

- Nothing schedules collection; `POST /v1/connectors/{id}/collect` is the only trigger.
- A live source's freshness window is 300 seconds, and a non-imported source that is not
  fresh makes **every** claim unsupported. Without an external cron, connecting a live source
  degrades clearance within minutes.
- There are no assurance-loss notifications (G11).

## 4. Clearance is short-lived and staging-only (runtime and state binding)

- Evidence expires at most 24 hours after execution (`src/threatveil/core/validity.py`),
  which expires the clearance.
- A `PRODUCTION` environment can never obtain qualified state provenance. ThreatVeil clears a
  staging boundary, not a production system, and has no deployment identity binding (G15).
- Only the fixture composes run → plan → release → state → decision; there is no generic
  verify-and-decide orchestration (G7).
- Automatic re-proof dispatches only inside the labelled synthetic sandbox; elsewhere it
  reports `NO_QUALIFIED_DISPATCHER`.

## 5. Product-truth defects in operator surfaces (G4)

Security truth holds in these cases, because the Gate stays `UNKNOWN`. The workspace can
still tell a more comforting story:

- recording an evidence-less state relabels an earlier authority expansion "covered by later
  verification" and files the system under Home → current;
- a signed Passport can be issued for a system with zero verified claims, and its public
  status reads CURRENT;
- Home's "awaiting review" also counts proposals that were already reviewed.

## 6. Declared inputs are not evidence

- A declared claim is a statement. `DECLARED` and `NOT_YET_VERIFIED` claims are never reported
  as supported, never enter the Gate and never produce a Passport conclusion.
- A proposed-change dry run compares declared configuration only. It executes nothing, and it
  cannot know whether the proposal shipped.
- Replayed configuration history is judged by today's claims and mappings, and is labelled
  REPLAYED.
- An observer contract is a declaration; ThreatVeil cannot verify that the named system is
  really the system of record.

## 7. Agent definitions and code-defined agents

- Parsing is deterministic and refuses to interpret code. LangGraph tool sets and OpenAI
  Agents SDK definitions stay `UNKNOWN`; OpenAI Agents appears only as a trace import (G22).
- Fields with no reviewed semantics are counted, not guessed.
- Authority direction is classified only for a small vocabulary of restriction and scope
  conditions plus interface exposure. Limits, schema bounds and MCP annotations are
  `UNKNOWN_IMPACT` (G8).

## 8. Dependency mapping

- Change scoping depends on human-reviewed mappings. An incorrect mapping narrows impact
  incorrectly; mappings are append-only, attributed and visible.
- With no mapping, every reachable claim needs review (conservative).
- Historical change impact is evaluated with the *current* mappings, not those in force at the
  time (G16). Mappings do not survive connector reinstallation (G10).
- Scope compatibility is an explicit allowlist; learned scope inference and measured
  false-ALLOW or false-VOID rates do not exist.

## 9. Synthetic fixture boundaries

- The canonical demonstration runs a labelled SANDBOX: three claims, committed synthetic SQL
  effects in a SQLite ledger, and a synthetic MCP tool gateway *imported* as a source. It is
  not a live MCP connection and not a PostgreSQL system of record.
- `finance-v1` has special-case handling in restoration (see §1). Behaviour shown in the demo
  is **not** evidence of behaviour on other systems.
- Timings measure a prepared local fixture, not onboarding or statistical reliability.
- Every assurance pack is DRAFT; no customer validated any of them.

## 10. Integrations

- GitHub pull-request checks never fetch repository contents; the PR number and link only
  label a result (G9). The GitHub App, webhooks and Checks were never accepted against a real
  installation.
- Parts of the UI label GitHub and Cloud Run as "live" sources and speak of watching; given §3
  this overstates support (G12).
- The read-only MCP stdio server (`threatveil mcp-serve`) exposes public contracts and
  authenticated tenant reads; it cannot execute tests or approve anything.
- No vendor logos are shipped; brand identity uses neutral monograms.

## 11. Commercial remnants

- Plans and pricing are hypotheses from the startup. Of 21 plan capabilities outside
  connector roles, only 4 gate code, and 6 have no implementation. `retention_days` is not
  enforced.
- Stripe, HubSpot and Resend delivery exist in code but were never accepted against real
  providers. Billing defaults to disabled, with a mock available locally only.
- The workspace still contains commercial surfaces (plans, billing, usage) from the startup. The
  top-bar contact link is hidden unless `NEXT_PUBLIC_TV_CONTACT_LABEL` is set.

## 12. Signing, provenance and trust

- Receipts, Passports and change records are Ed25519 DSSE/in-toto envelopes. Locally a
  `LOCAL_DEMONSTRATION` key is generated under `.local/receipt-signing/`; it is not a trust
  root.
- Operator key distribution, rotation and KMS custody are not implemented or accepted (G18).
  Sigstore keyless identity and transparency-log inclusion are not implemented.
- ThreatVeil signs its evidence, not its own build artefacts (no SLSA-style provenance).
- Passport share links are bearer capabilities until revoked or expired. Browser verification
  requires WebCrypto Ed25519.

## 13. Cloud deployment

- The Terraform in `infra/` and `.github/workflows/gcp-dev.yml` describe a private GCP
  deployment (Cloud Run API, web, broker, launcher and runner job). They were validated with
  mocked providers and **never applied**; `cloud_accepted = false`.
- No live IAM, egress, restore, deletion or multi-region recovery drill was run.

## 14. Scale, performance and security assurance

- Evidence queries inspect complete relevant history and favour correctness over large-ledger
  scalability. Large-tenant latency and load are not validated.
- No independent penetration test, formal verification or compliance certification. Clean
  dependency and image scans are not an absence of vulnerabilities.
- Retention: short local retention affects new raw captures. Provider-side data, backups,
  logs and exported copies need separate workflows.

## 15. Local development caveats

- Local identity is accepted only from a loopback peer and only in `local`/`test`. The Compose
  stack binds every port to 127.0.0.1; never expose it to a network.
- `TV_WEB_ORIGIN` must match the browser origin exactly: use `http://127.0.0.1:3000`, not
  `localhost`.
- Compose uses placeholder database passwords for a database it never publishes.
- Host development needs PostgreSQL 17 binaries; the Docker path does not.
- In some Colima setups container DNS fails and builds cannot download packages. Starting
  Colima with explicit resolvers (for example `--dns 1.1.1.1`) resolves it.

## 16. No real-world validation

- No real customer, design partner or production system has used ThreatVeil. Every end-to-end
  result in this repository comes from synthetic fixtures, tests or the author's own local runs.
- Usability, onboarding time, false-warning rates and the cost of producing evidence for a real
  system are unmeasured.
- The model's central claim is argued and demonstrated, not empirically validated: that reviewed
  dependency mappings can scope evidence invalidation precisely enough to be useful.

---

## Earlier wave notes (preserved)

These notes were written during development and are kept for their detail. Where they
conflict with the sections above, the sections above are current.

### 2026-09-10

The [category implementation report](history/THREATVEIL_IMPLEMENTATION_REPORT.md) supersedes
older capability gaps where it supplies new evidence. Current limits include local-only one-click finance orchestration; same-process synthetic observations; read/import connectors without provider acceptance; no general running-deployment proof; external enforcement requests without a delivered/verified ack; catalog retention without plan-based purging; no hosted operator contract provisioning; and unaccepted private GCP/Stripe/customer workflows.

- No live GCP deployment, cloud IAM/egress/restore/deletion drill, customer target, real GitHub App check, Stripe payment or paid conversion has been established in this execution.
- Local Ed25519 DSSE/in-toto receipts are implemented. Operator public-key distribution/rotation and hosted key custody need acceptance. Sigstore keyless identity/transparency-log inclusion is not implemented.
- GitHub changes are authenticated signals; they do not automatically reconstruct a full agent fingerprint or execute customer targets. Checks need configured maintenance and branch protection. Polling and remote revocation are asynchronous, and old superseded decisions are not continuously refreshed.
- Scope compatibility is an explicit human-reviewed allowlist. Learned causal/semantic scope inference and measured false-ALLOW/false-VOID rates are not implemented. Uncertain scope blocks positive reuse.
- Evidence queries inspect complete relevant history and currently favor correctness over large-ledger scalability; large-tenant latency/load targets are not validated.
- Multi-run re-proof can be partial; accepted runs remain associated and missing obligations cannot authorize ALLOW. There is no automatic customer patching or unattended promotion.
- Short local retention affects new raw captures. Cloud retention customization, provider/legal holds, shared-user/account deletion, logs, backups and exported copies require separate workflows.
- The local demo is synthetic with committed business state. Its elapsed time is not a customer onboarding or statistical reliability benchmark.
- No public SDK/OSS package publication, compliance certification, independent penetration test, live multi-region recovery or current container-image revalidation is claimed.
- Existing execution metrics and launch events provide raw measurement inputs. A full customer/cohort/economics dashboard and real recurring-value metrics are not established.
- No fleet/insurance business, physical actuation, arbitrary attack platform or self-authorizing AI policy has been built.

### Category-complete wave

- Authority direction is classified only for a small vocabulary of restriction and scope conditions, plus interface exposure. Everything else is UNKNOWN_IMPACT by design.
- Change scoping depends on reviewed mappings. A reviewer who maps incorrectly narrows impact incorrectly; mappings are append-only, attributed and visible in the System Map and Passport.
- Historical change impact is evaluated with the *current* reviewed mappings, not the mappings in force at the time.
- Patterns in assurance memory require at least three comparable observations; restoration medians need three completed cycles.
- The synthetic tool gateway is an IMPORTED source inside the finance sandbox. It is not a live MCP connection.
- Passport share links are bearer capabilities until revoked or expired. Anyone holding one sees that passport and its status.
- Browser verification requires WebCrypto Ed25519. Otherwise the page points to the offline verifier.
- Gate and passport consumption is recorded at hourly granularity per consumer label or share.

### Final pre-GCP wave (2026-09-12)

- A declared claim is a statement, not evidence. `DECLARED` and `NOT_YET_VERIFIED` claims are never reported as supported, never enter the Assurance Gate, and never produce a passport conclusion.
- A proposed-change dry run compares declared configuration only. It does not execute the agent, a tool or a test, and it cannot know whether the proposal was actually shipped.
- Replayed configuration history is judged by *today's* claims and mappings, not those in force at the time. It is labelled REPLAYED and never counts as activation.
- Agent-definition parsing is deterministic and refuses to interpret code. LangGraph tool sets and OpenAI Agents SDK definitions stay UNKNOWN; fields with no reviewed semantics are counted, not guessed.
- An observer contract is a declaration. ThreatVeil cannot verify that the named system is really the system of record; the harness and a human review are the controls.
- Qualification is bound to one exact contract digest and expires (default 90 days). Facts recorded while unqualified never become evidence retroactively.
- Automatic re-proof dispatches only inside the labelled synthetic sandbox. For any other environment the planner reports ELIGIBLE and then NO_QUALIFIED_DISPATCHER, because no qualified automatic dispatcher exists. There is no remediation path at all.
- Every assurance pack is DRAFT: ThreatVeil wrote it and no customer has validated it. Support/refund is a leading hypothesis, not a validated archetype.
- AI assistance is off by default, proposal-only, mock-tested, and refuses to run a paid provider without a configured budget. No model output can change an assurance status.
- Passports issued under the STANDARD disclosure profile withhold internal identifiers and resource names. Passports issued before this wave (INTERNAL shape) keep what they were signed with, which is correct and unchangeable.
- RPS, precision and activation are computed per tenant on request. There is no cross-customer aggregation, and no number is precomputed into a warehouse.
- Operator business measurement requires the migration identity and is unreachable from the product API. It is internal, append-only and audited, but it is one person's discipline away from being incomplete: a session nobody logs is a number nobody has.
- The dependency-advisory scan reported no known vulnerabilities for 276 locked packages. Advisory-database freshness cannot be verified offline, and a clean scan is not an absence of vulnerabilities.
- Signed build provenance (SLSA-style attestation of the build itself) is not implemented. ThreatVeil signs its evidence, not yet its own artefacts.
