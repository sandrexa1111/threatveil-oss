# ThreatVeil build report

**Build reviewed:** 7 September 2026  
**Workspace:** repository root  
**Product:** Continuous security verification for AI agents  
**Founding thesis:** Security memory for autonomous software

## Executive assessment

ThreatVeil now has a working local application that can preserve a security failure as an executable property, verify a useful fix, replay the property against a changed system, and block a regression. The implementation includes the customer workspace, security execution and evidence services, SDKs, commercial workflows, and GCP deployment configuration.

The local acceptance suite passes. This is evidence of implemented product behavior and tested integration contracts—not evidence of a live SaaS deployment, real customer assurance, payment, or retention. Those milestones require external credentials, authorized customer systems and deployment acceptance.

This is a new implementation. The old ThreatVeil GitHub product was not used. The prior reference pack and V3 strategy documents remain available as historical context.

## 1. The core product

The implemented workflow connects:

**Finding → reviewed security property → authorized execution → observed outcome → evidence → useful fix → baseline → replay → regression → release decision.**

The first complete demonstration is a procurement agent interacting with a synthetic beneficiary ledger. Its tool changes actual SQLite state; PostgreSQL retains the application's records and lineage. No real payment or third-party attack occurs.

| Demonstrated case | Security outcome | Business-task outcome | Product behavior |
|---|---|---|---|
| Vulnerable agent changes beneficiary details from untrusted content | FAIL | Task may complete | Retain violation evidence; block release |
| Fixed agent preserves the boundary and legitimate workflow | PASS | SUCCESS | Permit useful-fix verification and baseline creation |
| Later version reintroduces the same prohibited outcome | FAIL / historical regression | Task may complete | Link the regression to history and BLOCK |
| Required authoritative observation is missing | INCONCLUSIVE | UNKNOWN | Do not infer safety or verify a fix |
| “Fix” disables the legitimate operation | PASS | FAILURE | Reject useful-fix verification and block release |

A confirmed prohibited outcome fails immediately. Statistical significance is not required to recognize an observed security violation.

A later sampled PASS also cannot erase a retained, qualified failure for the same artifact and observed configuration. Changing a caller-supplied version label or selecting a convenient successful retry cannot restore release eligibility. This protection covers incomplete runs, raw-evidence expiry and concurrent capture/finalization.

## 2. Customer-facing application

The Next.js/React workspace is connected to the API and PostgreSQL. It includes:

- Sign-in, organizations, membership roles, invitations and scoped API tokens.
- System registration, access/action descriptions and threat-model suggestions.
- Finding ingestion, 20 initial property templates, draft review and approval.
- Target registration, ownership/authorization verification, expiry and revocation.
- Observer registration, source qualification and revocation.
- Runs, captured observations, security/task verdicts, evidence, fixes, baselines and regressions.
- Change-impact analysis, candidate comparisons, selection audits and cross-system property adoption.
- Gauntlet scoping/status, system reports, billing, usage and integration readiness.
- Public homepage, product, pricing, security/trust, documentation, contact/demo and login pages.

The interface identifies synthetic/local activity and unconfigured integrations. It does not invent customer findings, paid subscriptions, customers or certifications.

## 3. Proprietary assurance components

| Component | Implemented behavior | Important scope |
|---|---|---|
| Behavioral property/evaluator engine | Evaluates qualified receipts, identity/authority, action phase, protected resources, side effects and legitimate-task success | Missing coverage cannot silently become PASS |
| Finding-to-property compiler | Structured AI-assisted proposals, source excerpts, provenance, unknowns, reproduction requirements and witness suggestions | Provider key required for live generation; proposal cannot approve or execute itself |
| Templates and threat modeling | Twenty starter templates and suggestions from a system's access/actions | Each customer still needs an appropriate binding and observation contract |
| Repeated-trial/statistical analysis | Exact binomial intervals and independent baseline/candidate comparison with multiplicity adjustment | External correlated trials do not establish statistical independence automatically |
| Bounded variants | Five reviewed procurement attack transformations with stable identifiers/digests | This is an initial supported attack family, not a universal autonomous attack generator |
| System fingerprints | Typed component versions/digests for available application/model/prompt/tool/MCP/RAG/permission/memory configuration | Declared configuration is distinguished from observed candidate identity |
| Change-impact selection | Rules map changed components to relevant approved properties | Periodic/full-suite selection audits can reveal excluded failures; the selector is not assumed infallible |
| Candidate canaries | Assess explicit candidate runs against historical baselines, including useful behavior, identity, compatibility and freshness | Assessment uses existing runs; it does not launch unbudgeted experiments |
| Adversarial memory | Retained failure/fix/capture/version/decision relationships and tenant-scoped semantic queries | No graph database; imported records and raw captures have different retention scopes |
| Cross-system adoption | Recommend and copy relevant properties as destination-bound drafts | Approval or assurance does not transfer automatically between systems |
| Consequential-tool contracts | Install six drafts covering authorization, identity, approval, errors, side effects and state transitions | One bounded tool/identity/resource/state binding; every property requires review and qualified observation |

Canaries distinguish preserved, regressed, stale, incompatible and unknown evidence. Selection audits distinguish an excluded failure from a demonstrated historical regression. This avoids presenting a missing comparison as a stronger conclusion than the evidence supports.

## 4. Execution and observation architecture

The backend uses Python 3.13, FastAPI, Pydantic, SQLAlchemy/Alembic and PostgreSQL 17. The web application uses Next.js 16, React 19 and TypeScript. Services are organized as a control API, trusted credential/evidence broker, launcher and shared worker.

The shared-runner protocol follows the founder-approved design:

1. The control plane creates an organization-bound run and immutable execution specification.
2. A shared job receives a run ID and a single-use bootstrap capability valid for five minutes.
3. The worker proves its service identity and possession of an ephemeral signing key.
4. The broker grants a short, fenced, signed lease for that exact assignment.
5. The worker obtains only authorized specification/credential access, submits assigned trial observations and exits.
6. The server reconstructs the outcome from stored captures instead of trusting a worker-submitted aggregate PASS.

The configured worker identity has no direct database, Secret Manager or evidence-bucket permission. Authorization, expiry, nonce and fence checks apply throughout execution. Recovery avoids automatically replaying ambiguous work that had already started.

External assurance requires scoped observer and independent ground-truth signatures plus assigned known-permitted, known-prohibited and missing-observation controls. These checks establish reviewed qualification for a specific boundary and source version. They do not remotely attest that a customer collector is independent or uncompromised.

The transport validates HTTPS origins, pins validated DNS destinations and rejects private/metadata addresses, redirects, routing-header injection and oversized responses. This protects vetted adapters. It is not a sandbox for arbitrary customer code, and the trusted workload-identity client still needs metadata access.

## 5. Developer integrations

Implemented adapters cover generic HTTP test endpoints, structured traces, supported remote MCP calls and OpenAI-compatible APIs. An adapter interface separates preparation, stimulation, observation, traces/state and cleanup.

Python and TypeScript packages provide instrumentation and API clients; Python also provides signing helpers. The CLI supports the standalone demo and customer/operator workflows. A structured trace import is one recorded sample, not evidence of repeated live executions. Model output alone cannot establish authoritative side effects.

The GitHub Action uses signed workflow identity rather than a shared permanent API secret. Server-side checks bind the repository, trusted workflow and exact candidate to qualified execution evidence. The initial binding covers its explicitly configured property/target plan, not an implicit organization-wide guarantee. A live repository installation and protected-release exercise remain pending.

Finding ingestion uses a canonical source-aware model and manual/structured input. Dedicated import parsers for every named pentesting or discovery vendor have not been built.

## 6. Evidence, tenancy and internal assurance

Tenant isolation is exercised against an actual non-owner PostgreSQL role with FORCE RLS. The application checks tenant-bound references, roles, sessions, CSRF/origins, token revocation and immutable records. The API and broker currently share a trusted runtime database role; they are not mutually isolated database security domains.

Each trial retains compact metadata, evaluation, observation digest, source provenance and an exact raw-object reference. Raw captures are immutable on creation, bounded to 2 MiB each and 16 MiB per run, and expire after 30 days. The GCP configuration adds a seven-day Storage soft-delete recovery window. Conclusions and lineage can remain after raw expiry.

System reports are available as JSON and escaped HTML. An organization-bound NDJSON export includes supported immutable records and relationships with an explicit completion trailer. Credentials and authentication material are excluded. Raw capture bodies are retrieved separately before expiry.

Operational logging uses allowed fields and excludes raw observations, credentials, request bodies and exception text. Internal security tests cover tenant isolation, unauthorized execution, credential scope, lease replay, evidence injection, bad fixes, adverse-history suppression and billing/usage races. See [internal assurance coverage](security/SELF_ASSURANCE.md).

## 7. Commercial and revenue workflows

Gauntlet records connect scoped properties, executions, actual findings, verified fixes and installed security memory. Reports and status counts are calculated from persisted records. These workflows support the planned Gauntlet-to-recurring-Verify conversion path.

The implemented public subscription structure is:

| Plan | Displayed monthly price | Protected systems | Active property families |
|---|---:|---:|---:|
| Starter | $199 | 1 | 20 |
| Growth | $499 | 5 | 100 |
| Pro | $999 | 15 | 500 |
| Enterprise | Custom | Agreed | Agreed |

These are implemented offers, not validated willingness-to-pay or measured margins. Execution allowances must be agreed from workload economics. Drafts and retained property versions do not consume extra active-property slots. Started work consumes its reserved execution units even on error/timeout; never-started work is refunded. No automatic monetary overage is charged.

Stripe checkout, portal and webhook reconciliation paths are implemented. Paid entitlements require current provider state and successful positive live payment evidence. Replay, cancellation, refunds, disputes, failed/test/zero payments and concurrency have local coverage with intercepted provider calls. Local pilot access does not count as revenue.

Transactional invitation delivery uses Resend with a durable outbox and bounded idempotent retries. Consented demo requests route allowed contact fields to HubSpot; free-text findings and security evidence are not sent. API and broker receive matching narrowly scoped provider configuration, with delivery disabled by default. No real email or CRM operation has been performed.

## 8. Deployment and supply chain

Terraform configuration covers Cloud Run services and Jobs, Cloud SQL, Secret Manager, Cloud Storage, Artifact Registry, Tasks/Scheduler, IAM and monitoring. Resource-inventory and database-bootstrap scripts support adopting approved resources before deployment. Public web exposure and scheduled execution are explicit activation steps.

CI configuration includes Python/PostgreSQL tests, SDK and frontend checks, browser acceptance, Terraform tests, secret scanning, SAST, dependency/container scanning and SBOM production. Actions and dependency lockfiles are pinned. Separate non-root Python and web runtime images have been built and probed locally.

No GCP resources were created, no image was published, and no GitHub workflow ran remotely. Local image acceptance used Linux ARM64; it does not certify a future AMD64 cloud build.

## 9. Recorded verification results

These are the final implementation-pass results, reviewed for this report. No application behavior was changed and no test suite was rerun merely to produce the report.

| Verification | Recorded result |
|---|---|
| Python core, API, security and integration suite | 301 passed |
| Browser acceptance | 7 passed |
| TypeScript SDK | 3 passed |
| Infrastructure policy tests | 7 passed, offline mocked provider |
| Type checking / optimized frontend build | Passed |
| Ruff / workflow lint / Terraform fmt and validate | Passed |
| Semgrep | 96 files; zero findings and zero parsing errors in configured rules |
| Gitleaks | Six directory scans; zero findings; no Git-history scan claimed |
| OSV dependency scan | Zero findings across 89 Python and 187 pnpm packages at scan time |
| Web image HIGH/CRITICAL gate | Zero findings |
| Python image HIGH/CRITICAL gate | Six raw findings, six verified absent-component dispositions, zero remaining |
| Runtime probes / SBOM schemas | Passed |

The Python dispositions are limited to exact image/package/component conditions, not blanket vulnerability exclusions. Their review expires on 14 September 2026. New builds and later vulnerability data require fresh gates. Python tests emitted 15 upstream deprecation warnings. Detailed image hashes, scan artifacts, limitations and reproduction steps are in [the supply-chain record](security/SCAN_RESULTS_2026-09-07.md).

## 10. What remains

| Remaining work | Why it is not yet accepted |
|---|---|
| Private GCP dev deployment and operational tests | Project/access, region/budget and approved resource inventory are pending |
| Managed sign-in and domain | Firebase/provider/domain/DNS configuration is pending |
| Live compiler and model execution | Real provider credentials and approved data handling are required |
| First customer Gauntlet | Needs an authorized staging system, fixtures, qualified collectors and real execution |
| Live GitHub release dependency | Needs a new trusted repository/workflow installation and release protection |
| Billing activation | Needs Stripe products/prices, measured allowances, sandbox exercise and live payment |
| Email/CRM activation | Needs verified sender, CRM configuration and designated live acceptance recipients |
| Operational production readiness | Real IAM denials, job failure recovery, alert delivery, backup restoration and customer retention/deletion procedures need validation |
| Business proof | No paid conversion, retention, expansion, margin or customer time-to-value has been measured |

Deferred product scope includes broad vendor-specific imports/adapters, richer attack generation, runtime enforcement, organization-wide policy management, arbitrary code execution, private enterprise runners, broad benchmarking and the calibrated digital-twin moonshot. Physical-autonomy-compatible types are present; physical actuation, robotics integrations and safety certification are not.

The next practical milestone is a private GCP deployment followed by one controlled customer Gauntlet and real integration acceptance. The current product supports demonstrating the security-memory proposition locally and preparing that engagement.

## Operating references

- [Start and verify the application](../README.md)
- [Engineering status](ENGINEERING_STATUS.md)
- [Commercial acceptance](COMMERCIAL_ACCEPTANCE.md)
- [Observer qualification](OBSERVATION_QUALIFICATION.md)
- [Evidence and retention](EVIDENCE_OPERATIONS.md)
- [Canaries and selection audits](ASSURANCE.md)
- [Consequential-tool contracts](TOOL_CONTRACTS.md)
- [GCP deployment](deployment/GCP.md)
