# Security review readiness

Direct answers for a customer's security reviewer. Nothing here claims a certification ThreatVeil has not obtained. There is no SOC 2 report, no penetration-test certificate and no formal verification.

**What data does ThreatVeil collect?**

The descriptions you give it:

- systems, environments and the authority boundary (principals, actions, resources, constraints)
- approved security claims

Bounded source facts:

- component identities and digests
- MCP tool names and bounded authorization facts
- a Git SHA
- Cloud Run configuration digests

Verification records:

- execution results, qualified observations and evidence records
- decisions and passports

All of it is tenant-scoped and classified `PRIVATE_CUSTOMER_DATA`.

**What is never collected?**

- Prompt bodies, tool arguments, tool outputs and span bodies from imports.
- Raw IAM members and environment values (kept only as digests).
- Credentials, which live only as references to your secret store.

**What credentials does it need?**

Narrow, expiring, read-only references per source, for example a GitHub read token or a Cloud Run `run.services.get`/`getIamPolicy` identity. MCP collection uses only the verified target binding. An import needs no credential. The GitHub App's `checks:write` is separate and optional.

**What gets executed?**

Only approved properties against targets you authorized and verified, inside the isolated worker; the API process never executes a fixture in a hosted deployment. Executions are bounded:

- by trial count
- by allowed paths, methods and tools
- by a per-run verification budget

**What gets stored and signed?**

Records are append-only (a database trigger forbids updates) under PostgreSQL FORCE row-level security. Decisions and passports are DSSE/in-toto statements signed with Ed25519, published in `/v1/trust/keys`.

**Can ThreatVeil access production systems?**

Only if you register and verify a production target, and only through the bounded adapters. An unobserved PRODUCTION deployment cannot borrow a staging or synthetic observation. Enforcement outside the local sandbox registry remains `AWAITING_QUALIFIED_ENFORCER`: ThreatVeil does not change your deployment.

**How is business-effect observation qualified?**

A qualified observer must read committed state after the transaction, correlated to the trial, with explicit tenant and resource. It must also demonstrate that it detects a known prohibited action, recognizes a known permitted action, and reports missing observations as inconclusive. A tool response alone never establishes a committed business effect. Missing ground truth stays INCONCLUSIVE.

**What happens if ThreatVeil is unavailable?**

Your consumer applies its own fail-open or fail-closed policy ([Assurance Gate](ASSURANCE_GATE.md)). Answers expire within 60 seconds, and signed decisions within five minutes. Nothing continues to authorize on its own.

**What does an ALLOW mean?**

All of the following held for this exact system state, environment, authority boundary, audience and epoch, at a stated time:

- every approved claim has fresh qualified evidence
- the forbidden outcome was prevented
- the legitimate task succeeded

It does not grant IAM permissions and does not prove enforcement.

**What does UNKNOWN mean?**

ThreatVeil cannot establish the conclusion. It never means cleared, and it is never promoted to a positive result.

**How are records independently verified?**

With the SDK or the `threatveil verify-*` commands, against a key or a trust directory you obtained yourself. The shared passport page also verifies in the browser. Neither method requires an account.

**Historical authenticity vs current status?**

A signature proves who issued a statement and when; it stays valid after the system changes. Current status is a separate online check (the gate, the decision status, or the passport status), recomputed on each request.

**How are tenants isolated?**

- FORCE RLS on every tenant table, under a non-owner NOSUPERUSER/NOBYPASSRLS runtime role.
- Every reference is checked against the organization, system and environment.
- Cross-tenant access returns 404 (tested across the new gate, intelligence and passport endpoints).
- Shared passport links are HMAC capabilities bound to one organization and passport.

**Does billing affect conclusions?**

No. Commercial state can deny capacity; it cannot change a verdict, decision, passport or current status (tested across upgrades to Business).

**What does ThreatVeil explicitly not claim?**

- universal safety
- runtime prevention
- identity management
- secrets management
- behavior outside the listed claims
- live customer enforcement before a qualified enforcer exists
- certification

See also [security model](SECURITY_MODEL.md), [known limitations](KNOWN_LIMITATIONS.md) and [data governance](DATA_GOVERNANCE.md).
