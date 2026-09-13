# Observation qualification

ThreatVeil distinguishes target ownership, collector identity, collector qualification, security outcome and candidate identity. A verified HTTPS domain does not establish a trustworthy observer.

## Registered contract

Register an approved property and active HTTP/MCP staging target with two distinct Ed25519 public keys, a source ID/version, initial-state digest, fixture reference and the exact candidate fingerprint component ID. Record a review explaining how the observer and independent ground-truth collector obtain their data and how their keys remain outside the agent's permissions. Public keys are metadata; private keys stay at the customer collectors. A distinct key alone is not proof of architectural independence.

An `Observation` carries receipts, witnesses, a typed system fingerprint, initial-state digest and `attestations` containing `observer` and `ground_truth` signatures. Both signatures cover the canonical observation digest with separate role/version domains. The ground-truth collector must independently read the actual side-effect sink and compare the observation to that state before signing. It must not blindly sign bytes supplied by the agent or the observer.

Use `threatveil.sdk.signing.sign_observation` at each collector boundary. Never load both production signing keys into the agent or runner. Core schema definitions are in `src/threatveil/core/contracts.py`; key canonicalization and binding checks live in `observers.py`.

## Qualification workflow

1. Create the source binding in the workspace.
2. Run `KNOWN_PERMITTED`, `KNOWN_PROHIBITED`, and `MISSING_OBSERVATION`, each as a separate active, one-sample run with explicit approved staging stimuli.
3. Return the assigned correlation ID unchanged. Sign the observation and the checked ground-truth digest. The prepared staging fixture supplies the known safe/unsafe/missing controls; do not execute unsafe controls against production.
4. ThreatVeil validates assignment, source version, both signatures, initial-state digest and the observation contract. It expects useful PASS, confirmed FAIL, and INCONCLUSIVE respectively.
5. A security owner reviews the three persisted run/evidence references and source independence, then approves a new immutable observer version. Qualification control runs cannot become verified remediation baselines.
6. Ordinary assurance runs select that exact approved source binding. A changed key, target, property or observation source requires a new qualification. Revocation takes effect for execution access and current applicability.

Expected candidate identity is separate from the observed fingerprint. For a versioned application/model, supply the expected component digest. For GitHub, a verified workflow SHA must equal the signed observed application version on the registered component. Missing or mismatched candidate identity cannot establish a useful verified fix.

## Limits

Signatures establish provenance and detect substitution; they do not prove a collector is uncompromised or correctly implemented. Human source review and known control executions remain necessary. Historical evidence is scoped to the recorded source, boundary, candidate and fixture. Imported traces cannot install a qualified source. Customer-managed state resets do not establish independence of stochastic model/provider behavior; statistical degradation is withheld when that assumption is unsupported.

Local acceptance uses real PostgreSQL, signing keys and an actual synthetic SQL sink behind a simulated HTTPS transport. It is not a live customer endpoint qualification.
