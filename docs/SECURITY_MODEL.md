# Security model

The additive [change-assurance profile](CHANGE_ASSURANCE.md) treats imported source assertions, customer-declared relationships and deployment configuration as insufficient for positive evidence. State and authority scope, source freshness, exact candidate, complete properties, audience, nonce, expiry and prior operating epoch are checked independently. The commercial service can deny capacity, but cannot alter security/evidence records. Synthetic acknowledgements are limited to an explicit sandbox registry. Machine full-release grants use a separate expiring `tvrel_` authority, never elevated `tvk_` execution credentials. See [P0 threat and gate evidence](P0_ACCEPTANCE_2026-09-10.md).

Customer observations, model output, imported traces, webhooks and candidate labels are untrusted inputs. Only authorized targets and reviewed properties may execute; only qualified observations can establish assurance. A submitted expected fingerprint is planning input, not proof of deployment.

Positive release authority requires exact candidate type, identifier, version and digest, plus an independently observed complete fingerprint from the same target/observer boundary. Synthetic fixture evidence cannot authorize Git commits. Git evidence requires the verified workflow repository and exact SHA. Failure memory deliberately uses broader content identity: renaming a version does not hide a failure against the same artifact digest.

The suite checks non-owner tenant RLS, roles, immutable records, CSRF, real-peer authentication rate limits, SSRF/redirect boundaries, worker identity/possession/lease replay, quota races, adverse history, missing witnesses and exception/revocation behavior. Reviewer-supplied scope may not omit dependencies declared by the approved property. Two distinct security actors are required for exception request and approval.

System locking serializes source/member revocation and evidence changes with release signing. Expiry is evaluated at decision time; a signed historical ALLOW is not a perpetual authorization. External check propagation remains asynchronous. Customer-controlled staging can lie unless the independent observer and ground-truth qualification boundary is correctly established.

Raw local objects use content-addressed organization/run/digest namespaces, private files and descriptor-relative traversal rejecting child symlinks. Local erasure requires an owner request and a separate migration identity; runtime roles cannot enable append-only deletion by setting a transaction variable. Backups, provider data and downloaded exports remain separate erasure scopes.

These are tested engineering controls, not a penetration-test certification, formal verification, SOC 2 claim or guarantee of absence of vulnerabilities. Current images and live cloud deployment still require fresh acceptance.
