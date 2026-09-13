# Release and activation gates — 10 September 2026

This records local implementation evidence. It does not close private GCP or customer acceptance.

| Gate | Implemented and verified locally | Externally pending |
|---|---|---|
| P0-1 GitHub ingress/publication | Exact webhook route forwards HMAC signature, event and delivery headers with untouched body bytes. API and broker receive matching App ID/private key; API alone receives webhook secret; runner/launcher/web are excluded. | Actual hosted signed push, App permissions, published exact check, external branch/deployment policy and stale-check behavior. |
| P0-2 Complete machine decision | Separate expiring exact-plan capability invokes the same complete-property canonical issuer and signing path. Policy, property versions and issuer authority are rechecked transactionally. | Actual customer's CI credential custody and release workflow; genuine qualified Git candidate observation and external gate acceptance. |
| P0-3 Assisted setup | Owned by the connected customer journey implementation; see implementation report. | Fresh customer/operator observation qualification and accepted scope. |
| P0-4 Activation readiness | Read-only preflight validates signing, managed auth/origin, runtime role/FORCE RLS/migration head, required providers, image digests, alerts, budgets, rollback and recovery/retention configuration. | Managed login, effective cloud IAM, two-tenant drills, delivery, restore, retention and rollback. |

## Machine release contract

Normal `tvk_` execute credentials retain developer authority. They cannot approve policies, create release authorizations or issue unrestricted complete releases. A separate `tvrel_` capability has authority only at `POST /v1/release-machine/decide`; it cannot run tests, approve properties, modify policy or read unrelated records.

1. Execute the approved proof-plan obligations using the existing bounded execution path and an execute credential.
2. A security/owner/admin session posts `/v1/release-policies` with `system_id`, `policy` and review `reason`. The server captures all approved property content digests and allocates the next system policy epoch under its transaction lock.
3. That session posts `/v1/release-authorizations` with `plan_id`, current `policy_id`, and optional `expires_in_seconds` (1–3600; default 900). The response includes the one-time displayed token, binding and expiry. Its stored record contains only the token hash.
4. The machine submits exact `organization_id`, `system_id`, `plan_id`, `repository_id` (null for nongit candidates), `candidate`, `candidate_fingerprint_digest`, complete `property_ids`, `policy_id` and `policy_epoch`. It cannot submit an alternate policy or exceptions.
5. The server verifies expiry/revocation, current security membership, unchanged complete property contents, policy epoch and active exact GitHub installation where relevant. Issuance and consumption are atomic under the same system lock. One grant yields one canonical signed release; replay returns 409 plus the existing release ID, without issuing a new decision.
6. Signed history retains `machine_authority` metadata. Current assessment becomes restrictive if its authority expires, is revoked, loses an active authorizer or changes policy. The historical envelope is unchanged.

The capability is an intentionally bounded bearer credential. Security approval remains per exact plan, not a permanent unattended lease. A fresh candidate needs a fresh review/grant. Protect its short-lived value as a CI secret and never place it in source or logs. GitHub OIDC remains the existing execution path; this change does not claim automatic OIDC exchange for full-system release authority.

Python: `ThreatVeilClient(base_url, token=release_token).decide_authorized_release(binding)`.
TypeScript: `new ThreatVeilClient(baseUrl, releaseToken).decideAuthorizedRelease(binding)`.
CLI: set `TV_RELEASE_TOKEN` from the reviewed grant and run `threatveil decide-authorized-release binding.json --output decision.json`. `TV_API_URL` may be the hosted `/api/backend` base. Non-ALLOW policy results exit 2. Existing `decide-release` still requires a security-authorized interactive transport; an ordinary API token does not gain that authority.

No database table rewrite is required. New append-only kinds are `release_policy`, `release_authorization`, `release_authorization_revocation` and `release_authorization_use`, under existing tenant-safe Record/Edge storage. Existing receipt profiles and historical signatures are unchanged.

## Evidence

- `scripts/check_github_relay.py` starts the actual FastAPI application and an isolated Next host with a byte-for-byte copy of the current relay handler. Local real HTTP acceptance: direct 202; relay 202 with matching response; tampered bytes 401; absent signature 401. `.local/p0-acceptance/github-relay.json` records the source digest. This does not test Google IAM or a real GitHub sender.
- `infra/tests/security.tftest.hcl`: ten mocked provider tests passed, including incomplete/misplaced App configuration rejection and exact API/broker mounts with runner exclusion. Terraform validation passed. No GCP requests or resource application occurred.
- The combined targeted Python run passed 85 tests across machine release, existing release integrity/security, GitHub lifecycle, activation, receipts, token scopes and Python SDK. After strengthening the machine fixture to two approved properties, all 18 machine/readiness tests passed. Omission now exercises a nonempty subset, not just invalid empty input.
- Negatives cover wrong tenant/system/repository/candidate/fingerprint/policy/epoch, omitted approved property, changed scope/policy, expired/revoked authorization, demoted approver and replay. A real synthetic committed-state PASS plus legitimate SUCCESS reaches ALLOW through the machine SDK, and policy change restricts current eligibility without changing independently verified historical receipt bytes.
- `.local/activation-readiness-local.json` deliberately reports `configuration_ready=false`, `cloud_accepted=false`: local role/FORCE RLS/head validation passes; deployment key/provider/identity/images/alerts/budgets and operational acceptance are not configured.

## Activation procedure

Copy `infra/activation-profile.example.json` into an ignored operator profile and fill real owners, immutable current/prior image digests, monitored notification destinations, explicit cloud/pilot budgets, public-key trust reference and accepted recovery/retention scope. Keep credentials in environment/Secret Manager; the profile contains references only.

Run `python -m threatveil.activation_readiness --profile /path/to/reviewed-profile.json --output /path/to/preflight.json` from the packaged repository root using the runtime service settings and runtime database role. A nonzero exit blocks activation. `/healthz` remains a process-health signal and cannot substitute for this check. Preflight never modifies database schema, cloud infrastructure or billing, and cannot set `cloud_accepted=true`.

Configure `github_app` in Terraform for shared publisher custody. Move prior `TV_GITHUB_*` entries out of `api_secret_bindings`; those legacy API-only placements are now rejected. Keep the receipt signing key in the API-only binding. Never mount either class of credential on workers. Independently distribute and archive the public signing key before accepting exported records.

Budget alerts are notifications, not a total-spend hard cap. Pilot verification capacity must also be provisioned through the commercial allowance controls. Record provider caps where available and the operator's disable/recovery response. Existing backup/PITR and storage lifecycle configuration do not prove a restore or complete customer-data erasure.

Private cloud acceptance must record exact principals, image digests and evidence for managed login/origin, two tenants, worker denials/replay, real signed ingress/publication, signed release verification, delivered alerts, isolated restore/projection recovery, retention boundaries and rollback. Before accepted production BLOCK, test alternate deployment paths, bypass privileges, stale/superseded checks and exact activated artifacts. Public activation, cloud apply and real charges remain separately authorized external actions.
