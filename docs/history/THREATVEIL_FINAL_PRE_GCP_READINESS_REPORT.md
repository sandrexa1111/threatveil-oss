# ThreatVeil — Final Pre-GCP Correction & Deployment-Readiness Report

**Date:** 11 September 2026. **Scope:** local repository only. No GCP resource was created, no Terraform was applied, no Stripe call was made, no card was charged, no customer or external system was contacted or modified. A local Colima VM ran isolated acceptance containers and was stopped at the end.

## A. Executive result

# READY_FOR_PRIVATE_GCP

All three structural P0s from the frontier-readiness audit are fixed, and so is the trust-distribution prerequisite. The complete historical regression passes, and the new adversarial regression passes too. The activation preflight now fails only on real external deployment inputs.

| Gate | Result |
|---|---|
| Python suite | **603 passed**, 21 dependency warnings, 31.16 s (baseline 564) |
| Ruff | clean |
| Strict TypeScript | clean |
| Next.js 16.3.4 production build | passed (10 routes, 8 static pages) |
| Browser acceptance (Playwright) | **13 passed** (prior baseline 12; one new information-architecture test) |
| TypeScript SDK | build + **4 passed** |
| Terraform 1.16.1 | `validate` success + **10 mocked tests passed** |
| End-to-end finance demonstration | completed; **8 signed records independently verified** |
| Activation preflight | `configuration_ready=false`, `cloud_accepted=false`; the database check passes; every failing check is an external input |

How these were run, stated plainly because it is not the usual path. This machine has no Node on PATH. I ran strict TypeScript with the Node binary bundled in ChatGPT.app, read-only. That binary cannot load Next's native addons: macOS code-signing rejects them because they carry a different Team ID. So the production build, the browser suite and the SDK tests ran in clean Linux containers: `node:24-alpine` and `mcr.microsoft.com/playwright:v1.63.0-noble`. Those containers ran against an isolated `postgres:17-alpine`, provisioned with the same role model as `scripts/local_db.sh` (`threatveil_app` NOSUPERUSER/NOBYPASSRLS). Terraform ran in `hashicorp/terraform:1.16.1`. Python ran on the host against the project's local PostgreSQL. **Re-run `pnpm build` and `pnpm test:web` on a machine with a normal Node install before deploying.** I expect identical results, but I did not observe them on that toolchain.

## B. Repository state before corrections

Head was `0007`, and the audit's baseline reproduced exactly: 564 Python tests. Each defect was confirmed in code before I changed anything:

- `POST /v1/change-assurance/finance/assess` raised 409 when `not settings().is_local`, and the UI hid every change control behind a `local` flag.
- MCP: `SUPPORTED_PROTOCOLS = ("2025-11-25",)`. The adapter hard-failed unless `initialize` returned exactly that revision. The collector forced `source_version = "MCP 2025-11-25"`, and `sdk/mcp_server.py` served only the handshake.
- 17 flat navigation items, with the change-assurance flow as item 2. `/app` led with the procurement demonstration. Every public CTA pointed at "Discuss Integrity Launch". Hosted Google sign-in never sent an organization name, so the API defaulted it to "My organization".
- `enforcement.ci` was listed in the catalog but **checked nowhere in code**, so a label, not a boundary.
- There was no published trust root and no rotation semantics.

**Where the audit and the code disagreed, the code won:**

- The audit framed P0-1 as "remove the local gate." The code showed why the gate existed: `_finance_assess` calls `execute_run` directly, which is the local control-plane executor. Lifting the gate would have run fixtures inside the hosted API process and broken the broker/worker isolation. The fix is asynchronous instead (§C).
- The audit said MCP 2026-07-28 "deleted" the handshake. The specification is more precise: it defines a *dual-era* model with an explicit HTTP fallback procedure. I implemented that model, not a version swap.

## C. P0-1 — hosted Free correction

**Old defect.** A hosted Free signup could create the Finance Agent, using its entire system allowance and 3 of its 5 property families, and then hit a 409.

**Fix** (`change_assurance_api.py`). The assessment now always executes through the ordinary `create_run` path, which enqueues the outbox that the isolated worker drains. The worker already supported `run_finance` (`worker.py`). The endpoint is resumable:

1. The first call dispatches one run per approved claim and records an append-only `finance_assessment_dispatched` checkpoint with the run IDs.
2. While any run is unsettled, it returns **202** `{status: "RUNNING", run_ids, pending, next_action}` with the limitation "An unfinished run establishes no security conclusion."
3. Once every run has settled with a persisted result, the same call continues through the unchanged plan → release → state → transition → decision path and returns **201**.

Only `_api_executes_runs()` (true in local/test) runs verification inline, because local development has no separate worker. The existing idempotency and version-conflict protections apply to the new checkpoint as well. The UI's `assess()` polls on 202, and every `local` gate is gone.

**Isolation (§22).** The sandbox is structurally bound, and none of these checks was relaxed: a SANDBOX environment, the `finance-v1` profile on both system and target, the `synthetic_procurement` adapter, and a fresh `sqlite3.connect(":memory:")` per trial. The assessment refuses any system without the finance profile (422). Synthetic enforcement refuses any environment that is not that sandbox (403). No URL, credential, command or customer database is reachable from the fixture.

**What is not proven locally.** The hosted path was exercised through the API with in-process execution disabled, and `execute_run` stood in for the worker. The real Cloud Run job, broker and launcher delivery is only demonstrable in cloud acceptance.

## D. P0-2 — MCP modernization

I read the official specification before touching any code: overview, versioning, Streamable HTTP, base `_meta`, tools, `server/discover` and caching. New module: `integrations/mcp_protocol.py`, shared by the client, discovery, the connector and ThreatVeil's own server.

| Revision | Era | Status |
|---|---|---|
| `2026-07-28` | Modern (stateless) | **Preferred** |
| `2025-11-25` | Legacy (handshake) | Supported during the specification's 12-month deprecation window |
| Anything else | — | Refused, fail closed |

**Behavior differences implemented:**

- **Per-request metadata.** Every modern request carries `_meta` with `io.modelcontextprotocol/protocolVersion` and `clientCapabilities` (both required) plus `clientInfo`.
- **Header mirroring.** `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` for named methods, using the specification's Base64 sentinel encoding.
- **Accept header.** `Accept: application/json, text/event-stream` on every request.
- **No sessions.** No `initialize` and no `Mcp-Session-Id` in the modern era.
- **Era detection by observation.** The client probes `server/discover` at the modern revision. A recognized specification error (-32020, -32021 or -32022) identifies a modern server; on -32022 it picks a mutually supported revision from `data.supported` and retries once. Any other response is treated as a legacy server, including the JSON-RPC error a handshake-era server returns under HTTP 200. There is no silent downgrade and no silent upgrade.
- **Result types.** `resultType` is validated: absent means `complete`, per the specification. An interim `input_required` result is refused, and unknown result types are invalid.
- **SSE responses.** Request-scoped SSE responses are parsed for the final response, with bounded event counts.
- **Cache hints.** `ttlMs` and `cacheScope` follow the specification (absent or negative is treated as 0). Across pages, the least fresh TTL bounds the joined catalog, and conflicting scopes abort the collection.
- **ThreatVeil's own server is dual-era.** Modern requests are stateless and implement `server/discover`, -32022 with a `supported` list, and `resultType` plus cache hints on cacheable results. It uses -32602 instead of the retired -32002. `initialize` still selects the legacy revision.
- **Transport allowlists.** Both allowlists now admit `mcp-method` and `mcp-name`; credential headers remain broker-only. `Mcp-Param-*` is deliberately not admitted, because ThreatVeil does not emit it.

**Declared coverage** (`FEATURE_SUPPORT`, also in the connector manifest limitations):

| Status | Features |
|---|---|
| SUPPORTED | per-request metadata; protocol-version header; header/body mirroring; `server/discover`; `tools/list` pagination; cache hints; unsupported-version renegotiation; legacy handshake; JSON responses; `resultType: complete` |
| PARTIAL | SSE responses (final response only); `x-mcp-header` (preserved in catalog identity, not emitted) |
| IGNORED | Tasks extension; MCP Apps |
| UNKNOWN | Enterprise-Managed Authorization; Client ID Metadata Documents — neither implemented nor claimed |
| UNSUPPORTED | multi round-trip requests / `input_required`; `subscriptions/listen`; stdio; elicitation/sampling/roots |

**How MCP feeds the model (§6).** The negotiated revision, era, supported versions, cache TTL and cache scope are new `MCPToolSnapshot` fields and connector facts (`protocol_era`, `catalog_cache_ttl_ms`, `catalog_cache_scope`). They are **deliberately excluded from the catalog identity digest**, so a changed TTL is never mistaken for a changed tool contract. `supported_versions` joins the metadata diff (`mcp-contract-diff-v2`). Tool components keep their `mcp:` and `permissions:` dependencies, so a catalog change still flows through source change → change event → claim dependency impact → applicability reassessment. Nothing auto-escalates: unknown mappings remain UNKNOWN.

## E. P0-3 — unified product experience

| Before (17 flat items) | After |
|---|---|
| Overview · Protect a system · Releases · Systems · Properties · Targets · Findings · Runs · Evidence ledger · Fixes · Regressions · Integrity Launch · Integrations · Reports · Change explorer · Schedules · Property reuse | **ASSURANCE:** Systems · What changed · What still holds · Decisions · Sources · Records |
| | **Advanced** (collapsed; opens automatically when inside it): Protection journey · Releases · System register · Security properties · Authorized targets · Findings · Execution history · Evidence ledger · Verified fixes · Regressions · Procurement demonstration · Integrity Launch · Integrations · Reports · Change explorer · Schedules · Property reuse |

Nothing was deleted. The procurement demonstration moved to `/app/demo`, and "New run" moved to the execution surfaces (`demo`, `runs`). `/app` now leads with the control question: *"Does current evidence still justify this system's authority to act?"* It shows the current-assurance status, obligations and the system list. Internal nouns are translated at the UX boundary only; applicability, for example, becomes *"The evidence was created for an earlier system state."*

**Public site.** The primary CTA is now **Start free** in the header, hero, pricing and closing sections; "Discuss an Integrity Launch" is secondary. The hero reads *"Your agent changed. Which of your security conclusions are still true?"* **Autonomous Release Integrity** remains the concrete product wedge.

## F. Signup / organization provisioning

The managed sign-in screen now asks for a **workspace name** and sends it as `organization_name` in `/v1/auth/exchange`. The button reads "Start free with Google". Name validation is the existing server-side `min_length=1, max_length=120`. The name is optional, and the API default still applies to direct API callers who omit it. New organizations are provisioned on Free atomically, unchanged. Managed sign-in itself still requires Firebase configuration, an external input.

## G. Decision-status UX

The `AssuranceStatus` card is the largest object on the Systems, What still holds and Decide surfaces. It shows:

- a headline, e.g. "The earlier clearance no longer speaks for this system";
- the clearance label (Cleared / Expired / Superseded / Needs reassessment / Revoked) and its plain-language meaning;
- issued and expiry times;
- a "Still supported" list and a "Needs fresh evidence" list.

The underlying values (`CURRENT`, `EXPIRED`, `SUPERSEDED`, `REASSESS`, `REVOKED`) are unchanged and recomputed on read. No numeric trust score was introduced. The decision panel's own heading was changed to "The exact decision and its scope," so the conclusion is not stated twice.

## H. Assurance obligations

`projection()` now also returns `assurance_obligations`, derived only from the existing per-claim rows, source health and environment reasons. The kinds are RE_ESTABLISH (FAIL or task failure), RE_VERIFY (INVALID/STALE), CONFIRM (not enough evidence), RECONNECT_SOURCE, REVIEW (boundary reasons) and NONE. It adds no policy, proposes no remediation and never promotes an unknown. The existing technical `obligations` (proof-plan re-proof) are untouched.

## I. Commercial catalog changes

Catalog `2026-09-11.1`, still externally replaceable through `TV_COMMERCIAL_CATALOG_PATH`. Prices are unchanged hypotheses.

| Plan | USD/mo | Systems | Envs/system | Property families | Units/period | Retention | Enforcement capabilities |
|---|---:|---:|---:|---:|---:|---:|---|
| Free | 0 | 1 | **2** (was 1) | 5 | **1,000** (was 500) | 14 d | `enforcement.warn` |
| Pro | 99 | 3 | **3** (was 2) | 20 | 2,000 | 90 d | + **`enforcement.ci`**, `connector.github.enforce` (moved from Team) |
| Team | 399 | 10 | **5** (was 3) | 100 | 10,000 | 365 d | + collaboration, approval workflow, shared policy |
| Business | 2,000 | 30 | 10 | 300 | 30,000 | 730 d | + `enforcement.production`, advanced observers, governance, evidence sharing |
| Enterprise | contract | 30 base | 10 base | 300 base | 30,000 base | 730 d base | + contract, dedicated support, private deployment |

Free's second environment exists because one environment cannot express a state transition. The Pro/Team environment steps moved up to keep the ladder monotonic. Record export and verification are in every tier, and trust-root verification requires no account at all. Legacy plan interpretation is untouched (`test_entitlements.py` still passes).

## J. WARN / CI / production enforcement boundaries

**The CI boundary is now enforced in code, not only listed in the catalog.** `issue_release` requires `enforcement.ci` whenever `policy.mode == "BLOCK"` **or** any `property_modes` value is `BLOCK`. That second clause closes the laundering route, where a WARN policy with one BLOCK property would publish a failing check.

The GitHub check conclusion derives from the effective `release_action`: ALLOW→success, BLOCK→failure, otherwise neutral. A Free tenant therefore cannot produce a `failure` conclusion. Its check title still shows the honest underlying result, for example "WARN — underlying BLOCK."

`enforcement.warn` is **descriptive**: WARN is available by default. The boundaries actually enforced are `enforcement.ci` for BLOCK policies and `enforcement.production` for non-sandbox enforcement requests, which remained `AWAITING_QUALIFIED_ENFORCER`. **An entitlement is not a deployed integration**; the catalog, docs and UI say so. The tests assert that billing never changes a conclusion: identical `security_verdict` and `evidence_digest` across upgrade to Business and downgrade to Free.

## K. Key directory / trust distribution

`GET /v1/trust/keys` is unauthenticated, publicly cacheable (the only route exempt from the global `no-store`), and carries no tenant data. It serves a `threatveil-trust-directory/v1` document. Each entry has: keyid, algorithm, signature profile, status, `valid_from`, `valid_until`, `revoked_at` / reason, public PEM, and `supersedes`.

- **Keyids are re-derived** from the key material on load, so a directory cannot rename or substitute keys.
- **Private material is refused.** At most one key may be ACTIVE.
- **The service refuses to publish** an operator directory that does not list its own signer as ACTIVE (503).
- **Without configuration** it derives a single-key directory, labelled `LOCAL_DEMONSTRATION` or `DERIVED`, never `OPERATOR_PROVISIONED`.

The configuration is `TV_TRUST_DIRECTORY_PATH`, `TV_TRUST_ISSUER`, and a stable default window. Full specification: [docs/TRUST_DISTRIBUTION.md](docs/TRUST_DISTRIBUTION.md).

## L. Key rotation

- **ACTIVE** signs new records.
- **RETIRED** no longer signs, but still verifies anything signed inside its window.
- **REVOKED** verifies nothing, including historical records, because a compromised key cannot separate genuine from forged signatures.

A record signed outside its key's window is refused even if the signature is arithmetically valid. Rotation never touches a signed record. There is no automated rotation schedule: rotation is an operator action, and the directory records the result.

## M. Independent verifier behavior

`sdk/trust_directory.py` has no backend dependency.

- `verify_change_record` remains the primitive: the caller supplies a key it already trusts.
- `verify_change_record_with_directory` resolves the key from a directory the caller trusts, then applies status and window checks before the signature check.

**Offline historical authenticity is kept separate from the online current-status check** (`status_uri`). A record can be authentic while its decision is no longer current. There is still one algorithm profile, and no transparency log.

## N. Security invariants preserved

The full historical suite passes unchanged in meaning. It covers:

- tenant isolation, FORCE RLS and append-only history;
- complete-property release semantics, useful-task validation and qualified evidence;
- conservative invalidation, explicit UNKNOWN and exception semantics;
- audience, nonce, state-digest, envelope-digest and policy-epoch binding;
- signing verification, billing/security separation and worker/broker separation.

The hosted assessment adds no execution path inside the API. The only header-allowlist change admits protocol routing metadata that is mirrored from the body. Nothing weakened a check to make a test pass.

## O. Sandbox/demo isolation

See §C. Tested adversarially:

- a foreign system cannot run the finance assessment (422);
- an idempotency key cannot be rebound to another configuration (409);
- no state, decision or evidence exists while runs are pending (evidence returns 409);
- synthetic enforcement is sandbox-only;
- cross-tenant access is covered by the existing RLS suites.

## P. Tests executed

| Command | Result |
|---|---|
| `uv run ruff check src/ tests/ scripts/` | clean |
| `uv run pytest -p no:cacheprovider` | **603 passed**, 21 warnings, 31.16 s |
| `node node_modules/typescript/bin/tsc --noEmit -p tsconfig.json` (apps/web) | clean |
| `pnpm install --frozen-lockfile && pnpm build` (apps/web, container) | passed |
| `npx playwright test` (full stack in container, isolated Postgres 17) | **13 passed** in 21.0 s |
| `pnpm build && pnpm test` (TypeScript SDK, container) | **4 passed** |
| `terraform init -backend=false && terraform validate && terraform test` | valid; **10 passed** |
| `scripts/change_assurance_demo.py --trusted-public-key <independently exported key>` | completed; 8 records verified |
| `python -m threatveil.activation_readiness --profile infra/activation-profile.example.json` | correctly blocked (§X) |

**New test files:**

- `tests/security/test_trust_directory.py` (11)
- `tests/integration/test_hosted_free_activation.py` (4)

**Expanded test files:**

- MCP intake/adapter/server/connector conformance, covering both eras, version renegotiation, no mutually supported revision, TTL 0, conflicting scope, SSE, `input_required`, header mirroring, and a `tools/call` blocked by the read transport.
- `test_commercial_platform.py` (+4): Free WARN-not-BLOCK, plan change never alters truth, Business production boundary, per-property laundering.
- `test_activation_readiness.py` (+1): no trust root blocks activation.
- One new browser test for the information architecture and trust root.

Evidence is archived under `.local/pre-gcp-correction/`.

## Q. Failures encountered and fixes

**Existing tests I had to change** — I list them because edited tests are a risk:

- Legacy MCP fixtures now answer `server/discover` with a JSON-RPC error, which is how real handshake-era servers behave. Their expected method lists now start with the probe.
- Release-semantics suites call `with_enforcement()` (buy Pro) before creating BLOCK policies. That is 18 failures caused by the new CI gate, which is correct behavior.
- One commercial test hard-coded the old 500-unit budget; it now reads the plan.
- The activation "ready" test now supplies an operator trust directory.
- Browser specs were updated for the new routes and labels, `/app/demo`, and the `enforcement.ci` upgrade.

**Code defects found and fixed during the session:**

- A legacy fallback that missed the HTTP-200 JSON-RPC error case.
- The preflight was reading global settings instead of the configuration passed to it.
- The trust route was being cached as `no-store`.
- TypeScript projection types (`Record<string, unknown>` versus `RecordData`).
- A duplicated decision headline.

**Environment problems** (not product defects): the borrowed Node's code-signing conflict, macOS AppleDouble `._*` files in the container tarball breaking Alembic, the Python `tests/` directory missing from the first tarball, a stale web server holding the port, and a web-origin mismatch after a port change. All of these were resolved before the final runs reported above.

## R. Full end-to-end demonstration

The local HTTP demonstration, verified with an independently exported public key:

1. Free provisioned.
2. Baseline: PASS + SUCCESS → **ALLOW**; sandbox activation ACKNOWLEDGED.
3. Mock Pro unlocked a second system.
4. Imported MCP permission change → prior support affected → **REQUIRE_APPROVAL**.
5. Regressed approval: committed forbidden beneficiary update → FAIL → **BLOCK**.
6. Bad fix: security PASS, task FAILURE → **BLOCK**.
7. Proper fix: **ALLOW**; activation epoch 2.
8. Scheduled downgrade, with historical FAIL unchanged.

Eight signed records were independently verified, in 1.66 s elapsed. All data is synthetic; no money, customer system or provider was touched.

## S. MCP conformance evidence

Covered by tests:

- Modern: stateless discovery and `tools/list` with mirrored headers and no session; freshness recorded.
- Legacy: fallback via both an HTTP-200 JSON-RPC error and a 400 with a non-modern body.
- Renegotiation: on -32022, a mutually supported revision is chosen and retried.
- Refusal when the server offers only an unimplemented revision.
- TTL 0 recorded as immediately stale; a conflicting page scope aborts.
- Missing `supportedVersions` is rejected; identity mismatch and cursor cycle both abort, in both eras.
- SSE final-response extraction; `input_required` refused.
- ThreatVeil's server: `server/discover`, -32022 with a `supported` list, missing `clientCapabilities` rejected, the handshake refused for stateless requests, a legacy revision refused as request metadata, -32602 versus -32002 by era, and tool results that are never cacheable.
- The connector's read transport refuses `tools/call`.

Fixtures are built from the specification's own example shapes.

## T. Hosted Free acceptance evidence

`test_hosted_free_activation.py` runs with the API refusing in-process execution. It covers: new organization on Free → finance boundary → **202 RUNNING** (repeat calls stay 202 with identical run IDs) → worker completes → **201 ALLOW** → regressed change → **FAIL/BLOCK** → the journey shows what holds and what does not → the prior ALLOW is no longer CURRENT → the signed record verifies against an independent key → the published trust root resolves the signer. A second system is refused with 402, `upgrade_url` and "retained"; history stays readable and unchanged.

The browser suite drives the same journey through the UI, including obligations and export.

## U. Subscription acceptance evidence

All 17 commercial-platform tests pass, covering the existing lifecycle plus the four new boundary tests in §P. The browser test covers Free → Pro → payment grace → recovery → scheduled Free, and pricing on mobile.

## V. Trust/rotation acceptance evidence

All 11 trust tests pass:

- rotation preserves historical verification;
- the historical record is byte-identical after rotation;
- a record signed after its key's retirement is refused;
- revocation invalidates history without affecting the successor key;
- unknown and wrong keys fail;
- a tampered record fails;
- a tampered directory fails (substituted material, renamed keyid, two ACTIVE keys, wrong profile);
- private material is refused;
- revocation must be timestamped;
- the endpoint is public, cacheable and secret-free;
- a directory that omits the signer is refused, and one that lists it is published as operator-provisioned.

## W. Remaining external GCP requirements

Machine-readable, from the preflight (full output: `.local/pre-gcp-correction/activation-readiness.json`):

```json
{
  "failing_checks_all_external": {
    "managed_auth_origin": "HTTPS web origin + Firebase project; local auth off",
    "receipt_signing": "Operator Ed25519 key in Secret Manager + signing_trust_reference in the activation profile",
    "trust_directory": "TV_TRUST_DIRECTORY_PATH: operator-managed directory listing the signer ACTIVE, >30 days before expiry",
    "managed_storage": "TV_SECRET_PROJECT and TV_EVIDENCE_BUCKET",
    "cloud_dispatch": "Cloud project/region, HTTPS broker URL, *.iam.gserviceaccount.com worker identity",
    "github_app": "Numeric App ID, RSA-2048+ private key, webhook secret >= 32 chars",
    "immutable_images": "python and web images pinned by sha256 digest",
    "rollback": "Named operator, rollback runbook, previous image digests",
    "alerts": "projects/*/notificationChannels/* destinations",
    "cost_guardrails": "Monthly budget, budget alert reference, pilot verification budget",
    "recovery_retention": "Restore runbook + accepted retention scope"
  },
  "passing_repository_internal": ["database", "provider_contract"],
  "external_acceptance_pending": [
    "Managed login and hosted origin/cookies",
    "Two-tenant isolation under deployed runtime roles",
    "Real GitHub signed push ingress and delivered exact check",
    "Worker IAM/bootstrap/replay denials",
    "Signed release independently verified with configured trust key",
    "Published trust directory reachable and mirrored by an external verifier",
    "Delivered monitoring and budget alerts",
    "Isolated backup restore, projection recovery and retention scope",
    "Rollback to recorded image digests"
  ]
}
```

With every input supplied, including an operator trust directory, the preflight reports `configuration_ready: true` and still `cloud_accepted: false` (`test_valid_static_configuration_never_implies_cloud_acceptance`).

## X. Activation preflight result

`configuration_ready: false`, `cloud_accepted: false`. `database` passes: runtime role is non-superuser/NOBYPASSRLS, FORCE RLS is on, and the head is `0007`. `provider_contract` passes. The eleven failures are exactly the external inputs in §W. The gate was not bypassed.

## Y. What remains deliberately NOT built

Anthropic `ConfigChange`, AWS AgentCore, A2A delegation semantics, Agent 365, Vertex Agent Engine, OpenAI Connector Registry, multi-agent derived authority, tenant-private learning, the system passport, REGIONAL HA, projection optimization, retention lifecycle enforcement, SOC 2, new vertical fixtures, production BLOCK integrations, autonomous remediation, MCP Enterprise-Managed Authorization / CIMD / Tasks / MRTR / subscriptions / stdio, a second signature algorithm, and a transparency log.

**Not renamed.** The audit's naming concern (Threat/Veil mis-signal) is recorded for a founder decision before the first long-lived contract. Package names, domains and the signed-record issuer are unchanged.

**Frontier architecture check (§25/§33).** Each point was checked against the code; none needs to be built now.

- **Without GitHub:** the model remains coherent; GitHub is one connector.
- **Protocol changes:** MCP protocol handling is isolated behind `mcp_protocol.py` and the connector contract.
- **Non-code permission changes:** a permission change without a commit is representable today, as a `permission_envelope` supersession or a `permissions:` source component.
- **Gateway tool authority:** an AgentCore Gateway change maps onto the same tool and permission components.
- **Delegation:** A2A delegation can extend the inert `delegates_to` relationship without redefining System.
- **External consumers:** decisions are already audience-, nonce- and epoch-bound, with a status URI, so they are ready for external consumption.
- **Verification without an account:** a buyer can now verify a record without an account, using the SDK and the published directory.

## Z. Exact next action

Prepare and review the private GCP activation profile from `infra/activation-profile.example.json`. Provision the operator signing key and an **operator-managed trust directory** before the first hosted record is signed. Review the Terraform plan, cost and IAM changes. Obtain explicit authorization for the infrastructure apply, then perform cloud acceptance, starting with two-tenant isolation and a real worker completing a hosted Free assessment. Before deploying, re-run the web build and browser suite on a machine with a standard Node install.

**Final product test (§32), answered from the product:**

| Question | Answer |
|---|---|
| Start without talking to sales? | Yes — Start free |
| Protect one system? | Yes |
| See a meaningful change? | Yes |
| See which prior conclusion is no longer current, and why? | Yes — per claim, in plain language |
| See what must be re-established? | Yes — obligations |
| See whether a prior clearance is still current? | Yes |
| Install a safe WARN control point? | Yes — it cannot block |
| Export and verify? | Yes — including with no account |
| Do it without learning ten internal nouns? | Yes — they live under Advanced |

Coding stops here; control is handed back to the founder.
