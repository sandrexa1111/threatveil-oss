# Local adversarial review before private GCP activation

**Scope.** Every surface added in this wave, plus a re-review of the boundaries those surfaces
touch. Method: read the code adversarially, then write a test that tries to break it. Findings
that are fixed say so; findings that are accepted say why.

This is a self-review by the people who wrote the code. It is not a third-party assessment, and
no certification is claimed.

---

## 1. Findings found and fixed in this wave

| # | Finding | Severity | Fix | Test |
|---|---|---|---|---|
| 1 | **A shared passport disclosed internal identifiers and resource names.** The signed document carried organization, system, environment and state IDs, the decision ID, and every resource name behind each authority. A share link handed all of it to an outside party | High (privacy) | Disclosure profiles. `STANDARD` (the default) withholds all of it and carries a pseudonymous `system.reference` digest instead; internal references moved into the record payload, where status recomputation reads them. `INTERNAL` keeps them for recipients already inside the trust boundary. A signature covers exactly what it signs, so the redaction happens at issuance, not at share time | `test_a_shareable_passport_withholds_identifiers_and_resource_names`, `test_a_shared_passport_carries_no_internal_identifier` |
| 2 | **Sharing needed no confirmation of what would be disclosed.** | Medium | `confirm_disclosure: true` is now required, and `GET /v1/passports/{id}/disclosure-preview` shows exactly what an external recipient would see, before any link exists. The workspace requires reviewing it first | passport tests + the browser suite |
| 3 | **No input model rejected control characters.** A NUL byte in any free-text field would reach PostgreSQL and fail as a 500 instead of a clean refusal | Medium (availability, hygiene) | The shared `Input` base now refuses C0/C1 controls and DEL across strings, lists and nested objects (newline, carriage return and tab stay allowed), and every new request model inherits it | `test_control_characters_and_unbounded_documents_are_refused` |
| 4 | **A proposed-change reference id accepted path-looking values** (`../../etc/passwd`). Nothing opened it, but a label that looks like a path invites a future mistake | Low | Reference ids reject `..` and leading `/`; URLs must be `https`, are bounded, and are never fetched | same test |
| 5 | **The AI endpoints answered the feature flag before checking tenancy**, so a caller could learn whether AI was enabled for a system they cannot see | Low (information exposure) | Tenancy is resolved first; the provider is constructed afterwards | cross-tenant sweep |
| 6 | **59 record kinds were unexportable.** A customer could not take their own change-assurance history with them | Medium (portability) | The export allowlist now covers every tenant record kind, with exactly one deliberate exclusion (`credential`, which names a secret-manager version). A source-scanning test fails if a new kind is added without a decision | `tests/core/test_export_coverage.py` |

## 2. Boundaries re-verified (with where the verification lives)

| Boundary | Result | Where |
|---|---|---|
| Cross-tenant reads on every new endpoint (13 reads, 8 writes) | 404, never 403-with-detail; "not found" and "not yours" are indistinguishable | `test_no_new_surface_answers_another_tenant` |
| PostgreSQL row security under the runtime role | `threatveil_app` is `NOSUPERUSER`/`NOBYPASSRLS`; FORCE RLS applies to the owner too | existing product tests + new operator tests |
| Operator store isolation | the runtime role is denied on `operator_records` (privileges revoked, RLS with no policy for it); even with `tv.operator_read` set it sees zero rows of any other tenant; no product route touches it | `test_operator_store_is_unreachable_by_the_runtime_role`, `test_the_product_api_exposes_no_operator_surface` |
| Operator cross-tenant read path | narrow by construction: the organization list only, then each organization measured **inside its own tenant context**; every report run appends an `operator_access` record | `test_founder_report_counts_only_classified_external_organizations` |
| Append-only memory | `UPDATE` on a feedback record fails for the runtime role; `UPDATE` on `operator_records` fails for the operator too | both tests above |
| Share tokens | 118-char HMAC capability over org + passport + share + expiry, HKDF-derived from the signing key with domain separation; forged, truncated and wrong-length tokens are 404; revocation gives 410; 30 status checks per minute per share | existing passport tests |
| Forged or altered passport | tampered payload, wrong key and wrong expected scope all fail verification | `test_passport_verifies_offline_with_a_trusted_key_or_the_published_directory` |
| Wrong trust root / expired signer | key resolution requires the key to have been valid at issue time and not revoked | trust-directory tests |
| Role boundaries | mapping review, observer qualification, passport issuance, auto re-proof approval and operator actions all require the SECURITY role set; viewers cannot write | endpoint `require(...)` plus role tests |
| CSRF | cookie sessions require `X-CSRF-Token` and an exact origin match; API tokens are bearer-only and carry no cookie authority | existing auth tests |
| Rate limiting | 120 writes/minute per identity per route globally (20 on auth and lead routes), plus 30 proposed-change evaluations per organization per minute and 30 public passport checks per minute per share | middleware + `proposed_changes._limit` |
| Request body bound | 2 MB, enforced while streaming rather than from `Content-Length`; a 3 MB proposal is 413 | adversarial test |
| Document bombs | bounded depth, breadth, leaf count and size on every imported or proposed document; YAML anchors and aliases refused; deep (80 levels) and wide (20 000 keys) payloads are refused | adversarial test + `test_yaml_is_bounded_and_anchors_are_refused` |
| Arbitrary SQL | none exists. The PostgreSQL observer composes validated identifiers with `psycopg.sql`, runs `READ ONLY` with a statement timeout and a row limit, and rolls back. Identifier injection attempts fail validation | `test_observer_contracts_are_bounded_honest_and_tenant_isolated` |
| SSRF | the only outbound calls are to operator-configured connector endpoints through verified target bindings. Proposed-change reference URLs are labels and are never fetched | code review + reference validation |
| Path traversal | no endpoint takes a filesystem path. Evidence object keys are derived, never supplied. Reference ids reject `..` | review + adversarial test |
| Command execution | no server code shells out. The only `subprocess` use is in the **local** CLI (`git log` / `git show`) with list arguments, no shell, a 30-second timeout and a size bound | `grep subprocess src/threatveil` → `cli.py` only |
| Webhook replay | provider event ids are recorded in `webhook_events` and replays are idempotent; GitHub signatures are verified with `hmac.compare_digest` | existing billing and GitHub tests |
| Malicious MCP metadata | tool descriptions and annotations stay unreviewed declarations and never grant authority; catalogue parts are compared by digest; protocol era comes from an observed response | source-semantics tests |
| SSE bounds | event count, byte size and UTF-8 validity bounded; a non-JSON or oversized stream is a protocol error | `mcp_protocol` bounds |
| Secret and error leakage | parse failures return content-free messages (a test asserts a marker string in a rejected payload does not appear in the response); environment values, headers and tokens are dropped by the agent-definition parser; `credential` records are never exported | adversarial tests + `test_mcp_servers_are_named_and_secret_values_are_never_retained` |
| Tenant identifiers on public pages | the public passport view contains no organization, user, system, environment, target or installation identifier, and no resource names | `test_a_shared_passport_carries_no_internal_identifier` |
| Unauthenticated access | `/v1/build-info`, `/v1/measurements/*` and every system route return 401 without a session or token | adversarial test |

## 3. Accepted risks (stated, not hidden)

| Risk | Why it is accepted now | What would change it |
|---|---|---|
| Self-review, not third-party | pre-revenue, pre-deployment; a paid assessment before a single customer would buy a report about a product that may still change shape | an external review before the first production (non-staging) customer |
| No SOC 2 / ISO certification | none is claimed anywhere in the product or marketing | enterprise procurement demand, after revenue |
| Operator access uses the migration identity | it is the only identity that can read across tenants, and it is already the most protected credential; every use is recorded | a dedicated read-only operator role with its own policies, when more than one person holds it |
| A wrong observer contract yields a confident wrong answer | the harness plus a human review is the control; ThreatVeil cannot verify that the named system really is the system of record | requalification evidence from real engagements |
| Declared claims can be wrong | they are labelled `NOT_YET_VERIFIED` everywhere and never reported as supported | nothing; this is the correct design |
| The runtime role can set `tv.operator_read` | it has no policy granting it anything, so setting it changes nothing (verified) | — |
| Dependencies are pinned by lockfile, not by digest for every transitive artifact | `uv.lock` and `pnpm-lock.yaml` pin versions and hashes; container images are pinned by digest in Terraform | a full SBOM-diff gate in CI, after deployment |

## 4. What to do at activation, before a customer exists

1. Provision the operator signing key and the published trust directory; do not rely on the
   derived single-key directory.
2. Set `TV_SOURCE_REVISION`, `TV_BUILD_TIME` (image build) and `TV_IMAGE_DIGEST` (Terraform), then
   check `/v1/build-info` reports no `UNKNOWN`.
3. Confirm `TV_LOCAL_AUTH=false`, `TV_AI_PROVIDER=disabled`, `TV_AUTO_REPROOF_ENABLED=false`,
   `billing_provider` not `mock`.
4. Verify the runtime database role is `NOSUPERUSER`/`NOBYPASSRLS` in the deployed instance (the
   API refuses to start otherwise).
5. Run the container acceptance suite against the deployed image, not only locally.
6. Re-run this review the first time a real customer connects a live source, because that is the
   first time the threat model includes someone else's production data.
