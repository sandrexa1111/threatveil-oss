# Commercial platform — local foundation

The primary unit is a protected autonomous system with a bounded environment and consequential authority. Repositories, provider models, tools and ephemeral agents are components, not independent billing units. Autonomous Release Integrity remains the initial commercial wedge; the entitlement model is independent of GitHub.

## Implemented

New organizations receive Free automatically in the same transaction as organization creation. Existing accounts are not silently migrated. Versioned plan snapshots and append-only `billing_event` records live in the existing tenant-scoped `records` store. `accounts` remains the locked operational projection used for verification reservations and settlement. Existing RLS, append-only triggers and record references apply; no destructive schema migration is introduced.

`commercial.py` owns plan resolution, frozen allowances, overrides, system/environment/property/verification capacity and capability checks. Callers ask for a capability or allowance instead of branching on plan names. `entitlements.py` retains approved-property-family accounting: drafts and retained versions do not consume new slots. System and environment checks count the entire tenant scope rather than a bounded UI page.

Local mock billing supports immediate upgrades, scheduled downgrades and cancellation, one bounded trial per Free organization, failed-payment grace and recovery, promotional discounts and contract-defined Enterprise overrides. Trial/grace/contract expiry falls back to the frozen Free version. Promotion expiry removes the price modifier without changing the subscribed plan. Repeated failure events cannot extend grace. Downgrades preserve existing systems, records and evidence; new creation stops while over allowance. The period boundary resets consumed units and carries in-flight reservations forward. An upgrade does not reset consumed units.

Each mutation locks the tenant Account row. A deterministic tenant-scoped event identifier plus request digest makes identical replay idempotent and rejects conflicting reuse. Optional expected revision rejects stale reordered commands. The browser supplies it. Expiry transitions append new events when the subscription is next read or used; this local workflow does not require a scheduler.

The mock API requires an authenticated owner/admin and is rejected outside local/test. The API cannot select an organization in its request body. An Enterprise override is a local provisioning fixture, not a hosted owner privilege. Hosted operator provisioning needs a separate authenticated operator workflow before exposure.

## Initial catalog

Source of truth: `src/threatveil/data/commercial_plans.json`, version `2026-09-10.1`.

| Plan | Monthly USD hypothesis | Protected systems | Environments/system | Approved property families | Verification units/period | Retention allowance |
|---|---:|---:|---:|---:|---:|---:|
| Free | 0 | 1 | 2 | 5 | 1,000 | 14 days |
| Pro | 99 | 3 | 3 | 20 | 2,000 | 90 days |
| Team | 399 | 10 | 5 | 100 | 10,000 | 365 days |
| Business | 2,000 | 30 | 10 | 300 | 30,000 | 730 days |
| Enterprise | Custom annual contract | Contract-defined (30 base) | Contract-defined (10 base) | Contract-defined (300 base) | Contract-defined (30,000 base) | Contract-defined (730-day base) |

These are unvalidated launch hypotheses, not proof of hosted unit economics or willingness to pay. One synthetic security trial and its legitimate-task control consume two execution units. There are no automatic paid overages. Physical storage/retention deletion does not occur from plan changes; data-governance processes remain separate.

All plans expose scoped explanations, signed/exportable records, API/CLI and baseline change/import paths. Verifying a record is never sold: the published trust root and the verifier are available to everyone, including people without an account.

The enforcement ladder is the commercial spine and is enforced in code, not merely labelled:

- **Free** carries `enforcement.warn`: a real, non-blocking control point. Free sees the identical underlying security truth and can install a WARN-mode gate, but `issue_release` refuses a `BLOCK` policy without `enforcement.ci`, so a Free integration can never stop a candidate.
- **Pro** carries `enforcement.ci` and `connector.github.enforce`: the first tier that can obtain a machine-consumable BLOCK for a CI gate. This is deliberately the first paid step; a category whose control point begins at the third tier cannot be experienced before purchase.
- **Team** adds collaboration, approval workflow and shared policy.
- **Business** adds `enforcement.production`, advanced observers, governance and evidence sharing. It is the tier at which ThreatVeil may participate in production enforcement for consequential systems, subject to a qualified enforcer; the capability is an allowance, never a deployed integration.
- **Enterprise** uses contract overrides in the same engine.

A capability allowance never implies that an external connector, SSO service, private deployment or enforcement integration is installed, qualified or production-accepted. Buying a tier changes what ThreatVeil is permitted to do; it never changes a security conclusion.

Free is sized so the category is reachable without payment: two environments, because a single environment cannot express a state transition, and 1,000 verification units, because a three-claim baseline consumes twelve and a realistic sequence of changes consumes many multiples of that. It is intentionally enough to exercise the actual bounded synthetic value path, including failures, missing observations, useful-task controls and changes. Legacy `pilot`, `starter`, `growth`, and pre-catalog `pro` contracts keep their prior interpretation. Legacy/custom configuration remains accessible through `TV_COMMERCIAL_PLANS`; ambiguous historical `pro` records are never silently reinterpreted as the new Pro tier.

## Configuration and APIs

`TV_COMMERCIAL_CATALOG_PATH` may point to a validated JSON catalog with the same schema. Prices, limits, promotion/trial/grace durations and optional Stripe price IDs are data, not business-logic constants. New plan purchases pin a full catalog version snapshot. Editing a catalog does not retroactively alter a subscribed contract. Increment catalog versions for published changes and retain the original files under normal change control. `TV_STRIPE_PRICES` and `TV_STRIPE_TRIAL_ALLOWANCES` preserve existing measured-provider configuration.

`TV_BILLING_PROVIDER` is `disabled`, `mock` or `stripe`. Disabled resolves to mock only in local/test; it stays disabled in hosted environments. Mock is explicitly prohibited in hosted settings. Stripe Checkout rejects live keys unless `TV_STRIPE_LIVE_CHARGES_ENABLED=true` is explicitly configured. `TV_STRIPE_TEST_ENTITLEMENTS_ENABLED=false` by default; setting it true permits independently reconciled test subscription allowances only with a `sk_test_` key, nonlive signed event/subscription/invoice and confirmed test payment. The resulting provider is `stripe_test` and `paid` remains false. This implementation does not activate either flag or contact Stripe.

| Endpoint | Contract |
|---|---|
| `GET /v1/commercial/catalog` | Public versioned plan catalog and truthful checkout availability |
| `GET /v1/commercial` | Tenant subscription, effective allowances, usage, price modifier, bounded event history |
| `POST /v1/commercial/subscription` | Local owner/admin command: `upgrade`, `downgrade`, `cancel`, `start_trial`, `payment_failed`, `payment_recovered`; `renew` rejects premature manual budget resets |
| `POST /v1/commercial/promotion` | Local owner/admin code/program/percentage/expiry modifier |
| `POST /v1/commercial/override` | Local owner/admin contract reference, reason, bounded entitlement patch, explicit expiry |
| `POST /v1/billing/checkout`, `/portal` | Existing compatibility endpoints through the billing-provider boundary |

Commands use `idempotency_key` and optionally `expected_revision`. Expiry timestamps require a timezone. Unknown fields are rejected, including security verdicts and organization selectors. The pricing and billing UIs consume this catalog rather than maintaining a separate price list. Billing shows current usage, scheduled change, grace/trial periods, discounts and append-only event history. The optional local sandbox exercises payment failure/recovery, cancellation and access promotions without payment credentials.

## Security boundary

Billing has no dependency on an assurance evaluator and writes only commercial events, subscription snapshots and the Account projection. It never rewrites historical evidence, property results, exceptions or signed decisions. Capacity exhaustion prevents execution or creation; it cannot turn incomplete work into a passing assessment. Commercial upgrades leave FAIL, missing-ground-truth INCONCLUSIVE and UNKNOWN unchanged.

Supported enforcement must additionally satisfy role authorization, approved policy, exact target/environment scope, source qualification and a real enforcement mechanism. Buying an enforcement capability cannot bypass these checks or convert a requested acknowledgement into observed enforcement.

Schedule creation requires `release.automation`, and scheduled execution rechecks it in the execution transaction. A downgrade therefore prevents future scheduled dispatch while preserving schedule/history. New invitations require `team.collaboration`; existing membership reads, role revocation and owner-protection rules remain available. Manual security assessment and honest ALLOW/BLOCK/WARN decisions are never gated on an enforcement plan.

## Provider and external status

The provider boundary separates local mock commands from Stripe customer/Checkout/portal/webhook reconciliation. Existing Stripe signature checks, atomic webhook claim, current-provider re-read, customer mapping and independently confirmed live payment logic remain. New-plan provider reconciliation adds an immutable subscription snapshot; it does not let a stale mock snapshot remain the active entitlement source. Provider subscriptions do not receive free local-clock renewal.

Stripe TEST-mode hosted acceptance is **pending**: actual provider credentials, private cloud deployment, configured Price IDs and budgets, test customer/payment, subscription lifecycle and webhook delivery must be exercised. The reconciler requires confirmed live payment to mark `paid=true`; explicit test entitlement mode and mock activation never assert collected money. Default test-mode deliveries still do not activate allowances without the test-entitlement flag. There is no claim of a real payment, hosted subscription, invoice delivery or production readiness from local tests.

## Operational and optional measurements

`GET /v1/measurements` derives tenant-only aggregates from service records: registered systems and second-system adoption, current supported boundaries, synthetic versus customer systems, current property applicability, connector blockers, canonical/source/code changes, security/task result distributions, execution units/duration, exact authorization actions, requests versus enforcement acknowledgements, and actual quota attempts by plan/resource. Current protected counts additionally require the current exact-state decision and matching acknowledgement; these count systems with at least one supported/acknowledged boundary, not universal coverage. Current support calls the canonical semantic evaluator; a signup, checklist, analytics event or historical pass cannot inflate the protected count. Historical registration-to-first-supported-case time is reported separately from current support. Boundary evaluation is capped at 1,000 with explicit completeness/lower-bound status.

Quota denials use a minimized `service_metric` only after the denied transaction unwinds. This avoids both rolling the metric back with the refusal and taking a second database connection while the tenant Account remains locked. They contain plan/resource/count/request identifier, never rejected request bodies, names, prompts or evidence. Failure to persist a metric retains the original denial. The existing safe operational logger still excludes exception text and payloads.

`GET/POST /v1/measurements/consent` maintains append-only independent permissions for product analytics, research and cross-customer learning. All optional permissions default false; research/cross-customer permission requires a contract reference. Consent grants do not activate any export, research or training pipeline. Existing data-governance policies remain separate requirements and no cross-customer processing is implemented.

`POST /v1/measurements/events` accepts only enumerated event/feature/connector/stage/action fields, optional same-tenant system ID and bounded numeric effort/cost. Product analytics consent is checked under the same Account lock as collection, making revocation effective for subsequent events. Same-key identical replay is idempotent; changed data conflicts. Events are explicitly customer-reported and have no assurance authority. Reported upgrade triggers, decision use, support minutes and verification cost supplement operational facts; they do not masquerade as actual labor, provider invoices or external consumer acceptance. No free-form evidence/prompt/text field exists. The API records these optional reports when explicitly submitted; a background collector or cross-customer warehouse is not enabled.

## Local acceptance evidence

`tests/integration/test_commercial_platform.py` exercises new Free provisioning and a real demo setup, system limits, upgrade without evidence mutation, deterministic downgrade and carried reservations, verification exhaustion, concurrent identical replay, conflicting replay, stale revision, failure/grace expiry, promotion/trial/Enterprise expiry, owner permissions, forbidden organization/security fields, catalog snapshot stability, and cross-tenant event isolation. Tests use the real local PostgreSQL app role and preserve existing database contents.

`tests/integration/test_entitlements.py` explicitly provisions the historical pilot fixture so old 20-property/3-system semantics remain tested. `tests/integration/test_billing.py` explicitly restores the pre-subscription period boundary for its legacy provider fixtures. The final focused backend run passed 84 tests across commercial, entitlements, provider reconciliation, measurements, delivery, maintenance and product compatibility. It includes default versus explicitly enabled Stripe test allowances, wrong provider customer/invoice/subscription, pre-catalog Pro compatibility, and a scheduled downgrade preventing later automatic execution. Ruff and TypeScript checks passed. The local commercial browser workflow and responsive pricing tests passed (2 tests); the root integration report records the final full-suite results.

`apps/web/tests/commercial-platform.spec.ts` exercises Free→Pro→payment grace→recovery→scheduled Free through the actual UI, plus catalog pricing and mobile overflow. `TV_TEST_API_URL` optionally routes its browser API requests to an isolated local API without replacing a running user's API service. Screenshot files are written under `.local/browser-tests`.

Current operational debt: append-only subscription snapshot lookup uses the existing tenant/kind index and a revision sort; measured growth may justify a dedicated projection/index. Expiry is reconciled on access. Retention allowances are not automated purge policies. Real Stripe test-mode acceptance and sales-assisted hosted contract provisioning remain external/implementation gates. Optional analytics require explicit API reports and consent; no general background tracker or learning warehouse is enabled. None of this debt changes evidence truth.

## Value boundaries (category-complete wave)

**Free sells the category.** It includes the system map, authority map and diff, change consequences, evidence currency, re-establishment, lifecycle, history, the Assurance Gate, and Current Assurance Passports with share links (tested on Free).

**Upgrade moments** come from capabilities and facts, never plan names; the plan offered is the least expensive self-service plan in the catalog carrying the missing capability. They appear at a first clearance without `enforcement.ci`, a used system allowance, a PRODUCTION environment without `enforcement.production`, a second reviewer or a refused invitation without `approval.workflow`, and ≥80% verification usage.

**Enterprise interest** (`POST /v1/commercial/interest`: private deployment, enterprise retention, production enforcement, qualified observer, design partner, Integrity Launch) is recorded idempotently and contacts no one.

Buying Business does not create an enforcement integration: external requests remain `AWAITING_QUALIFIED_ENFORCER`, and every assurance view is identical before and after an upgrade (tested). See [activation metrics](ACTIVATION_METRICS.md).
