# Brand rename: what a new name would actually cost

**Status: audit only. Nothing was renamed, and no new name is proposed here.** This
document exists so that a rename is a decision with a known price rather than a surprise.

Every binding below is classified:

| Class | Meaning |
|---|---|
| **CONFIGURABLE** | Already deployment configuration. A rename is an environment change. |
| **MIGRATABLE** | Hard-coded, but renameable with a deprecation window in which both names work. |
| **HARD BINDING** | The old name is inside something already signed, hashed or published. It can never be retroactively changed; only superseded by a new version. |

---

## A. What this wave already moved behind configuration

| Binding | Before | Now |
|---|---|---|
| Passport `issuer` field | literal `"threatveil"` in the signed document | `settings().trust_issuer` (`TV_TRUST_ISSUER`) |
| Trust directory issuer | already `trust_issuer` | unchanged, now shared with passports |
| Passport schema `issuer` constraint | `{"const": "threatveil"}` | `{"type": "string", "minLength": 1}` — a verifier checks the issuer against the directory it trusts, not against a hard-coded name |

A verifier that pinned the literal string `threatveil` as the issuer must now pin the
issuer **it** trusts instead. That is the correct check in any case: the issuer name is a
label; the key identity is what matters.

---

## B. HARD BINDINGS (cannot be retroactively renamed)

| Binding | Where | Why it is hard | Migration path |
|---|---|---|---|
| `https://threatveil.com/attestation/assurance-passport/v1` | `passports.py`, `sdk/passports.py`, both passport schemas | Inside the signed DSSE statement of every passport ever issued | Introduce `…/assurance-passport/v2` under the new domain. Verifiers accept both for a stated window. Old passports keep the old predicate forever — that is correct, they were issued by that issuer |
| `https://threatveil.com/attestation/release-decision/v1` | `sdk/receipts.py`, receipt schema | Same, for release receipts | Same |
| `https://threatveil.com/attestation/change-authorization/v1` | `sdk/change_records.py` | Same, for change authorizations | Same |
| `threatveil-assurance-passport/v1`, `threatveil-assurance-gate/v1`, `connector/v1` profile strings | schema_version fields inside signed and recorded documents | Recorded in immutable records and signed payloads | New `…/v2` profile names; readers accept both |
| `b"threatveil-passport-share/v1\n"` | `passports.py` HMAC domain separator | Changing it invalidates every live share link | Accept both domains while existing links are valid (max 90 days), then drop the old |
| `threatveil-observation-v1:` | `observers.py` signing message prefix | Changing it invalidates existing observation attestations | Same dual-accept window, bounded by evidence retention |
| `threatveil_admin` | `migrations/0007`, inside the `tv_immutable()` trigger body | A SQL function compares the role name literally. Renaming the role without a migration breaks scoped erasure | A migration that rewrites the function with the new role name, applied in the same change as the role rename |
| Published JSON Schema `$id`s (4 files × 2 copies) | `schemas/`, `sdk/schemas/` | Third parties may have cached them | Serve the old `$id`s as permanent aliases of the new ones |

**Consequence:** a rename does not invalidate any existing evidence, and it must not try
to. Historical documents keep the issuer, predicate and profile they were signed with. A
rename is additive: new versions under the new name, old versions still verifiable.

---

## C. MIGRATABLE (hard-coded, renameable with a window)

| Binding | Where | Notes |
|---|---|---|
| Python distribution and import package `threatveil` | `pyproject.toml`, every module, console script `threatveil` | Rename the distribution; ship a thin alias package for one minor version so `import threatveil` keeps working |
| npm packages `@threatveil/sdk`, `@threatveil/web` | `sdk/typescript/package.json`, `apps/web/package.json` | Publish under the new scope; mark the old deprecated with a pointer |
| Environment prefix `TV_` | `config.py` (`env_prefix="TV_"`) | Accept both prefixes for one release; log when the old one is used |
| Session cookie `tv_session` | `auth.py` | Accept both cookie names during the window; issue only the new one |
| Consumer header `X-ThreatVeil-Consumer` | `assurance_api.py`, SDK, GitHub Action | Machine API surface. Accept both headers; document the new one |
| Database roles `threatveil_app` / `threatveil_admin`, database name `threatveil` | `scripts/local_db.sh`, infra, migration 0007 | A new deployment can start with new names. An existing deployment needs a coordinated role rename plus the migration in §B |
| Terraform label `application = "threatveil"` | `infra/main.tf` | Renaming breaks cost-history continuity in billing export. Prefer keeping the label value and renaming only the display name, or accept a documented discontinuity date |
| GitHub Action names (`ThreatVeil Verify`, `ThreatVeil — Change Assurance`) and check name | `integrations/` | The check **name** is what customers' branch protection may reference. Changing it can silently stop a required check from matching. Rename only with customer notice |
| Product copy, docs, titles, favicon, emails | `apps/web`, `docs/` | Text. The largest volume, the smallest risk |

---

## D. CONFIGURABLE (already deployment configuration)

- Web origin, API URL, firebase project, cloud project/region, bucket names, secret ids,
  SQL instance name, Terraform `var.name_prefix`.
- `TV_TRUST_ISSUER` (see §A).
- Share link path `/passport/{token}` — the path carries no brand; the domain is config.
- Signing key identity: key ids are `sha256` of the public key. Brand-free by construction.

---

## E. The order a rename has to happen in

1. Decide the name. Secure the domain, the npm scope and the PyPI name **before** anything
   else, so the migratable identifiers can actually take the new name.
2. Ship dual-accept for: env prefix, cookie, consumer header, schema `$id` aliases.
3. Publish new packages under the new name; deprecate the old with pointers.
4. Introduce `v2` predicate types and profile strings. Keep verifying `v1` indefinitely.
5. Rename database roles **together with** the migration that rewrites `tv_immutable()`.
6. Notify every customer whose branch protection references the check name, then rename it.
7. Change product copy, docs and the trust directory issuer last, when everything else
   already answers to the new name.

## F. What must never be automated

- Renaming predicate types or profile strings **in place**. That would silently change what
  an old document claims to be.
- Rewriting historical records or re-signing old evidence under a new issuer. The record of
  who said what, under which name, is the product.
- Changing the GitHub check name without telling the people whose gates depend on it.
