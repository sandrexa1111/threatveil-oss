# Assurance packs

A pack is a reviewed starting point for one archetype: the claims that archetype almost always
needs, the mapping proposals that usually apply, the observer it requires, and its own
limitations. Applying one turns a blank workspace into a set of declared claims and a review
queue in a single call.

**Every pack shipped today is `DRAFT`.** That means ThreatVeil wrote it and no customer has
validated it. Saying otherwise would be the easiest lie in this product to tell.

## Status ladder

| Status | Meaning |
|---|---|
| `DRAFT` | ThreatVeil wrote it; no customer has validated it |
| `INTERNAL_VALIDATED` | Exercised end to end against ThreatVeil's own fixtures |
| `CUSTOMER_VALIDATED` | A customer confirmed its claims and mappings for their own system |
| `DEPRECATED` | Superseded; kept for systems already using it |

## What ships

| Pack | Archetype | Claims |
|---|---|---|
| `generic_write_agent` | GENERIC_WRITE | approval required, tool allowlist, privileged action needs a human |
| `support_refund` | SUPPORT_REFUND | refund limit, approval before a refund, approval before an external message |
| `infrastructure` | INFRASTRUCTURE | production deploy needs approval, read-only boundary, privileged operations |
| `revenue_crm` | REVENUE_CRM | tenant isolation, no cross-tenant write, approval before a customer message |

`support_refund` is the current leading archetype hypothesis, not a validated market fact.

## Pack format

```
ID · VERSION · ARCHETYPE · NAME · STATUS · AUTHOR · RUNNABLE · SUMMARY
COMPATIBILITY        sources, whether a live source is required, environments, a note
CLAIMS               template id + resource + action + declared dependencies
DEPENDENCY PROPOSALS subject pattern → dependencies, with a reason and the evidence
OBSERVER REQUIREMENTS resource, system of record, observable effects, correlation, a note
LIMITATIONS          what this pack does not do
```

Claims reference the claim-template library rather than duplicating its text, so a wording fix
lands everywhere at once.

## What applying a pack does — and does not do

`POST /v1/systems/{id}/assurance-packs/{pack_id}/apply`

Does:

- declare each claim (`NOT_YET_VERIFIED`), recording the pack id, version and status on each;
- match each dependency-proposal pattern against the facts your source **actually reported**
  and queue a `PROPOSED` mapping proposal for each match, citing the pack and the source record;
- report every pattern that matched nothing, so the gaps are visible;
- return the observer requirements as instructions.

Does not:

- approve anything (`approved_anything: false`);
- create or qualify an observer (`created_observers: []`);
- establish any evidence, or change any clearance.

After applying, the claim ladder shows the declared claims at `NOT_YET_VERIFIED` and the
mapping overview shows nothing mapped. Both are accurate: a pack is a starting point, not an
assurance.

## The example gallery

`GET /v1/example-gallery` is what a new workspace offers:

- primary action **Connect my own agent**;
- secondary action **Explore an example**;
- five cards: the four packs as `TEMPLATE · NOT RUNNABLE · NOT VERIFIED FOR YOUR SYSTEM`, and
  exactly one runnable card — the Finance Agent demonstration, labelled
  `RUNNABLE · SYNTHETIC DATA ONLY` with `counts_as_customer_activity: false`.

One runnable example, clearly synthetic, is the honest shape. Four runnable "verticals" would
imply four validated markets.

## Writing a pack

Add a JSON file to `src/threatveil/data/assurance_packs/`. It is validated on load, so a
malformed or over-sized pack fails fast rather than half-applying. Keep `status: DRAFT` until a
named customer has confirmed its claims against their own system — then say so in the version
history, with the date.
