# System, authority and change intelligence

`src/threatveil/assurance_intelligence.py` derives every customer-facing assurance view from **one context per request**, loaded from the immutable record store. It writes no security truth, calls no model and infers no authority. Every relationship cites the record that established it. Every explanation is a fixed template over established facts, so it can never say more than the records do.

Endpoints (all tenant-scoped, read-only):

```
/v1/systems/{id}/intelligence       /summary     /system-map    /authority
/v1/systems/{id}/authority/changes  /changes     /evidence-currency
/v1/systems/{id}/lifecycle          /reestablishment              /history
```

## 1. System Map

The map is a projection of `records`/`record_edges`; there is no graph database. It has:

- **Nodes:** AGENT, MODEL, PROMPT, TOOL, MCP_SERVER, API, IDENTITY, PERMISSION, MEMORY, DATA_SOURCE, DEPLOYMENT, CODE, SUBAGENT; AUTHORITY_BOUNDARY, AUTHORITY, AUTHORITY_FACT, BUSINESS_RESOURCE; CLAIM, BUSINESS_EFFECT; EVIDENCE, DECISION; SOURCE, CHANGE; UNKNOWN.
- **Provenance per node:** DECLARED / CONNECTED / OBSERVED / VERIFIED / IMPORTED / UNKNOWN.

Relationships and the records that establish them:

| Relationship | Established by |
|---|---|
| system → HAS_COMPONENT → component | qualified `system_state` fingerprint |
| source → REPORTS → component | `source_batch` |
| component → DEPENDS_ON → component | fingerprint / batch component dependencies |
| boundary → PERMITS → action; → COVERS → resource; identity → HOLDS → boundary | `permission_envelope` |
| claim → DEPENDS_ON → component; → GOVERNS → action; → PREVENTS / PRESERVES → business effect | approved `property` |
| evidence → SUPPORTS / NO_LONGER_SUPPORTS → claim | current projection |
| change → INVALIDATES / REQUIRES_REVIEW_OF → claim | projection `affected_by` |
| source fact → MAPPED_TO → claim dependency | reviewed `dependency_mapping` |
| decision → COVERS → claim | `authorization_decision` |
| customer relationships | `relationship_assertion`; `delegates_to` is **inert** |

Authority is only ever permitted by the reviewed boundary. No edge lets a tool or a source grant authority (tested). A referenced but unobserved dependency stays UNKNOWN.

## 2. Authority Map

For each declared consequential action the map shows:

- action and label, resources, environment, principal
- tool/interface: a governing claim's dependency, or a same-name tool reported by a source, labelled *unreviewed*
- conditions: the declared boundary constraints, plus source-declared conditions labelled *unreviewed*
- source and freshness
- governing claims and the current assurance status: SUPPORTED, NEEDS_FRESH_EVIDENCE, FAILED, UNGOVERNED or UNKNOWN

**Basis** is kept distinct:

| Basis | Meaning |
|---|---|
| DECLARED | in the reviewed boundary |
| CONNECTED | a live source reports an interface for it |
| OBSERVED | qualified execution exercised it for this state |
| VERIFIED | every governing claim is currently supported |

A tool a source reports outside the boundary is listed as `undeclared_interfaces` with basis UNKNOWN. It is never a permission.

## 3. Authority Diff (`authority-semantics/v1`)

Direction is classified only from structured facts, using a small vocabulary:

- **Restriction conditions** (`approval_required`, `tenant_bound`, `read_only`, `human_in_loop`, …): relaxing one is an expansion; adding or tightening one is a contraction.
- **Scope lists** (`scopes`, `permissions`, `actions`, `resources`, …): an added item is an expansion; a removed item is a contraction.
- **Interfaces:** a newly exposed tool is an expansion (its own declared restrictions qualify that expansion; they do not count as a contraction); a withdrawn tool is a contraction; a changed tool contract is UNKNOWN.
- **Declared boundary** (envelope versions): added principals, actions or resources are an expansion; removed constraints are an expansion; added constraints are a contraction; reworded constraints are UNKNOWN (natural language is never compared).
- **Everything else** — an unrecognized field, a digest-only IAM change, a code revision — is `UNKNOWN_IMPACT`.

Combination is a lattice: **EXPANDED** if the new boundary is not contained in the old one (any expansion); otherwise UNKNOWN if anything is unknown; otherwise CONTRACTED; otherwise EQUIVALENT. A configuration change is never called an expansion by default. Server metadata changes with unchanged authorization are EQUIVALENT.

## 4. Change intelligence: change → assurance consequence

For each source change, recorded state transition and boundary revision, the view reports:

- what changed (named subjects)
- where it originated and when, with acquisition and qualification
- the authority diff
- which claims it reaches, and through which dependency
- which evidence relied on the previous state
- what still holds
- whether it is still open (needs re-proof), covered by later verification, or affected no claim
- which clearance was current before it, and that clearance's recomputed status
- a deterministic explanation

### Scoping with reviewed dependency mappings

Collected MCP catalogs now retain bounded, structured facts: a flattened authorization block, catalog-part digests and tool names. A source change can therefore be named precisely, for example `authorization/tools/beneficiary.update/approval_required`.

A `dependency_mapping` is an append-only, reviewed statement that such a subject corresponds to claim dependencies. Only these may create one: the SECURITY role (`CUSTOMER_REVIEWED`), or the labelled synthetic package (`SYNTHETIC_PACKAGE`). A mapping is validated three ways:

- the subject must be a fact the source reported
- targets must be reviewed dependencies of approved claims
- it can never grant permission or discharge a change

When **every** named subject of a later change is mapped, the projection limits the change's impact to the claims whose dependencies it reaches. **One unmapped subject**, a source gap or a connector reconfiguration keeps today's conservative meaning: every claim needs review. This is how "1 claim affected; 2 still hold" becomes a reviewed, auditable statement rather than a guess. The mappings are also a compounding, customer-specific asset.

## 5. Evidence currency

Security evidence has a shelf life. Each claim shows its applicability in plain language:

| State | Meaning |
|---|---|
| CURRENT | still describes the system running now |
| STALE | created for an earlier state |
| INVALID | a change means it no longer supports the current state |
| UNKNOWN | not enough qualified evidence |

Alongside that, each claim shows when its evidence was produced, whether that was for this state, which change affected it, and its security and useful-task outcomes.

## 6. Clearance lifecycle and status refinement

The lifecycle stages are:

BASELINE ESTABLISHED → CURRENT → RELEVANT CHANGE → CLEARANCE SUPERSEDED → REASSESSMENT REQUIRED → RE-PROOF → CLEARANCE RESTORED

They are computed in one chronological pass over decisions and loss moments: source changes that reach a claim, observed state transitions that changed a component, boundary revisions, and revocations.

`clearance_status()` separates *whether a clearance still speaks for the system* from the signed statement's own five-minute lifetime. The existing `_decision_status()` still returns EXPIRED first, so a consumer never acts on a lapsed signed statement.

One deliberate refinement: an **observed** source change that moves a clearance's support now yields `SUPERSEDED` (the system changed), not `REASSESS`. `REASSESS` remains for support that moved without an observed change. Both are non-current.

## 7. Re-establish assurance

The re-establishment plan lists seven things:

1. what changed
2. affected claims
3. what still holds
4. what needs fresh evidence
5. which security checks must run
6. which legitimate task must still succeed
7. what restores clearance

It also reports the latest outcome:

| Outcome | Result |
|---|---|
| SECURITY_FAILED | not cleared |
| USEFUL_TASK_FAILED | not cleared, even though security passed |
| RESTORED / ESTABLISHED | cleared |
| INCONCLUSIVE | not cleared |

ThreatVeil coordinates re-proof; it never remediates.

## 8. Historical assurance memory

`/history` reports:

- counts of observed changes by authority classification
- decisions, clearances, restorations and re-proof attempts
- per claim: how many changes reached it and how many it survived
- restoration durations
- sources not currently fresh

A pattern (for example "changes to X reached claim Y N times") is reported only after **three comparable observations**; below that, `insufficient_history` is true. Nothing is predicted. The value is the accumulated, accepted operating history, which cannot be recreated later.

## Performance

A request issues a bounded number of projections, independent of history length (tested). Change views are memoized per request, and projection work is shared between the summary, gate and lifecycle. Full-history reads remain the documented debt of the record store, as before.
