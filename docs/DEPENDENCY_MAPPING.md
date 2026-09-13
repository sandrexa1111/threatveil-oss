# Dependency mapping, and the AI seam around it

A mapping states that one named source fact corresponds to one claim dependency. It is the
difference between *"something changed, so re-prove everything"* and *"this approval field
changed, so exactly this claim needs fresh evidence"*.

Because a mapping narrows what ThreatVeil will tell you to check, **only an approved mapping
ever affects scoping**. Everything else in this document is a proposal.

---

## 1. The queue: suggestion → proposal → review → mapping

| Stage | Record | Affects scoping? |
|---|---|---|
| Suggestion | none (computed on read) | no |
| Proposal | `dependency_mapping_proposal` | no |
| Review | `dependency_mapping_review` | only the decision |
| Mapping | `dependency_mapping` | **yes**, latest per subject |

A reviewer can `APPROVE`, `EDIT` (approve with different dependencies) or `REJECT`. A proposal
can be reviewed once; a second review is a 409. Rejection leaves no mapping and changes
nothing.

## 2. Deterministic suggestions

`GET /v1/systems/{id}/mapping-suggestions?installation_id=…`

ThreatVeil compares the facts a source **actually reported** with the dependencies your claims
**actually declare**, and explains every correspondence it finds:

| Reason | Example |
|---|---|
| `TOOL_NAME_MATCH` | the source reports tool `refund.issue`; a claim depends on `tool:refund.issue` |
| `ACTION_NAME_MATCH` | the changed fact governs `beneficiary.update`; a dependency names it |
| `SCHEMA_FIELD_MATCH` | the declared condition `approval_required` matches `permissions:finance-approval` |
| `PERMISSION_SCOPE_MATCH` | a declared `allow` / `scopes` / `tools` list corresponds to a permission dependency |
| `CONFIG_KEY_MATCH` | an MCP catalogue part, model, prompt or policy key matches a dependency name |
| `RESOURCE_NAME_MATCH` | the resource an action governs matches the dependency's resource |

Confidence is a **category**, never a number: `EXACT_NAME`, `NORMALIZED_NAME`,
`TOKEN_OVERLAP`. ThreatVeil is not measuring probability, and a made-up percentage would
imply it was.

Every suggestion carries the source record that reported the fact, so a reviewer checks the
claim against evidence rather than against a hunch.

## 3. The mapping overview

`GET /v1/systems/{id}/mappings-overview` answers, per source:

- **mapped**: subject → dependencies, the review note, who approved it, when, the source record
  that reported the subject, and the proposal it came from;
- **unmapped**: every fact with no mapping, and the consequence spelled out — *a change to this
  fact cannot be scoped, so every claim it could reach needs fresh evidence*;
- **candidates**: the dependencies a mapping may point at, and whether each comes from an
  approved claim or a declared one.

A mapping may only name a dependency some claim actually declares, and a subject the source
actually reported. Both are enforced server-side; inventing either is a 422.

## 4. The AI seam: proposals only, off by default

A model may help **propose** a mapping. It may never decide one.

| Property | How it holds |
|---|---|
| Off by default | `TV_AI_PROVIDER=disabled`, `TV_AI_MAPPING_ENABLED=false`, `TV_AI_CLAIMS_ENABLED=false`. With the flag off, no provider object is constructed and no call is made |
| Tenancy first | The system and source are resolved before the provider is touched, so a caller learns nothing about configuration for a system they cannot see |
| Minimal context | The provider is given **names only**: unmapped subject names and candidate dependency names. No payloads, no evidence, no secrets, no customer data |
| Cites its inputs | Each proposal must name the exact inputs it used; they are stored in the proposal note |
| Cannot invent a subject | A proposal naming a subject the source never reported is dropped server-side |
| Human approval | Proposals are recorded with `origin: AI_PROPOSED`, `affects_scoping: false`, and enter the same review queue |
| Recorded | Provider, model, feature, tokens, latency, estimated cost and the result count land in an `ai_usage` record |
| Budgeted | A paid provider refuses to run without `TV_AI_MONTHLY_USD_BUDGET`, and stops at the budget |

Local and test deployments can use `TV_AI_PROVIDER=mock`: a deterministic stand-in with no
network and no cost, which is what the test suite exercises.

### The invariants, restated because they are the point

- No model output changes an assurance status, a clearance, evidence or authority.
- No model can turn `UNKNOWN` into `CURRENT`, `STALE` into `VALID`, or `FAIL` into `PASS`.
- ThreatVeil requires no model to operate. Every core answer is deterministic.

### The claim-authoring seam

`POST /v1/systems/{id}/ai/claim-draft` returns a **draft** labelled
`DRAFT / NOT VERIFIED FOR YOUR SYSTEM`, records nothing as a claim, and is subject to the same
flag, budget and usage accounting. The non-AI claim builder
(`docs/DECLARED_CHANGE_IMPACT.md`) is the default path and needs no provider at all.

### What is deliberately not built

No generic chatbot. No agent that can act in the workspace. No model in the path of any
security conclusion.

## 5. Cost visibility

`GET /v1/measurements/ai-usage` reports, per feature: calls, input and output tokens,
estimated cost, the providers used, the configured monthly budget and the spend this calendar
month. Zero is the normal answer, and the normal configuration.
