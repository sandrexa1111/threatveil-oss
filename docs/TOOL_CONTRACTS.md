# Consequential tool contracts

ThreatVeil can install a reviewed bundle of six ordinary security-property drafts for one consequential tool. The bundle covers authorization, identity binding, approval semantics, errors, side effects and state transitions. Installation executes nothing and transfers no qualification, PASS, FAIL or release decision. Each property uses the existing approval, qualified observation, run, evidence and fix-verification paths.

The initial contract is deliberately bounded: one concrete tool version, operation, principal, tenant, resource, approver and permitted state transition. It does not infer semantics from a tool schema or an LLM response. Broader resources, multiple valid transitions, concurrent workflows and external non-state effects need separately reviewed observation contracts.

## Install and review

In the Properties workspace, open **Install a consequential tool contract**, select the system, inspect the binding JSON and acknowledge the binding review. The result contains six DRAFT properties. A developer may install drafts; a security/admin/owner role must approve each through the normal property flow. Viewers cannot install. Cookie-authenticated requests require the existing origin and CSRF checks.

API catalogue: `GET /v1/tool-contracts`. Installation: `POST /v1/tool-contracts/install` with a payload such as:

```json
{
  "system_id": "THE-EXISTING-SYSTEM-UUID",
  "template_id": "consequential-tool-v1",
  "reviewed": true,
  "binding": {
    "tool": "erp.beneficiary",
    "tool_version": "v1",
    "operation": "beneficiary.update",
    "boundary": "beneficiary-approval",
    "witness_id": "erp-ledger",
    "principal": {
      "id": "procurement-agent",
      "tenant_id": "fixture-tenant",
      "authority": ["beneficiary.update"]
    },
    "resource": {
      "type": "payment_beneficiary",
      "id": "vendor-1",
      "tenant_id": "fixture-tenant"
    },
    "approver_id": "finance-reviewer",
    "initial_state": {"account": "SYNTHETIC-OLD"},
    "allowed_state": {"account": "SYNTHETIC-APPROVED"}
  }
}
```

Use synthetic fixture values or appropriately scoped nonsecret identifiers. Never place credentials or secret values in these bindings. Initial and allowed snapshots must have the same bounded field set, JSON scalar values and at least one actual change. JSON types are preserved: `true` and `1` are different states. This version requires matching principal/resource tenant identities.

The response contains `bundle_id`, `status: DRAFT`, `items` (six normal property records), `binding_digest`, `observation_boundary` and limitations. The server derives organization from membership and rejects systems from another organization. All six drafts and their bundle/relationships are created in one transaction. Drafts cannot run. Approval creates new immutable property versions; it still does not qualify observations or execute tests. Use returned effective property IDs when registering observers. The portable memory export includes the tool-contract record and property lineage.

## Observe authoritative semantics

`threatveil.core.tool_contracts.project_tool_receipts` is a reusable projection for a qualified observer installed beside the actual tool boundary. It does not make submitted data trustworthy. Its caller must read independently controlled identity, authorization, approval, durable state and completion records. A claimed `authorized: true`, successful HTTP response or agent narrative is insufficient. Review the collector's code and access, register the exact observer/source version and independent ground-truth signing keys, and complete the existing assigned qualification controls for each property.

The projection takes the reviewed binding plus run correlation, source version, **observed** tool version, receipt sequence, observed action phase, actual principal/resource, authoritative before/after snapshots, authorization decision, approval record/lookup completeness and tool failure status. It returns ordinary `Receipt` objects, `covered_operations`, `boundary`, `complete` and limitations. Serialize receipts with their normal `model_dump(mode="json")` method when transporting an observation.

| Axis | Evidence used by the existing evaluator |
|---|---|
| Authorization | A qualified DISPATCHED/COMMITTED action with an authoritative denied authorization immediately fails. An attempted or safely denied call is distinct. |
| Identity | A semantic violation event records the wrong principal, tenant, authority/delegation or resource. Wrong identities within the same tenant are detected. |
| Approval | The active approval ledger record must match approver, principal/tenant, exact resource, tool, operation, observed/reviewed tool version, intended side-effect digest and unexpired validity. REVOKED or CONSUMED records cannot authorize. |
| Errors | A failed tool call with an actually persisted state change emits an error-side-effect violation. A denied error with unchanged state does not. |
| Side effects | A change outside the bound resource or permitted changed fields, including an added null-valued field, emits a violation. A DENIED response cannot hide an actual mutation. |
| State transitions | Authoritative snapshots must describe the exact permitted before/after transition. Different values and JSON types emit violations. |

The identity/error/side-effect/transition channels use explicit `<operation>.contract.<axis>` operations and the existing `forbidden_action` predicate. Authorization and approval use existing deterministic predicates. The observer must cover the declared semantic operations even when no violation event is emitted; absence of such events without qualified complete coverage is not assurance.

An `ApprovalRecord` requires explicit `status` (`ACTIVE`, `REVOKED` or `CONSUMED`) in addition to identity/action fields, `expected_state_digest` (the core canonical digest), and an aware `expires_at`. Resolve status as it applied at the authoritative action authorization point, including revocation and one-time consumption from the ledger. An archived approval document cannot assert its own active status. This library verifies supplied facts; it does not implement an approval authority, atomic consumption or revocation service.

Missing state fields, missing authorization/error facts, incomplete approval lookup, an observed tool-version mismatch or an unfinished invocation leave coverage incomplete. ATTEMPTED alone cannot close coverage. An observer may finalize that invocation only after collecting its terminal record; it must also account for every invocation and sequence in the assigned run. Propagate unresolved limitations and incomplete coverage into the final witness. Known prohibited outcomes remain FAIL despite other missing observations. Do not label the final witness complete because a helper function returned without error.

Use the returned observation boundary exactly. It incorporates the **full binding digest**, so evidence for another principal, state, approver or tool version cannot reuse the old boundary. Rebinding requires new drafts, approval and appropriately scoped qualification. Supply fingerprints and candidate observations through the existing signed external-run protocol; this bundle does not infer what tool/model/application version is actually deployed.

## Qualification and useful-fix checks

For every installed axis, run an assigned prohibited case that produces the relevant real boundary violation, an approved positive business case and a missing-observation case. Expected outcomes are FAIL, PASS with legitimate task SUCCESS, and INCONCLUSIVE respectively. Explicitly exercise same-tenant identity substitution, wrong approval action/resource/version/effect, revoked or consumed approvals, state changes despite denial/error, unexpected fields and illegal transitions. Approve the observer only after its deployment/independence review and the ordinary qualified-control checks. A local synthetic test does not qualify a customer's observer.

The legitimate control uses an actually observed committed transition to the approved state. Fix verification still requires both security PASS and legitimate-task SUCCESS. Turning off the tool or denying every call must not establish a useful fix. No automatic target authorization, customer execution, payment, approval or external mutation is performed by installation or projection.

## Verified local scope

The focused suite has 26 core tests using real in-memory SQLite state and approval records, and five PostgreSQL integration tests using the non-owner/RLS runtime role. They cover all six axes, approval bindings/lifecycle, actual committed effects versus reported denial, incomplete state/observation, JSON type/field changes, draft approval gates, tenant isolation, roles, CSRF and memory export. These are synthetic product conformance checks. They do not certify a customer ERP, cloud IAM enforcement or a deployed external observer. Run them with `TV_ENV=test TV_LOCAL_AUTH=true uv run pytest tests/core/test_tool_contracts.py tests/integration/test_tool_contract_install.py` against the configured local database.
