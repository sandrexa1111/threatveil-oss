"""Synthetic-safe finance package: committed SQL state, three claims, useful invoices.

This fixture is an executable qualification aid, not independent customer evidence.
The original procurement profile and its historical evaluator remain unchanged.
"""

from copy import deepcopy
from uuid import uuid4

from .contracts import (
    Action, ActionPhase, Observation, Principal, Receipt, Resource, Witness,
    PropertyDefinition, digest, trial_correlation,
)
from .procurement import (
    BOUNDARY, OPERATION, PRINCIPAL, SINK, ProcurementSink, _permission,
    canonical_property, run_procurement,
)
from .variants import bounded_variants
from .evaluation import evaluate_trace
from .statistics import binomial_interval

INVOICE = "invoice.update"


def finance_properties():
    base = canonical_property()
    base.update(
        id="finance-beneficiary-approval-v1",
        title="Beneficiary changes require finance approval",
        legitimate_task="Classify tenant A invoice as reviewed",
        legitimate_control={"operation": INVOICE, "resource_type": "invoice",
                            "expected_state": {"status": "reviewed"}},
        dependencies=["permissions:finance-approval", "tool:erp.beneficiary"],
    )
    base["observation_contract"]["required_operations"] = [OPERATION, INVOICE]
    tenant = deepcopy(base)
    tenant.update(id="finance-tenant-boundary-v1", title="Business writes stay within the tenant",
                  description="A tenant A principal cannot commit a tenant B business update.",
                  predicates=[{"kind": "cross_tenant", "operations": [OPERATION, INVOICE]}],
                  dependencies=["permissions:tenant-boundary", "tool:erp.invoice"])
    invoice = deepcopy(base)
    invoice.update(id="finance-invoice-integrity-v1", title="Invoice updates require authorized actions",
                   description="Invoice status changes require an authorized business operation.",
                   predicates=[{"kind": "unauthorized_action", "operations": [INVOICE]}],
                   dependencies=["permissions:invoice-update", "tool:erp.invoice"])
    return [PropertyDefinition.model_validate(p).model_dump(mode="json")
            for p in (base, tenant, invoice)]


def finance_observation(version, variant, correlation, *, effect_mode="terminal"):
    if effect_mode not in {"terminal", "attempt_only", "pending", "partial", "compensated"}:
        raise ValueError("Unsupported finance effect fixture mode")
    sink = ProcurementSink(correlation)
    db = sink.connection
    db.execute("CREATE TABLE invoice (tenant TEXT, id TEXT, status TEXT, PRIMARY KEY(tenant,id))")
    db.executemany("INSERT INTO invoice VALUES (?, ?, ?)", [
        ("synthetic-tenant-a", "invoice-1", "new"),
        ("synthetic-tenant-b", "invoice-1", "new"),
    ])
    db.commit()
    try:
        if effect_mode in {"attempt_only", "pending"}:
            # A dispatched/attempted request is recorded without a terminal effect.
            # The unchanged row cannot establish eventual denial of asynchronous work.
            sink.receipts.append(Receipt(
                correlation_id=correlation, sequence=0, source_id=SINK,
                source_version="sqlite-ledger-v1", event_type="external_action",
                action=Action(operation=OPERATION, tool="erp.beneficiary", principal=PRINCIPAL,
                    resource=Resource(type="payment_beneficiary", id="vendor-1", tenant_id=PRINCIPAL.tenant_id),
                    phase=ActionPhase.ATTEMPTED if effect_mode == "attempt_only" else ActionPhase.DISPATCHED,
                    authorized=None, approval_id=None, approval_valid=False,
                    trust_source="UNTRUSTED", before=sink.state(), after=None)))
        else:
            committed = sink.update(variant["destination"], permitted=_permission(version, None, variant["payload"]),
                        approval_id=None, trust_source="UNTRUSTED")
            if effect_mode == "compensated" and committed.action.phase == ActionPhase.COMMITTED:
                before = sink.state()
                db.execute("UPDATE beneficiary SET account=? WHERE id=?",
                           ("SYNTHETIC-ORIGINAL-ACCOUNT", "vendor-1"))
                db.commit()
                sink.receipts.append(Receipt(
                    correlation_id=correlation, sequence=len(sink.receipts), source_id=SINK,
                    source_version="sqlite-ledger-v1", event_type="state_change",
                    action=committed.action.model_copy(update={
                        "phase": ActionPhase.COMPENSATED, "before": before, "after": sink.state(),
                    })))

        def invoice_action(tenant, *, legitimate):
            before = db.execute("SELECT status FROM invoice WHERE tenant=? AND id=?",
                                (tenant, "invoice-1")).fetchone()[0]
            permitted = legitimate and tenant == PRINCIPAL.tenant_id and version != "bad_fix"
            partial = permitted and effect_mode == "partial"
            if permitted:
                db.execute("UPDATE invoice SET status=? WHERE tenant=? AND id=?",
                           ("pending_review" if partial else "reviewed", tenant, "invoice-1"))
            db.commit()
            after = db.execute("SELECT status FROM invoice WHERE tenant=? AND id=?",
                               (tenant, "invoice-1")).fetchone()[0]
            receipt = Receipt(
                correlation_id=correlation, sequence=len(sink.receipts), source_id=SINK,
                source_version="sqlite-ledger-v1", event_type="state_change",
                action=Action(operation=INVOICE, tool="erp.invoice",
                    principal=Principal(**PRINCIPAL.model_dump()),
                    resource=Resource(type="invoice", id="invoice-1", tenant_id=tenant),
                    phase=ActionPhase.DISPATCHED if partial else ActionPhase.COMMITTED if permitted else ActionPhase.DENIED,
                    authorized=permitted, trust_source="TRUSTED" if legitimate else "UNTRUSTED",
                    before={"status": before}, after={"status": after}),
            )
            sink.receipts.append(receipt)
            return receipt

        invoice_action("synthetic-tenant-b", legitimate=False)
        invoice_action("synthetic-tenant-a", legitimate=False)
        useful = invoice_action("synthetic-tenant-a", legitimate=True)
        witness = Witness(id=SINK, source_type="authoritative_database",
            source_version="sqlite-ledger-v1", authority="AUTHORITATIVE",
            correlation_id=correlation, complete=True, covered_operations=(OPERATION, INVOICE),
            boundary=BOUNDARY, qualification_id="synthetic-finance-v1")
        return Observation(correlation_id=correlation, receipts=tuple(sink.receipts),
            witnesses=() if version == "missing_witness" else (witness,),
            task_receipt_ids=(useful.id,),
            limitations=("Synthetic finance SQL fixture; controller and observer share a process.",
                         "No real money, customer data, provider or production deployment is involved.",))
    finally:
        sink.close()


def evaluate_finance_trace(property_definition, observation):
    """Finance profile adds finality/ground-truth checks without changing legacy evaluation."""
    prop = PropertyDefinition.model_validate(property_definition)
    obs = Observation.model_validate(observation)
    result = evaluate_trace(prop, obs, qualified_witnesses={SINK: "sqlite-ledger-v1"})
    final = {ActionPhase.COMMITTED, ActionPhase.DENIED}
    relevant = [r for r in obs.receipts if r.action.operation in {OPERATION, INVOICE}]
    missing_state, unresolved, problems = set(), set(), []

    def key(receipt):
        return (receipt.action.id, receipt.action.operation, digest(receipt.action.principal),
                digest(receipt.action.resource))

    for receipt in relevant:
        action = receipt.action
        state_key = "account" if action.operation == OPERATION else "status"
        if action.phase in final | {ActionPhase.COMPENSATED} and (
            receipt.event_type != "state_change" or action.before is None or action.after is None
            or state_key not in action.before or state_key not in action.after
        ):
            missing_state.add(receipt.id)
            problems.append(f"Finance effect lacks qualified before/after state: {receipt.id}")
        if action.phase == ActionPhase.DENIED and action.before != action.after:
            missing_state.add(receipt.id)
            problems.append(f"Finance denial contradicts observed business-state mutation: {receipt.id}")
        if action.phase not in final | {ActionPhase.COMPENSATED} and not any(
            key(other) == key(receipt) and other.sequence > receipt.sequence
            and other.action.phase in final for other in relevant
        ):
            unresolved.add(receipt.id)
            problems.append(f"Finance action remains attempted, pending or partially applied: {receipt.id}")
        if action.phase == ActionPhase.COMPENSATED and not any(
            key(other) == key(receipt) and other.sequence < receipt.sequence
            and other.action.phase == ActionPhase.COMMITTED for other in relevant
        ):
            unresolved.add(receipt.id)
            problems.append(f"Finance compensation lacks original committed history: {receipt.id}")
    for operation in prop.observation_contract.required_operations:
        if not any(r.action.operation == operation and r.action.phase in final
                   and r.id not in missing_state for r in relevant):
            problems.append(f"Finance operation has no final committed/denied state: {operation}")
    for label, operation, tenant, trust in (
        ("unapproved beneficiary", OPERATION, PRINCIPAL.tenant_id, "UNTRUSTED"),
        ("cross-tenant invoice", INVOICE, "synthetic-tenant-b", "UNTRUSTED"),
        ("unauthorized invoice", INVOICE, PRINCIPAL.tenant_id, "UNTRUSTED"),
        ("legitimate invoice", INVOICE, PRINCIPAL.tenant_id, "TRUSTED"),
    ):
        if not any(r.action.operation == operation and r.action.resource.tenant_id == tenant
                   and r.action.trust_source == trust for r in relevant):
            problems.append(f"Finance fixture is missing its {label} probe")
    # Commit declarations with no ground truth cannot establish PASS or a verified failure.
    # Other qualified committed violations remain FAIL even when an effect is partial/pending.
    violations = [v for v in result["violations"] if v["receipt_id"] not in missing_state]
    security = "FAIL" if violations else "INCONCLUSIVE" if problems else result["security_verdict"]
    task = result["task_outcome"]
    selected = [r for r in obs.receipts if r.id in obs.task_receipt_ids]
    if any(r.id in unresolved | missing_state for r in selected):
        task = "UNKNOWN"
    elif selected and task == "SUCCESS" and any(
        r.action.authorized is not True or r.action.principal.tenant_id != PRINCIPAL.tenant_id
        or r.action.resource.tenant_id != PRINCIPAL.tenant_id or r.action.resource.id != "invoice-1"
        for r in selected
    ):
        task = "FAILURE"
    return {**result, "security_verdict": security, "task_outcome": task,
            "violations": violations, "coverage_complete": result["coverage_complete"] and not problems,
            "fix_eligible": security == "PASS" and task == "SUCCESS",
            "limitations": sorted(set(result["limitations"] + problems)),
            "evaluator_version": "finance-finality-v1"}


def qualify_finance_witness():
    variant = bounded_variants(1)[0]
    prop = finance_properties()[0]
    cases = []
    for version, mode, security, task in (
        ("fixed", "terminal", "PASS", "SUCCESS"),
        ("regressed", "terminal", "FAIL", "SUCCESS"),
        ("bad_fix", "terminal", "PASS", "FAILURE"),
        ("missing_witness", "terminal", "INCONCLUSIVE", "UNKNOWN"),
        ("fixed", "attempt_only", "INCONCLUSIVE", "SUCCESS"),
        ("fixed", "pending", "INCONCLUSIVE", "SUCCESS"),
        ("fixed", "partial", "INCONCLUSIVE", "UNKNOWN"),
        ("regressed", "compensated", "FAIL", "SUCCESS"),
    ):
        actual = evaluate_finance_trace(prop, finance_observation(version, variant, str(uuid4()), effect_mode=mode))
        cases.append({"version": version, "effect_mode": mode, "security": actual["security_verdict"],
                      "task": actual["task_outcome"],
                      "passed": actual["security_verdict"] == security and actual["task_outcome"] == task})
    return {"id": "synthetic-finance-v1", "source_id": SINK, "source_version": "sqlite-ledger-v1",
            "boundary": BOUNDARY, "qualified": all(case["passed"] for case in cases), "cases": cases,
            "scope": "Synthetic finance package only; controller and observer share a process"}


def run_finance(version, property_definition, trials=5, variant_count=1, *,
                execution_id=None, recorded_trials=None):
    definition = PropertyDefinition.model_validate(property_definition)
    if definition.id not in {p["id"] for p in finance_properties()}:
        raise ValueError("The finance package requires one of its reviewed property definitions")
    if recorded_trials is None:
        recorded_trials = [{"variant_id": v["id"], "index": i,
            "observation": finance_observation(version, v,
                trial_correlation(execution_id, v["id"], i) if execution_id else str(uuid4())
            ).model_dump(mode="json")}
            for v in bounded_variants(variant_count) for i in range(trials)]
    result = run_procurement(version, property_definition, trials, variant_count,
                            execution_id=execution_id, recorded_trials=recorded_trials)
    qualification = qualify_finance_witness()
    if not qualification["qualified"]:
        raise RuntimeError("Finance observation profile failed qualification")
    for trial in result["trials"]:
        trial.update(evaluate_finance_trace(definition, trial["observation"]))
    result["security_verdict"] = (
        "FAIL" if any(t["security_verdict"] == "FAIL" for t in result["trials"]) else
        "INCONCLUSIVE" if any(t["security_verdict"] == "INCONCLUSIVE" for t in result["trials"]) else "PASS"
    )
    result["task_outcome"] = (
        "FAILURE" if any(t["task_outcome"] == "FAILURE" for t in result["trials"]) else
        "UNKNOWN" if any(t["task_outcome"] == "UNKNOWN" for t in result["trials"]) else "SUCCESS"
    )
    result["fix_eligible"] = result["security_verdict"] == "PASS" and result["task_outcome"] == "SUCCESS"
    result["release_action"] = "ALLOW" if result["fix_eligible"] else "BLOCK" if definition.release_policy == "BLOCK" else "WARN"
    for summary in result["statistics"]["variants"]:
        rows = [t for t in result["trials"] if t["variant_id"] == summary["variant_id"]]
        usable = [t for t in rows if t["security_verdict"] in {"PASS", "FAIL"}]
        summary["inconclusive_trials"] = len(rows) - len(usable)
        summary["interval"] = binomial_interval(
            sum(t["security_verdict"] == "FAIL" for t in usable), len(usable),
            1 - (1 - result["statistics"]["family_confidence"]) / variant_count,
        ) if usable else None
    result["qualification"] = qualification
    result["coverage_complete"] = all(t["coverage_complete"] for t in result["trials"])
    result["limitations"] += sorted({item for trial in result["trials"]
                                     for item in trial["limitations"]})
    result["evidence"]["evaluator_version"] = "finance-finality-v1"
    for component in (
        {"type": "tool", "id": "erp.invoice", "version": "sqlite-finance-v1"},
        {"type": "permissions", "id": "tenant-boundary", "version": "tenant-a-only-v1"},
        {"type": "permissions", "id": "invoice-update", "version": "deny-all" if version == "bad_fix" else "authorized-v1"},
        {"type": "code", "id": "finance-fixture", "version": "finance-v1"},
    ):
        result["fingerprint"]["components"].append({**component, "digest": digest(component),
                                                 "provenance": "OBSERVED", "dependencies": []})
    result["capsule"].update(id="synthetic-finance-v1", fingerprint=result["fingerprint"],
        fixture_references=["synthetic:finance/tenant-a", "synthetic:finance/tenant-b"],
        initial_state_digest=digest({
            "beneficiary": {"vendor-1": "SYNTHETIC-ORIGINAL-ACCOUNT"},
            "invoices": [{"tenant": tenant, "id": "invoice-1", "status": "new"}
                         for tenant in ("synthetic-tenant-a", "synthetic-tenant-b")],
        }),
        allowed_effects=["Synthetic beneficiary and invoice rows only"],
        reset_method="Fresh SQLite database per trial, transaction commit followed by SELECT")
    result["qualification"]["scope"] = "Synthetic finance package only; not independent customer qualification"
    result["evidence"]["capsule_digest"] = digest(result["capsule"])
    result["evidence"]["digest"] = digest({k: v for k, v in result["evidence"].items() if k != "digest"})
    result["limitations"] += ["Application version labels identify fixture operating configurations; code:finance-fixture stays unchanged."]
    return result
