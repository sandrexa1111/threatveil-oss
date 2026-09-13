"""Conformance examples verify evaluator intent; these are not customer integration qualifications."""

import pytest

from threatveil.core import evaluate_trace, templates
from threatveil.core.contracts import Action, Observation, Principal, Receipt, Resource, Witness


@pytest.mark.parametrize("template", templates(), ids=lambda template: template["id"])
def test_every_template_detects_violation_permitted_case_and_missing_observation(template):
    prop = template["definition"]
    predicate = prop["predicates"][0]
    operation, witness_id = predicate["operations"][0], template["required_witnesses"][0]

    def fixture(violated=False, missing=False):
        tenant = "tenant-b" if violated and predicate["kind"] == "cross_tenant" else "tenant-a"
        action = Action(
            id="action",
            operation=operation,
            phase=predicate["phases"][0],
            principal=Principal(id="agent", tenant_id="tenant-a"),
            resource=Resource(type="synthetic", id="resource", tenant_id=tenant),
            approval_id=None if violated else "known-approval",
            approval_valid=not violated,
            authorized=not violated,
            trust_source="UNTRUSTED" if violated else "TRUSTED",
            after={"value": "SYNTHETIC-PROTECTED-MARKER" if violated else "public-value"},
        )
        receipt = Receipt(
            id="receipt",
            correlation_id="test",
            source_id=witness_id,
            source_version="semantic-fixture-v1",
            sequence=0,
            event_type="state_change",
            action=action,
        )
        witness = Witness(
            id=witness_id,
            source_type="semantic_conformance_fixture",
            source_version="semantic-fixture-v1",
            authority="AUTHORITATIVE",
            correlation_id="test",
            complete=True,
            covered_operations=(operation,),
            boundary=prop["observation_contract"]["boundary"],
        )
        return Observation(
            correlation_id="test", receipts=(receipt,), witnesses=() if missing else (witness,)
        )

    assert (
        evaluate_trace(prop, fixture(True), qualified_witnesses=(witness_id,))["security_verdict"]
        == "FAIL"
    )
    assert (
        evaluate_trace(prop, fixture(), qualified_witnesses=(witness_id,))["security_verdict"]
        == "PASS"
    )
    assert (
        evaluate_trace(prop, fixture(missing=True), qualified_witnesses=(witness_id,))[
            "security_verdict"
        ]
        == "INCONCLUSIVE"
    )
