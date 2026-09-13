from copy import deepcopy
from datetime import timedelta

import pytest
from pydantic import ValidationError

from threatveil.core.contracts import digest, utcnow
from threatveil.core.validity import ProofScope, change_set, configuration_digest, invalidate


def fp():
    return {"components": [
        {"type": "application", "id": "agent", "version": "v1", "digest": "a" * 64,
         "provenance": "OBSERVED", "dependencies": ["tool:pay"]},
        {"type": "tool", "id": "pay", "version": "v1", "digest": "b" * 64,
         "provenance": "OBSERVED", "dependencies": ["permissions:finance"]},
        {"type": "permissions", "id": "finance", "digest": "c" * 64, "provenance": "OBSERVED"},
        {"type": "prompt", "id": "unrelated", "digest": "d" * 64, "provenance": "DECLARED"},
    ]}


def review(**kwargs):
    return ProofScope(coverage="REVIEWED_DEPENDENCIES", authority="HUMAN_REVIEWED",
        review_reason="Property checks payment authority in its independent tool boundary",
        bindings=({"component": "tool:pay"},), **kwargs)


def check(old, new, scope=None, age=0):
    stamp = utcnow()
    return invalidate(scope or ProofScope(), old, new, created_at=stamp-timedelta(seconds=age), evaluated_at=stamp)


def test_order_and_provenance_do_not_change_content_identity():
    old, new = fp(), fp()
    new["components"].reverse()
    new["components"][0]["provenance"] = "OBSERVED"
    assert configuration_digest(old) == configuration_digest(new)
    assert change_set(old, new)["changes"] == []
    assert check(old, new)["status"] == "STILL_VALID"


def test_changed_transitive_dependency_invalidates_reviewed_proof():
    old, new = fp(), fp()
    new["components"][2]["digest"] = "e" * 64
    result = check(old, new, review())
    assert result["status"] == "VOID"
    assert result["changed_dimensions"] == ["permissions:finance"]


def test_independent_change_can_preserve_only_reviewed_scope():
    old, new = fp(), fp()
    new["components"][3]["digest"] = "e" * 64
    assert check(old, new)["status"] == "VOID"
    assert check(old, new, review())["status"] == "STILL_VALID"


@pytest.mark.parametrize("provenance", ["UNKNOWN", "INFERRED"])
def test_identical_unknown_components_never_become_valid(provenance):
    old = fp()
    old["components"][3]["provenance"] = provenance
    assert check(old, old, review())["status"] == "UNKNOWN"


def test_dangling_dependencies_and_new_components_widen_to_unknown():
    old, new = fp(), fp()
    old["components"][1]["dependencies"].append("identity:missing")
    assert check(old, deepcopy(old), review())["status"] == "UNKNOWN"
    new["components"].append({"type": "remote_agent", "id": "delegate", "version": "1", "provenance": "DECLARED"})
    assert check(fp(), new, review())["status"] == "UNKNOWN"


def test_cycles_terminate_and_removed_edges_cannot_hide_dependency():
    old, new = fp(), fp()
    old["components"][2]["dependencies"] = ["tool:pay"]
    assert check(old, old, review())["status"] == "STILL_VALID"
    new["components"][1]["dependencies"] = []
    new["components"][2]["digest"] = "e" * 64
    assert check(old, new, review())["status"] == "VOID"


@pytest.mark.parametrize("age", [-1, 86401])
def test_evidence_window_is_explicit(age):
    assert check(fp(), fp(), age=age)["status"] == "UNKNOWN"


def test_semantic_compatibility_enumerates_reviewed_content_not_fuzzy_versions():
    old, new = fp(), fp()
    new["components"][1]["digest"] = digest("reviewed-equivalent-contract")
    scope = ProofScope(coverage="REVIEWED_DEPENDENCIES", authority="HUMAN_REVIEWED",
        review_reason="Reviewed tool schema evolution preserves the payment authority boundary",
        bindings=({"component": "tool:pay", "relationship": "SEMANTIC", "compatible_digests": [new["components"][1]["digest"]], "rationale": "No permission or action changes"},))
    assert check(old, new, scope)["status"] == "STILL_VALID"
    new["components"][1]["dependencies"] = []
    assert check(old, new, scope)["status"] == "VOID"


def test_unapproved_or_empty_selective_scope_is_rejected():
    with pytest.raises(ValidationError):
        ProofScope(coverage="REVIEWED_DEPENDENCIES")
    with pytest.raises(ValidationError):
        ProofScope(bindings=({"component": "tool:pay"}, {"component": "tool:pay"}))


def test_missing_declared_property_dependency_cannot_be_silently_dropped():
    scope = ProofScope(bindings=({"component": "identity:authority"},))
    assert check(fp(), fp(), scope)["status"] == "UNKNOWN"
