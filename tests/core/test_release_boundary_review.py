"""Regression coverage for independently discovered proof-key ambiguity."""

from copy import deepcopy

import pytest
from pydantic import ValidationError

from threatveil.core.contracts import SystemFingerprint, utcnow
from threatveil.core.validity import ProofScope, invalidate


def test_component_type_cannot_alias_another_components_namespaced_identifier():
    with pytest.raises(ValidationError):
        SystemFingerprint.model_validate(
            {
                "components": [
                    {"type": "tool", "id": "a:b", "digest": "a" * 64, "provenance": "OBSERVED"},
                    {"type": "tool:a", "id": "b", "digest": "b" * 64, "provenance": "OBSERVED"},
                ]
            }
        )


def test_namespaced_component_ids_remain_valid_and_cannot_hide_changes():
    old = {
        "components": [{"type": "tool", "id": "a:b", "digest": "a" * 64, "provenance": "OBSERVED"}]
    }
    new = deepcopy(old)
    new["components"][0]["digest"] = "c" * 64
    stamp = utcnow()
    decision = invalidate(ProofScope(), old, new, created_at=stamp, evaluated_at=stamp)
    assert decision["status"] == "VOID" and decision["changed_dimensions"] == ["tool:a:b"]
