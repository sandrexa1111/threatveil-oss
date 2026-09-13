"""New execution must not implicitly discard unobserved non-code changes."""

from threatveil.change_assurance import source_change_reconciled


def test_external_permission_outside_reviewed_coverage_survives_fresh_evidence():
    event = {"acquisition": "IMPORTED", "change_kind": "COMPONENT_CHANGE",
             "changed_components": ["permissions:outside-observed-state"]}
    old_code = {"code:agent": {"digest": "code-a", "version": "1", "provenance": "OBSERVED"}}
    assert not source_change_reconciled(event, old_code, {"code:agent"}, {})
    # Billing, a claimed matching hash, or a reviewed dependency name alone cannot observe state.
    asserted = {"permissions:outside-observed-state": {"digest": "after", "version": None,
                                                       "provenance": "DECLARED"}}
    after = {"permissions:outside-observed-state": {"digest": "after", "version": None}}
    assert not source_change_reconciled(event, asserted, set(after), after)


def test_reconciliation_needs_reviewed_dependency_and_exact_observed_after_value():
    key = "permissions:approval"
    event = {"acquisition": "IMPORTED", "change_kind": "COMPONENT_CHANGE", "changed_components": [key]}
    captured = {key: {"digest": "after", "version": "2", "provenance": "OBSERVED"}}
    after = {key: {"digest": "after", "version": "2"}}
    assert not source_change_reconciled(event, captured, set(), after)
    assert not source_change_reconciled(event, captured, {key}, {key: {"digest": "before", "version": "1"}})
    assert source_change_reconciled(event, captured, {key}, after)
    assert not source_change_reconciled({**event, "change_kind": "SOURCE_GAP"}, captured, {key}, after)
    assert not source_change_reconciled({**event, "changed_components": [key, "tool:unknown"]}, captured, {key}, after)


def test_only_explicit_synthetic_fixture_can_discharge_an_imported_hint_without_external_state():
    event = {"acquisition": "IMPORTED", "changed_components": ["permissions:unknown"]}
    assert source_change_reconciled(event, {}, set(), {}, synthetic_fixture=True)
    assert not source_change_reconciled(event, {}, set(), {}, synthetic_fixture=False)
    assert not source_change_reconciled({**event, "acquisition": "API_OBSERVED"}, {}, set(), {}, synthetic_fixture=True)
