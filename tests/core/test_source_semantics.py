"""Authority semantics are deterministic, conservative and never guessed."""

from threatveil.assurance_intelligence import envelope_diff
from threatveil.source_semantics import (
    CONTRACTED, EQUIVALENT, EXPANDED, UNKNOWN, authorization_diff, bounded_authorization,
    classify_condition, combine, explain_source_change, mapping_index, pointer, scope_change,
)


def flat(tools):
    return bounded_authorization({"tools": tools})


def batch(tools, *, authorization=True, server="1", complete=True):
    """A structured MCP batch payload, as the collector records it."""
    return {"complete": complete, "source_identity": "source:gw",
            "components": {f"tool:source:gw:{name}": {"digest": f"d-{name}"} for name in tools},
            "facts": {"authorization": flat(tools) if authorization else None,
                      "catalog_parts": {"protocol_version": "2026-07-28", "server_info": server,
                                        "capabilities": "c", "catalog_metadata": "m"},
                      "tool_components": {f"tool:source:gw:{name}": name for name in tools}}}


def test_relaxing_a_restriction_is_an_expansion_and_tightening_a_contraction():
    before = flat({"beneficiary.update": {"approval_required": True, "tenant_bound": True}})
    after = flat({"beneficiary.update": {"approval_required": False, "tenant_bound": True}})
    diff = authorization_diff(before, after)
    assert diff["classification"] == EXPANDED
    assert [d["condition"] for d in diff["dimensions"]] == ["approval_required"]
    subject = diff["subjects"][0]
    assert subject["before"] == {"approval_required": True, "tenant_bound": True}
    assert subject["after"] == {"approval_required": False, "tenant_bound": True}
    assert authorization_diff(after, before)["classification"] == CONTRACTED


def test_unchanged_and_unrecognized_fields_are_never_guessed():
    same = flat({"invoice.update": {"approval_required": False}})
    assert authorization_diff(same, same)["classification"] == EQUIVALENT
    renamed = authorization_diff(flat({"t": {"owner": "finance"}}), flat({"t": {"owner": "ops"}}))
    assert renamed["classification"] == UNKNOWN
    assert classify_condition("authorization/t/approval", "maybe", "perhaps")[0] == UNKNOWN


def test_mixed_movement_is_an_expansion_because_the_new_boundary_is_not_contained():
    diff = authorization_diff(flat({"t": {"scopes": ["read", "write"]}}), flat({"t": {"scopes": ["read", "refund"]}}))
    assert diff["classification"] == EXPANDED
    assert "Scope added: refund" in diff["dimensions"][0]["reason"]
    assert "removed: write" in diff["dimensions"][0]["reason"]
    assert combine([CONTRACTED, UNKNOWN]) == UNKNOWN and combine([CONTRACTED, EQUIVALENT]) == CONTRACTED
    assert combine([]) == EQUIVALENT


def test_authorization_captured_on_one_side_only_is_unknown():
    assert authorization_diff(None, flat({"t": {"approval_required": True}}))["classification"] == UNKNOWN
    assert authorization_diff(None, None) is None


def test_bounded_authorization_is_digest_only_beyond_its_limits():
    long = bounded_authorization({"note": "x" * 500})
    assert long["authorization/note"].startswith("sha256:")
    huge = bounded_authorization({f"k{i}": True for i in range(400)})
    assert huge["authorization/__bounded__"] is True
    assert classify_condition("authorization/__bounded__", None, True, present_before=False)[0] == UNKNOWN


def test_a_new_interface_expands_authority_and_its_own_restrictions_do_not_read_as_contraction():
    before = batch({"invoice.update": {"approval_required": False}})
    after = batch({"invoice.update": {"approval_required": False},
                   "payment.execute": {"approval_required": True, "tenant_bound": True}})
    event = {"changed_components": ["mcp:source:gw", "permissions:source:gw", "tool:source:gw:payment.execute"],
             "change_kind": "COMPONENT_CHANGE", "source_identity": "source:gw"}
    explanation = explain_source_change(event, before, after)
    authority = explanation["authority"]
    assert authority["classification"] == EXPANDED
    assert {d["direction"] for d in authority["dimensions"] if d["kind"] == "AUTHORIZATION"} == {EQUIVALENT}
    assert authority["subjects"][0]["direction"] == EXPANDED
    # The new tool and its authorization facts are named, and none is mapped yet.
    assert "tool:source:gw:payment.execute" in explanation["subjects"]
    scope = scope_change(explanation, {})
    assert not scope["fully_mapped"] and scope["dependencies"] == []


def test_a_fully_mapped_change_scopes_to_reviewed_dependencies_and_one_gap_keeps_it_conservative():
    before = batch({"beneficiary.update": {"approval_required": True, "tenant_bound": True}})
    after = batch({"beneficiary.update": {"approval_required": False, "tenant_bound": True}})
    event = {"changed_components": ["mcp:source:gw", "permissions:source:gw"], "change_kind": "COMPONENT_CHANGE",
             "source_identity": "source:gw"}
    explanation = explain_source_change(event, before, after)
    path = pointer("authorization", "tools", "beneficiary.update", "approval_required")
    assert explanation["subjects"] == ["authorization/tools/beneficiary.update/approval_required"] == [path]
    assert not explanation["unexplained"]

    class Row:
        def __init__(self, identifier, payload):
            self.id, self.payload = identifier, payload

    rows = [Row("m2", {"installation_id": "i", "subject": path, "maps_to": ["permissions:finance-approval"]}),
            Row("m1", {"installation_id": "i", "subject": path, "maps_to": ["permissions:obsolete"]}),
            Row("m0", {"installation_id": "other", "subject": path, "maps_to": ["permissions:elsewhere"]})]
    index = mapping_index(rows, "i")
    scope = scope_change(explanation, index)
    assert scope == {"fully_mapped": True, "dependencies": ["permissions:finance-approval"],
                     "mapping_ids": ["m2"], "unmapped": []}
    wider = explain_source_change(event, before, batch({"beneficiary.update": {"approval_required": False,
                                                                                "tenant_bound": False}}))
    assert not scope_change(wider, index)["fully_mapped"]


def test_catalog_metadata_changes_are_named_and_gaps_are_never_scoped():
    before, after = batch({"t": {"approval_required": True}}), batch({"t": {"approval_required": True}}, server="2")
    explanation = explain_source_change(
        {"changed_components": ["mcp:source:gw"], "change_kind": "COMPONENT_CHANGE", "source_identity": "source:gw"},
        before, after)
    assert explanation["subjects"] == ["mcp/server_info"]
    assert explanation["authority"]["classification"] == EQUIVALENT
    gap = explain_source_change({"changed_components": ["mcp:source:gw"], "change_kind": "SOURCE_GAP"}, before, after)
    assert gap["conservative"] and not scope_change(gap, {"mcp:source:gw": {"id": "x", "maps_to": ["a"]}})["fully_mapped"]
    initial = explain_source_change({"changed_components": ["tool:source:gw:t"], "change_kind": "COMPONENT_CHANGE"},
                                    None, after)
    assert initial["initial"] and initial["authority"]["classification"] == UNKNOWN


def test_unstructured_permission_changes_are_unknown_and_code_changes_claim_nothing():
    cloud = explain_source_change({"changed_components": ["permissions:projects/p/services/s"],
                                   "change_kind": "COMPONENT_CHANGE"}, {"facts": {}}, {"facts": {}})
    assert cloud["authority"]["classification"] == UNKNOWN
    assert cloud["authority"]["dimensions"][0]["kind"] == "DIGEST"
    code = explain_source_change({"changed_components": ["git_commit:1"], "change_kind": "COMPONENT_CHANGE"},
                                 {"facts": {}}, {"facts": {}})
    assert code["authority"]["classification"] == UNKNOWN and not code["authority"]["dimensions"]


def test_declared_boundary_diff_distinguishes_direction_and_rewording():
    base = {"principals": ["agent"], "actions": ["invoice.update"], "resources": ["invoice"],
            "constraints": ["Approval required"]}
    assert envelope_diff(base, {**base, "actions": ["invoice.update", "refund.issue"]})["classification"] == EXPANDED
    assert envelope_diff(base, {**base, "resources": []})["classification"] == CONTRACTED
    assert envelope_diff(base, {**base, "constraints": []})["classification"] == EXPANDED
    assert envelope_diff(base, {**base, "constraints": ["Approval required", "Tenant only"]})["classification"] == CONTRACTED
    assert envelope_diff(base, {**base, "constraints": ["Approval is required"]})["classification"] == UNKNOWN
    assert envelope_diff(base, dict(base))["classification"] == EQUIVALENT
