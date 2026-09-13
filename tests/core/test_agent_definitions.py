"""Deterministic agent-definition parsing, and the authority direction it establishes.

Every adapter is pure: no code is executed, no file is fetched, no model is called.
Secret values never enter a snapshot, and a format that declares nothing in data
stays UNKNOWN.
"""

import pytest

from threatveil.agent_definitions import DefinitionError, infer_format, snapshot
from threatveil.business_measurement import category, claim_basis
from threatveil.core.contracts import digest
from threatveil.source_semantics import explain_source_change

IDENTITY = "agent-definition:support"
SETTINGS = {"permissions": {"allow": ["Bash(git diff:*)", "Read"], "deny": ["Bash(rm:*)"], "ask": ["WebFetch"],
                            "defaultMode": "default"},
            "enabledMcpjsonServers": ["billing"], "model": "claude-opus-5"}


def batch(fmt, document):
    value = snapshot({"format": fmt, "document": document}, IDENTITY)
    return {"components": value.components, "facts": value.facts, "complete": value.complete,
            "source_identity": IDENTITY}, value


def direction(fmt, before_document, after_document):
    before, _ = batch(fmt, before_document)
    after, _ = batch(fmt, after_document)
    changed = sorted(key for key in before["components"].keys() | after["components"].keys()
                     if digest(before["components"].get(key)) != digest(after["components"].get(key)))
    return explain_source_change({"changed_components": changed, "change_kind": "COMPONENT_CHANGE",
                                  "source_identity": IDENTITY}, before, after)


def permissions(**changes):
    return {**SETTINGS, "permissions": {**SETTINGS["permissions"], **changes}}


def test_allowing_a_new_tool_expands_declared_authority():
    explanation = direction("claude_settings", SETTINGS, permissions(allow=["Bash(git diff:*)", "Read", "Write"]))
    assert explanation["authority"]["classification"] == "AUTHORITY_EXPANDED"
    dimension = next(d for d in explanation["authority"]["dimensions"] if d["condition"] == "allow")
    assert dimension["direction"] == "AUTHORITY_EXPANDED" and "Write" in dimension["reason"]
    assert explanation["subjects"] == ["authorization/permissions/allow"] and not explanation["unexplained"]


def test_removing_a_denial_expands_and_adding_a_confirmation_contracts():
    assert direction("claude_settings", SETTINGS, permissions(deny=[]))[
        "authority"]["classification"] == "AUTHORITY_EXPANDED"
    tightened = permissions(ask=["WebFetch", "Bash(git push:*)"])
    assert direction("claude_settings", SETTINGS, tightened)[
        "authority"]["classification"] == "AUTHORITY_CONTRACTED"


def test_permission_mode_is_ordered_and_unknown_modes_are_never_guessed():
    assert direction("claude_settings", SETTINGS, permissions(defaultMode="bypassPermissions"))[
        "authority"]["classification"] == "AUTHORITY_EXPANDED"
    assert direction("claude_settings", SETTINGS, permissions(defaultMode="plan"))[
        "authority"]["classification"] == "AUTHORITY_CONTRACTED"
    assert direction("claude_settings", SETTINGS, permissions(defaultMode="anything-else"))[
        "authority"]["classification"] == "UNKNOWN_IMPACT"


def test_a_changed_model_is_named_without_claiming_an_authority_change():
    explanation = direction("claude_settings", SETTINGS, {**SETTINGS, "model": "claude-sonnet-5"})
    assert explanation["subjects"] == ["model:settings"]
    assert explanation["authority"]["classification"] == "AUTHORITY_EQUIVALENT"


def test_a_removed_guard_hook_is_a_named_subject():
    guarded = {**SETTINGS, "hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "guard.sh"}]}]}}
    assert "policy:hooks" in direction("claude_settings", guarded, SETTINGS)["subjects"]


def test_mcp_servers_are_named_and_secret_values_are_never_retained():
    document = {"mcpServers": {
        "billing": {"type": "http", "url": "https://billing.internal.example/mcp",
                    "headers": {"Authorization": "Bearer super-secret-token"}},
        "local": {"command": "/usr/bin/node", "args": ["server.js"], "env": {"API_KEY": "secret-value-42"}}}}
    value, parsed = batch("mcp_json", document)
    assert "super-secret-token" not in str(value) and "secret-value-42" not in str(value)
    assert parsed.components["mcp:local"]["digest"] and parsed.components["mcp:billing"]["digest"]
    assert parsed.facts["authorization"]["authorization/mcp/servers"] == ["billing", "local"]
    removed = {"mcpServers": {"billing": document["mcpServers"]["billing"]}}
    assert direction("mcp_json", document, removed)["authority"]["classification"] == "AUTHORITY_CONTRACTED"


def test_a_subagent_inherits_every_tool_unless_it_declares_its_own():
    inherited = "---\nname: refunder\ndescription: Handles refunds\n---\nYou process refunds."
    explicit = "---\nname: refunder\ndescription: Handles refunds\ntools: Read, Write\n---\nYou process refunds."
    _, parsed = batch("claude_subagent", inherited)
    assert parsed.facts["authorization"]["authorization/agents/refunder/tools"] == "INHERITED_ALL"
    assert direction("claude_subagent", inherited, explicit)[
        "authority"]["classification"] == "UNKNOWN_IMPACT"
    with pytest.raises(DefinitionError):
        snapshot({"format": "claude_subagent", "document": "no frontmatter here"}, IDENTITY)


def test_manifest_tool_conditions_reuse_the_restriction_semantics():
    before = {"agents": {"support": {"tools": ["refund.issue"], "requires_approval": ["refund.issue"]}},
              "tools": {"refund.issue": {"tenant_bound": True}}}
    after = {"agents": {"support": {"tools": ["refund.issue"]}},
             "tools": {"refund.issue": {"tenant_bound": True}}}
    explanation = direction("manifest", before, after)
    assert explanation["authority"]["classification"] == "AUTHORITY_EXPANDED"
    dimension = next(d for d in explanation["authority"]["dimensions"] if d["condition"] == "approval_required")
    assert dimension["subject"] == "refund.issue" and "restriction was removed" in dimension["reason"]


def test_crewai_delegation_expands_and_langgraph_stays_unknown():
    before = {"researcher": {"role": "Researcher", "goal": "Find facts", "allow_delegation": False}}
    after = {"researcher": {"role": "Researcher", "goal": "Find facts", "allow_delegation": True}}
    assert direction("crewai", before, after)["authority"]["classification"] == "AUTHORITY_EXPANDED"
    _, parsed = batch("langgraph", {"graphs": {"agent": "./agent.py:graph"}})
    assert parsed.complete is False and "defined in code" in parsed.facts["unknown"][0]
    assert parsed.facts["authorization"] is None
    with pytest.raises(DefinitionError):
        snapshot({"format": "openai_agents", "document": {}}, IDENTITY)


def test_yaml_is_bounded_and_anchors_are_refused():
    with pytest.raises(DefinitionError):
        snapshot({"format": "crewai", "document": "researcher: &base\n  role: R\nhelper: *base\n"}, IDENTITY)
    with pytest.raises(DefinitionError):
        snapshot({"format": "crewai", "document": "a: " + "x" * 300_000}, IDENTITY)
    with pytest.raises(DefinitionError):
        snapshot({"format": "invented_format", "document": {}}, IDENTITY)


def test_format_inference():
    assert infer_format(".claude/settings.json") == "claude_settings"
    assert infer_format(".claude/settings.local.json") == "claude_settings"
    assert infer_format(".mcp.json") == "mcp_json"
    assert infer_format(".claude/agents/refunder.md") == "claude_subagent"
    assert infer_format("langgraph.json") == "langgraph"
    assert infer_format("config/agents.yaml") == "crewai"
    assert infer_format("threatveil-agent.yaml") == "manifest"
    assert infer_format("README.md") is None


def test_only_a_determinate_claim_level_answer_is_a_consequence_category():
    evidenced = {"claims_affected": [{"property_id": "p", "title": "Approval required"}], "effect": "OPEN"}
    assert (category(evidenced), claim_basis(evidenced)) == ("INVALIDATION", "EVIDENCED")
    no_impact = {"claims_affected": [], "effect": "NO_CLAIM_AFFECTED"}
    assert (category(no_impact), claim_basis(no_impact)) == ("NO_IMPACT", "EVIDENCED")
    declared = {"claims_affected": [], "effect": "NO_BASELINE", "declared_claims_affected": [],
                "declared_effect": "NO_DECLARED_CLAIM_AFFECTED"}
    assert (category(declared), claim_basis(declared)) == ("NO_IMPACT", "DECLARED")
    silent = {"claims_affected": [], "effect": "NO_BASELINE"}
    assert (category(silent), claim_basis(silent)) == ("OTHER", "NONE")
