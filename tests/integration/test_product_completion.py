"""Product completion: format detection, the factual system stack, and reliance.

Every addition here is a read-only projection. None of them may create a record, infer
a vendor from a model string or a name, or present an imported snapshot as a live
connection.
"""

import json
from datetime import timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from threatveil.agent_definitions import detect_format
from threatveil.api import app
from threatveil.db import now
from test_assurance_intelligence import change, cleared, finance, intel
from test_product import customer as customer  # noqa: F401


SETTINGS = {"permissions": {"allow": ["Bash(git:*)", "mcp__payments__refund_issue"], "deny": ["WebFetch"],
                            "ask": ["Bash(rm:*)"]},
            "mcpServers": {"payments": {"command": "payments-mcp"}}, "model": "claude-opus-5"}
CREW = "researcher:\n  role: Researcher\n  goal: Find sources\n  allow_delegation: true\n  tools: [search]\n"
CATALOG = {"protocol_version": "2026-07-28", "supported_versions": ["2026-07-28"], "complete": True,
           "server_info": {"name": "refund-gateway", "version": "1"},
           "tools": [{"name": "refund.issue", "description": "Issue a refund", "inputSchema": {"type": "object"}}],
           "authorization": {"tools": {"refund.issue": {"approval_required": True}}}}
# Fits both a CrewAI agents file and a ThreatVeil manifest; only a file name can settle it.
EITHER = {"agents": {"role": {"tools": []}, "goal": {"tools": []}}}


def preview(client, document, filename=None):
    response = client.post("/v1/connectors/definition-preview",
                           json={"format": "auto", "document": document, "filename": filename})
    assert response.status_code == 200, response.text
    return response.json()


def test_detection_is_structural_and_never_guesses():
    assert detect_format(json.dumps(SETTINGS), "settings.json")["format"] == "claude_settings"
    assert detect_format({"mcpServers": {"a": {"command": "x"}}})["format"] == "mcp_json"
    assert detect_format("---\nname: reviewer\n---\nReview.", "reviewer.md")["format"] == "claude_subagent"
    assert detect_format('{"graphs": {"agent": "./a.py:graph"}}')["format"] == "langgraph"
    assert detect_format(CREW)["format"] == "crewai"
    assert detect_format(CATALOG)["format"] == "mcp_tools"
    # A familiar key is not enough: the candidate must also parse under its adapter.
    assert detect_format({"permissions": "not a mapping"})["status"] == "UNSUPPORTED"
    # Two formats fit: without a settling file name the caller must ask.
    ambiguous = detect_format(EITHER)
    assert ambiguous["status"] == "AMBIGUOUS" and set(ambiguous["candidates"]) == {"crewai", "manifest"}
    assert detect_format(EITHER, "agents.yaml")["format"] == "crewai"
    assert detect_format(EITHER, "threatveil.yaml")["format"] == "manifest"
    # A file name alone never selects a format.
    assert detect_format({"unrelated": True}, "settings.json")["status"] == "UNSUPPORTED"
    assert detect_format({"spans": []})["hint"] == "OPENAI_AGENTS_TRACE"
    assert detect_format("{broken")["status"] == "UNSUPPORTED"


def test_auto_preview_returns_declared_facts_and_writes_nothing(customer):
    systems_before = customer.get("/v1/systems").json()
    connectors_before = customer.get("/v1/connectors").json()
    body = preview(customer, json.dumps(SETTINGS), "settings.json")
    assert body["detection"]["status"] == "DETECTED"
    assert body["format"] == "claude_settings"
    assert body["models"] == ["claude-opus-5"]
    assert body["permissions"]["deny"] == ["WebFetch"] and body["permissions"]["ask"] == ["Bash(rm:*)"]
    assert body["mcp_servers"] == ["payments"]
    assert body["ecosystem"] == ["claude_code", "mcp"]
    assert customer.get("/v1/systems").json() == systems_before
    assert customer.get("/v1/connectors").json() == connectors_before


def test_auto_preview_reads_yaml_markdown_and_tool_catalogs(customer):
    crew = preview(customer, CREW, "agents.yaml")
    assert crew["format"] == "crewai" and crew["ecosystem"] == ["crewai"]
    assert crew["delegation"] == ["researcher"] and crew["tools"] == ["search"]
    subagent = preview(customer, "---\nname: reviewer\nmodel: sonnet\n---\nReview code.", "reviewer.md")
    # Omitting tools inherits every parent tool: stated, never shown as an empty list.
    assert subagent["format"] == "claude_subagent" and subagent["inherits_all_tools"] == ["reviewer"]
    catalog = preview(customer, CATALOG)
    assert catalog["format"] == "mcp_tools" and catalog["tools"] == ["refund.issue"]
    assert catalog["ecosystem"] == ["mcp"]


def test_auto_preview_asks_when_ambiguous_and_never_echoes_content(customer):
    ambiguous = preview(customer, EITHER)
    assert ambiguous["detection"]["status"] == "AMBIGUOUS" and "tools" not in ambiguous
    secret = f"customer-secret-{uuid4()}"
    unsupported = customer.post("/v1/connectors/definition-preview",
                                json={"format": "auto", "document": {"spans": [secret]}})
    assert unsupported.status_code == 200
    assert unsupported.json()["detection"]["hint"] == "OPENAI_AGENTS_TRACE"
    assert secret not in unsupported.text


def test_a_model_string_never_establishes_a_vendor(customer):
    body = preview(customer, "agents:\n  support:\n    model: gpt-5\n    tools: [refund.issue]\n  "
                             "review:\n    model: claude-opus-5\n", "threatveil.yaml")
    assert body["format"] == "manifest"
    assert body["models"] == ["claude-opus-5", "gpt-5"]
    assert body["ecosystem"] == []


def test_the_synthetic_example_stack_is_an_imported_mcp_snapshot_only(customer):
    setup = finance(customer)
    items = intel(customer, setup)["stack"]["items"]
    assert [item["id"] for item in items] == ["mcp"]
    assert items[0]["relationship"] == "IMPORTED" and items[0]["connected"] is False
    assert "tool catalog snapshot" in items[0]["basis"]


def test_an_imported_definition_names_its_format_and_declared_servers_once(customer):
    system = customer.post("/v1/systems", json={"name": "Refund agent", "description": "Issues refunds.",
                                                 "access": [], "actions": []}).json()
    environment = customer.post("/v1/change-assurance/environments", json={
        "system_id": system["id"], "name": "Staging", "purpose": "STAGING",
        "boundary": "Staging refund workflow only.", "owner": "Owner"}).json()

    def imported(fmt, document):
        installation = customer.post("/v1/connectors", json={
            "system_id": system["id"], "environment_id": environment["id"], "connector_id": "agent_definition",
            "mode": "IMPORT", "roles": ["DISCOVER", "CHANGE"], "name": f"{fmt} import", "configuration": {},
            "expires_at": (now() + timedelta(days=7)).isoformat()})
        assert installation.status_code == 201, installation.text
        result = customer.post(f"/v1/connectors/{installation.json()['id']}/import", json={
            "event_id": str(uuid4()), "valid_at": now().isoformat(), "payload": {"format": fmt, "document": document}})
        assert result.status_code == 201, result.text

    imported("claude_settings", SETTINGS)
    imported("claude_settings", json.dumps(SETTINGS))  # uploaded text is accepted as-is
    imported("crewai", CREW)
    body = customer.get(f"/v1/systems/{system['id']}/intelligence").json()
    items = {item["id"]: item for item in body["stack"]["items"]}
    assert list(items) == ["claude_code", "mcp", "crewai"]
    assert items["claude_code"]["relationship"] == "IMPORTED"
    assert items["mcp"]["relationship"] == "DECLARED"
    # Nothing imported is ever presented as connected, and no vendor is read from the model string.
    assert not any(item["connected"] for item in items.values())
    assert "openai_agents" not in items and "github" not in items


def test_reliance_counts_machine_gate_reads_only(customer):
    setup, _ = cleared(customer)
    system_id = setup["system_id"]
    customer.get(f"/v1/systems/{system_id}/assurance/current", headers={"x-threatveil-consumer": "browser"})
    reliance = intel(customer, setup)["reliance"]
    assert reliance["machine_check_windows"] == 0 and reliance["last_machine_check_at"] is None
    token = customer.post("/v1/api-tokens", json={"name": "CI gate", "permission": "read",
                                                  "expires_at": (now() + timedelta(days=7)).isoformat()})
    if token.status_code != 201:
        token = customer.post("/v1/api-tokens", json={"name": "CI gate", "permission": "read"})
    assert token.status_code == 201, token.text
    secret = token.json().get("token") or token.json().get("secret")
    machine = TestClient(app, client=("127.203.1.1", 50000))
    assert machine.get(f"/v1/systems/{system_id}/assurance/current", headers={
        "authorization": f"Bearer {secret}", "x-threatveil-consumer": "ci-gate"}).status_code == 200
    reliance = intel(customer, setup)["reliance"]
    assert reliance["machine_check_windows"] == 1
    assert reliance["machine_consumers"] == ["ci-gate"] and reliance["last_machine_check_at"]
    assert reliance["external_check_windows"] == 0


def test_home_activity_identifies_each_change_and_its_source(customer):
    setup, _ = cleared(customer)
    change(customer, setup, "beneficiary_approval_relaxed")
    ids = {view["id"] for view in intel(customer, setup)["changes"]}
    activity = [item for item in customer.get("/v1/home").json()["activity"] if item["kind"] == "CHANGE"]
    assert activity and all(item["id"] in ids for item in activity)
    # A source change names its connector; a declared boundary has no connector, and none is invented.
    assert {item["connector"] for item in activity} <= {"mcp", None}
    assert "mcp" in {item["connector"] for item in activity}


def test_evidence_names_its_ground_truth_as_recorded(customer):
    setup, _ = cleared(customer)
    claims = [c for c in intel(customer, setup)["evidence"]["claims"] if c["evidence"]]
    assert claims
    for claim in claims:
        evidence = claim["evidence"]
        # The synthetic ledger is named as the record states it; no database brand is inferred.
        assert evidence["ground_truth"] == "Synthetic committed SQLite ledger"
        assert evidence["synthetic"] is True and evidence["limitations"]
