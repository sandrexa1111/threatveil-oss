"""The claim builder, declared claims, reviewed dependency mapping and the AI seam.

A template is a starting point, a draft is not a claim, a declared claim is never
supported without evidence, and a proposal — deterministic, customer-written or
model-written — changes nothing until a person approves it.
"""


from threatveil.config import settings
from test_assurance_intelligence import other_tenant
from test_business_measurement import imported, observed, real_source
from test_product import customer as customer  # noqa: F401

NOT_VERIFIED = "STARTER TEMPLATE / NOT VERIFIED FOR YOUR SYSTEM"


def templates(client):
    response = client.get("/v1/claim-templates")
    assert response.status_code == 200, response.text
    return response.json()


def draft(client, template_id, resource, **extra):
    return client.post("/v1/claim-templates/draft", json={"template_id": template_id, "resource": resource, **extra})


def declare_from(client, system_id, environment_id, value, dependencies):
    response = client.post(f"/v1/systems/{system_id}/claim-definitions", json={
        "environment_id": environment_id, "action": value["action"], "claim": value["claim"],
        "permitted_outcome": value["permitted_outcome"], "forbidden_outcome": value["forbidden_outcome"],
        "legitimate_task": value["legitimate_task"], "ground_truth_source": value["ground_truth_source"],
        "declared_dependencies": dependencies, "template_id": value["template_id"],
        "resource": value["resource"], "expected_conditions": value["expected_conditions"][:10]})
    assert response.status_code == 201, response.text
    return response.json()


def suggestions(client, system_id, installation_id):
    response = client.get(f"/v1/systems/{system_id}/mapping-suggestions",
                          params={"installation_id": installation_id})
    assert response.status_code == 200, response.text
    return response.json()


def propose(client, system_id, body):
    return client.post(f"/v1/systems/{system_id}/mapping-proposals", json=body)


def review(client, proposal_id, decision, note="Reviewed against the source record and the claim dependency",
           maps_to=None):
    body = {"decision": decision, "review_note": note}
    if maps_to is not None:
        body["maps_to"] = maps_to
    return client.post(f"/v1/mapping-proposals/{proposal_id}/review", json=body)


def mapped_change(client, system_id):
    return observed(client, system_id)["mapping"]["fully_mapped"]


def declared_system(client, monkeypatch, name="Refund agent"):
    """A real system, an imported agent source, a declared claim and one observed change."""
    system, environment, installation = real_source(client, monkeypatch, name)
    imported(client, installation, ("ticket.update",), 1)
    imported(client, installation, ("ticket.update", "refund.issue"), 2)
    value = draft(client, "refund_limit", "refunds").json()
    definition = declare_from(client, system["id"], environment["id"], value, ["tool:refund.issue"])
    return system, environment, installation, definition


def test_templates_are_neutral_and_a_draft_is_never_a_claim(customer, monkeypatch):
    catalog = templates(customer)
    assert catalog["status_label"] == NOT_VERIFIED and len(catalog["templates"]) == 10
    assert {t["label"] for t in catalog["templates"]} >= {
        "APPROVAL REQUIRED", "TENANT ISOLATION", "MAXIMUM TRANSACTION LIMIT", "READ-ONLY BOUNDARY",
        "PRODUCTION DEPLOY REQUIRES APPROVAL", "REFUND LIMIT", "EXTERNAL MESSAGE APPROVAL",
        "PRIVILEGED ACTION REQUIRES HUMAN CONFIRMATION", "NO CROSS-TENANT WRITE", "TOOL ALLOWLIST"}
    actions = {a["action"] for a in catalog["starter_actions"]}
    assert actions == {"read", "create", "update", "delete", "send", "refund", "pay", "provision", "deploy",
                       "approve", "grant", "revoke", "execute"}
    assert all(t["archetype"] for t in catalog["templates"])
    built = draft(customer, "approval_required", "beneficiary records")
    assert built.status_code == 200, built.text
    value = built.json()
    assert value["status"] == NOT_VERIFIED and value["recorded"] is False
    assert value["establishes_evidence"] is False and "beneficiary records" in value["claim"]
    assert any("prove" in step.lower() or "NOT_YET_VERIFIED" in step for step in value["next_steps"])
    assert draft(customer, "does_not_exist", "anything").status_code == 404
    assert draft(customer, "approval_required", "x").status_code == 422
    # A declared claim is never supported, and the ladder never merges the four levels.
    system, environment, installation, definition = declared_system(customer, monkeypatch, "Template agent")
    ladder = customer.get(f"/v1/systems/{system['id']}/claims").json()
    entry = next(c for c in ladder["claims"] if c["id"] == definition["id"])
    assert entry["verification"] == "NOT_YET_VERIFIED" and entry["kind"] == "DECLARED_CLAIM"
    assert ladder["counts"] == {"DECLARED": 0, "NOT_YET_VERIFIED": 1, "QUALIFIED": 0, "CURRENT": 0}
    assert set(ladder["levels"]) == {"DECLARED", "NOT_YET_VERIFIED", "QUALIFIED", "CURRENT"}
    currency = customer.get(f"/v1/systems/{system['id']}/evidence-currency").json()
    declared = next(c for c in currency["claims"] if c.get("claim_definition_id") == definition["id"])
    assert declared["status"] == "DEFINED" and declared["evidence"] is None
    assert currency["counts"]["SUPPORTED"] == 0
    assert installation["id"]


def test_a_mapping_proposal_changes_nothing_until_a_person_approves_it(customer, monkeypatch):
    system, environment, installation, definition = declared_system(customer, monkeypatch, "Mapping agent")
    found = suggestions(customer, system["id"], installation["id"])
    assert found["unmapped_subjects"] >= 1
    subject = next(item for item in found["items"]
                   if "refund.issue" in item["names"] and item["kind"] == "TOOL")
    best = subject["suggestions"][0]
    assert best["dependency"] == "tool:refund.issue" and best["reason"] == "TOOL_NAME_MATCH"
    assert best["confidence"] == "EXACT_NAME" and best["basis"] == "DECLARED_CLAIM"
    assert best["claims"][0]["title"] == definition["claim"]
    assert "not a reviewed fact" in subject["note"]
    # Before any approval the change cannot be scoped.
    assert mapped_change(customer, system["id"]) is False
    body = {"environment_id": environment["id"], "installation_id": installation["id"],
            "subject": subject["subject"], "maps_to": [best["dependency"]], "reason": best["reason"],
            "confidence": best["confidence"], "origin": "DETERMINISTIC",
            "evidence": f"Source record {subject['source_record']} reports the tool {subject['names'][0]}"}
    created = propose(customer, system["id"], body)
    assert created.status_code == 201, created.text
    proposal = created.json()
    assert proposal["status"] == "PROPOSED" and proposal["affects_scoping"] is False
    assert mapped_change(customer, system["id"]) is False
    listed = customer.get(f"/v1/systems/{system['id']}/mapping-proposals").json()
    assert listed["open"] == 1 and listed["items"][0]["id"] == proposal["id"]
    # Approval is the only path to an effective mapping.
    assert review(customer, proposal["id"], "EDITED").status_code == 422
    approved = review(customer, proposal["id"], "APPROVED")
    assert approved.status_code == 201, approved.text
    assert approved.json()["affects_scoping"] is True and approved.json()["mapping_id"]
    assert review(customer, proposal["id"], "REJECTED").status_code == 409
    assert mapped_change(customer, system["id"]) is True
    consequence = observed(customer, system["id"])
    assert consequence["consequence"]["declared_effect"] == "DECLARED_CLAIMS_AFFECTED"
    # The overview shows who approved what, from which source record, and what is still unmapped.
    overview = customer.get(f"/v1/systems/{system['id']}/mappings-overview").json()
    source = next(s for s in overview["sources"] if s["installation_id"] == installation["id"])
    row = next(m for m in source["mapped"] if m["subject"] == subject["subject"])
    assert row["approved_by"] and row["source_record"] and row["affects_scoping"] is True
    assert row["maps_to"] == ["tool:refund.issue"]
    assert all(item["affects_scoping"] is False for item in source["unmapped"])
    assert all("cannot be scoped" in item["consequence"] for item in source["unmapped"])
    assert any(c["dependency"] == "tool:refund.issue" for c in overview["candidates"])
    # A mapping to something no claim depends on is refused outright.
    invented = propose(customer, system["id"], {**body, "maps_to": ["tool:not-a-dependency"]})
    assert invented.status_code == 201
    assert review(customer, invented.json()["id"], "APPROVED").status_code == 422
    # Another tenant sees none of it.
    other = other_tenant()
    assert other.get(f"/v1/systems/{system['id']}/mapping-suggestions",
                     params={"installation_id": installation["id"]}).status_code == 404
    assert other.get(f"/v1/systems/{system['id']}/mappings-overview").status_code == 404
    assert other.post(f"/v1/mapping-proposals/{proposal['id']}/review",
                      json={"decision": "APPROVED", "review_note": "Not my proposal to review"}).status_code == 404


def test_ai_assistance_is_off_by_default_and_can_only_propose(customer, monkeypatch):
    system, environment, installation, definition = declared_system(customer, monkeypatch, "AI seam agent")
    assist = {"installation_id": installation["id"], "environment_id": environment["id"]}
    disabled = customer.post(f"/v1/systems/{system['id']}/ai/mapping-proposals", json=assist)
    assert disabled.status_code == 409 and "disabled" in disabled.text
    assert customer.post(f"/v1/systems/{system['id']}/ai/claim-draft", json={
        "resource": "refunds", "intent": "Resolve refund requests for customers"}).status_code == 409
    usage = customer.get("/v1/measurements/ai-usage").json()
    assert usage["enabled"] == {"dependency_mapping": False, "claim_authoring": False}
    assert usage["spent_this_month_usd"] == 0.0 and usage["features"] == []
    # Enable the deterministic mock provider: local only, no network, no cost.
    monkeypatch.setenv("TV_AI_PROVIDER", "mock")
    monkeypatch.setenv("TV_AI_MAPPING_ENABLED", "true")
    monkeypatch.setenv("TV_AI_CLAIMS_ENABLED", "true")
    settings.cache_clear()
    proposed = customer.post(f"/v1/systems/{system['id']}/ai/mapping-proposals", json=assist)
    assert proposed.status_code == 201, proposed.text
    result = proposed.json()
    assert result["provider"] == "mock" and result["affects_scoping"] is False
    assert any("proposes" in line for line in result["invariants"])
    ai_proposal = next(item for item in result["items"] if item["maps_to"] == ["tool:refund.issue"])
    assert ai_proposal["origin"] == "AI_PROPOSED" and ai_proposal["status"] == "PROPOSED"
    assert ai_proposal["model"] == "deterministic-mock/v1" and "Cited inputs" in ai_proposal["note"]
    # A model's proposal is inert: nothing is scoped until a person approves it.
    assert mapped_change(customer, system["id"]) is False
    assert review(customer, ai_proposal["id"], "APPROVED").json()["affects_scoping"] is True
    assert mapped_change(customer, system["id"]) is True
    # A model may not invent a subject the source never reported.
    assert all(item["subject"] for item in result["items"])
    drafted = customer.post(f"/v1/systems/{system['id']}/ai/claim-draft", json={
        "resource": "refunds", "intent": "Resolve refund requests for customers"})
    assert drafted.status_code == 200, drafted.text
    assert drafted.json()["recorded_as_claim"] is False
    assert drafted.json()["status"] == "DRAFT / NOT VERIFIED FOR YOUR SYSTEM"
    assert drafted.json()["draft"]["cited_inputs"] == ["refunds"]
    usage = customer.get("/v1/measurements/ai-usage").json()
    features = {item["feature"]: item for item in usage["features"]}
    assert features["dependency_mapping"]["calls"] == 1 and features["claim_authoring"]["calls"] == 1
    assert features["dependency_mapping"]["providers"] == ["mock"]
    assert usage["spent_this_month_usd"] == 0.0
    # A paid provider cannot run without a configured budget.
    monkeypatch.setenv("TV_AI_PROVIDER", "openai")
    monkeypatch.setenv("TV_OPENAI_API_KEY", "sk-local-test-not-used")
    settings.cache_clear()
    refused = customer.post(f"/v1/systems/{system['id']}/ai/mapping-proposals", json=assist)
    assert refused.status_code == 409 and "budget" in refused.text
    monkeypatch.delenv("TV_AI_PROVIDER")
    monkeypatch.delenv("TV_AI_MAPPING_ENABLED")
    monkeypatch.delenv("TV_AI_CLAIMS_ENABLED")
    monkeypatch.delenv("TV_OPENAI_API_KEY")
    settings.cache_clear()
    assert definition["id"]
    # No model output ever changed a conclusion: the declared claim is still not verified.
    ladder = customer.get(f"/v1/systems/{system['id']}/claims").json()
    assert ladder["counts"]["CURRENT"] == 0 and ladder["counts"]["NOT_YET_VERIFIED"] == 1
    assert customer.get(f"/v1/systems/{system['id']}/consequence-feedback").status_code == 200
