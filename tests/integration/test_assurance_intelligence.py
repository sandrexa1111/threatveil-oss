"""Category-complete assurance intelligence over the real API and PostgreSQL RLS.

The Finance Agent sandbox is the canonical demonstration: a clearance, a change to
the synthetic tool gateway outside any repository, the exact claim that stopped
holding, re-proof, and restoration. Every assertion reads a deterministic
projection of immutable records.
"""

import json
from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from threatveil.api import app
from threatveil.db import get_record, transaction
from threatveil.release_signing import signing_key
from threatveil.sdk.change_records import verify_change_record
from test_product import ORIGIN, customer as customer  # noqa: F401


def finance(client):
    response = client.post("/v1/change-assurance/finance/setup", json={
        "owner": "Finance security owner", "confirm_synthetic_scope": True})
    assert response.status_code == 201, response.text
    return response.json()


def assess(client, setup, version="fixed"):
    response = client.post("/v1/change-assurance/finance/assess", json={
        "system_id": setup["system_id"], "version": version, "idempotency_key": str(uuid4())})
    assert response.status_code == 201, response.text
    return response.json()


def change(client, setup, name, key=None):
    response = client.post("/v1/change-assurance/finance/simulate-change", json={
        "system_id": setup["system_id"], "change": name, "idempotency_key": key or str(uuid4())})
    assert response.status_code == 201, response.text
    return response.json()


def intel(client, setup):
    response = client.get(f"/v1/systems/{setup['system_id']}/intelligence")
    assert response.status_code == 200, response.text
    return response.json()


def cleared(client):
    setup = finance(client)
    baseline = assess(client, setup)
    assert baseline["action"] == "ALLOW"
    return setup, baseline


def other_tenant():
    client = TestClient(app, client=("127.201.1.1", 50000))
    login = client.post("/v1/auth/local", json={"email": f"{uuid4()}@local.invalid"}, headers={"origin": ORIGIN})
    assert login.status_code == 200, login.text
    client.headers.update({"origin": ORIGIN, "x-csrf-token": login.json()["csrf_token"]})
    return client


def test_system_map_cites_records_and_never_grants_authority(customer):
    setup, _ = cleared(customer)
    graph = customer.get(f"/v1/systems/{setup['system_id']}/system-map").json()
    kinds = {node["kind"] for node in graph["nodes"]}
    assert {"AGENT", "TOOL", "PERMISSION", "MCP_SERVER", "SOURCE", "AUTHORITY_BOUNDARY", "AUTHORITY",
            "BUSINESS_RESOURCE", "IDENTITY", "CLAIM", "BUSINESS_EFFECT", "EVIDENCE", "DECISION",
            "AUTHORITY_FACT"} <= kinds
    nodes = {node["id"]: node for node in graph["nodes"]}
    assert all(edge["basis"]["record"] and edge["basis"]["id"] for edge in graph["edges"])
    # Authority is only ever permitted by the reviewed boundary, never by a tool or a source.
    for edge in graph["edges"]:
        if edge["relation"] == "PERMITS":
            assert nodes[edge["source"]]["kind"] == "AUTHORITY_BOUNDARY"
        if nodes[edge["target"]]["kind"] == "AUTHORITY":
            assert nodes[edge["source"]]["kind"] in {"AUTHORITY_BOUNDARY", "CLAIM"}
    # The component -> authority -> claim -> evidence -> decision chain is navigable.
    claim = next(n for n in graph["nodes"] if n["kind"] == "CLAIM" and "approval" in n["label"])
    relations = {(e["relation"], nodes[e["target"]]["kind"]) for e in graph["edges"] if e["source"] == claim["id"]}
    assert ("DEPENDS_ON", "PERMISSION") in relations and ("GOVERNS", "AUTHORITY") in relations
    assert any(e["target"] == claim["id"] and e["relation"] == "SUPPORTS" for e in graph["edges"])
    assert any(e["target"] == claim["id"] and e["relation"] == "COVERS" for e in graph["edges"])
    assert any(e["relation"] == "MAPPED_TO" and e["authority_basis"] == "SYNTHETIC_PACKAGE" for e in graph["edges"])


def test_delegation_is_recorded_as_inert_traceability(customer):
    setup, _ = cleared(customer)
    delegated = customer.post("/v1/change-assurance/relationships", json={
        "system_id": setup["system_id"], "environment_id": setup["environment_id"],
        "source_id": setup["system_id"], "target_id": setup["target_id"], "relationship": "delegates_to",
        "review_note": "Finance agent delegates bounded invoice work to a helper"})
    assert delegated.status_code == 201, delegated.text
    graph = customer.get(f"/v1/systems/{setup['system_id']}/system-map").json()
    edge = next(e for e in graph["edges"] if e["relation"] == "DELEGATES_TO")
    assert edge["inert"] is True and edge["grants_permissions"] is False
    assert next(n for n in graph["nodes"] if n["id"] == edge["target"])["kind"] == "SUBAGENT"
    authority = customer.get(f"/v1/systems/{setup['system_id']}/authority").json()
    assert [a["action"] for a in authority["authorities"]] == ["beneficiary.update", "invoice.update"]


def test_intelligence_is_tenant_isolated(customer):
    setup, baseline = cleared(customer)
    other = other_tenant()
    base = f"/v1/systems/{setup['system_id']}"
    for path in ("/intelligence", "/system-map", "/authority", "/authority/changes", "/changes",
                 "/evidence-currency", "/lifecycle", "/reestablishment", "/history", "/summary",
                 "/assurance/current", "/passports"):
        assert other.get(base + path).status_code == 404, path
    assert other.post("/v1/change-assurance/finance/simulate-change", json={
        "system_id": setup["system_id"], "change": "gateway_restored", "idempotency_key": str(uuid4())}).status_code == 404
    assert other.post(base + "/passports", json={}).status_code == 404


def test_authority_basis_moves_from_declared_to_verified_and_unknown_stays_unknown(customer):
    setup = finance(customer)
    before = {a["action"]: a for a in customer.get(f"/v1/systems/{setup['system_id']}/authority").json()["authorities"]}
    assert before["beneficiary.update"]["basis"] == "DECLARED"
    assert before["beneficiary.update"]["assurance"] == "UNKNOWN"
    source = before["beneficiary.update"]["conditions"]["source_declared"][0]
    assert source["conditions"] == {"approval_required": True, "tenant_bound": True}
    assert source["qualification"] == "UNREVIEWED"
    assess(customer, setup)
    after = {a["action"]: a for a in customer.get(f"/v1/systems/{setup['system_id']}/authority").json()["authorities"]}
    assert after["beneficiary.update"]["basis"] == "VERIFIED" and after["beneficiary.update"]["assurance"] == "SUPPORTED"
    change(customer, setup, "beneficiary_approval_relaxed")
    moved = {a["action"]: a for a in customer.get(f"/v1/systems/{setup['system_id']}/authority").json()["authorities"]}
    assert moved["beneficiary.update"]["basis"] == "OBSERVED"
    assert moved["beneficiary.update"]["assurance"] == "NEEDS_FRESH_EVIDENCE"
    assert moved["invoice.update"]["basis"] == "VERIFIED"
    change(customer, setup, "payment_tool_added")
    authority = customer.get(f"/v1/systems/{setup['system_id']}/authority").json()
    undeclared = authority["undeclared_interfaces"]
    assert [u["label"] for u in undeclared] == ["payment.execute"] and undeclared[0]["basis"] == "UNKNOWN"
    assert "payment.execute" not in [a["action"] for a in authority["authorities"]]
    assert all(i["basis"] != "SOURCE_NAME_MATCH" or "not reviewed" in i["note"]
               for a in authority["authorities"] for i in a["interfaces"])


def test_a_mapped_authority_expansion_reaches_exactly_the_dependent_claim(customer):
    setup, baseline = cleared(customer)
    change(customer, setup, "beneficiary_approval_relaxed")
    view = intel(customer, setup)
    diff = view["authority_changes"][0]
    assert diff["classification"] == "AUTHORITY_EXPANDED"
    assert diff["headline"] == "Beneficiary update authority expanded"
    assert diff["subjects"][0]["before"] == {"approval_required": True, "tenant_bound": True}
    assert diff["subjects"][0]["after"] == {"approval_required": False, "tenant_bound": True}
    consequence = diff["consequence"]
    assert consequence["claims_affected"] == 1 and consequence["evidence_stale"] == 1
    assert consequence["still_holds"] == 2 and consequence["effect"] == "OPEN"
    assert consequence["claims"][0]["title"] == "Beneficiary changes require finance approval"
    assert consequence["claims"][0]["via"] == ["permissions:finance-approval"]
    assert consequence["previous_clearance"]["id"] == baseline["authorization_id"]
    assert consequence["previous_clearance"]["status"] == "SUPERSEDED"
    assert consequence["required"] == ["Re-establish “Beneficiary changes require finance approval”"]
    # Unaffected claims keep current, applicable evidence.
    claims = {c["title"]: c for c in view["evidence"]["claims"]}
    assert claims["Business writes stay within the tenant"]["applicability"] == "CURRENT"
    assert claims["Invoice updates require authorized actions"]["status"] == "SUPPORTED"
    stale = claims["Beneficiary changes require finance approval"]
    assert stale["status"] == "NEEDS_FRESH_EVIDENCE" and stale["applicability"] == "INVALID"
    assert stale["affected_by"][0]["headline"] == "Beneficiary update authority expanded"
    assert view["summary"]["clearance"]["state"] == "NEEDS_REASSESSMENT"
    assert view["summary"]["why"] == "Beneficiary update authority expanded"
    assert view["summary"]["claims"]["supported"] == 2


def test_the_explanation_is_deterministic_and_says_no_more_than_the_records(customer):
    setup, _ = cleared(customer)
    change(customer, setup, "beneficiary_approval_relaxed")
    first = customer.get(f"/v1/systems/{setup['system_id']}/authority/changes").json()["items"][0]["explanation"]
    second = customer.get(f"/v1/systems/{setup['system_id']}/authority/changes").json()["items"][0]["explanation"]
    assert first == second
    text = " ".join(first)
    assert "beneficiary.update approval_required changed from true to false" in text
    assert "authority expansion" in text and "2 other claims remain supported." in text
    assert "depends on permissions:finance-approval, which a reviewed mapping links to what changed" in text


def test_an_unmapped_new_interface_keeps_every_claim_conservative(customer):
    setup, _ = cleared(customer)
    change(customer, setup, "payment_tool_added")
    view = intel(customer, setup)
    diff = view["authority_changes"][0]
    assert diff["classification"] == "AUTHORITY_EXPANDED"
    assert diff["consequence"]["claims_affected"] == 3 and diff["consequence"]["still_holds"] == 0
    assert all(not c["via"] for c in diff["consequence"]["claims"])
    assert any("not fully mapped" in line for line in diff["explanation"])
    assert {c["applicability"] for c in view["evidence"]["claims"]} == {"UNKNOWN"}


def test_restoring_the_gateway_is_a_contraction_and_is_covered_by_fresh_proof(customer):
    setup, _ = cleared(customer)
    change(customer, setup, "beneficiary_approval_relaxed")
    change(customer, setup, "gateway_restored")
    items = customer.get(f"/v1/systems/{setup['system_id']}/authority/changes").json()["items"]
    assert [i["classification"] for i in items[:2]] == ["AUTHORITY_CONTRACTED", "AUTHORITY_EXPANDED"]
    assess(customer, setup)
    changes = customer.get(f"/v1/systems/{setup['system_id']}/changes").json()["items"]
    sources = [c for c in changes if c["kind"] == "SOURCE_CHANGE" and not c["initial"]]
    assert {c["consequence"]["effect"] for c in sources} == {"COVERED_BY_LATER_VERIFICATION"}
    assert intel(customer, setup)["summary"]["clearance"]["state"] == "CLEARED"


def test_a_prior_allow_becomes_superseded_while_its_signed_record_stays_authentic(customer):
    setup, baseline = cleared(customer)
    url = f"/v1/change-assurance/decisions/{baseline['authorization_id']}"
    before = customer.get(url).json()
    assert before["current_status"] == "CURRENT"
    change(customer, setup, "beneficiary_approval_relaxed")
    after = customer.get(url).json()
    assert after["current_status"] == "SUPERSEDED"
    assert after["envelope"] == before["envelope"] and after["action"] == "ALLOW"
    verified = verify_change_record(after["envelope"], signing_key().public_key(),
        organization_id=after["organization_id"], system_id=setup["system_id"],
        environment_id=setup["environment_id"], state_digest=after["state_digest"], audience=after["audience"])
    assert verified["predicate"]["action"] == "ALLOW"


def test_reestablishment_names_checks_tasks_and_every_outcome(customer):
    setup, _ = cleared(customer)
    change(customer, setup, "beneficiary_approval_relaxed")
    plan = customer.get(f"/v1/systems/{setup['system_id']}/reestablishment").json()
    steps = {s["step"]: s["items"] for s in plan["steps"]}
    assert plan["required"] is True
    assert [i["title"] for i in steps["AFFECTED_CLAIMS"]] == ["Beneficiary changes require finance approval"]
    assert len(steps["STILL_HOLDS"]) == 2 and steps["WHAT_CHANGED"][0]["headline"].endswith("authority expanded")
    assert "without the required approval" in steps["SECURITY_CHECKS"][0]["check"]
    assert steps["LEGITIMATE_TASKS"][0]["task"]
    assert plan["execution"]["mode"] == "SYNTHETIC_SANDBOX"
    assess(customer, setup, "regressed")
    outcome = customer.get(f"/v1/systems/{setup['system_id']}/reestablishment").json()["latest_outcome"]
    assert outcome["case"] == "SECURITY_FAILED" and not outcome["cleared"]
    assess(customer, setup, "bad_fix")
    outcome = customer.get(f"/v1/systems/{setup['system_id']}/reestablishment").json()["latest_outcome"]
    assert outcome["case"] == "USEFUL_TASK_FAILED" and not outcome["cleared"]
    change(customer, setup, "gateway_restored")
    assess(customer, setup)
    restored = customer.get(f"/v1/systems/{setup['system_id']}/reestablishment").json()
    assert restored["latest_outcome"]["case"] == "RESTORED" and restored["latest_outcome"]["cleared"]
    lifecycle = customer.get(f"/v1/systems/{setup['system_id']}/lifecycle").json()
    cycle = lifecycle["completed_cycles"][-1]
    assert cycle["cause"] == "SOURCE_CHANGE" and cycle["attempts"] == 2 and cycle["restore_seconds"] >= 0
    stages = {s["stage"]: s for s in lifecycle["stages"]}
    assert stages["CLEARANCE_RESTORED"]["reached"] and stages["CURRENT"]["current"]


def test_lifecycle_shows_each_stage_while_reassessment_is_pending(customer):
    setup, _ = cleared(customer)
    change(customer, setup, "beneficiary_approval_relaxed")
    stages = {s["stage"]: s for s in customer.get(f"/v1/systems/{setup['system_id']}/lifecycle").json()["stages"]}
    assert all(stages[k]["reached"] for k in ("BASELINE_ESTABLISHED", "CURRENT", "RELEVANT_CHANGE",
                                              "CLEARANCE_SUPERSEDED", "REASSESSMENT_REQUIRED"))
    assert stages["REASSESSMENT_REQUIRED"]["current"] and stages["CLEARANCE_SUPERSEDED"]["detail"] == "SUPERSEDED"
    assert not stages["CLEARANCE_RESTORED"]["reached"]


def test_history_reports_counts_but_withholds_patterns_until_enough_observations(customer):
    setup, _ = cleared(customer)
    change(customer, setup, "beneficiary_approval_relaxed")
    change(customer, setup, "gateway_restored")
    memory = customer.get(f"/v1/systems/{setup['system_id']}/history").json()
    assert memory["counts"]["authority_changes"]["AUTHORITY_EXPANDED"] == 1
    assert memory["counts"]["authority_changes"]["AUTHORITY_CONTRACTED"] == 1
    assert memory["insufficient_history"] and memory["patterns"] == []
    assert memory["restoration"]["median_seconds"] is None
    claims = {c["title"]: c for c in memory["claims"]}
    assert claims["Beneficiary changes require finance approval"]["reached"] == 2
    assert claims["Business writes stay within the tenant"]["survived"] == 2
    for _ in range(2):
        change(customer, setup, "beneficiary_approval_relaxed")
        change(customer, setup, "gateway_restored")
    patterns = customer.get(f"/v1/systems/{setup['system_id']}/history").json()["patterns"]
    assert any(p["claim"] == "Beneficiary changes require finance approval" and p["observations"] >= 3 for p in patterns)


def test_dependency_mappings_only_name_reported_facts_and_reviewed_dependencies(customer):
    setup, _ = cleared(customer)
    base = {"environment_id": setup["environment_id"], "installation_id": setup["gateway_installation_id"],
            "review_note": "Security reviewed which claim this gateway setting controls"}
    path = "/v1/systems/%s/dependency-mappings" % setup["system_id"]
    unreviewed = customer.post(path, json={**base, "subject": "authorization/tools/invoice.update/tenant_bound",
                                           "maps_to": ["permissions:not-a-claim-dependency"]})
    assert unreviewed.status_code == 422
    invented = customer.post(path, json={**base, "subject": "authorization/tools/refund.issue/approval_required",
                                         "maps_to": ["permissions:tenant-boundary"]})
    assert invented.status_code == 422
    reviewed = customer.post(path, json={**base, "subject": "authorization/tools/invoice.update/tenant_bound",
                                         "maps_to": ["permissions:tenant-boundary", "tool:erp.invoice"]})
    assert reviewed.status_code == 201, reviewed.text
    assert reviewed.json()["authority_basis"] == "CUSTOMER_REVIEWED" and reviewed.json()["grants_permissions"] is False
    change(customer, setup, "invoice_tenant_binding_removed")
    diff = customer.get(f"/v1/systems/{setup['system_id']}/authority/changes").json()["items"][0]
    titles = {c["title"] for c in diff["consequence"]["claims"]}
    # The latest reviewed mapping now reaches both claims that depend on the invoice tool.
    assert titles == {"Business writes stay within the tenant", "Invoice updates require authorized actions"}
    assert diff["classification"] == "AUTHORITY_EXPANDED"


def test_claim_definitions_are_visible_but_never_supported(customer):
    setup, _ = cleared(customer)
    defined = customer.post(f"/v1/systems/{setup['system_id']}/claim-definitions", json={
        "action": "refund.issue", "claim": "Refunds above the limit require a second approver",
        "permitted_outcome": "Refund under the limit is issued", "forbidden_outcome": "Large refund without approval",
        "legitimate_task": "Issue a small refund for a verified return", "ground_truth_source": "Payments ledger"})
    assert defined.status_code == 201, defined.text
    view = intel(customer, setup)
    entry = next(c for c in view["evidence"]["claims"] if c.get("claim_definition_id"))
    assert entry["status"] == "DEFINED" and entry["evidence"] is None
    assert view["summary"]["claims"]["defined_not_executable"] == 1
    assert view["summary"]["clearance"]["state"] == "CLEARED"
    assert any(n["kind"] == "CLAIM" and n.get("verifiable") is False for n in view["system_map"]["nodes"])
    draft = customer.post("/v1/properties", json={"system_id": setup["system_id"], "title": "Draft",
                                                  "description": "Draft only", "definition": {}})
    if draft.status_code == 201:
        bound = customer.post(f"/v1/systems/{setup['system_id']}/claim-definitions", json={
            "action": "refund.issue", "claim": "Bound to an unapproved draft claim",
            "permitted_outcome": "x" * 6, "forbidden_outcome": "y" * 6, "legitimate_task": "z" * 6,
            "ground_truth_source": "ledger", "property_id": draft.json()["id"]})
        assert bound.status_code == 422


def test_synthetic_changes_are_enumerated_idempotent_and_sandbox_only(customer):
    setup, _ = cleared(customer)
    key = str(uuid4())
    first = change(customer, setup, "beneficiary_approval_relaxed", key)
    again = change(customer, setup, "beneficiary_approval_relaxed", key)
    assert first["id"] == again["id"]
    conflict = customer.post("/v1/change-assurance/finance/simulate-change", json={
        "system_id": setup["system_id"], "change": "gateway_restored", "idempotency_key": key})
    assert conflict.status_code == 409
    free_form = customer.post("/v1/change-assurance/finance/simulate-change", json={
        "system_id": setup["system_id"], "change": "arbitrary", "idempotency_key": str(uuid4()),
        "payload": {"tools": []}})
    assert free_form.status_code == 422
    org = UUID(customer.get("/v1/auth/me").json()["organization"]["id"])
    with transaction(org_id=org) as session:
        batch = get_record(session, org, first["batch_id"], "source_batch")
        assert batch.payload["acquisition"] == "IMPORTED" and batch.payload["qualification"] == "UNREVIEWED"


def test_intelligence_does_not_scale_projections_with_history(customer, monkeypatch):
    import threatveil.assurance_intelligence as intelligence_module
    import threatveil.change_assurance_api as api_module

    setup, _ = cleared(customer)
    counts = {"n": 0}
    real = intelligence_module.projection

    def counted(*args, **kwargs):
        counts["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(intelligence_module, "projection", counted)
    monkeypatch.setattr(api_module, "projection", counted)
    change(customer, setup, "beneficiary_approval_relaxed")
    intel(customer, setup)
    few = counts["n"]
    for _ in range(3):
        change(customer, setup, "gateway_restored")
        change(customer, setup, "beneficiary_approval_relaxed")
    counts["n"] = 0
    body = intel(customer, setup)
    assert counts["n"] <= few
    assert len(json.dumps(body)) < 2_000_000


def test_home_answers_what_needs_attention_before_opening_any_system(customer):
    empty = customer.get("/v1/home")
    assert empty.status_code == 200, empty.text
    assert empty.json()["counts"] == {"systems": 0, "shown": 0, "needs_attention": 0,
                                      "claims_needing_evidence": 0, "open_changes": 0,
                                      "sources_needing_attention": 0, "awaiting_review": 0}
    assert empty.json()["attention"] == [] and empty.json()["current"] == []

    setup, _ = cleared(customer)
    body = customer.get("/v1/home").json()
    assert body["schema_version"] == "assurance-home/v1"
    assert body["counts"]["systems"] == 1 and body["counts"]["needs_attention"] == 0
    row = body["current"][0]
    assert row["id"] == setup["system_id"]
    assert row["clearance"]["state"] == "CLEARED" and row["clearance"]["label"] == "Cleared"
    assert row["claims"]["total"] == 3 and row["claims"]["supported"] == 3
    assert row["needs_attention"] is False and row["next_action"] == "SHARE"
    assert row["baseline"] is True

    change(customer, setup, "beneficiary_approval_relaxed")
    moved = customer.get("/v1/home").json()
    assert moved["counts"]["needs_attention"] == 1 and moved["current"] == []
    attention = moved["attention"][0]
    assert attention["clearance"]["state"] == "NEEDS_REASSESSMENT"
    assert attention["next_action"] == "REVIEW_CHANGE"
    assert attention["open_changes"] and "authority expanded" in attention["open_changes"][0]["headline"].lower()
    assert attention["why"] == attention["open_changes"][0]["headline"]
    assert any(item["kind"] == "CHANGE" for item in moved["activity"])
    # Home never concludes anything the system projection does not already hold.
    summary = customer.get(f"/v1/systems/{setup['system_id']}/summary").json()
    assert attention["clearance"]["state"] == summary["clearance"]["state"]


def test_home_never_files_a_system_without_a_baseline_as_current(customer):
    declared = customer.post("/v1/systems", json={
        "name": "Declared only", "description": "No baseline has been established for it.",
        "access": [], "actions": []})
    assert declared.status_code == 201, declared.text
    body = customer.get("/v1/home").json()
    assert body["counts"]["needs_attention"] == 1 and body["current"] == []
    row = body["attention"][0]
    assert row["baseline"] is False
    assert row["next_action"] == "SET_UP"
    assert row["clearance"]["state"] == "NOT_ESTABLISHED"
    # Nothing is claimed about a system nobody has established anything for.
    assert row["claims"] == {"total": 0, "supported": 0, "needs_fresh_evidence": 0, "failed": 0,
                             "unknown": 0, "declared_not_executable": 0}


def test_home_is_tenant_scoped_and_never_leaks_another_organization(customer):
    setup, _ = cleared(customer)
    outsider = other_tenant()
    body = outsider.get("/v1/home")
    assert body.status_code == 200
    assert body.json()["counts"]["systems"] == 0
    assert all(row["id"] != setup["system_id"] for row in body.json()["systems"])
