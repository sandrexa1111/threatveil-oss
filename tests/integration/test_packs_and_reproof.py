"""Assurance packs, the example gallery, and bounded automatic re-proof.

Applying a pack declares claims and queues proposals; it approves nothing. Automatic
re-proof repeats one already-approved verification and refuses the moment any approved
precondition moves. There is no remediation path at all.
"""

from datetime import timedelta
from uuid import uuid4

from threatveil.auto_reproof import plan as plan_policy
from threatveil.change_assurance_api import gateway_payload
from threatveil.db import now, transaction
from threatveil.observer_platform import REQUIRED_ANSWER
from test_assurance_intelligence import change, cleared, other_tenant
from test_business_measurement import identity, real_source
from test_observer_platform import CONTRACT, qualify
from test_product import customer as customer  # noqa: F401


class StubPolicy:
    """A policy shape the planner must refuse, without recording it."""

    def __init__(self, payload):
        self.payload, self.id = payload, uuid4()


def define_observer(client, system_id, environment_id, **overrides):
    response = client.post(f"/v1/systems/{system_id}/observer-definitions",
                           json={**CONTRACT, "environment_id": environment_id, **overrides})
    assert response.status_code == 201, response.text
    return response.json()


def qualified_observer(client, system_id, environment_id, **overrides):
    definition = define_observer(client, system_id, environment_id, **overrides)
    result = qualify(client, definition, {"harness_version": "manual-review/v1", "results": dict(REQUIRED_ANSWER)})
    assert result.status_code == 201, result.text
    assert result.json()["qualification"]["state"] == "QUALIFIED"
    return definition


def tool_catalog(tools):
    """An MCP catalogue with tool-level declared authorization, in the shape sources report."""
    return gateway_payload({name: {"approval_required": True, "tenant_bound": True} for name in tools})


def import_catalog(client, installation, tools, sequence):
    response = client.post(f"/v1/connectors/{installation['id']}/import", json={
        "event_id": str(uuid4()), "payload": tool_catalog(tools), "valid_at": now().isoformat(),
        "sequence": sequence})
    assert response.status_code in {200, 201}, response.text


def test_applying_a_pack_declares_claims_and_queues_proposals_only(customer, monkeypatch):
    catalog = customer.get("/v1/assurance-packs").json()
    assert {pack["id"] for pack in catalog["items"]} == {
        "generic_write_agent", "support_refund", "infrastructure", "revenue_crm"}
    assert all(pack["status"] == "DRAFT" for pack in catalog["items"])
    assert all(pack["label"] == "TEMPLATE · NOT RUNNABLE · NOT VERIFIED FOR YOUR SYSTEM"
               for pack in catalog["items"])
    assert all(pack["observer_requirements"] and pack["limitations"] for pack in catalog["items"])
    gallery = customer.get("/v1/example-gallery").json()
    runnable = [card for card in gallery["cards"] if card["runnable"]]
    assert len(runnable) == 1 and runnable[0]["synthetic"] is True
    assert runnable[0]["counts_as_customer_activity"] is False
    assert gallery["primary_action"]["id"] == "connect_my_own_agent"
    assert gallery["secondary_action"]["id"] == "explore_an_example"
    assert len(gallery["cards"]) == 5
    # Applying a pack to a real system with a real source.
    system, environment, installation = real_source(customer, monkeypatch, "Pack agent")
    import_catalog(customer, installation, ("refund.issue", "ticket.update"), 1)
    applied = customer.post(f"/v1/systems/{system['id']}/assurance-packs/support_refund/apply",
                            json={"environment_id": environment["id"], "installation_id": installation["id"]})
    assert applied.status_code == 201, applied.text
    result = applied.json()
    assert result["pack"]["status"] == "DRAFT" and result["approved_anything"] is False
    assert result["created_observers"] == [] and result["observer_requirements"]
    assert len(result["declared_claims"]) == 3
    assert all(claim["verification"] == "NOT_YET_VERIFIED" for claim in result["declared_claims"])
    proposal = next(p for p in result["mapping_proposals"] if "refund.issue" in p["subject"])
    assert proposal["status"] == "PROPOSED" and proposal["affects_scoping"] is False
    assert any("max_amount" in item["subject_pattern"] for item in result["unmatched_proposals"])
    # Nothing is supported, and nothing is mapped, until people act.
    ladder = customer.get(f"/v1/systems/{system['id']}/claims").json()
    assert ladder["counts"]["NOT_YET_VERIFIED"] == 3 and ladder["counts"]["CURRENT"] == 0
    overview = customer.get(f"/v1/systems/{system['id']}/mappings-overview").json()
    assert all(not source["mapped"] for source in overview["sources"])
    listed = customer.get(f"/v1/systems/{system['id']}/mapping-proposals").json()
    assert listed["open"] == len(result["mapping_proposals"])
    # Unknown packs and other tenants get nothing.
    assert customer.post(f"/v1/systems/{system['id']}/assurance-packs/not_a_pack/apply",
                         json={"environment_id": environment["id"]}).status_code == 404
    other = other_tenant()
    assert other.post(f"/v1/systems/{system['id']}/assurance-packs/support_refund/apply",
                      json={"environment_id": environment["id"]}).status_code == 404


def test_auto_reproof_repeats_one_verification_and_can_never_widen_scope(customer):
    setup, _ = cleared(customer)
    system_id, environment_id = setup["system_id"], setup["environment_id"]
    ladder = customer.get(f"/v1/systems/{system_id}/claims").json()
    claim = next(c for c in ladder["claims"] if c["kind"] == "EXECUTABLE_CLAIM" and c["approved"])
    observer = qualified_observer(customer, system_id, environment_id, name="Synthetic ledger observer")
    body = {"environment_id": environment_id, "property_id": claim["id"], "target_id": setup["target_id"],
            "observer_definition_id": observer["id"], "trial_count": 1, "max_runs_per_window": 1,
            "window_hours": 24, "confirm_no_remediation": True,
            "justification": "Repeat the approved beneficiary approval check after an observed change, in the "
                             "labelled synthetic sandbox only."}
    created = customer.post(f"/v1/systems/{system_id}/auto-reproof-policies", json=body)
    assert created.status_code == 201, created.text
    policy = created.json()
    assert (policy["level"], policy["remediation"], policy["auto_reproof"]) == ("LEVEL_2_3_ONLY", "NONE", True)
    assert policy["plan"]["decision"] == "SKIPPED" and policy["plan"]["reason"] == "NOTHING_TO_REPROVE"
    assert any("never widen scope" in item for item in policy["limitations"])
    # The approver must confirm that re-proof never remediates.
    assert customer.post(f"/v1/systems/{system_id}/auto-reproof-policies",
                         json={**body, "confirm_no_remediation": False}).status_code == 422
    # Eligible only once assurance is actually lost.
    change(customer, setup, "beneficiary_approval_relaxed")
    plan = customer.get(f"/v1/auto-reproof-policies/{policy['id']}/plan").json()
    assert plan["decision"] == "ELIGIBLE" and plan["scope"]["widened"] is False
    assert plan["scope"]["property_id"] == claim["id"] and plan["budget"] == 1
    run = customer.post(f"/v1/auto-reproof-policies/{policy['id']}/run")
    assert run.status_code == 201, run.text
    outcome = run.json()
    assert outcome["decision"] == "COMPLETED" and outcome["remediation"] == "NONE"
    assert outcome["scope"] == {"property_id": claim["id"], "target_id": setup["target_id"],
                                "environment_id": environment_id,
                                "envelope_digest": policy["authority_scope"]["envelope_digest"], "widened": False}
    assert outcome["assessment"]["action"] == "ALLOW"
    # The bounded budget stops the next run in this window.
    change(customer, setup, "invoice_tenant_binding_removed")
    assert customer.get(f"/v1/auto-reproof-policies/{policy['id']}/plan").json()["reason"] == "BUDGET_EXHAUSTED"
    # A changed authority boundary ends the standing permission.
    with transaction(org_id=identity(customer)[1]) as session:
        from sqlalchemy import select

        from threatveil.db import Record
        envelope_id = str(session.scalars(select(Record.id).where(
            Record.organization_id == identity(customer)[1], Record.kind == "permission_envelope",
            Record.payload["system_id"].astext == system_id).order_by(Record.created_at.desc()).limit(1)).first())
    superseded = customer.post("/v1/change-assurance/envelopes", json={
        "system_id": system_id, "environment_id": environment_id,
        "principals": ["synthetic-tenant-a/finance-agent"], "actions": ["beneficiary.update", "invoice.update"],
        "resources": ["synthetic-tenant-a/vendor-1", "synthetic-tenant-a/invoice-1"],
        "constraints": ["Finance approval required for beneficiary changes", "Tenant A resources only",
                        "Authorized invoice updates must remain useful", "Reviewed again after the change"],
        "expires_at": (now() + timedelta(days=30)).isoformat(), "supersedes_id": envelope_id})
    assert superseded.status_code == 201, superseded.text
    assert customer.get(f"/v1/auto-reproof-policies/{policy['id']}/plan").json()["reason"] == "AUTHORITY_SCOPE_CHANGED"
    # Losing the observer ends it too.
    assert customer.post(f"/v1/observer-definitions/{observer['id']}/revoke",
                         json={"reason": "Observer replaced during the sandbox exercise"}).status_code == 201
    assert customer.get(f"/v1/auto-reproof-policies/{policy['id']}/plan").json()["reason"] == "OBSERVER_NOT_QUALIFIED"
    # Outside a labelled sandbox the planner refuses unless the deployment enables it.
    user, org = identity(customer)
    with transaction(user, org) as session:
        stub = StubPolicy({"system_id": system_id, "environment_id": environment_id, "enabled": True,
                           "environment_purpose": "PRODUCTION", "authority_scope": policy["authority_scope"],
                           "property_id": claim["id"], "target_id": setup["target_id"],
                           "observer_definition_id": observer["id"], "max_runs_per_window": 1, "window_hours": 24})
        refused = plan_policy(session, org, stub)
    assert refused["decision"] == "SKIPPED" and refused["reason"] == "FLAG_DISABLED_OUTSIDE_SANDBOX"
    assert customer.get(f"/v1/systems/{system_id}/auto-reproof-policies").json()["enabled_outside_sandbox"] is False
    # Tenant isolation for the whole path.
    other = other_tenant()
    assert other.get(f"/v1/auto-reproof-policies/{policy['id']}/plan").status_code == 404
    assert other.post(f"/v1/auto-reproof-policies/{policy['id']}/run").status_code == 404
