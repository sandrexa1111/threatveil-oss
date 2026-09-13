"""Adversarial review of every surface this wave added.

Each new endpoint is probed from another tenant, with hostile and malformed input, and
for the invariant that must hold even when someone is trying to break it: no cross-tenant
read, no unbounded document, no control character reaching storage, no internal identifier
leaving in a shared passport, and no operator data reachable through the product API.
"""

import json
from uuid import uuid4

from fastapi.testclient import TestClient

from threatveil.api import app
from threatveil.change_assurance_api import GATEWAY_BASELINE, gateway_payload
from test_assurance_intelligence import change, cleared, other_tenant
from test_business_measurement import identity, imported, observed, real_source
from test_observer_platform import CONTRACT
from test_product import customer as customer  # noqa: F401


def test_no_new_surface_answers_another_tenant(customer, monkeypatch):
    setup, _ = cleared(customer)
    system = setup["system_id"]
    change(customer, setup, "beneficiary_approval_relaxed")
    consequence = observed(customer, system)["id"]
    proposed = customer.post(f"/v1/systems/{system}/proposed-changes", json={
        "installation_id": setup["gateway_installation_id"], "payload": gateway_payload(GATEWAY_BASELINE),
        "idempotency_key": str(uuid4())})
    assert proposed.status_code == 201, proposed.text
    observer = customer.post(f"/v1/systems/{system}/observer-definitions",
                             json={**CONTRACT, "environment_id": setup["environment_id"]})
    assert observer.status_code == 201, observer.text
    definition = observer.json()["id"]
    other = other_tenant()
    reads = [f"/v1/systems/{system}/claims", f"/v1/systems/{system}/guidance",
             f"/v1/systems/{system}/consequence-feedback", f"/v1/systems/{system}/proposed-changes",
             f"/v1/systems/{system}/mappings-overview", f"/v1/systems/{system}/mapping-proposals",
             f"/v1/systems/{system}/observer-definitions", f"/v1/systems/{system}/auto-reproof-policies",
             f"/v1/systems/{system}/consequences/{consequence}/feedback",
             f"/v1/proposed-changes/{proposed.json()['id']}", f"/v1/observer-definitions/{definition}",
             f"/v1/observer-definitions/{definition}/effects?correlation_value=anything",
             f"/v1/systems/{system}/mapping-suggestions?installation_id={setup['gateway_installation_id']}"]
    for path in reads:
        assert other.get(path).status_code == 404, path
    writes = [
        (f"/v1/systems/{system}/consequences/{consequence}/feedback",
         {"verdict": "CORRECT", "idempotency_key": str(uuid4())}),
        (f"/v1/systems/{system}/proposed-changes", {"installation_id": setup["gateway_installation_id"],
                                                    "payload": {}, "idempotency_key": str(uuid4())}),
        (f"/v1/systems/{system}/history-replay", {"installation_id": setup["gateway_installation_id"],
                                                  "revisions": [], "idempotency_key": str(uuid4())}),
        (f"/v1/systems/{system}/observer-definitions", {**CONTRACT, "environment_id": setup["environment_id"]}),
        (f"/v1/observer-definitions/{definition}/revoke", {"reason": "Not my observer to revoke"}),
        (f"/v1/systems/{system}/claim-definitions", {"action": "x", "claim": "x" * 12,
                                                     "permitted_outcome": "xxxxx", "forbidden_outcome": "xxxxx",
                                                     "legitimate_task": "xxxxx", "ground_truth_source": "xxx"}),
        (f"/v1/systems/{system}/assurance-packs/support_refund/apply",
         {"environment_id": setup["environment_id"]}),
        (f"/v1/systems/{system}/ai/mapping-proposals", {"installation_id": setup["gateway_installation_id"]}),
    ]
    for path, body in writes:
        assert other.post(path, json=body).status_code in {404, 422}, path
    # The other tenant's own measurement sees nothing of this organization.
    summary = other.get("/v1/measurements/business").json()
    assert summary["systems"] == {"customer": 0, "synthetic": 0}
    assert summary["consequences"]["counted"] == 0 and summary["north_star"]["current"] == 0
    # An identical idempotency key in another tenant can never collide with this one.
    shared_key = "shared-idempotency-key-0001"
    mine = customer.post(f"/v1/systems/{system}/consequences/{consequence}/feedback",
                         json={"verdict": "CORRECT", "idempotency_key": shared_key})
    assert mine.status_code == 201, mine.text
    their_system, _, their_installation = real_source(other, monkeypatch, "Their own agent")
    imported(other, their_installation, ("ticket.update",), 1)
    imported(other, their_installation, ("ticket.update", "refund.issue"), 2)
    theirs = other.post(f"/v1/systems/{their_system['id']}/consequences/"
                        f"{observed(other, their_system['id'])['id']}/feedback",
                        json={"verdict": "INCORRECT", "idempotency_key": shared_key})
    assert theirs.status_code == 201 and theirs.json()["id"] != mine.json()["id"]


def test_control_characters_and_unbounded_documents_are_refused(customer):
    setup, _ = cleared(customer)
    system = setup["system_id"]
    change(customer, setup, "beneficiary_approval_relaxed")
    consequence = observed(customer, system)["id"]
    # A NUL byte can never reach storage through any input model.
    for comment in ("a\x00b", "bell\x07here", "del\x7fhere"):
        response = customer.post(f"/v1/systems/{system}/consequences/{consequence}/feedback",
                                 json={"verdict": "CORRECT", "comment": comment,
                                       "idempotency_key": str(uuid4())})
        assert response.status_code == 422, comment
    assert customer.post(f"/v1/systems/{system}/claim-definitions", json={
        "action": "refund.issue", "claim": "A refund\x00 is never issued without approval",
        "permitted_outcome": "Refund after approval", "forbidden_outcome": "Refund with no approval",
        "legitimate_task": "Resolve a refund", "ground_truth_source": "Ledger"}).status_code == 422
    # Newlines and tabs are ordinary text and stay accepted.
    assert customer.post(f"/v1/systems/{system}/consequences/{consequence}/feedback", json={
        "verdict": "PARTIALLY_CORRECT", "comment": "line one\nline two\tend",
        "idempotency_key": str(uuid4())}).status_code == 201
    # A proposed configuration is bounded in depth, breadth and size.
    deep = current = {}
    for _ in range(80):
        current["next"] = {}
        current = current["next"]
    wide = {f"key-{index}": index for index in range(20_000)}
    for payload in (deep, wide, {"tools": [{"name": "x" * 5000}]}):
        response = customer.post(f"/v1/systems/{system}/proposed-changes", json={
            "installation_id": setup["gateway_installation_id"], "payload": payload,
            "idempotency_key": str(uuid4())})
        assert response.status_code in {413, 422}, response.status_code
    huge = customer.post(f"/v1/systems/{system}/proposed-changes", content=json.dumps({
        "installation_id": setup["gateway_installation_id"], "payload": {"blob": "x" * 3_000_000},
        "idempotency_key": str(uuid4())}), headers={"content-type": "application/json"})
    assert huge.status_code == 413
    # A reference is a label for people: only https, never fetched, always bounded.
    for reference in ({"type": "PULL_REQUEST", "url": "http://example.com/pr/1"},
                      {"type": "PULL_REQUEST", "url": "javascript:alert(1)"},
                      {"type": "PULL_REQUEST", "url": "https://example.com/" + "a" * 600},
                      {"type": "PULL_REQUEST", "id": "../../etc/passwd"},
                      {"type": "INVENTED"}):
        response = customer.post(f"/v1/systems/{system}/proposed-changes", json={
            "installation_id": setup["gateway_installation_id"], "payload": gateway_payload(GATEWAY_BASELINE),
            "reference": reference, "idempotency_key": str(uuid4())})
        assert response.status_code == 422, reference


def test_a_shared_passport_carries_no_internal_identifier(customer):
    setup, _ = cleared(customer)
    system = setup["system_id"]
    user, org = identity(customer)
    passport = customer.post(f"/v1/systems/{system}/passports", json={})
    assert passport.status_code == 201, passport.text
    shared = customer.post(f"/v1/passports/{passport.json()['id']}/share",
                           json={"label": "Adversarial review", "confirm_disclosure": True})
    assert shared.status_code == 201, shared.text
    outsider = TestClient(app, client=("127.210.9.9", 50000))
    public = outsider.get(f"/v1/public/passports/{shared.json()['token']}")
    assert public.status_code == 200, public.text
    text = public.text
    for identifier in (str(org), str(user), system, setup["environment_id"], setup["target_id"],
                       setup["gateway_installation_id"]):
        assert identifier not in text, identifier
    # Resource names and the withheld field list are distinct: the names are gone, and the
    # document says which fields were withheld so the recipient knows what it is not seeing.
    for value in ("synthetic-tenant-a/vendor-1", "synthetic-tenant-a/invoice-1"):
        assert value not in text, value
    document = public.json()["passport"]
    assert document["disclosure"] == "STANDARD"
    assert {"organization.id", "system.id", "environment.id", "state.id", "clearance.decision_id",
            "authority.consequential_actions[].resources"} <= set(document["withheld"])
    assert "id" not in document["system"] and "id" not in document["state"]
    assert all("resources" not in action for action in document["authority"]["consequential_actions"])
    # The token is a capability: no other passport, system or tenant is reachable with it.
    assert outsider.get("/v1/public/passports/" + "A" * 118).status_code == 404
    assert outsider.get(f"/v1/systems/{system}/claims").status_code == 401
    assert outsider.get("/v1/build-info").status_code == 401
    assert outsider.get("/v1/measurements/business").status_code == 401


def test_the_product_api_exposes_no_operator_surface(customer):
    # The published schema is the authoritative surface; routers are resolved lazily.
    paths = list(app.openapi()["paths"])
    assert not [path for path in paths if "operator" in path.lower()]
    assert not [path for path in paths if "founder" in path.lower() or "investor" in path.lower()]
    # The tenant-facing measurement endpoints exist and are tenant-scoped.
    assert "/v1/measurements/business" in paths and "/v1/measurements/ai-usage" in paths
    response = customer.get("/v1/measurements/ai-usage")
    assert response.status_code == 200 and response.json()["spent_this_month_usd"] == 0.0


def test_an_unqualified_observer_cannot_be_made_to_speak(customer):
    setup, _ = cleared(customer)
    system, environment = setup["system_id"], setup["environment_id"]
    definition = customer.post(f"/v1/systems/{system}/observer-definitions",
                               json={**CONTRACT, "environment_id": environment}).json()
    # Claiming a passing harness for a different contract is refused.
    from threatveil.observer_platform import REQUIRED_ANSWER

    forged = customer.post(f"/v1/observer-definitions/{definition['id']}/qualification", json={
        "contract_digest": "f" * 64, "harness_version": "forged/v1", "results": dict(REQUIRED_ANSWER),
        "evidence_reference": "claimed elsewhere", "review_note": "This qualification is for another contract"})
    assert forged.status_code == 409
    # A partially passing harness cannot qualify it either.
    partial = {**REQUIRED_ANSWER, "WRONG_TENANT": "COMMITTED"}
    attempted = customer.post(f"/v1/observer-definitions/{definition['id']}/qualification", json={
        "contract_digest": definition["contract_digest"], "harness_version": "partial/v1", "results": partial,
        "evidence_reference": "local harness", "review_note": "Reviewed: one scenario answered wrongly"})
    assert attempted.status_code == 201 and attempted.json()["outcome"] == "FAILED"
    assert attempted.json()["failed_scenarios"] == ["WRONG_TENANT"]
    assert customer.get(f"/v1/observer-definitions/{definition['id']}").json()["produces_evidence"] is False
    # Its facts are recorded and are never evidence.
    recorded = customer.post(f"/v1/observer-definitions/{definition['id']}/observations", json={
        "correlation_value": "attempt-1", "effect": "COMMITTED", "action": "refund.issue",
        "resource_reference": "refund/1", "observed_at": "2026-09-12T10:00:00+00:00",
        "idempotency_key": str(uuid4())})
    assert recorded.status_code == 201 and recorded.json()["qualified"] is False
    effects = customer.get(f"/v1/observer-definitions/{definition['id']}/effects",
                           params={"correlation_value": "attempt-1"}).json()
    assert effects["effect"] == "UNKNOWN" and effects["committed"] is None
    # An auto re-proof policy cannot be approved on an observer that is not qualified.
    ladder = customer.get(f"/v1/systems/{system}/claims").json()
    claim = next(c for c in ladder["claims"] if c["kind"] == "EXECUTABLE_CLAIM" and c["approved"])
    refused = customer.post(f"/v1/systems/{system}/auto-reproof-policies", json={
        "environment_id": environment, "property_id": claim["id"], "target_id": setup["target_id"],
        "observer_definition_id": definition["id"], "confirm_no_remediation": True,
        "justification": "Attempting to stand up automatic re-proof without a qualified observer at all."})
    assert refused.status_code == 422 and "QUALIFIED" in refused.text
