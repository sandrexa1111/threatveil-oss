"""The hosted Free journey, driven only through hosted-capable API contracts.

Every step here runs with the in-process executor disabled, exactly as it is in a
deployed environment: the API never executes a fixture, so verification must be
completed by the separate worker before any conclusion is read. If this file
passes, a hosted Free account can reach the category rather than a dead end.
"""

import uuid
from uuid import UUID

import pytest

from threatveil.api import execute_run
from threatveil.release_signing import signing_key
from threatveil.sdk.change_records import verify_change_record
from test_product import customer as customer  # noqa: F401


@pytest.fixture
def hosted(monkeypatch):
    """Report a deployed environment to the assessment path only.

    Authentication and storage keep their local test behaviour; the single
    difference is that the API process refuses to execute verification itself.
    """
    from threatveil import change_assurance_api

    monkeypatch.setattr(change_assurance_api, "_api_executes_runs", lambda: False)


def worker(client, response):
    """Stand in for the Cloud Run worker that drains the dispatch outbox."""
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "RUNNING" and body["run_ids"]
    organization = UUID(client.get("/v1/auth/me").json()["organization"]["id"])
    for run_id in body["run_ids"]:
        execute_run(organization, UUID(run_id))
    return body


def assess(client, setup, version, key):
    """Request an assessment, let the worker finish, then read the decision."""
    payload = {"system_id": setup["system_id"], "version": version, "idempotency_key": key}
    first = client.post("/v1/change-assurance/finance/assess", json=payload)
    if first.status_code == 202:
        worker(client, first)
        second = client.post("/v1/change-assurance/finance/assess", json=payload)
        assert second.status_code == 201, second.text
        return second.json()
    assert first.status_code == 201, first.text
    return first.json()


def test_a_hosted_free_account_reaches_a_decision_without_local_execution(customer, hosted):
    # 1. A new organization is provisioned on Free.
    plan = customer.get("/v1/commercial").json()
    assert plan["plan"] == "free" and not plan["paid"]
    assert plan["entitlements"]["protected_system_limit"] == 1

    # 2. First protected system, its sandbox environment and its reviewed authority.
    setup = customer.post("/v1/change-assurance/finance/setup", json={
        "owner": "Finance security owner", "confirm_synthetic_scope": True})
    assert setup.status_code == 201, setup.text
    setup = setup.json()

    # 3. The API refuses to execute; verification is dispatched to the worker.
    key = str(uuid.uuid4())
    payload = {"system_id": setup["system_id"], "version": "fixed", "idempotency_key": key}
    queued = customer.post("/v1/change-assurance/finance/assess", json=payload)
    assert queued.status_code == 202
    assert queued.json()["status"] == "RUNNING"
    assert "establishes no security conclusion" in " ".join(queued.json()["limitations"])

    # Asking again before the worker finishes must not invent a conclusion.
    still = customer.post("/v1/change-assurance/finance/assess", json=payload)
    assert still.status_code == 202 and still.json()["run_ids"] == queued.json()["run_ids"]

    worker(customer, queued)
    baseline = customer.post("/v1/change-assurance/finance/assess", json=payload)
    assert baseline.status_code == 201, baseline.text
    baseline = baseline.json()
    assert (baseline["security"], baseline["legitimate_task"], baseline["action"]) == (
        "PASS", "SUCCESS", "ALLOW",
    )

    # 4. A meaningful change is assessed, and prior support does not survive it.
    regressed = assess(customer, setup, "regressed", str(uuid.uuid4()))
    assert regressed["security"] == "FAIL" and regressed["action"] == "BLOCK"

    # 5. The customer can see what still holds and what does not.
    journey = customer.get(f"/v1/change-assurance/systems/{setup['system_id']}").json()
    scope = journey["environments"][0]
    assert len(journey["properties"]) == 3
    assert any(t["change_type"] for t in scope["transitions"])
    assert scope["current"]["security"] == "FAIL"

    # 6. The earlier clearance is retained as history and is no longer current.
    prior = customer.get(f"/v1/change-assurance/decisions/{baseline['authorization_id']}").json()
    assert prior["action"] == "ALLOW"
    assert prior["current_status"] in {"SUPERSEDED", "REASSESS", "EXPIRED"}

    # 7. The signed record exports and verifies against an independently held key.
    current = customer.get(
        f"/v1/change-assurance/decisions/{regressed['authorization_id']}"
    ).json()
    verified = verify_change_record(
        current["envelope"], signing_key().public_key(),
        organization_id=current["organization_id"], system_id=setup["system_id"],
        environment_id=setup["environment_id"], state_digest=current["state_digest"],
        audience=current["audience"],
    )
    assert verified["predicate"]["action"] == "BLOCK"

    # 8. The published trust root resolves the key that signed it.
    from threatveil.sdk.trust_directory import key_id, load_directory

    directory = load_directory(customer.get("/v1/trust/keys").json())
    assert key_id(signing_key().public_key()) in directory["keys"]


def test_free_capacity_is_refused_cleanly_without_losing_history(customer, hosted):
    setup = customer.post("/v1/change-assurance/finance/setup", json={
        "owner": "Finance security owner", "confirm_synthetic_scope": True}).json()
    baseline = assess(customer, setup, "fixed", str(uuid.uuid4()))
    assert baseline["action"] == "ALLOW"

    # A second protected system exceeds Free and is refused with an upgrade path.
    refused = customer.post("/v1/systems", json={
        "name": "Second system", "description": "Another workflow", "actions": [], "access": []})
    assert refused.status_code == 402, refused.text
    detail = refused.json()["detail"]
    assert detail["code"] == "entitlement_limit"
    assert detail["resource"] == "protected_systems" and detail["upgrade_url"] == "/app/billing"
    assert "retained" in detail["message"]

    # Existing history remains readable and its security truth is unchanged.
    journey = customer.get(f"/v1/change-assurance/systems/{setup['system_id']}").json()
    assert len(journey["properties"]) == 3
    decision = customer.get(
        f"/v1/change-assurance/decisions/{baseline['authorization_id']}"
    ).json()
    assert decision["action"] == "ALLOW" and decision["security"] == "PASS"

    # The plan surface presents the upgrade without altering any conclusion.
    catalog = customer.get("/v1/commercial/catalog").json()
    assert [p["id"] for p in catalog["plans"]][:2] == ["free", "pro"]


def test_the_hosted_api_never_executes_a_fixture_itself(customer, hosted):
    """The broker/worker boundary is the reason this path is asynchronous."""
    setup = customer.post("/v1/change-assurance/finance/setup", json={
        "owner": "Finance security owner", "confirm_synthetic_scope": True}).json()
    key = str(uuid.uuid4())
    queued = customer.post("/v1/change-assurance/finance/assess", json={
        "system_id": setup["system_id"], "version": "fixed", "idempotency_key": key})
    assert queued.status_code == 202
    # No result exists, so no decision, state or assurance case may exist either.
    journey = customer.get(f"/v1/change-assurance/systems/{setup['system_id']}").json()
    assert not journey["environments"][0]["decision"]
    for run_id in queued.json()["run_ids"]:
        assert customer.get(f"/v1/runs/{run_id}/evidence").status_code == 409


def test_a_sandbox_assessment_cannot_be_pointed_at_another_system(customer, hosted):
    setup = customer.post("/v1/change-assurance/finance/setup", json={
        "owner": "Finance security owner", "confirm_synthetic_scope": True}).json()
    # The demonstration is bound to its declared fixture profile, not to any system.
    other = customer.get("/v1/systems").json()["items"]
    foreign = next((s for s in other if s["id"] != setup["system_id"]), None)
    if foreign is not None:
        refused = customer.post("/v1/change-assurance/finance/assess", json={
            "system_id": foreign["id"], "version": "fixed",
            "idempotency_key": str(uuid.uuid4())})
        assert refused.status_code == 422

    # A key already bound to one operating configuration cannot be reused for another.
    key = str(uuid.uuid4())
    assess(customer, setup, "fixed", key)
    conflict = customer.post("/v1/change-assurance/finance/assess", json={
        "system_id": setup["system_id"], "version": "regressed", "idempotency_key": key})
    assert conflict.status_code == 409
