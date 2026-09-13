"""Local commercial acceptance against real PostgreSQL/RLS and immutable history."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select

from threatveil.api import app
from threatveil import commercial
from threatveil.config import settings
from threatveil.db import Account, Membership, Record, add_record, now, transaction

ORIGIN = "http://127.0.0.1:3000"


@pytest.fixture
def customer(monkeypatch):
    monkeypatch.setenv("TV_ENV", "test")
    monkeypatch.setenv("TV_LOCAL_AUTH", "true")
    monkeypatch.setenv("TV_BILLING_PROVIDER", "mock")
    settings.cache_clear()
    with TestClient(app) as client:
        login = client.post("/v1/auth/local", json={"email": f"{uuid4()}@local.invalid"},
                            headers={"origin": ORIGIN})
        assert login.status_code == 200, login.text
        client.headers.update({"origin": ORIGIN, "x-csrf-token": login.json()["csrf_token"]})
        view = client.get("/v1/commercial")
        assert view.status_code == 200, view.text
        org = UUID(view.json()["subscription"]["organization_id"])
        yield client, org
    settings.cache_clear()


def transition(client, action, **fields):
    return client.post("/v1/commercial/subscription", json={"action": action,
                       "idempotency_key": str(uuid4()), **fields})


def create_system(client, name="Finance Agent"):
    return client.post("/v1/systems", json={"name": name,
                "description": "Tenant-bound beneficiary and invoice authority",
                "access": ["payments"], "actions": ["write"]})


def test_new_free_real_value_upgrade_quota_and_history(customer):
    client, org = customer
    free = client.get("/v1/commercial").json()
    assert free["plan"] == "free" and free["status"] == "free" and not free["paid"]
    assert free["entitlements"]["monthly_verification_budget"] >= 50
    demo = client.post("/v1/demo/setup", json={})
    assert demo.status_code == 200, demo.text
    assert client.get("/v1/commercial").json()["plan"] == "free"
    assert create_system(client).status_code == 402
    with transaction(org_id=org) as s:
        adverse = add_record(s, org, "result", {"verdict": "FAIL", "security_assessment": "FAIL",
                            "legitimate_task": "FAILURE", "evidence_applicability": "UNKNOWN"})
        previous = {str(r.id): r.payload for r in s.scalars(select(Record).where(
            Record.organization_id == org, Record.kind != "billing_event",
            Record.kind != "commercial_subscription"))}
        adverse_id = adverse.id
    upgraded = transition(client, "upgrade", plan="pro")
    assert upgraded.status_code == 200, upgraded.text
    pro = upgraded.json()
    assert pro["plan"] == "pro" and pro["status"] == "active" and not pro["paid"]
    assert pro["entitlements"]["protected_system_limit"] == 3
    assert create_system(client, "Second meaningful system").status_code == 201
    assert create_system(client, "Third meaningful system").status_code == 201
    assert create_system(client, "Fourth meaningful system").status_code == 402
    with transaction(org_id=org) as s:
        assert all(s.get(Record, UUID(identifier)).payload == payload for identifier, payload in previous.items())
        assert s.get(Record, adverse_id).payload["verdict"] == "FAIL"
    assert client.get("/v1/commercial").json()["usage"]["protected_systems"] == 3


def test_downgrade_preserves_overage_history_and_reservations(customer, monkeypatch):
    client, org = customer
    assert transition(client, "upgrade", plan="pro").status_code == 200
    assert create_system(client).status_code == 201
    assert create_system(client, "Second system").status_code == 201
    with transaction(org_id=org) as s:
        account = s.get(Account, org)
        account.consumed, account.reserved = 450, 60
    scheduled = transition(client, "downgrade", plan="free").json()
    assert scheduled["plan"] == "pro" and scheduled["subscription"]["scheduled_change"]["plan"] == "free"
    boundary = commercial._stamp(scheduled["subscription"]["period_end"])
    monkeypatch.setattr(commercial, "now", lambda: boundary + timedelta(seconds=1))
    applied = client.get("/v1/commercial").json()
    assert applied["plan"] == "free" and applied["usage"]["protected_systems"] == 2
    assert applied["usage"]["consumed"] == 0 and applied["usage"]["reserved"] == 60
    assert create_system(client, "Blocked extra system").status_code == 402
    assert client.get("/v1/systems").status_code == 200
    assert transition(client, "renew").status_code == 409


def test_verification_exhaustion_blocks_without_mutating_truth(customer):
    client, org = customer
    with transaction(org_id=org) as s:
        account = s.get(Account, org)
        budget = commercial.resolve(s, org)[2]["monthly_verification_budget"]
        account.consumed, account.reserved = budget - 10, 10
        result = add_record(s, org, "result", {"verdict": "INCONCLUSIVE", "ground_truth": "MISSING"})
        result_id = result.id
    with transaction(org_id=org) as s:
        with pytest.raises(Exception) as error:
            commercial.require_verification_capacity(s, org, 1)
        assert error.value.status_code == 402
    assert transition(client, "upgrade", plan="pro").status_code == 200
    with transaction(org_id=org) as s:
        commercial.require_verification_capacity(s, org, 1)
        assert s.get(Account, org).consumed == budget - 10
        assert s.get(Record, result_id).payload == {"verdict": "INCONCLUSIVE", "ground_truth": "MISSING"}


def test_duplicate_concurrent_conflicting_and_reordered_commands(customer):
    client, org = customer
    revision = client.get("/v1/commercial").json()["revision"]
    body = {"action": "upgrade", "plan": "pro", "idempotency_key": str(uuid4()), "expected_revision": revision}

    def submit(_):
        with TestClient(app) as concurrent:
            concurrent.cookies.update(client.cookies)
            concurrent.headers.update(client.headers)
            return concurrent.post("/v1/commercial/subscription", json=body)

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(submit, range(2)))
    assert all(r.status_code == 200 for r in responses)
    assert sum(r.json().get("duplicate", False) for r in responses) == 1
    assert client.post("/v1/commercial/subscription", json={**body, "plan": "team"}).status_code == 409
    assert transition(client, "upgrade", plan="team", expected_revision=revision).status_code == 409
    with transaction(org_id=org) as s:
        assert len(list(s.scalars(select(Record).where(Record.kind == "billing_event",
                    Record.payload["action"].as_string() == "upgrade")))) == 1


def test_payment_failure_grace_does_not_extend_and_expiry_falls_back(customer, monkeypatch):
    client, _ = customer
    assert transition(client, "upgrade", plan="pro").status_code == 200
    failure = transition(client, "payment_failed").json()
    assert failure["status"] == "grace" and failure["entitlements"]["protected_system_limit"] == 3
    deadline = commercial._stamp(failure["subscription"]["grace_until"])
    monkeypatch.setattr(commercial, "now", lambda: deadline - timedelta(seconds=1))
    again = transition(client, "payment_failed").json()
    assert again["subscription"]["grace_until"] == failure["subscription"]["grace_until"]
    monkeypatch.setattr(commercial, "now", lambda: deadline + timedelta(seconds=1))
    expired = client.get("/v1/commercial").json()
    assert expired["plan"] == "free" and expired["status"] == "free"
    assert transition(client, "payment_recovered").status_code == 409


def test_promotion_trial_and_enterprise_expiry_are_independent(customer, monkeypatch):
    client, _ = customer
    clock = now()
    promoted = client.post("/v1/commercial/promotion", json={"idempotency_key": str(uuid4()),
        "code": "OSS-SIX-MONTHS", "kind": "open_source", "percent_off": 100,
        "expires_at": (clock + timedelta(days=180)).isoformat()})
    assert promoted.status_code == 200 and promoted.json()["plan"] == "free"
    trial = transition(client, "start_trial", plan="pro").json()
    assert trial["status"] == "trialing"
    monkeypatch.setattr(commercial, "now", lambda: clock + timedelta(days=15))
    expired = client.get("/v1/commercial").json()
    assert expired["plan"] == "free" and expired["subscription"]["promotion"]
    assert transition(client, "start_trial", plan="pro").status_code == 409
    contract = client.post("/v1/commercial/override", json={"idempotency_key": str(uuid4()),
        "entitlements": {"protected_system_limit": 75, "monthly_verification_budget": 42000},
        "contract_reference": "LOCAL-CONFORMANCE-001", "reason": "Local enterprise contract acceptance",
        "expires_at": (clock + timedelta(days=30)).isoformat()})
    assert contract.status_code == 200, contract.text
    assert contract.json()["plan"] == "enterprise"
    assert contract.json()["entitlements"]["protected_system_limit"] == 75
    monkeypatch.setattr(commercial, "now", lambda: clock + timedelta(days=181))
    final = client.get("/v1/commercial").json()
    assert final["plan"] == "free" and final["subscription"]["promotion"] is None
    assert final["subscription"]["override"] is None


def test_commercial_commands_cannot_select_tenant_or_change_security_fields(customer):
    client, org = customer
    assert transition(client, "upgrade", plan="pro", organization_id=str(uuid4())).status_code == 422
    malformed = client.post("/v1/commercial/override", json={"idempotency_key": str(uuid4()),
        "entitlements": {"security_assessment": "PASS"}, "contract_reference": "LOCAL",
        "reason": "Cannot buy security truth", "expires_at": (now() + timedelta(days=1)).isoformat()})
    assert malformed.status_code == 422
    user_id = UUID(client.get("/v1/auth/me").json()["user"]["id"])
    with transaction(org_id=org) as s:
        s.get(Membership, (org, user_id)).role = "developer"
    assert transition(client, "upgrade", plan="pro").status_code == 403


def test_subscription_freezes_catalog_version_and_quota(customer, monkeypatch, tmp_path):
    client, _ = customer
    frozen = client.get("/v1/commercial").json()["entitlements"]
    changed = commercial.catalog().model_dump(mode="json")
    changed["version"] = "future-hypothesis"
    changed["plans"][0]["entitlements"]["protected_system_limit"] = 8
    path = tmp_path / "catalog.json"
    import json
    path.write_text(json.dumps(changed))
    monkeypatch.setenv("TV_COMMERCIAL_CATALOG_PATH", str(path))
    settings.cache_clear()
    assert client.get("/v1/commercial/catalog").json()["catalog_version"] == "future-hypothesis"
    assert client.get("/v1/commercial").json()["entitlements"] == frozen


def test_cross_tenant_read_and_idempotency_scope(customer):
    client, org = customer
    key = str(uuid4())
    assert transition(client, "upgrade", plan="pro", idempotency_key=key).status_code == 200
    with TestClient(app) as other:
        login = other.post("/v1/auth/local", json={"email": f"{uuid4()}@local.invalid"}, headers={"origin": ORIGIN})
        other.headers.update({"origin": ORIGIN, "x-csrf-token": login.json()["csrf_token"]})
        view = other.get("/v1/commercial").json()
        assert view["plan"] == "free" and view["subscription"]["organization_id"] != str(org)
        assert transition(other, "upgrade", plan="team", idempotency_key=key).status_code == 200
        assert all(e["organization_id"] != str(org) for e in other.get("/v1/commercial").json()["events"])
    assert client.get("/v1/commercial").json()["plan"] == "pro"


def test_pre_catalog_pro_contract_is_never_reinterpreted_by_provider_event(customer):
    from threatveil.db import Membership, Organization

    client, _ = customer
    owner_id = UUID(client.get("/v1/auth/me").json()["user"]["id"])
    legacy_org = uuid4()
    with transaction(user_id=owner_id, org_id=legacy_org) as session:
        session.add(Organization(id=legacy_org, name="Historical Pro contract", owner_user_id=owner_id))
        session.flush()
        session.add(Membership(organization_id=legacy_org, user_id=owner_id, role="owner"))
        account = Account(organization_id=legacy_org, plan="pro", status="active",
                          max_systems=15, trial_limit=50000, paid=True)
        session.add(account)
        session.flush()
        commercial.record_provider_subscription(session, account, "evt_legacy_compatibility")
        _, state, allowed = commercial.resolve(session, legacy_org)
        assert state is None and account.max_systems == 15
        assert allowed["approved_property_limit"] == 500
        assert allowed["monthly_verification_budget"] == 50000
        assert not list(session.scalars(select(Record).where(Record.kind == "commercial_subscription")))


def test_free_can_warn_but_can_never_block(customer):
    """The control point is reachable on Free; the authority to stop is not."""
    client, org = customer
    free = client.get("/v1/commercial").json()
    capabilities = set(free["entitlements"]["capabilities"])
    assert "enforcement.warn" in capabilities
    assert "enforcement.ci" not in capabilities
    assert "enforcement.production" not in capabilities
    # Free must be able to express a change, so it needs a second environment.
    assert free["entitlements"]["environments_per_system_limit"] >= 2
    assert free["entitlements"]["monthly_verification_budget"] >= 1000

    demo = client.post("/v1/demo/setup", json={}).json()
    result = client.post("/v1/runs", json={
        "system_id": demo["system"]["id"], "property_id": demo["property"]["id"],
        "target_id": demo["target"]["id"], "version": "vulnerable", "trials": 2,
        "variant_count": 1, "idempotency_key": str(uuid4())})
    assert result.status_code == 202, result.text
    from threatveil.api import execute_run
    execute_run(org, UUID(result.json()["id"]))
    detail = client.get(f"/v1/runs/{result.json()['id']}").json()
    plan = client.post("/v1/proof-plans", json={
        "system_id": demo["system"]["id"], "candidate": detail["candidate"],
        "fingerprint": detail["fingerprint"], "trials_per_variant": 2})
    assert plan.status_code == 201, plan.text

    # A blocking policy is refused, with the upgrade path and no loss of truth.
    blocked = client.post("/v1/releases", json={
        "plan_id": plan.json()["id"], "policy": {"mode": "BLOCK"}})
    assert blocked.status_code == 402
    assert blocked.json()["detail"]["resource"] == "enforcement.ci"

    # WARN is available and reports the identical underlying security conclusion.
    warned = client.post("/v1/releases", json={
        "plan_id": plan.json()["id"], "policy": {"mode": "WARN"}})
    assert warned.status_code == 201, warned.text
    warn = warned.json()
    assert warn["release_action"] == "WARN" and warn["underlying_action"] == "BLOCK"
    assert warn["gate_enforced"] is False

    # Paying changes only the authority to stop, never the assessment.
    assert transition(client, "upgrade", plan="pro").status_code == 200
    gated = client.post("/v1/releases", json={
        "plan_id": plan.json()["id"], "policy": {"mode": "BLOCK"}})
    assert gated.status_code == 201, gated.text
    assert gated.json()["underlying_action"] == warn["underlying_action"] == "BLOCK"
    assert gated.json()["gate_enforced"] is True


def test_a_plan_change_never_alters_a_recorded_security_conclusion(customer):
    client, org = customer
    assert transition(client, "upgrade", plan="pro").status_code == 200
    demo = client.post("/v1/demo/setup", json={}).json()
    result = client.post("/v1/runs", json={
        "system_id": demo["system"]["id"], "property_id": demo["property"]["id"],
        "target_id": demo["target"]["id"], "version": "vulnerable", "trials": 2,
        "variant_count": 1, "idempotency_key": str(uuid4())})
    from threatveil.api import execute_run
    execute_run(org, UUID(result.json()["id"]))
    before = client.get(f"/v1/runs/{result.json()['id']}").json()
    assert before["security_verdict"] == "FAIL"

    for action, plan in (("upgrade", "business"), ("downgrade", "free")):
        assert transition(client, action, plan=plan).status_code == 200
        after = client.get(f"/v1/runs/{result.json()['id']}").json()
        assert after["security_verdict"] == "FAIL"
        assert after["evidence_digest"] == before["evidence_digest"]


def test_production_enforcement_requires_the_business_boundary(customer):
    client, _ = customer
    for plan, expected in (("pro", False), ("team", False), ("business", True)):
        assert transition(client, "upgrade", plan=plan).status_code == 200
        capabilities = set(client.get("/v1/commercial").json()["entitlements"]["capabilities"])
        assert ("enforcement.production" in capabilities) is expected
        # Every paid tier keeps the CI gate it was sold.
        assert "enforcement.ci" in capabilities


def test_free_cannot_launder_a_block_through_a_per_property_mode(customer):
    """A WARN policy with one BLOCK property would publish a failing check.

    The GitHub check conclusion follows the effective release action, so the only
    way a Free tenant could fail a required check is a BLOCK hidden in
    property_modes. That path is refused exactly like a top-level BLOCK.
    """
    client, org = customer
    demo = client.post("/v1/demo/setup", json={}).json()
    run = client.post("/v1/runs", json={
        "system_id": demo["system"]["id"], "property_id": demo["property"]["id"],
        "target_id": demo["target"]["id"], "version": "vulnerable", "trials": 2,
        "variant_count": 1, "idempotency_key": str(uuid4())})
    from threatveil.api import execute_run
    execute_run(org, UUID(run.json()["id"]))
    detail = client.get(f"/v1/runs/{run.json()['id']}").json()
    plan = client.post("/v1/proof-plans", json={
        "system_id": demo["system"]["id"], "candidate": detail["candidate"],
        "fingerprint": detail["fingerprint"], "trials_per_variant": 2}).json()
    laundered = client.post("/v1/releases", json={"plan_id": plan["id"], "policy": {
        "mode": "WARN", "property_modes": {demo["property"]["id"]: "BLOCK"}}})
    assert laundered.status_code == 402
    assert laundered.json()["detail"]["resource"] == "enforcement.ci"
    # Every release a Free tenant can record projects to a non-failing check.
    warned = client.post("/v1/releases", json={"plan_id": plan["id"], "policy": {"mode": "WARN"}})
    assert warned.status_code == 201 and warned.json()["release_action"] in {"ALLOW", "WARN"}
