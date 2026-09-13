"""Current Assurance Passport: portable, verifiable, and authentic without being current."""

import json
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from threatveil.api import app
from threatveil.db import Record, transaction
from threatveil.release_signing import signing_key
from threatveil.sdk.passports import read_passport, verify_passport, verify_passport_with_directory
from threatveil.sdk.receipts import ReceiptVerificationError
from threatveil.sdk.trust_directory import load_directory
from test_assurance_intelligence import assess, change, cleared, finance, other_tenant
from test_product import customer as customer  # noqa: F401


def issue(client, setup, **body):
    response = client.post(f"/v1/systems/{setup['system_id']}/passports", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def share(client, passport_id, label="Acme vendor security review"):
    response = client.post(f"/v1/passports/{passport_id}/share",
                           json={"label": label, "confirm_disclosure": True})
    assert response.status_code == 201, response.text
    return response.json()


def public(token, n):
    """An external party with no ThreatVeil account."""
    return TestClient(app, client=(f"127.203.{n}.1", 50000)).get(f"/v1/public/passports/{token}")


def test_passport_describes_a_bounded_case_in_the_buyers_language(customer):
    setup, _ = cleared(customer)
    detail = issue(customer, setup, audience="Acme vendor security review")
    passport = detail["passport"]
    assert passport["schema_version"] == "threatveil-assurance-passport/v1"
    assert passport["audience"] == "Acme vendor security review"
    assert (passport["clearance"]["state"], passport["clearance"]["label"]) == ("CLEARED", "Cleared")
    assert len(passport["claims"]["supported"]) == 3 and not passport["claims"]["needs_fresh_evidence"]
    assert passport["authority"]["grants_permissions"] is False
    assert {a["label"] for a in passport["authority"]["consequential_actions"]} == {"Beneficiary update", "Invoice update"}
    assert any("certification" in item for item in passport["not_claims"])
    assert any("trust score" in item for item in passport["not_claims"])
    assert passport["system"]["synthetic"] is True and any("synthetic" in item for item in passport["limitations"])
    assert detail["current_status"]["status"] == "CURRENT"
    text = json.dumps(passport)
    for internal in ("proof_scope", "receipts", "fingerprint", "run_id", "capsule", "observation_contract"):
        assert internal not in text


def test_passport_verifies_offline_with_a_trusted_key_or_the_published_directory(customer):
    setup, _ = cleared(customer)
    detail = issue(customer, setup)
    envelope = detail["envelope"]
    statement = verify_passport(envelope, signing_key().public_key(), passport_id=detail["id"],
                                system_reference=detail["passport"]["system"]["reference"])
    assert statement["predicate"] == detail["passport"] == read_passport(envelope)
    assert statement["subject"][0]["digest"]["sha256"] == detail["passport"]["state"]["digest"]
    directory = load_directory(customer.get("/v1/trust/keys").json())
    assert verify_passport_with_directory(envelope, directory, passport_id=detail["id"])
    with pytest.raises(ReceiptVerificationError):
        verify_passport({**envelope, "payload": envelope["payload"][:-12] + "QUFBQUFBQUE="}, signing_key().public_key())
    with pytest.raises(ReceiptVerificationError):
        verify_passport(envelope, signing_key().public_key(), system_id=str(uuid4()))
    with pytest.raises(ReceiptVerificationError):
        verify_passport(envelope, Ed25519PrivateKey.generate().public_key())


def test_a_shared_passport_stays_authentic_while_its_status_becomes_superseded(customer):
    setup, _ = cleared(customer)
    detail = issue(customer, setup)
    link = share(customer, detail["id"])
    assert link["page_path"] == f"/passport/{link['token']}"
    first = public(link["token"], 1)
    assert first.status_code == 200, first.text
    assert first.json()["current_status"]["status"] == "CURRENT"
    assert first.json()["share"]["label"] == "Acme vendor security review"
    assert public(link["token"], 2).status_code == 200
    change(customer, setup, "beneficiary_approval_relaxed")
    later = public(link["token"], 3).json()
    assert later["current_status"]["status"] == "SUPERSEDED"
    assert later["envelope"] == first.json()["envelope"]
    assert verify_passport(later["envelope"], signing_key().public_key())
    assert later["verification"]["authenticity_and_status_are_separate"] is True
    org = UUID(customer.get("/v1/auth/me").json()["organization"]["id"])
    with transaction(org_id=org) as session:
        checks = session.scalar(select(func.count()).select_from(Record).where(
            Record.organization_id == org, Record.kind == "service_metric",
            Record.payload["name"].astext == "passport.status_checked"))
        assert checks == 1


def test_a_passport_issued_while_reassessment_is_pending_stays_current_until_the_system_moves(customer):
    setup, _ = cleared(customer)
    change(customer, setup, "beneficiary_approval_relaxed")
    detail = issue(customer, setup)
    passport = detail["passport"]
    assert passport["clearance"]["state"] == "NEEDS_REASSESSMENT"
    assert [c["title"] for c in passport["claims"]["needs_fresh_evidence"]] == ["Beneficiary changes require finance approval"]
    assert detail["current_status"]["status"] == "CURRENT"
    assess(customer, setup, "regressed")
    assert customer.get(f"/v1/passports/{detail['id']}").json()["current_status"]["status"] == "SUPERSEDED"


def test_shared_links_are_capabilities_that_can_be_withdrawn(customer):
    setup, _ = cleared(customer)
    detail = issue(customer, setup)
    link = share(customer, detail["id"])
    token = link["token"]
    forged = token[:-6] + ("AAAAAA" if not token.endswith("AAAAAA") else "BBBBBB")
    for attempt, n in ((forged, 4), ("x" * 118, 5), ("short", 6)):
        assert public(attempt, n).status_code == 404
    assert customer.post(f"/v1/passports/shares/{link['share_id']}/revoke",
                         json={"reason": "Review finished; link withdrawn"}).status_code == 201
    assert public(token, 7).status_code == 410
    second = share(customer, detail["id"], "Second reviewer")["token"]
    assert customer.post(f"/v1/passports/{detail['id']}/revoke",
                         json={"reason": "Issuer withdrew this passport"}).status_code == 201
    assert public(second, 8).json()["current_status"]["status"] == "REVOKED"
    assert customer.post(f"/v1/passports/{detail['id']}/share", json={
        "label": "After revocation", "confirm_disclosure": True}).status_code == 409


def test_passports_require_a_baseline_and_are_tenant_isolated(customer):
    setup = finance(customer)
    assert customer.post(f"/v1/systems/{setup['system_id']}/passports", json={}).status_code == 409
    assess(customer, setup)
    detail = issue(customer, setup)
    other = other_tenant()
    assert other.get(f"/v1/passports/{detail['id']}").status_code == 404
    assert other.post(f"/v1/passports/{detail['id']}/share", json={
        "label": "Not my passport", "confirm_disclosure": True}).status_code == 404
    assert other.get(f"/v1/passports/{detail['id']}/disclosure-preview").status_code == 404
    listed = customer.get(f"/v1/systems/{setup['system_id']}/passports").json()["items"]
    assert listed[0]["id"] == detail["id"] and listed[0]["current_status"]["status"] == "CURRENT"


def test_a_shareable_passport_withholds_identifiers_and_resource_names(customer):
    setup, _ = cleared(customer)
    detail = issue(customer, setup)
    passport = detail["passport"]
    assert passport["disclosure"] == "STANDARD" and "system.id" in passport["withheld"]
    assert "id" not in passport["system"] and "id" not in passport["organization"]
    assert "id" not in passport["environment"] and "id" not in passport["state"]
    assert "decision_id" not in passport["clearance"]
    assert len(passport["system"]["reference"]) == 64
    text = json.dumps(passport)
    for identifier in (setup["system_id"], setup["environment_id"], setup["target_id"]):
        assert identifier not in text
    actions = passport["authority"]["consequential_actions"]
    assert actions and all("resources" not in a and a["resource_count"] >= 1 for a in actions)
    # Status still recomputes, because the identifiers live in the record, not the document.
    assert detail["current_status"]["status"] == "CURRENT"
    preview = customer.get(f"/v1/passports/{detail['id']}/disclosure-preview").json()
    assert preview["disclosure"] == "STANDARD" and preview["discloses"]["internal_identifiers"] == []
    assert preview["discloses"]["resource_names"] == [] and preview["discloses"]["claim_titles"]
    assert preview["discloses"]["system_reference"] == passport["system"]["reference"]
    # Sharing requires confirming that reviewed disclosure.
    assert customer.post(f"/v1/passports/{detail['id']}/share",
                         json={"label": "No confirmation"}).status_code == 422
    assert share(customer, detail["id"])["token"]
    # An internal passport may carry identifiers, and says so.
    internal = issue(customer, setup, disclosure="INTERNAL")
    assert internal["passport"]["system"]["id"] == setup["system_id"]
    assert internal["passport"]["withheld"] == []
    assert any(a.get("resources") for a in internal["passport"]["authority"]["consequential_actions"])
    assert "system.id" in customer.get(
        f"/v1/passports/{internal['id']}/disclosure-preview").json()["discloses"]["internal_identifiers"]
    assert verify_passport(internal["envelope"], signing_key().public_key(), system_id=setup["system_id"])
    assert verify_passport(detail["envelope"], signing_key().public_key(),
                           system_reference=passport["system"]["reference"])
    with pytest.raises(ReceiptVerificationError):
        verify_passport(detail["envelope"], signing_key().public_key(), system_id=setup["system_id"])
