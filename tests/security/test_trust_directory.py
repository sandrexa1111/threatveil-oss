"""Trust distribution and key rotation for long-lived ThreatVeil records.

Rotation must never invalidate history. Revocation must invalidate it completely.
Both are asserted here against the same verifier an external consumer would use.
"""

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from threatveil.sdk.change_records import (
    ReceiptVerificationError,
    sign_change_record,
    verify_change_record,
)
from threatveil.sdk.trust_directory import (
    ALGORITHMS,
    PROFILE,
    TrustError,
    key_id,
    load_directory,
    resolve_verification_key,
    serialize_directory,
    verify_change_record_with_directory,
)

ORGANIZATION, SYSTEM, ENVIRONMENT = str(uuid4()), str(uuid4()), str(uuid4())
DIGEST = "c" * 64
AUDIENCE = "ci.example"
SCOPE = {
    "organization_id": ORGANIZATION,
    "system_id": SYSTEM,
    "environment_id": ENVIRONMENT,
    "state_digest": DIGEST,
    "audience": AUDIENCE,
}


def pem(key):
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def decision(signed_at):
    return {
        "schema_version": "change-assurance/v1",
        "signature_profile": "dsse-in-toto-ed25519/v1",
        "algorithm": "Ed25519",
        "issuer": "threatveil",
        "id": str(uuid4()),
        "organization_id": ORGANIZATION,
        "system_id": SYSTEM,
        "environment_id": ENVIRONMENT,
        "state_digest": DIGEST,
        "audience": AUDIENCE,
        "action": "ALLOW",
        "not_before": signed_at.isoformat(),
        "expires_at": (signed_at + timedelta(minutes=5)).isoformat(),
    }


def entry(key, status, valid_from, valid_until, revoked_at=None, supersedes=None):
    return {
        "keyid": key_id(key.public_key()),
        "algorithm": "Ed25519",
        "signature_profile": ALGORITHMS["Ed25519"],
        "status": status,
        "valid_from": valid_from.isoformat(),
        "valid_until": valid_until.isoformat() if valid_until else None,
        "revoked_at": revoked_at.isoformat() if revoked_at else None,
        "public_key_pem": pem(key),
        "supersedes": supersedes,
    }


@pytest.fixture
def rotation():
    """Key A signed last year and has been retired. Key B is active now."""
    old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rotated = datetime(2026, 6, 1, tzinfo=timezone.utc)
    end = datetime(2027, 6, 1, tzinfo=timezone.utc)
    document = serialize_directory(
        "threatveil",
        [
            entry(old, "RETIRED", start, rotated),
            entry(new, "ACTIVE", rotated, end, supersedes=key_id(old.public_key())),
        ],
    )
    return old, new, document, start, rotated, end


def test_rotation_preserves_historical_verification_and_moves_new_issuance(rotation):
    old, new, document, start, rotated, _ = rotation
    directory = load_directory(document)
    historical = sign_change_record(decision(start + timedelta(days=1)), old)
    current = sign_change_record(decision(rotated + timedelta(days=1)), new)

    # A record signed inside the retired key's window still verifies unchanged.
    assert verify_change_record_with_directory(historical, directory, **SCOPE)
    assert verify_change_record_with_directory(current, directory, **SCOPE)

    # The retired key may no longer be selected for new issuance.
    assert directory["keys"][key_id(old.public_key())]["status"] == "RETIRED"
    assert directory["keys"][key_id(new.public_key())]["status"] == "ACTIVE"
    assert sum(1 for k in directory["keys"].values() if k["status"] == "ACTIVE") == 1


def test_rotation_does_not_alter_the_historical_signed_record(rotation):
    old, _, document, start, _, _ = rotation
    signed_at = start + timedelta(days=1)
    record = sign_change_record(decision(signed_at), old)
    before = json.dumps(record, sort_keys=True)
    load_directory(document)
    verify_change_record_with_directory(record, load_directory(document), **SCOPE)
    assert json.dumps(record, sort_keys=True) == before


def test_a_record_signed_outside_its_key_window_is_refused(rotation):
    old, _, document, _, rotated, _ = rotation
    directory = load_directory(document)
    # Signed after the key was retired: arithmetically valid, not authorized.
    late = sign_change_record(decision(rotated + timedelta(days=2)), old)
    with pytest.raises(ReceiptVerificationError):
        verify_change_record_with_directory(late, directory, **SCOPE)


def test_revocation_invalidates_every_record_including_historical_ones(rotation):
    old, new, _, start, rotated, end = rotation
    revoked = serialize_directory(
        "threatveil",
        [
            entry(old, "REVOKED", start, rotated, revoked_at=rotated),
            entry(new, "ACTIVE", rotated, end),
        ],
    )
    directory = load_directory(revoked)
    historical = sign_change_record(decision(start + timedelta(days=1)), old)
    with pytest.raises(ReceiptVerificationError):
        verify_change_record_with_directory(historical, directory, **SCOPE)
    # The uncompromised key is unaffected by its predecessor's revocation.
    assert verify_change_record_with_directory(
        sign_change_record(decision(rotated + timedelta(days=1)), new), directory, **SCOPE
    )


def test_unknown_and_wrong_keys_fail_closed(rotation):
    _, _, document, _, rotated, _ = rotation
    directory = load_directory(document)
    stranger = Ed25519PrivateKey.generate()
    record = sign_change_record(decision(rotated + timedelta(days=1)), stranger)
    with pytest.raises(ReceiptVerificationError):
        verify_change_record_with_directory(record, directory, **SCOPE)
    with pytest.raises(TrustError):
        resolve_verification_key(directory, "0" * 64)
    # The single-key verifier still refuses a key that did not sign the record.
    with pytest.raises(ReceiptVerificationError):
        verify_change_record(record, Ed25519PrivateKey.generate().public_key(), **SCOPE)


def test_a_tampered_record_fails_under_a_valid_directory(rotation):
    _, new, document, _, rotated, _ = rotation
    directory = load_directory(document)
    record = sign_change_record(decision(rotated + timedelta(days=1)), new)
    record["payload"] = record["payload"][:-8] + "AAAAAAAA"
    with pytest.raises(ReceiptVerificationError):
        verify_change_record_with_directory(record, directory, **SCOPE)


def test_a_tampered_directory_is_rejected_before_any_verification(rotation):
    old, new, document, start, rotated, end = rotation
    stranger = Ed25519PrivateKey.generate()

    # Substituting key material under an existing identifier is detected.
    forged = json.loads(json.dumps(document))
    forged["keys"][1]["public_key_pem"] = pem(stranger)
    with pytest.raises(TrustError):
        load_directory(forged)

    # So is renaming a key, promoting two signers, or omitting the profile.
    renamed = json.loads(json.dumps(document))
    renamed["keys"][0]["keyid"] = "f" * 64
    with pytest.raises(TrustError):
        load_directory(renamed)
    two_active = serialize_directory(
        "threatveil", [entry(old, "ACTIVE", start, end), entry(new, "ACTIVE", rotated, end)]
    )
    with pytest.raises(TrustError):
        load_directory(two_active)
    wrong_profile = json.loads(json.dumps(document))
    wrong_profile["schema_version"] = "something-else"
    with pytest.raises(TrustError):
        load_directory(wrong_profile)


def test_a_directory_may_never_carry_private_material(rotation):
    old, _, document, start, rotated, _ = rotation
    leaked = json.loads(json.dumps(document))
    leaked["keys"][0]["public_key_pem"] = old.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    with pytest.raises(TrustError):
        load_directory(leaked)
    assert "PRIVATE" not in json.dumps(document)


def test_revoked_entries_must_record_when_they_were_revoked(rotation):
    old, _, _, start, rotated, _ = rotation
    inconsistent = serialize_directory("threatveil", [entry(old, "REVOKED", start, rotated)])
    with pytest.raises(TrustError):
        load_directory(inconsistent)
    unbounded = serialize_directory("threatveil", [entry(old, "ACTIVE", start, None)])
    with pytest.raises(TrustError):
        load_directory(unbounded)


def test_published_directory_is_public_and_carries_no_secret_material():
    from starlette.testclient import TestClient

    from threatveil.api import app

    # No session, no API token: an external consumer must be able to fetch this.
    response = TestClient(app).get("/v1/trust/keys")
    assert response.status_code == 200
    document = response.json()
    assert document["schema_version"] == PROFILE
    assert load_directory(document)["issuer"]
    body = response.text
    assert "PRIVATE" not in body and "BEGIN OPENSSH" not in body
    assert response.headers["cache-control"].startswith("public")
    # The published document is exactly what an external verifier consumes.
    assert all(item["status"] in {"ACTIVE", "RETIRED", "REVOKED"} for item in document["keys"])


def test_the_service_refuses_to_publish_a_directory_that_omits_its_signer(tmp_path, monkeypatch):
    from threatveil import trust

    stranger = Ed25519PrivateKey.generate()
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    document = serialize_directory(
        "threatveil", [entry(stranger, "ACTIVE", start, start + timedelta(days=365))]
    )
    path = tmp_path / "trust.json"
    path.write_text(json.dumps(document))
    base = trust.settings()
    monkeypatch.setattr(
        trust, "settings", lambda: base.model_copy(update={"trust_directory_path": str(path)})
    )
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as failure:
        trust.directory_document()
    assert failure.value.status_code == 503

    # A directory that does list this signer as active is published as provisioned.
    active = trust._active_public_key()
    document["keys"].append(
        {
            "keyid": key_id(active),
            "algorithm": "Ed25519",
            "signature_profile": ALGORITHMS["Ed25519"],
            "status": "ACTIVE",
            "valid_from": start.isoformat(),
            "valid_until": (start + timedelta(days=365)).isoformat(),
            "revoked_at": None,
            "public_key_pem": active.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            "supersedes": None,
        }
    )
    document["keys"][0]["status"] = "RETIRED"
    path.write_text(json.dumps(document))
    published = trust.directory_document()
    assert published["trust"] == "OPERATOR_PROVISIONED"
    assert trust.rotation_state()["active_key_id"] == key_id(active)
    assert trust.rotation_state()["retired"] == 1
