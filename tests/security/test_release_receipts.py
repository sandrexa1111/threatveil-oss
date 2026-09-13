import base64
import copy
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from threatveil.sdk import receipts


@pytest.fixture
def decision():
    return {
        "id": "release-123",
        "organization_id": "org-123",
        "system_id": "system-123",
        "evaluated_at": "2026-09-10T10:00:00+00:00",
        "candidate_fingerprint_digest": "a" * 64,
        "candidate": {"type": "git_commit", "id": "456", "version": "b" * 40, "digest": "b" * 40},
        "release_action": "BLOCK",
        "underlying_action": "BLOCK",
        "policy": {"mode": "BLOCK", "property_modes": {}},
        "properties": [
            {
                "property_id": "property-123",
                "evidence_id": "evidence-123",
                "validity": "VOID",
                "security_verdict": "FAIL",
                "task_outcome": "SUCCESS",
                "release_action": "BLOCK",
                "reasons": ["Qualified ledger confirms an unauthorized mutation"],
            }
        ],
        "exceptions": [],
        "limitations": ["Bounded staging execution"],
        "lineage": {"previous_release_id": "release-122"},
    }


def verify(envelope, key, **overrides):
    return receipts.verify_release_receipt(
        envelope,
        key.public_key(),
        **{
            "expected_candidate_fingerprint_digest": "a" * 64,
            "expected_organization_id": "org-123",
            "expected_system_id": "system-123",
            **overrides,
        },
    )


def test_dsse_protocol_reference_vector_and_utf8_lengths():
    assert receipts.dsse_pae("http://example.com/HelloWorld", b"hello world") == (
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    )
    assert receipts.dsse_pae("é", b"hi") == b"DSSEv1 2 \xc3\xa9 2 hi"


def test_standard_signature_can_be_verified_without_threatveil_helpers(decision):
    key = Ed25519PrivateKey.generate()
    envelope = receipts.sign_release_receipt(decision, key)
    payload = base64.b64decode(envelope["payload"])
    # Independently reconstruct DSSE bytes and use only standard Ed25519 verification.
    message = (
        b"DSSEv1 28 application/vnd.in-toto+json " + str(len(payload)).encode() + b" " + payload
    )
    key.public_key().verify(base64.b64decode(envelope["signatures"][0]["sig"]), message)
    statement = verify(json.dumps(envelope), key)
    assert statement["predicate"] == decision
    assert statement["subject"][0]["digest"] == {"sha256": "a" * 64}
    assert statement["predicate"]["candidate"]["digest"] == "b" * 40
    assert statement["predicate"]["lineage"] == decision["lineage"]


def test_signing_is_deterministic_with_frozen_snapshot_and_pem(decision):
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    envelope = receipts.sign_release_receipt(decision, pem)
    assert envelope == receipts.sign_release_receipt(copy.deepcopy(decision), key)
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    result = receipts.verify_release_receipt(
        envelope,
        public,
        expected_candidate_fingerprint_digest="a" * 64,
        expected_organization_id="org-123",
    )
    assert result["predicate"]["release_action"] == "BLOCK"


@pytest.mark.parametrize(
    "field,value",
    [
        ("release_action", "ALLOW"),
        ("organization_id", "another-org"),
        ("candidate_fingerprint_digest", "c" * 64),
        ("exceptions", [{"approved": True}]),
        ("lineage", {}),
    ],
)
def test_tampering_with_any_signed_field_is_rejected(decision, field, value):
    key = Ed25519PrivateKey.generate()
    envelope = receipts.sign_release_receipt(decision, key)
    statement = json.loads(base64.b64decode(envelope["payload"]))
    statement["predicate"][field] = value
    envelope["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
    with pytest.raises(receipts.ReceiptVerificationError, match="signature"):
        verify(envelope, key)


@pytest.mark.parametrize(
    "overrides",
    [
        {"expected_organization_id": "another-org"},
        {"expected_system_id": "another-system"},
        {"expected_candidate_fingerprint_digest": "c" * 64},
        {"expected_decision_id": "another-release"},
        {"expected_candidate": {"type": "git_commit", "digest": "d" * 40}},
    ],
)
def test_valid_signature_does_not_make_receipt_applicable_to_another_scope(decision, overrides):
    key = Ed25519PrivateKey.generate()
    envelope = receipts.sign_release_receipt(decision, key)
    with pytest.raises(receipts.ReceiptVerificationError, match="expected tenant or candidate"):
        verify(envelope, key, **overrides)


def test_untrusted_key_and_injected_embedded_key_are_rejected(decision):
    trusted, attacker = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    envelope = receipts.sign_release_receipt(decision, attacker)
    with pytest.raises(receipts.ReceiptVerificationError, match="trusted key"):
        verify(envelope, trusted)
    envelope["publicKey"] = "attacker-provided"
    with pytest.raises(receipts.ReceiptVerificationError, match="envelope fields"):
        verify(envelope, attacker)


def test_payload_type_is_authenticated_and_constrained(decision):
    key = Ed25519PrivateKey.generate()
    envelope = receipts.sign_release_receipt(decision, key)
    envelope["payloadType"] = "application/json"
    with pytest.raises(receipts.ReceiptVerificationError, match="payload type"):
        verify(envelope, key)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"payload": "a", "payload": "b"}',
        b'{"x": NaN}',
        b'{"x": Infinity}',
        b'{"x": {"y": 1, "y": 2}}',
    ],
)
def test_ambiguous_json_is_rejected(raw):
    with pytest.raises(receipts.ReceiptVerificationError):
        receipts.read_receipt(raw)


def test_duplicate_key_in_validly_signed_payload_is_rejected(decision):
    key = Ed25519PrivateKey.generate()
    envelope = receipts.sign_release_receipt(decision, key)
    original = base64.b64decode(envelope["payload"])
    payload = original.replace(
        b'"release_action":"BLOCK"', b'"release_action":"ALLOW","release_action":"BLOCK"', 1
    )
    envelope["payload"] = base64.b64encode(payload).decode()
    envelope["signatures"][0]["sig"] = base64.b64encode(
        key.sign(receipts.dsse_pae(receipts.PAYLOAD_TYPE, payload))
    ).decode()
    with pytest.raises(receipts.ReceiptVerificationError, match="ambiguous"):
        verify(envelope, key)


def test_urlsafe_base64_and_optional_keyid_interoperate(decision):
    key = Ed25519PrivateKey.generate()
    envelope = receipts.sign_release_receipt(decision, key)
    for obj, field in ((envelope, "payload"), (envelope["signatures"][0], "sig")):
        obj[field] = obj[field].replace("+", "-").replace("/", "_").rstrip("=")
    del envelope["signatures"][0]["keyid"]
    assert verify(envelope, key)["predicate"]["id"] == decision["id"]


@pytest.mark.parametrize("signature", ["!", "a", "AA==", " A" * 50, "A" * 88 + "======="])
def test_malformed_signature_encoding_is_rejected(decision, signature):
    key = Ed25519PrivateKey.generate()
    envelope = receipts.sign_release_receipt(decision, key)
    envelope["signatures"][0]["sig"] = signature
    with pytest.raises(receipts.ReceiptVerificationError):
        verify(envelope, key)


def test_signing_rejects_missing_scope_and_keeps_override_visible(decision):
    key = Ed25519PrivateKey.generate()
    for field in (
        "organization_id",
        "candidate",
        "candidate_fingerprint_digest",
        "policy",
        "underlying_action",
    ):
        incomplete = {k: v for k, v in decision.items() if k != field}
        with pytest.raises(receipts.ReceiptVerificationError):
            receipts.sign_release_receipt(incomplete, key)
    decision["release_action"] = "WARN"
    decision["exceptions"] = [
        {"id": "exception-1", "approver": "security-owner", "expires_at": "2026-09-10T11:00:00Z"}
    ]
    result = verify(receipts.sign_release_receipt(decision, key), key)["predicate"]
    assert result["underlying_action"] == "BLOCK"
    assert result["properties"][0]["security_verdict"] == "FAIL"
    assert result["exceptions"] == decision["exceptions"]


def test_statement_subject_cannot_disagree_with_signed_candidate(decision):
    key = Ed25519PrivateKey.generate()
    envelope = receipts.sign_release_receipt(decision, key)
    statement = json.loads(base64.b64decode(envelope["payload"]))
    statement["subject"][0]["digest"]["sha256"] = hashlib.sha256(b"another candidate").hexdigest()
    payload = json.dumps(statement).encode()
    envelope["payload"] = base64.b64encode(payload).decode()
    envelope["signatures"][0]["sig"] = base64.b64encode(
        key.sign(receipts.dsse_pae(receipts.PAYLOAD_TYPE, payload))
    ).decode()
    with pytest.raises(receipts.ReceiptVerificationError, match="Subject"):
        verify(envelope, key)


def test_cli_offline_verification_and_required_action(decision, tmp_path, monkeypatch, capsys):
    key = Ed25519PrivateKey.generate()
    receipt, public = tmp_path / "receipt.json", tmp_path / "public.pem"
    receipt.write_text(json.dumps(receipts.sign_release_receipt(decision, key)))
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    argv = [
        "receipts",
        str(receipt),
        "--public-key",
        str(public),
        "--candidate-fingerprint",
        "a" * 64,
        "--organization",
        "org-123",
    ]
    monkeypatch.setattr("sys.argv", argv)
    receipts.main()
    result = json.loads(capsys.readouterr().out)
    assert result["signature_valid"] and not result["current_deployment_authorized"]
    monkeypatch.setattr("sys.argv", argv + ["--require-action", "ALLOW"])
    with pytest.raises(SystemExit) as error:
        receipts.main()
    assert error.value.code == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("evaluated_at", "2026-09-10T12:00:00"),
        ("evaluated_at", "tomorrow"),
        ("candidate_fingerprint_digest", "main"),
        ("underlying_action", []),
        ("policy", {"mode": "WARN", "property_modes": {"x": "ALLOW"}}),
        ("limitations", [123]),
        ("exceptions", ["approved"]),
    ],
)
def test_invalid_decision_metadata_cannot_be_signed(decision, field, value):
    decision[field] = value
    with pytest.raises(receipts.ReceiptVerificationError):
        receipts.sign_release_receipt(decision, Ed25519PrivateKey.generate())
