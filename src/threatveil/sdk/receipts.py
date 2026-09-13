"""Offline DSSE/in-toto release receipts; no hosted state or implicit key trust.

The public key and expected tenant/candidate must come from the verifier's own
trusted configuration. A valid signature proves the issuer signed a historical
decision. It is not a new evaluation or proof that an exception is still active.
"""

import argparse
import base64
import binascii
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://threatveil.com/attestation/release-decision/v1"
MAX_RECEIPT_BYTES = 1_000_000
HEX256 = re.compile(r"[0-9a-f]{64}")
ACTIONS = {"ALLOW", "WARN", "BLOCK"}


class ReceiptVerificationError(ValueError):
    """Malformed, untrusted or differently scoped receipt."""


def _json_bytes(value):
    try:
        result = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ReceiptVerificationError("Receipt must contain finite JSON values") from None
    if len(result) > MAX_RECEIPT_BYTES:
        raise ReceiptVerificationError("Receipt exceeds 1 MB")
    return result


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptVerificationError("Duplicate JSON key")
        result[key] = value
    return result


def _constant(_value):
    raise ReceiptVerificationError("Non-finite JSON value")


def read_receipt(value):
    """Parse once, rejecting ambiguous JSON before any signature processing."""
    if isinstance(value, dict):
        value = _json_bytes(value)
    if not isinstance(value, (str, bytes)) or len(value) > MAX_RECEIPT_BYTES:
        raise ReceiptVerificationError("Receipt must be bounded JSON")
    try:
        result = json.loads(value, object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ReceiptVerificationError("Invalid or ambiguous receipt JSON") from None
    if not isinstance(result, dict):
        raise ReceiptVerificationError("Receipt must be a JSON object")
    return result


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding; lengths count UTF-8 bytes."""
    encoded_type = payload_type.encode("utf-8")
    return b" ".join(
        (
            b"DSSEv1",
            str(len(encoded_type)).encode(),
            encoded_type,
            str(len(payload)).encode(),
            payload,
        )
    )


def _text(value, label):
    if not isinstance(value, str) or not value.strip() or len(value) > 1000:
        raise ReceiptVerificationError(f"Missing or invalid {label}")


def _hex256(value, label):
    if not isinstance(value, str) or not HEX256.fullmatch(value):
        raise ReceiptVerificationError(f"Invalid SHA-256 {label}")


def _candidate(value):
    if not isinstance(value, dict):
        raise ReceiptVerificationError("Exact candidate required")
    for key in ("type", "id", "version", "digest"):
        _text(value.get(key), "candidate " + key)
    if value["type"] == "git_commit":
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value["digest"]):
            raise ReceiptVerificationError("Invalid Git object digest")
        if value["version"] != value["digest"]:
            raise ReceiptVerificationError("Git version and digest differ")
    elif value["type"] in {"application_version", "model_version"}:
        _hex256(value["digest"], "candidate")
    else:
        raise ReceiptVerificationError("Unsupported candidate type")


def _decision(decision):
    if not isinstance(decision, dict):
        raise ReceiptVerificationError("Decision must be an object")
    for key in ("id", "organization_id", "system_id", "evaluated_at"):
        _text(decision.get(key), key)
    _hex256(decision.get("candidate_fingerprint_digest"), "candidate fingerprint")
    _candidate(decision.get("candidate"))
    try:
        if datetime.fromisoformat(decision["evaluated_at"]).tzinfo is None:
            raise ValueError()
    except ValueError:
        raise ReceiptVerificationError(
            "Decision requires a timezone-aware evaluation time"
        ) from None
    for key in ("release_action", "underlying_action"):
        if not isinstance(decision.get(key), str) or decision[key] not in ACTIONS:
            raise ReceiptVerificationError("Invalid " + key)
    policy = decision.get("policy")
    if not isinstance(policy, dict) or policy.get("mode") not in ("OBSERVE", "WARN", "BLOCK"):
        raise ReceiptVerificationError("Explicit OBSERVE/WARN/BLOCK policy required")
    modes = policy.get("property_modes")
    if not isinstance(modes, dict) or any(
        not isinstance(key, str) or value not in ("OBSERVE", "WARN", "BLOCK")
        for key, value in modes.items()
    ):
        raise ReceiptVerificationError("Invalid property policy modes")
    for key in ("properties", "exceptions", "limitations"):
        if not isinstance(decision.get(key), list) or len(decision[key]) > 500:
            raise ReceiptVerificationError("A bounded " + key + " list is required")
    if any(not isinstance(item, str) for item in decision["limitations"]):
        raise ReceiptVerificationError("Limitations must be text")
    if any(not isinstance(item, dict) for item in decision["exceptions"]):
        raise ReceiptVerificationError("Exception snapshots must be objects")
    seen = set()
    for row in decision["properties"]:
        if not isinstance(row, dict):
            raise ReceiptVerificationError("Property result must be an object")
        _text(row.get("property_id"), "property identity")
        if row["property_id"] in seen:
            raise ReceiptVerificationError("Duplicate property identity")
        seen.add(row["property_id"])
        if (
            "evidence_id" not in row
            or row["evidence_id"] is not None
            and not isinstance(row["evidence_id"], str)
        ):
            raise ReceiptVerificationError("Explicit evidence reference or null required")
        enums = {
            "validity": ("STILL_VALID", "VOID", "UNKNOWN", "INCOMPATIBLE"),
            "security_verdict": ("PASS", "FAIL", "INCONCLUSIVE", "UNKNOWN"),
            "task_outcome": ("SUCCESS", "FAILURE", "UNKNOWN"),
            "release_action": ("ALLOW", "WARN", "BLOCK"),
        }
        for key, values in enums.items():
            if row.get(key) not in values:
                raise ReceiptVerificationError("Invalid property " + key)
        if not isinstance(row.get("reasons"), list) or any(
            not isinstance(reason, str) for reason in row["reasons"]
        ):
            raise ReceiptVerificationError("Property reasons must be text")
    return decision


def _private_key(key):
    if isinstance(key, str):
        key = key.encode()
    if isinstance(key, bytes):
        key = serialization.load_pem_private_key(key, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ReceiptVerificationError("An Ed25519 private signing key is required")
    return key


def _public_key(key):
    if isinstance(key, str):
        key = key.encode()
    if isinstance(key, bytes):
        key = serialization.load_pem_public_key(key)
    if not isinstance(key, Ed25519PublicKey):
        raise ReceiptVerificationError("An externally trusted Ed25519 public key is required")
    return key


def public_key_id(key):
    key = _public_key(key)
    return hashlib.sha256(
        key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()


def sign_release_receipt(decision: dict, private_key) -> dict:
    """Sign an already authorized immutable snapshot; never decide release policy."""
    decision = _decision(read_receipt(decision))
    key = _private_key(private_key)
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": f"threatveil:system:{decision['system_id']}",
                "digest": {"sha256": decision["candidate_fingerprint_digest"]},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": decision,
    }
    payload = _json_bytes(statement)
    envelope = {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {
                "keyid": public_key_id(key.public_key()),
                "sig": base64.b64encode(key.sign(dsse_pae(PAYLOAD_TYPE, payload))).decode(),
            }
        ],
    }
    _json_bytes(envelope)
    return envelope


def _decode(value):
    if not isinstance(value, str) or not value or len(value) > MAX_RECEIPT_BYTES:
        raise ReceiptVerificationError("Invalid base64 value")
    try:
        # DSSE requires both standard and URL-safe base64. Accept padding-free
        # encodings too, but reject whitespace, stray padding and nonzero pad bits.
        result = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        normalized = value.replace("-", "+").replace("_", "/")
        if base64.b64encode(result).decode().rstrip("=") != normalized.rstrip("="):
            raise ValueError()
        return result
    except (ValueError, binascii.Error):
        raise ReceiptVerificationError("Invalid base64 value") from None


def verify_release_receipt(
    envelope,
    public_key,
    *,
    expected_candidate_fingerprint_digest: str,
    expected_organization_id: str,
    expected_system_id: str | None = None,
    expected_decision_id: str | None = None,
    expected_candidate: dict | None = None,
) -> dict:
    """Return the verified statement, requiring independent scope expectations."""
    _hex256(expected_candidate_fingerprint_digest, "expected candidate fingerprint")
    _text(expected_organization_id, "expected organization")
    envelope = read_receipt(envelope)
    if set(envelope) != {"payloadType", "payload", "signatures"}:
        raise ReceiptVerificationError("Unsupported DSSE envelope fields")
    if envelope["payloadType"] != PAYLOAD_TYPE:
        raise ReceiptVerificationError("Unsupported DSSE payload type")
    payload = _decode(envelope["payload"])
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or not 1 <= len(signatures) <= 32:
        raise ReceiptVerificationError("A bounded signature list is required")
    key = _public_key(public_key)
    key_id, verified = public_key_id(key), False
    for signature in signatures:
        if not isinstance(signature, dict) or set(signature) - {"keyid", "sig"}:
            raise ReceiptVerificationError("Malformed DSSE signature")
        signature_bytes = _decode(signature.get("sig"))
        if len(signature_bytes) != 64:
            raise ReceiptVerificationError("Invalid Ed25519 signature length")
        if signature.get("keyid", "") not in ("", key_id):
            continue
        try:
            key.verify(signature_bytes, dsse_pae(PAYLOAD_TYPE, payload))
            verified = True
        except InvalidSignature:
            continue
    if not verified:
        raise ReceiptVerificationError("Receipt signature is not from the trusted key")
    # Parse precisely the bytes verified above; never retrieve payload a second time.
    statement = read_receipt(payload)
    if statement.get("_type") != STATEMENT_TYPE or statement.get("predicateType") != PREDICATE_TYPE:
        raise ReceiptVerificationError("Unsupported in-toto statement or release predicate")
    decision = _decision(statement.get("predicate"))
    expected_subject = [
        {
            "name": f"threatveil:system:{decision['system_id']}",
            "digest": {"sha256": decision["candidate_fingerprint_digest"]},
        }
    ]
    if statement.get("subject") != expected_subject:
        raise ReceiptVerificationError("Subject and release candidate differ")
    expectations = {
        "candidate_fingerprint_digest": expected_candidate_fingerprint_digest,
        "organization_id": expected_organization_id,
        "system_id": expected_system_id,
        "id": expected_decision_id,
        "candidate": expected_candidate,
    }
    if any(value is not None and decision.get(key) != value for key, value in expectations.items()):
        raise ReceiptVerificationError("Receipt does not match the expected tenant or candidate")
    return statement


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--candidate-fingerprint", required=True)
    parser.add_argument("--organization", required=True)
    parser.add_argument("--system")
    parser.add_argument("--decision")
    parser.add_argument("--require-action", choices=sorted(ACTIONS))
    args = parser.parse_args()
    try:
        if (
            args.receipt.stat().st_size > MAX_RECEIPT_BYTES
            or args.public_key.stat().st_size > 16000
        ):
            raise ReceiptVerificationError("Input file exceeds size limit")
        statement = verify_release_receipt(
            args.receipt.read_bytes(),
            args.public_key.read_bytes(),
            expected_candidate_fingerprint_digest=args.candidate_fingerprint,
            expected_organization_id=args.organization,
            expected_system_id=args.system,
            expected_decision_id=args.decision,
        )
        if args.require_action and statement["predicate"]["release_action"] != args.require_action:
            raise ReceiptVerificationError(
                "Signed release action does not meet the requested policy"
            )
    except (ValueError, OSError) as error:
        parser.exit(1, f"Receipt verification failed: {error}\n")
    print(
        json.dumps(
            {
                "signature_valid": True,
                "scope_matches": True,
                "historical_decision": statement["predicate"],
                "current_deployment_authorized": False,
                "limitations": [
                    "Offline verification does not re-evaluate evidence or current exceptions."
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
