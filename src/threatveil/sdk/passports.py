"""Independent verification for Current Assurance Passports.

A passport reuses ThreatVeil's existing DSSE/in-toto encoding and Ed25519 profile:
it is a new predicate, not a new cryptographic system. This module has no backend
dependency, so a buyer can verify a passport with a key or trust directory they
obtained themselves.

Offline verification establishes that the issuer signed exactly this statement at
its issue time. It cannot establish that the statement is still current: that is
the separate, online status check named inside the passport. A passport therefore
remains authentic after the system changes, while its current status becomes
SUPERSEDED.
"""

import base64
import hashlib
import json
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .receipts import PAYLOAD_TYPE, STATEMENT_TYPE, ReceiptVerificationError, dsse_pae, read_receipt

PREDICATE = "https://threatveil.com/attestation/assurance-passport/v1"
SCHEMA = "threatveil-assurance-passport/v1"
SIGNATURE_PROFILE = "dsse-in-toto-ed25519/v1"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode()


def _public(key):
    if isinstance(key, (bytes, str)):
        key = serialization.load_pem_public_key(key.encode() if isinstance(key, str) else key)
    if not isinstance(key, Ed25519PublicKey):
        raise ReceiptVerificationError("An independently trusted Ed25519 public key is required")
    return key


def subject_name(passport):
    """The system identifier when disclosed, otherwise its stable pseudonymous reference."""
    system = passport["system"]
    name = system.get("id") or system.get("reference")
    if not isinstance(name, str) or not name:
        raise ReceiptVerificationError("A passport must name its system or carry a system reference")
    return name


def sign_passport(passport, key):
    if not isinstance(key, Ed25519PrivateKey):
        raise ReceiptVerificationError("Unsupported signing profile; Ed25519 key required")
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    statement = {"_type": STATEMENT_TYPE,
                 "subject": [{"name": subject_name(passport), "digest": {"sha256": passport["state"]["digest"]}}],
                 "predicateType": PREDICATE, "predicate": passport}
    payload = _canonical(statement)
    return {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(),
            "signatures": [{"keyid": hashlib.sha256(raw).hexdigest(),
                            "sig": base64.b64encode(key.sign(dsse_pae(PAYLOAD_TYPE, payload))).decode()}]}


def read_passport(envelope):
    """Decode a passport for display. This performs no verification."""
    document = read_receipt(envelope)
    try:
        return read_receipt(base64.b64decode(document["payload"], validate=True))["predicate"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ReceiptVerificationError("Unreadable passport envelope") from exc


def verify_passport(envelope, public_key, *, passport_id=None, organization_id=None,
                    system_id=None, system_reference=None, at=None):
    """Verify authenticity against a key the caller already trusts.

    Returns the verified in-toto statement. `at` optionally checks the passport's
    own validity window; omitting it verifies the historical statement only.

    A passport issued under the STANDARD disclosure profile withholds internal
    identifiers. Expecting one of those identifiers then fails, by design: verify
    such a passport against its `system_reference` instead.
    """
    envelope = read_receipt(envelope)
    key = _public(public_key)
    try:
        if envelope["payloadType"] != PAYLOAD_TYPE or len(envelope["signatures"]) != 1:
            raise ValueError()
        payload = base64.b64decode(envelope["payload"], validate=True)
        signature = envelope["signatures"][0]
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if signature["keyid"] != hashlib.sha256(raw).hexdigest():
            raise ValueError()
        key.verify(base64.b64decode(signature["sig"], validate=True), dsse_pae(PAYLOAD_TYPE, payload))
        statement = read_receipt(payload)
        passport = statement["predicate"]
        if statement["_type"] != STATEMENT_TYPE or statement["predicateType"] != PREDICATE:
            raise ValueError()
        if passport["schema_version"] != SCHEMA or passport["signature_profile"] != SIGNATURE_PROFILE:
            raise ValueError()
        if passport["algorithm"] != "Ed25519":
            raise ValueError()
        if statement["subject"] != [{"name": subject_name(passport),
                                     "digest": {"sha256": passport["state"]["digest"]}}]:
            raise ValueError()
        expected = {"passport_id": passport_id, "organization_id": organization_id, "system_id": system_id,
                    "system_reference": system_reference}
        actual = {"passport_id": passport["passport_id"],
                  "organization_id": passport["organization"].get("id"),
                  "system_id": passport["system"].get("id"),
                  "system_reference": passport["system"].get("reference")}
        if any(value is not None and actual[name] != str(value) for name, value in expected.items()):
            raise ValueError()
        issued, expires = datetime.fromisoformat(passport["issued_at"]), datetime.fromisoformat(passport["expires_at"])
        if not issued.tzinfo or not expires.tzinfo or expires <= issued or (at is not None and not issued <= at < expires):
            raise ValueError()
        return statement
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        raise ReceiptVerificationError("Invalid, expired or differently scoped assurance passport") from exc


def verify_passport_with_directory(envelope, directory, **expected):
    """Resolve the signing key from a trust directory the caller trusts, then verify.

    The key must have been valid at the passport's issue time and must not be
    revoked. This still establishes authenticity only, never current status.
    """
    from .trust_directory import TrustError, resolve_verification_key

    document = read_receipt(envelope)
    signatures = document.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1 or not isinstance(signatures[0].get("keyid"), str):
        raise ReceiptVerificationError("Exactly one keyed signature is required")
    try:
        issued = datetime.fromisoformat(read_passport(document)["issued_at"])
    except (KeyError, TypeError, ValueError):
        issued = None
    try:
        entry = resolve_verification_key(directory, signatures[0]["keyid"], signed_at=issued)
    except TrustError as error:
        raise ReceiptVerificationError(str(error)) from None
    return verify_passport(document, entry["public_key"], **expected)
