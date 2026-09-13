"""Trust distribution for ThreatVeil records: keyid to public verification key.

A signed record is only durable evidence if a stranger can resolve the key that
signed it years later. This module defines that resolution and its rotation
semantics. It contains no secret material and never reaches the ThreatVeil API,
so an independent verifier can use it with a directory obtained out of band.

Rotation semantics, stated once and enforced here:

* ACTIVE   — may sign new records; verifies records inside its validity window.
* RETIRED  — must not sign new records; still verifies records that were signed
             inside its validity window. Rotation therefore never invalidates
             history.
* REVOKED  — the private key is considered compromised. Genuine and forged
             signatures can no longer be distinguished, so nothing signed by it
             verifies, whatever its date.
"""

import base64
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROFILE = "threatveil-trust-directory/v1"
STATUSES = ("ACTIVE", "RETIRED", "REVOKED")
ALGORITHMS = {"Ed25519": "dsse-in-toto-ed25519/v1"}


class TrustError(ValueError):
    """Raised when a directory is malformed or a key cannot be trusted."""


def _aware(value, label):
    if not isinstance(value, str):
        raise TrustError(f"{label} must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise TrustError(f"{label} is not a valid timestamp") from None
    if parsed.tzinfo is None:
        raise TrustError(f"{label} requires a timezone")
    return parsed


def _public_key(entry):
    material = entry.get("public_key_pem")
    if not isinstance(material, str) or "PUBLIC KEY" not in material:
        raise TrustError("Directory entries carry a PEM public key and never secret material")
    if "PRIVATE" in material:
        raise TrustError("A trust directory must never contain private key material")
    try:
        key = serialization.load_pem_public_key(material.encode())
    except (ValueError, TypeError):
        raise TrustError("Unreadable public key in trust directory") from None
    if not isinstance(key, Ed25519PublicKey):
        raise TrustError("Only Ed25519 verification keys are implemented")
    return key


def key_id(key: Ed25519PublicKey) -> str:
    """The DSSE keyid ThreatVeil emits: SHA-256 over the raw public key."""
    import hashlib

    return hashlib.sha256(
        key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).hexdigest()


def load_directory(document: dict) -> dict:
    """Validate a directory document without trusting any field to be well formed."""
    if not isinstance(document, dict):
        raise TrustError("A trust directory must be a JSON object")
    if document.get("schema_version") != PROFILE:
        raise TrustError("Unknown trust directory profile")
    issuer = document.get("issuer")
    if not isinstance(issuer, str) or not 1 <= len(issuer) <= 200:
        raise TrustError("A trust directory names exactly one issuer")
    entries = document.get("keys")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 200:
        raise TrustError("A trust directory lists between one and two hundred keys")
    seen, validated, active = set(), [], 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise TrustError("Each directory entry must be an object")
        algorithm = entry.get("algorithm")
        if algorithm not in ALGORITHMS:
            raise TrustError("Unsupported signing algorithm in trust directory")
        if entry.get("signature_profile") != ALGORITHMS[algorithm]:
            raise TrustError("Directory entry profile does not match its algorithm")
        status = entry.get("status")
        if status not in STATUSES:
            raise TrustError("Unknown trust directory key status")
        key = _public_key(entry)
        identifier = entry.get("keyid")
        # The identifier is derived, never asserted: a directory cannot rename a key.
        if identifier != key_id(key):
            raise TrustError("Directory keyid does not match its public key")
        if identifier in seen:
            raise TrustError("Duplicate keyid in trust directory")
        seen.add(identifier)
        valid_from = _aware(entry.get("valid_from"), "valid_from")
        valid_until = (
            _aware(entry["valid_until"], "valid_until")
            if entry.get("valid_until") is not None
            else None
        )
        if valid_until is not None and valid_until <= valid_from:
            raise TrustError("A key validity window must be ordered")
        revoked_at = (
            _aware(entry["revoked_at"], "revoked_at")
            if entry.get("revoked_at") is not None
            else None
        )
        if (status == "REVOKED") != (revoked_at is not None):
            raise TrustError("A revoked key records exactly when it was revoked")
        if status == "ACTIVE":
            active += 1
            if valid_until is None:
                raise TrustError("An active signing key must declare its validity end")
        if status == "RETIRED" and valid_until is None:
            raise TrustError("A retired key must record when it stopped signing")
        validated.append(
            {
                "keyid": identifier,
                "algorithm": algorithm,
                "signature_profile": entry["signature_profile"],
                "status": status,
                "valid_from": valid_from,
                "valid_until": valid_until,
                "revoked_at": revoked_at,
                "revocation_reason": entry.get("revocation_reason"),
                "public_key": key,
                "supersedes": entry.get("supersedes"),
            }
        )
    if active > 1:
        raise TrustError("Exactly one key may be active for new issuance")
    return {"issuer": issuer, "keys": {item["keyid"]: item for item in validated}}


def resolve_verification_key(directory: dict, keyid: str, *, signed_at=None):
    """Return the entry that may verify a record, or explain why none may.

    `signed_at` is the record's own `not_before`. A record signed outside a key's
    validity window is refused even when the signature itself is arithmetically
    valid: the key was not authorized to make that statement at that time.
    """
    entry = directory.get("keys", {}).get(keyid)
    if entry is None:
        raise TrustError("No directory entry for this signing key")
    if entry["status"] == "REVOKED":
        raise TrustError("This signing key is revoked; records signed by it are not trusted")
    if signed_at is not None:
        if signed_at.tzinfo is None:
            raise TrustError("A signing time requires a timezone")
        if signed_at < entry["valid_from"]:
            raise TrustError("The record predates this key's validity window")
        if entry["valid_until"] is not None and signed_at >= entry["valid_until"]:
            raise TrustError("The record was signed after this key's validity window")
    return entry


def verify_change_record_with_directory(envelope, directory: dict, **expected):
    """Verify against a directory the caller trusts, rather than a single key.

    Offline verification establishes a historical statement. It cannot establish
    that the decision is still current; that requires the record's status URI.
    """
    from .change_records import ReceiptVerificationError, read_receipt

    envelope_document = read_receipt(envelope)
    signatures = envelope_document.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise ReceiptVerificationError("Exactly one signature is required")
    keyid = signatures[0].get("keyid")
    if not isinstance(keyid, str):
        raise ReceiptVerificationError("The signature carries no key identifier")
    payload = envelope_document.get("payload")
    signed_at = None
    if isinstance(payload, str):
        try:
            decision = read_receipt(base64.b64decode(payload, validate=True))
            signed_at = datetime.fromisoformat(decision["predicate"]["not_before"])
        except (ValueError, TypeError, KeyError):
            signed_at = None
    try:
        entry = resolve_verification_key(directory, keyid, signed_at=signed_at)
    except TrustError as error:
        raise ReceiptVerificationError(str(error)) from None
    from .change_records import verify_change_record

    return verify_change_record(envelope, entry["public_key"], **expected)


def serialize_directory(issuer: str, entries: list[dict]) -> dict:
    """Render a directory document. Callers supply public keys only."""
    return {
        "schema_version": PROFILE,
        "issuer": issuer,
        "keys": entries,
        "limitations": [
            "A directory establishes which key signed a record, never that the record's "
            "decision is still current.",
            "Retiring a key does not invalidate records it signed inside its window.",
            "A revoked key invalidates every record signed by it, including historical ones.",
        ],
    }
