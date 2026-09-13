"""Independent verification for versioned, scoped change authorization records.

Uses the existing DSSE/in-toto encoding. Algorithm identifiers are explicit;
unknown profiles fail closed. A verified signature does not verify current status.
"""

import base64
import hashlib
import json
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .receipts import PAYLOAD_TYPE, STATEMENT_TYPE, ReceiptVerificationError, dsse_pae, read_receipt

PROFILE = "https://threatveil.com/attestation/change-authorization/v1"


def sign_change_record(decision, key):
    if not isinstance(key, Ed25519PrivateKey):
        raise ReceiptVerificationError("Unsupported signing profile; Ed25519 key required")
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    statement = {"_type": STATEMENT_TYPE,
        "subject": [{"name": decision["system_id"], "digest": {"sha256": decision["state_digest"]}}],
        "predicateType": PROFILE, "predicate": decision}
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    return {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": hashlib.sha256(public).hexdigest(),
                        "sig": base64.b64encode(key.sign(dsse_pae(PAYLOAD_TYPE, payload))).decode()}]}


def verify_change_record(envelope, public_key, *, organization_id, system_id,
                         environment_id, state_digest, audience, at=None):
    envelope = read_receipt(envelope)
    if not isinstance(public_key, Ed25519PublicKey):
        raise ReceiptVerificationError("An independently trusted Ed25519 public key is required")
    try:
        if envelope["payloadType"] != PAYLOAD_TYPE or len(envelope["signatures"]) != 1:
            raise ValueError()
        payload = base64.b64decode(envelope["payload"], validate=True)
        signature = envelope["signatures"][0]
        public = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if signature["keyid"] != hashlib.sha256(public).hexdigest():
            raise ValueError()
        public_key.verify(base64.b64decode(signature["sig"], validate=True), dsse_pae(PAYLOAD_TYPE, payload))
        statement = read_receipt(payload)
        decision = statement["predicate"]
        if statement["_type"] != STATEMENT_TYPE or statement["predicateType"] != PROFILE:
            raise ValueError()
        expected = {"organization_id": organization_id, "system_id": system_id,
                    "environment_id": environment_id, "state_digest": state_digest, "audience": audience}
        if any(decision[k] != str(v) for k, v in expected.items()):
            raise ValueError()
        if statement["subject"] != [{"name": str(system_id), "digest": {"sha256": state_digest}}]:
            raise ValueError()
        if decision["schema_version"] != "change-assurance/v1" or decision["signature_profile"] != "dsse-in-toto-ed25519/v1":
            raise ValueError()
        if decision["algorithm"] != "Ed25519" or decision["action"] not in {"ALLOW", "WARN", "BLOCK", "REQUIRE_APPROVAL"}:
            raise ValueError()
        start, end = datetime.fromisoformat(decision["not_before"]), datetime.fromisoformat(decision["expires_at"])
        if not start.tzinfo or not end.tzinfo or end <= start or (at is not None and not start <= at < end):
            raise ValueError()
        return statement
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        raise ReceiptVerificationError("Invalid, expired or differently scoped change record") from exc
