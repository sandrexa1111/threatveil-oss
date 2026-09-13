"""Published trust root for ThreatVeil records.

A record is durable evidence only if a third party can resolve the key that signed
it without asking ThreatVeil for permission. This module serves that directory. It
reads public key material only; the active private key never leaves the signer.

The directory is control-plane state, not tenant state: it is identical for every
organization and is therefore served without authentication and without RLS.
"""

import json
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from .config import settings
from .sdk.trust_directory import (
    ALGORITHMS,
    PROFILE,
    TrustError,
    key_id,
    load_directory,
    serialize_directory,
)

router = APIRouter(prefix="/v1/trust", tags=["trust"])
MAX_DIRECTORY_BYTES = 262144


def _pem(public_key) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def _active_public_key(configuration=None):
    """Resolve the public half of the key this service signs with."""
    if configuration is not None and configuration.receipt_signing_private_key:
        return serialization.load_pem_private_key(
            configuration.receipt_signing_private_key.encode(), None
        ).public_key()
    from .release_signing import signing_key

    return signing_key().public_key()


def _derived(public_key, configuration) -> dict:
    """A single-key directory for an environment with no operator-managed history.

    The window is configured and stable, so a record signed yesterday still falls
    inside the same window tomorrow.
    """
    entry = {
        "keyid": key_id(public_key),
        "algorithm": "Ed25519",
        "signature_profile": ALGORITHMS["Ed25519"],
        "status": "ACTIVE",
        "valid_from": configuration.trust_key_valid_from,
        "valid_until": configuration.trust_key_valid_until,
        "revoked_at": None,
        "public_key_pem": _pem(public_key),
        "supersedes": None,
    }
    document = serialize_directory(configuration.trust_issuer, [entry])
    document["trust"] = (
        "LOCAL_DEMONSTRATION" if not configuration.receipt_signing_private_key else "DERIVED"
    )
    document["limitations"] = [
        *document["limitations"],
        "This directory was derived from the running signing key rather than an "
        "operator-managed rotation history.",
    ]
    return document


def directory_document(configuration=None) -> dict:
    """Build the servable directory, refusing to publish one that omits the signer."""
    configuration = configuration or settings()
    public_key = _active_public_key(configuration)
    path = configuration.trust_directory_path
    if not path:
        return _derived(public_key, configuration)
    location = Path(path)
    try:
        raw = location.read_bytes()
    except OSError:
        raise HTTPException(503, "The configured trust directory could not be read") from None
    if len(raw) > MAX_DIRECTORY_BYTES:
        raise HTTPException(503, "The configured trust directory exceeds its bound")
    try:
        document = json.loads(raw)
        parsed = load_directory(document)
    except (ValueError, TrustError) as error:
        raise HTTPException(503, f"The configured trust directory is invalid: {error}") from None
    identifier = key_id(public_key)
    entry = parsed["keys"].get(identifier)
    if entry is None or entry["status"] != "ACTIVE":
        # Publishing a directory that cannot verify what this service signs would
        # produce unverifiable records for as long as the mistake went unnoticed.
        raise HTTPException(503, "The trust directory does not list this signer as active")
    document["trust"] = "OPERATOR_PROVISIONED"
    return document


def rotation_state(configuration=None) -> dict:
    """Operational summary used by the read-only activation preflight."""
    configuration = configuration or settings()
    try:
        document = directory_document(configuration)
    except HTTPException as error:
        return {"configured": bool(configuration.trust_directory_path), "error": error.detail}
    keys = document["keys"]
    now = datetime.now().astimezone()
    active = next((k for k in keys if k["status"] == "ACTIVE"), None)
    expiry = datetime.fromisoformat(active["valid_until"]) if active else None
    return {
        "configured": bool(configuration.trust_directory_path),
        "trust": document["trust"],
        "issuer": document["issuer"],
        "key_count": len(keys),
        "active_key_id": active["keyid"] if active else None,
        "active_expires_at": active["valid_until"] if active else None,
        "active_expires_in_days": (expiry - now).days if expiry else None,
        "retired": sum(1 for k in keys if k["status"] == "RETIRED"),
        "revoked": sum(1 for k in keys if k["status"] == "REVOKED"),
    }


@router.get("/keys")
def published_keys():
    """Public verification material. Safe to cache and to mirror."""
    document = directory_document()
    return JSONResponse(
        document,
        headers={
            "Cache-Control": "public, max-age=300",
            "X-ThreatVeil-Trust-Profile": PROFILE,
        },
    )
