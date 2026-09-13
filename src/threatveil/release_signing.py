"""Control-plane signing; an operator-provisioned key is mandatory outside local tests."""

import fcntl
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException

from .config import settings
from .sdk.receipts import sign_release_receipt


def signing_key():
    cfg = settings()
    if cfg.receipt_signing_private_key:
        return serialization.load_pem_private_key(cfg.receipt_signing_private_key.encode(), None)
    if not cfg.is_local:
        raise HTTPException(503, "Release signing key is not provisioned; no signed decision was issued")
    path = Path(".local/receipt-signing/key.pem")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # The local demonstration key is stable across restarts, never a public trust root.
    with os.fdopen(os.open(path.parent / "key.lock", os.O_RDWR | os.O_CREAT, 0o600), "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not path.exists():
            pem = Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
                output.write(pem)
        if path.stat().st_mode & 0o077:
            raise HTTPException(503, "Local signing key permissions must be 0600")
        return serialization.load_pem_private_key(path.read_bytes(), None)


def sign_decision(decision):
    key = signing_key()
    if not isinstance(key, Ed25519PrivateKey):
        raise HTTPException(503, "Receipt signing requires an Ed25519 private key")
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return {
        "envelope": sign_release_receipt(decision, key),
        "public_key_pem": public,
        "trust": "LOCAL_DEMONSTRATION" if not settings().receipt_signing_private_key else "OPERATOR_PROVISIONED",
        "transparency_log": None,
        "limitations": [
            "Verify with a separately trusted public key; the key bundled here is informational.",
            "DSSE/in-toto with Ed25519; no Sigstore identity or transparency-log inclusion is claimed.",
        ],
    }
