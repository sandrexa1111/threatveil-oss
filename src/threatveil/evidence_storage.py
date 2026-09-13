"""Content-addressed raw evidence. Only the control plane touches storage."""

import hashlib
import json
import os
import stat
from datetime import datetime, timedelta
from uuid import UUID

from fastapi import HTTPException

from .config import settings
from .db import now
from .local_files import components, directory_fd, read_file, unlink_file

MAX_OBJECT_BYTES = 2 * 1024 * 1024
RAW_RETENTION_DAYS = 30


def object_key(org_id, run_id, sha256):
    if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
        raise ValueError("Invalid object digest")
    return f"raw/{UUID(str(org_id))}/{UUID(str(run_id))}/{sha256}.json"


def store_observation(org_id, run_id, observation, *, retention_days=RAW_RETENTION_DAYS):
    if not 1 <= retention_days <= RAW_RETENTION_DAYS:
        raise ValueError("Raw retention must be between 1 and 30 days")
    data = json.dumps(
        observation, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    if len(data) > MAX_OBJECT_BYTES:
        raise HTTPException(413, "Raw observation exceeds evidence limit")
    sha256 = hashlib.sha256(data).hexdigest()
    key = object_key(org_id, run_id, sha256)
    cfg = settings()
    generation = None
    if cfg.is_local:
        parts = components(key)
        with directory_fd(cfg.evidence_dir, parts[:-1], create=True) as directory:
            try:
                fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=directory)
            except FileExistsError:
                existing = read_file(directory, parts[-1], MAX_OBJECT_BYTES)
                if hashlib.sha256(existing).hexdigest() != sha256:
                    raise RuntimeError("Immutable evidence object integrity failure") from None
            else:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fsync(directory)
    else:
        from google.cloud import storage
        from google.api_core.exceptions import PreconditionFailed

        blob = storage.Client().bucket(cfg.evidence_bucket).blob(key)
        try:
            blob.upload_from_string(
                data, content_type="application/json", if_generation_match=0, timeout=30
            )
        except PreconditionFailed:
            blob.reload(timeout=15)
            if blob.size != len(data):
                raise RuntimeError("Immutable evidence object size mismatch") from None
            existing = blob.download_as_bytes(if_generation_match=blob.generation, timeout=30)
            if hashlib.sha256(existing).hexdigest() != sha256:
                raise RuntimeError("Immutable evidence object integrity failure") from None
        generation = str(blob.generation)
    return {
        "key": key,
        "sha256": sha256,
        "bytes": len(data),
        "generation": generation,
        "expires_at": (now() + timedelta(days=retention_days)).isoformat(),
        "media_type": "application/json",
        "storage": "local" if cfg.is_local else "gcs",
    }


def load_observation(org_id, run_id, reference):
    key = object_key(org_id, run_id, reference["sha256"])
    if key != reference["key"] or not 0 < reference["bytes"] <= MAX_OBJECT_BYTES:
        raise RuntimeError("Evidence reference does not match its authorized scope")
    if datetime.fromisoformat(reference["expires_at"]) <= now():
        raise HTTPException(
            410, "Raw observation retention expired; evaluation and lineage remain available"
        )
    cfg = settings()
    try:
        if cfg.is_local:
            if reference["storage"] != "local":
                raise RuntimeError("Storage environment mismatch")
            parts = components(key)
            with directory_fd(cfg.evidence_dir, parts[:-1]) as directory:
                data = read_file(directory, parts[-1], MAX_OBJECT_BYTES)
        else:
            from google.cloud import storage

            if reference["storage"] != "gcs" or not reference.get("generation"):
                raise RuntimeError("Storage environment mismatch")
            generation = int(reference["generation"])
            blob = storage.Client().bucket(cfg.evidence_bucket).blob(key, generation=generation)
            # Bound transfer even if an object was replaced or a reference is corrupt.
            data = blob.download_as_bytes(
                start=0, end=MAX_OBJECT_BYTES, if_generation_match=generation, timeout=30
            )
    except FileNotFoundError:
        raise HTTPException(
            410, "Raw evidence object is unavailable; no replacement evidence is inferred"
        ) from None
    if len(data) != reference["bytes"] or hashlib.sha256(data).hexdigest() != reference["sha256"]:
        raise RuntimeError("Evidence object failed integrity verification")
    return json.loads(data)


def purge_local_expired():
    """Purge expired references, or 30-day orphans, inside the local raw namespace."""
    cfg = settings()
    if not cfg.is_local:
        return 0
    from sqlalchemy import select
    from .db import Record, transaction

    cutoff = (now() - timedelta(days=RAW_RETENTION_DAYS)).timestamp()
    removed = 0
    for path in (cfg.evidence_dir / "raw").glob("*/*/*.json"):
        try:
            org, run, digest = UUID(path.parent.parent.name), UUID(path.parent.name), path.stem
            expected = object_key(org, run, digest)
            if path != cfg.evidence_dir / expected:
                continue
            parts = components(expected)
            with directory_fd(cfg.evidence_dir, parts[:-1]) as directory:
                info = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    continue
                # A current reference wins even if an old object was reused. File
                # mtime alone is authoritative only for an unreferenced orphan.
                with transaction(org_id=org) as session:
                    references = list(session.scalars(select(Record.payload["raw_evidence"]).where(
                        Record.organization_id == org, Record.kind == "trial_capture",
                        Record.payload["run_id"].astext == str(run),
                        Record.payload["raw_evidence"]["sha256"].astext == digest,
                    )))
                expired = all(
                    r["key"] == expected and r["storage"] == "local"
                    and datetime.fromisoformat(r["expires_at"]) <= now()
                    for r in references
                ) if references else info.st_mtime < cutoff
                if expired:
                    os.unlink(parts[-1], dir_fd=directory)
                    os.fsync(directory)
                    removed += 1
        except (OSError, ValueError, KeyError, TypeError):
            # Invalid namespaces/references and symlinks are left for an operator;
            # a malformed object must never widen the scope of a deletion.
            continue
    return removed


def delete_local_object(root, org_id, run_id, sha256):
    """Delete exactly one namespace-validated object; safe to retry when absent."""
    return unlink_file(root, object_key(org_id, run_id, sha256))
