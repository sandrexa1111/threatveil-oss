"""Owner-requested local erasure with private, authenticated crash recovery.

Cloud objects, provider state and backups require deployment-specific acceptance.
This command makes no claim about them and refuses provider-backed organizations.
"""

import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from .config import settings
from .db import Account, GitHubBinding, Organization, Outbox, Record, context, now
from .evidence_storage import delete_local_object, object_key
from .governance import pending_deletion
from .local_files import directory_fd, read_file, unlink_file
from .release_integrity import lock_organization_systems

MANIFEST_SCHEMA = "threatveil-local-erasure/v2"
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
LIMITATIONS = [
    "Local primary data only; backups, logs and downloaded exports are not erased by this command.",
    "Shared authentication user profiles and unscoped abuse/provider event records remain; account deletion is a separate scope.",
    "No cloud, provider, legal-hold or backup erasure is claimed.",
]


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _key(directory, *, create):
    try:
        value = read_file(directory, ".manifest-key", 32)
    except FileNotFoundError:
        if not create:
            raise ValueError("Recovery key is missing; operator reconciliation is required") from None
        value = os.urandom(32)
        fd = os.open(".manifest-key", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=directory)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(directory)
    if len(value) != 32:
        raise ValueError("Invalid erasure recovery key")
    return value


def _write_report(directory, name, manifest, key):
    data = _canonical({"manifest": manifest,
        "hmac_sha256": hmac.new(key, _canonical(manifest), hashlib.sha256).hexdigest()})
    if len(data) > MAX_MANIFEST_BYTES:
        raise ValueError("Erasure manifest exceeds the supported local recovery limit")
    temporary = f".{uuid4()}.pending"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def _validate_manifest(value, org, request_id, evidence_root, workspace):
    """Authenticate separately, then enforce exact operation and namespace binding."""
    if (value.get("schema") != MANIFEST_SCHEMA
        or value.get("organization_id") != str(org)
        or value.get("request_id") != str(request_id)
        or value.get("status") not in {"PREPARED", "CORE_ERASED"}
        or value.get("evidence_root") != str(evidence_root)
        or value.get("workspace_root") != str(workspace)):
        raise ValueError("Erasure manifest does not match this operation and configured roots")
    if not isinstance(value.get("raw_objects"), list) or not isinstance(value.get("local_credentials"), list):
        raise ValueError("Invalid erasure object manifest")
    for item in value["raw_objects"]:
        if not isinstance(item, dict) or set(item) != {"run_id", "sha256", "key"}:
            raise ValueError("Invalid raw object manifest entry")
        if item["key"] != object_key(org, item["run_id"], item["sha256"]):
            raise ValueError("Erasure raw object is outside the exact organization/run/digest scope")
    for identifier in value["local_credentials"]:
        if identifier != str(UUID(identifier)):
            raise ValueError("Invalid local credential identifier")
    return value


def _load_report(directory, name, key, org, request_id, evidence_root, workspace):
    envelope = json.loads(read_file(directory, name, MAX_MANIFEST_BYTES))
    if not isinstance(envelope, dict) or not isinstance(envelope.get("manifest"), dict):
        raise ValueError("Unsigned legacy erasure manifest requires operator reconciliation")
    expected = hmac.new(key, _canonical(envelope["manifest"]), hashlib.sha256).hexdigest()
    if not isinstance(envelope.get("hmac_sha256"), str) or not hmac.compare_digest(expected, envelope["hmac_sha256"]):
        raise ValueError("Erasure manifest authentication failed")
    return _validate_manifest(envelope["manifest"], org, request_id, evidence_root, workspace)


def _cleanup(manifest, evidence_root, workspace):
    for item in manifest["raw_objects"]:
        delete_local_object(evidence_root, manifest["organization_id"], item["run_id"], item["sha256"])
    for identifier in manifest["local_credentials"]:
        unlink_file(workspace, f".local/secrets/{identifier}")


def erase_local_organization(organization_id, request_id, confirmation):
    org, request_id = UUID(str(organization_id)), UUID(str(request_id))
    if confirmation != str(org):
        raise ValueError("Repeat the exact organization UUID to authorize erasure")
    cfg = settings()
    if not cfg.is_local or not cfg.admin_database_url:
        raise ValueError("Local erasure requires local/test mode and the separate migration connection")
    workspace, evidence_root = Path.cwd().resolve(), cfg.evidence_dir.resolve()
    report_name = f"{request_id}.json"
    # Relative descriptor traversal rejects .local/report-directory symlinks.
    # The file lock also serializes separate operator processes and key creation.
    with directory_fd(workspace, (".local", "deletion-receipts"), create=True) as directory:
        lock = os.open(".operation-lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600, dir_fd=directory)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                os.stat(report_name, dir_fd=directory, follow_symlinks=False)
                prior_exists = True
            except FileNotFoundError:
                prior_exists = False
            key = _key(directory, create=not prior_exists)
            prior = _load_report(directory, report_name, key, org, request_id, evidence_root, workspace) if prior_exists else None
            db = create_engine(cfg.admin_database_url, pool_pre_ping=True)
            try:
                with Session(db) as session, session.begin():
                    if session.execute(text("SELECT current_user, session_user")).one() != ("threatveil_admin", "threatveil_admin"):
                        raise ValueError("Erasure requires the dedicated migration role, never runtime credentials")
                    context(session, org_id=org)
                    # Same order as execution/request creation: system locks, account.
                    lock_organization_systems(session, org)
                    account = session.get(Account, org, with_for_update=True)
                    organization = session.get(Organization, org)
                    request = pending_deletion(session, org)
                    if organization is None:
                        if prior is None:
                            raise ValueError("No organization or authenticated prepared erasure exists")
                        # DB commit succeeded earlier; only this authenticated
                        # operation's already-enumerated files may be retried.
                        manifest = prior
                    else:
                        if request is None or request.id != request_id:
                            raise ValueError("An active matching owner erasure request is required")
                        if account and (account.paid or account.stripe_customer or account.stripe_subscription):
                            raise ValueError("Provider billing and retention must be resolved before local erasure")
                        rows = list(session.scalars(select(Record).where(Record.organization_id == org)))
                        if (session.scalar(select(GitHubBinding.repository_id).where(GitHubBinding.organization_id == org))
                            or any(row.kind in {"github_app_installation", "github_check_publication"} for row in rows)
                            or session.scalar(select(Outbox.id).where(Outbox.organization_id == org, Outbox.attempts > 0))):
                            raise ValueError("External delivery and GitHub state must be reconciled before local erasure")
                        raw, credentials = {}, []
                        for row in rows:
                            if row.kind == "trial_capture":
                                ref = row.payload["raw_evidence"]
                                expected = object_key(org, row.payload["run_id"], ref["sha256"])
                                if ref["key"] != expected or ref["storage"] != "local":
                                    raise ValueError("Unexpected raw evidence scope or nonlocal storage; operator reconciliation required")
                                raw[expected] = {"run_id": str(UUID(row.payload["run_id"])),
                                    "sha256": ref["sha256"], "key": expected}
                            if row.kind == "credential":
                                if not row.payload.get("reference", "").startswith("local:"):
                                    raise ValueError("Provider credentials must be resolved before local erasure")
                                credentials.append(str(row.id))
                        manifest = {
                            "schema": MANIFEST_SCHEMA, "organization_id": str(org),
                            "request_id": str(request_id), "status": "PREPARED", "prepared_at": now().isoformat(),
                            "record_count": len(rows), "raw_objects": sorted(raw.values(), key=lambda item: item["key"]),
                            "local_credentials": sorted(credentials), "evidence_root": str(evidence_root),
                            "workspace_root": str(workspace), "limitations": LIMITATIONS,
                        }
                        _validate_manifest(manifest, org, request_id, evidence_root, workspace)
                        _write_report(directory, report_name, manifest, key)
                        session.execute(text("SELECT set_config('tv.erase_org', :org, true)"), {"org": str(org)})
                        session.execute(text("DELETE FROM lease_nonces WHERE lease_id IN (SELECT id FROM run_leases WHERE organization_id=:org)"), {"org": org})
                        # Fixed identifiers only, no caller-supplied SQL identifiers.
                        for table in (
                            "capability_routes", "run_leases", "record_edges", "run_state", "target_state",
                            "api_tokens", "schedules", "github_bindings", "customer_routes", "outbox",
                            "invitations", "login_sessions", "memberships", "accounts", "records",
                            "operator_records",
                        ):
                            session.execute(text(f"DELETE FROM {table} WHERE organization_id=:org"), {"org": org})  # noqa: S608
                        session.execute(text("DELETE FROM organizations WHERE id=:org"), {"org": org})
                if manifest["status"] == "CORE_ERASED":
                    return manifest
                _cleanup(manifest, evidence_root, workspace)
                manifest.update(status="CORE_ERASED", completed_at=now().isoformat())
                _write_report(directory, report_name, manifest, key)
                return manifest
            finally:
                db.dispose()
        finally:
            os.close(lock)
