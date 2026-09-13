"""Credential references are scoped to an organization even before provider IAM checks."""

import re
from pathlib import Path

from fastapi import HTTPException

from .config import settings


def validate_reference(version, organization_id):
    cfg = settings()
    namespace = f"tv-org-{organization_id}-"
    if cfg.is_local:
        valid = version.startswith("local:test:")
    else:
        valid = re.fullmatch(
            rf"projects/{re.escape(cfg.secret_project)}/secrets/{namespace}[A-Za-z0-9_-]+/versions/[1-9][0-9]*",
            version,
        )
    if not valid:
        raise HTTPException(
            422,
            "Credential reference must use this organization's namespace and a pinned secret version",
        )


def read_reference(record):
    validate_reference(record.payload["secret_version"], record.organization_id)
    if settings().is_local:
        path = Path(".local/secrets") / str(record.id)
        if not path.exists():
            raise HTTPException(503, "Local test credential is not provisioned")
        value = path.read_text()
    else:
        from google.cloud import secretmanager

        value = (
            secretmanager.SecretManagerServiceClient()
            .access_secret_version(name=record.payload["secret_version"])
            .payload.data.decode()
        )
    if not value or len(value) > 16000 or "\r" in value or "\n" in value:
        raise HTTPException(503, "Credential must be one bounded header-safe token")
    return value
