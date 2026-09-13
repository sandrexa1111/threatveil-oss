"""Read-only activation preflight. Configuration success never means cloud acceptance."""

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text


class ActivationProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operational_owner: str = ""
    images: dict[str, str] = Field(default_factory=dict)
    previous_images: dict[str, str] = Field(default_factory=dict)
    notification_channels: list[str] = Field(default_factory=list)
    monthly_cloud_budget_usd: int = Field(default=0, ge=0)
    budget_alert_reference: str = ""
    pilot_verification_budget: int = Field(default=0, ge=0)
    signing_trust_reference: str = ""
    rollback_runbook: str = ""
    recovery_runbook: str = ""
    retention_scope_accepted: bool = False
    required_providers: list[str] = Field(default_factory=lambda: ["github"])


def database_readiness():
    """Validate runtime role, forced tenancy and actual migration head without DDL."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from .db import transaction

    with transaction() as session:
        role = session.execute(text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user")).one()
        if role.rolsuper or role.rolbypassrls:
            raise ValueError("Runtime database role must be non-superuser and NOBYPASSRLS")
        tables = session.execute(text("""SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
            c.relowner = (SELECT oid FROM pg_roles WHERE rolname=current_user) AS owns
            FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid
            WHERE n.nspname='public' AND c.relname IN ('records','record_edges','memberships')""")).all()
        if len(tables) != 3 or any(not t.relrowsecurity or not t.relforcerowsecurity or t.owns for t in tables):
            raise ValueError("Tenant tables require FORCE RLS and a non-owner runtime role")
        installed = set(session.scalars(text("SELECT version_num FROM alembic_version")))
        expected = set(ScriptDirectory.from_config(Config("alembic.ini")).get_heads())
        if installed != expected:
            raise ValueError("Database migrations are not at the packaged head")
        return {"migration_heads": sorted(installed), "tenant_tables": [t.relname for t in tables]}


def preflight(cfg, profile: ActivationProfile, *, inspect_database=True):
    checks = []

    def check(name, condition, detail):
        checks.append({"check": name, "status": "PASS" if condition else "FAIL", "detail": detail})

    origin = urlsplit(cfg.web_origin)
    check("managed_auth_origin", not cfg.is_local and not cfg.local_auth and bool(cfg.firebase_project)
        and origin.scheme == "https" and bool(origin.hostname) and origin.path in ("", "/")
        and not origin.username and not origin.password and not origin.query and not origin.fragment,
        "Managed identity with an exact HTTPS origin is required for cloud activation")
    try:
        key = serialization.load_pem_private_key(cfg.receipt_signing_private_key.encode(), None)
        usable = isinstance(key, Ed25519PrivateKey)
        if usable:
            message = b"threatveil-activation-key-self-check-v1"
            key.public_key().verify(key.sign(message), message)
    except (ValueError, TypeError):
        usable = False
    check("receipt_signing", usable and bool(profile.signing_trust_reference),
        "Usable supported signing key and independently distributed verification-key reference")
    # A hosted record is durable evidence only if a third party can resolve its key
    # years later. This must be provisioned before the first customer record is signed.
    trust = {}
    try:
        from .trust import rotation_state

        trust = rotation_state(cfg)
        published = (
            trust.get("trust") == "OPERATOR_PROVISIONED"
            and trust.get("active_key_id") is not None
            and (trust.get("active_expires_in_days") or 0) > 30
        )
    except Exception:
        published = False
    check("trust_directory", published,
        "Operator-managed key directory listing the active signer, with rotation history "
        "and at least thirty days before the active key expires")
    check("managed_storage", bool(cfg.secret_project and cfg.evidence_bucket),
        "Secret project and evidence bucket configured; effective access requires cloud acceptance")
    check("cloud_dispatch", bool(cfg.cloud_project and cfg.cloud_region and cfg.broker_url.startswith("https://")
        and cfg.worker_identity.endswith(".iam.gserviceaccount.com")),
        "Cloud dispatch project, region, broker origin and bounded worker identity configured")
    supported = {"github", "openai", "stripe_test"}
    check("provider_contract", set(profile.required_providers) <= supported,
        "Only declared supported provider checks may satisfy activation configuration")
    if "github" in profile.required_providers:
        try:
            github_key = serialization.load_pem_private_key(cfg.github_private_key.encode(), None)
            github_ready = isinstance(github_key, RSAPrivateKey) and github_key.key_size >= 2048
        except (ValueError, TypeError):
            github_ready = False
        check("github_app", github_ready and bool(re.fullmatch(r"[1-9][0-9]{0,19}", cfg.github_app_id))
            and len(cfg.github_webhook_secret) >= 32,
            "Numeric App ID, RSA signing key and webhook secret; live installation/publication remain pending")
    if "openai" in profile.required_providers:
        check("openai", bool(cfg.openai_api_key and cfg.compiler_model),
            "Provider credentials/model configured; provider authorization must be accepted live")
    if "stripe_test" in profile.required_providers:
        check("stripe_test", cfg.stripe_secret_key.startswith("sk_test_") and bool(cfg.stripe_webhook_secret),
            "Stripe TEST MODE credentials required; this preflight never creates a charge")
    image_pattern = r"[^\s]+@sha256:[0-9a-f]{64}"
    check("immutable_images", set(profile.images) == {"python", "web"} and all(
        re.fullmatch(image_pattern, v) for v in profile.images.values()),
        "Both activation images must be pinned by digest")
    check("rollback", bool(profile.operational_owner and profile.rollback_runbook)
        and set(profile.previous_images) == {"python", "web"} and all(
            re.fullmatch(image_pattern, v) for v in profile.previous_images.values()),
        "Named operator, rollback runbook and prior immutable images; no automatic database downgrade")
    check("alerts", bool(profile.notification_channels) and all(
        re.fullmatch(r"projects/[^/]+/notificationChannels/[^/]+", v) for v in profile.notification_channels),
        "Monitoring destinations configured; delivered alert must be demonstrated in cloud")
    check("cost_guardrails", profile.monthly_cloud_budget_usd > 0 and profile.pilot_verification_budget > 0
        and bool(profile.budget_alert_reference),
        "Cloud budget alert reference and finite pilot verification budget; an alert is not a hard spend cap")
    check("recovery_retention", bool(profile.recovery_runbook and profile.retention_scope_accepted),
        "Documented restore procedure and accepted raw/storage/backup/export retention boundaries")
    if inspect_database:
        try:
            detail = database_readiness()
            check("database", True, detail)
        except Exception as error:
            # Do not serialize DB URLs, credentials, SQL parameters or provider errors.
            check("database", False, {"error_type": type(error).__name__,
                "message": "Runtime role, FORCE RLS or packaged migration head validation failed"})
    else:
        checks.append({"check": "database", "status": "PENDING", "detail": "Database was not inspected"})
    ready = all(c["status"] == "PASS" for c in checks)
    return {"profile": "threatveil.activation-readiness.v1", "configuration_ready": ready,
        "cloud_accepted": False, "checks": checks, "image_digests": profile.images,
        "trust_directory": trust,
        "external_pending": ["Managed login and hosted origin/cookies", "Two-tenant isolation under deployed runtime roles",
            "Real GitHub signed push ingress and delivered exact check", "Worker IAM/bootstrap/replay denials",
            "Signed release independently verified with configured trust key",
            "Published trust directory reachable and mirrored by an external verifier",
            "Delivered monitoring and budget alerts",
            "Isolated backup restore, projection recovery and retention scope", "Rollback to recorded image digests"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        from .config import settings
        profile = ActivationProfile.model_validate_json(args.profile.read_text())
        result = preflight(settings(), profile)
    except Exception as error:
        result = {"configuration_ready": False, "cloud_accepted": False,
            "error_type": type(error).__name__, "detail": "Invalid activation profile or service settings; no secret values emitted"}
    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")
    return 0 if result["configuration_ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
