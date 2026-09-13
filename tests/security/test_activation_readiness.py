import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from threatveil.activation_readiness import ActivationProfile, preflight
from threatveil.config import Settings


def pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()


def trust_directory(signing_key, path):
    """An operator-managed key directory, as a real deployment must provision."""
    import json
    from datetime import datetime, timedelta, timezone

    from threatveil.sdk.trust_directory import ALGORITHMS, key_id, serialize_directory

    public = signing_key.public_key()
    start = datetime.now(timezone.utc) - timedelta(days=1)
    document = serialize_directory("threatveil", [{
        "keyid": key_id(public), "algorithm": "Ed25519",
        "signature_profile": ALGORITHMS["Ed25519"], "status": "ACTIVE",
        "valid_from": start.isoformat(),
        "valid_until": (start + timedelta(days=365)).isoformat(),
        "revoked_at": None, "supersedes": None,
        "public_key_pem": public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
    }])
    path.write_text(json.dumps(document))
    return str(path)


def configured(trust_path=""):
    signing = Ed25519PrivateKey.generate()
    cfg = Settings(_env_file=None, env="dev", web_origin="https://assurance.example.com",
        firebase_project="reviewed-project", secret_project="reviewed-project", evidence_bucket="reviewed-evidence",  # noqa: S106 - project ID, not credential
        receipt_signing_private_key=pem(signing), cloud_project="reviewed-project",
        cloud_region="europe-west1", broker_url="https://broker.example.com",
        worker_identity="runner@reviewed-project.iam.gserviceaccount.com", github_app_id="123",
        github_private_key=pem(generate_private_key(public_exponent=65537, key_size=2048)),
        github_webhook_secret=secrets.token_urlsafe(32),
        trust_directory_path=trust_directory(signing, trust_path) if trust_path else "")
    images = {name: "registry.example.com/" + name + "@sha256:" + "a" * 64 for name in ("python", "web")}
    profile = ActivationProfile(operational_owner="Security operator", images=images, previous_images=images,
        notification_channels=["projects/reviewed-project/notificationChannels/123"],
        monthly_cloud_budget_usd=500, pilot_verification_budget=100,
        budget_alert_reference="reviewed-budget-alert", signing_trust_reference="independent-public-key-reference",
        rollback_runbook="docs/deployment/GCP.md", recovery_runbook="docs/deployment/GCP.md",
        retention_scope_accepted=True)
    return cfg, profile


def test_missing_activation_configuration_is_not_healthy():
    report = preflight(Settings(_env_file=None), ActivationProfile(), inspect_database=False)
    assert not report["configuration_ready"] and not report["cloud_accepted"]
    failed = {c["check"] for c in report["checks"] if c["status"] == "FAIL"}
    assert {"managed_auth_origin", "receipt_signing", "github_app", "cost_guardrails", "alerts", "rollback"} <= failed


def test_valid_static_configuration_never_implies_cloud_acceptance(monkeypatch, tmp_path):
    cfg, profile = configured(tmp_path / "trust.json")
    monkeypatch.setattr("threatveil.activation_readiness.database_readiness", lambda: {"migration_heads": ["test-head"]})
    report = preflight(cfg, profile)
    assert report["configuration_ready"] and not report["cloud_accepted"]
    assert any("Two-tenant" in item for item in report["external_pending"])
    assert cfg.receipt_signing_private_key not in str(report)
    assert report["trust_directory"]["trust"] == "OPERATOR_PROVISIONED"


def test_a_signed_record_without_a_published_trust_root_blocks_activation(monkeypatch, tmp_path):
    """Durable evidence requires key resolution; a derived directory is not that."""
    monkeypatch.setattr("threatveil.activation_readiness.database_readiness", lambda: {"migration_heads": ["h"]})
    cfg, profile = configured()
    report = preflight(cfg, profile)
    assert not report["configuration_ready"]
    assert "trust_directory" in {c["check"] for c in report["checks"] if c["status"] == "FAIL"}

    # A directory listing a different signer is refused rather than published.
    other = Ed25519PrivateKey.generate()
    cfg_wrong, _ = configured()
    cfg_wrong = cfg_wrong.model_copy(
        update={"trust_directory_path": trust_directory(other, tmp_path / "other.json")}
    )
    wrong = preflight(cfg_wrong, profile)
    assert "trust_directory" in {c["check"] for c in wrong["checks"] if c["status"] == "FAIL"}
    assert cfg_wrong.receipt_signing_private_key not in str(wrong)


def test_wrong_key_and_unmigrated_database_fail_closed(monkeypatch):
    cfg, profile = configured()
    cfg.receipt_signing_private_key = cfg.github_private_key
    def failed_database():
        raise ValueError("secret-password-in-database-error")
    monkeypatch.setattr("threatveil.activation_readiness.database_readiness", failed_database)
    report = preflight(cfg, profile)
    assert not report["configuration_ready"]
    assert {"receipt_signing", "database"} <= {c["check"] for c in report["checks"] if c["status"] == "FAIL"}
    assert "secret-password" not in str(report)
