from functools import lru_cache
from pathlib import Path
from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CommercialPlan(BaseModel):
    label: str = Field(min_length=1, max_length=80)
    systems: int = Field(ge=1, le=1000)
    properties: int = Field(ge=1, le=500)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TV_", env_file=(".local/database.env", ".env"), extra="ignore"
    )
    env: str = "local"
    database_url: str = "postgresql+psycopg://threatveil_app@127.0.0.1:55432/threatveil"
    admin_database_url: str = ""
    local_auth: bool = False
    web_origin: str = "http://127.0.0.1:3000"
    evidence_dir: Path = Path(".local/evidence")
    firebase_project: str = ""
    worker_identity: str = "local-worker"
    broker_audience: str = "threatveil-broker"
    broker_url: str = "http://127.0.0.1:8001"
    bootstrap_ttl_seconds: int = 300
    lease_ttl_seconds: int = 120
    secret_project: str = ""
    evidence_bucket: str = ""
    stripe_secret_key: str = ""
    stripe_live_charges_enabled: bool = False
    stripe_test_entitlements_enabled: bool = False
    stripe_webhook_secret: str = ""
    stripe_prices: dict[str, str] = {}
    stripe_trial_allowances: dict[str, int] = {}
    commercial_plans: dict[str, CommercialPlan] = {}
    commercial_catalog_path: str = ""
    billing_provider: str = "disabled"
    openai_api_key: str = ""
    compiler_model: str = "gpt-5.4-mini-2026-03-17"
    # Bounded AI assistance. Off by default; a paid provider also needs a budget.
    ai_provider: str = "disabled"
    ai_model: str = "gpt-5.4-mini-2026-03-17"
    ai_mapping_enabled: bool = False
    ai_claims_enabled: bool = False
    ai_price_per_million_input: float = 0.0
    ai_price_per_million_output: float = 0.0
    ai_monthly_usd_budget: float = 0.0
    # Bounded automatic re-proof outside a labelled sandbox. Off unless explicitly enabled.
    auto_reproof_enabled: bool = False
    hubspot_token: str = ""
    hubspot_delivery_enabled: bool = False
    hubspot_owner_id: str = ""
    resend_api_key: str = ""
    resend_delivery_enabled: bool = False
    email_from: str = ""
    github_app_id: str = ""
    github_private_key: str = ""
    github_webhook_secret: str = ""
    receipt_signing_private_key: str = ""
    # Published trust root. Without an operator-managed history the service derives
    # a single-key directory and labels it as derived rather than provisioned.
    trust_directory_path: str = ""
    trust_issuer: str = "threatveil"
    trust_key_valid_from: str = "2026-01-01T00:00:00+00:00"
    trust_key_valid_until: str = "2031-01-01T00:00:00+00:00"
    # Build provenance: bound at image build time, reported as UNKNOWN when unbound.
    source_revision: str = ""
    image_digest: str = ""
    build_time: str = ""
    cloud_project: str = ""
    cloud_region: str = ""
    runner_job: str = ""
    sentry_dsn: str = ""

    @model_validator(mode="after")
    def production_boundaries(self):
        if self.billing_provider not in {"disabled", "mock", "stripe"}:
            raise ValueError("Unknown billing provider")
        if self.billing_provider == "mock" and self.env not in {"local", "test"}:
            raise ValueError("Mock billing is prohibited outside local/test")
        if any(not key or len(key) > 20 or not key.replace("_", "").replace("-", "").isalnum()
               for key in self.commercial_plans):
            raise ValueError("Commercial plan identifiers must be bounded alphanumeric names")
        if self.ai_provider not in {"disabled", "mock", "openai"}:
            raise ValueError("Unknown AI provider")
        if self.ai_provider == "mock" and self.env not in {"local", "test"}:
            raise ValueError("The mock AI provider is prohibited outside local/test")
        if self.ai_provider == "openai" and not self.openai_api_key:
            raise ValueError("A provider credential is required to enable AI assistance")
        if self.ai_monthly_usd_budget < 0 or self.ai_monthly_usd_budget > 100000:
            raise ValueError("The AI budget must be a bounded non-negative amount")
        if self.env not in {"local", "test", "dev", "staging", "production"}:
            raise ValueError("Unknown environment")
        if self.env not in {"local", "test"}:
            if self.local_auth:
                raise ValueError("Local identity is prohibited outside local/test")
            if not self.web_origin.startswith("https://") or not self.firebase_project:
                raise ValueError("Managed identity and HTTPS web origin are required")
            if not self.secret_project or not self.evidence_bucket:
                raise ValueError("Managed secret and evidence storage are required")
        if self.bootstrap_ttl_seconds > 300 or self.bootstrap_ttl_seconds < 1:
            raise ValueError("Bootstrap expiry must be at most five minutes")
        return self

    @property
    def is_local(self):
        return self.env in {"local", "test"}


@lru_cache
def settings():
    return Settings()
