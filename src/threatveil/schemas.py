import re
from datetime import datetime
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# A PostgreSQL text or jsonb value cannot hold a NUL byte, and no legitimate claim, note or
# name needs another C0/C1 control character. Rejecting them at the edge turns a would-be
# storage error into a clear 422. Newline, carriage return and tab stay allowed.
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
MAX_DEPTH = 8


def has_control(value, depth=0):
    if depth > MAX_DEPTH:
        return False
    if isinstance(value, str):
        return bool(CONTROL.search(value))
    if isinstance(value, (list, tuple, set)):
        return any(has_control(item, depth + 1) for item in value)
    if isinstance(value, dict):
        return any(has_control(key, depth + 1) or has_control(item, depth + 1) for key, item in value.items())
    return False


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def printable_text_only(self):
        for name, value in self:
            if has_control(value):
                raise ValueError(f"{name} contains control characters")
        return self


class LocalLogin(Input):
    email: str = Field(min_length=5, max_length=320)
    name: str = Field(default="Founder", min_length=1, max_length=120)
    organization_name: str = Field(default="My organization", min_length=1, max_length=120)

    @field_validator("email")
    @classmethod
    def email_valid(cls, v):
        if "@" not in v or any(c.isspace() for c in v):
            raise ValueError("Valid email required")
        return v.lower()


class Exchange(LocalLogin):
    id_token: str = Field(min_length=50, max_length=12000)


class SystemInput(Input):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=4000)
    access: list[str] = Field(default_factory=list, max_length=30)
    actions: list[str] = Field(default_factory=list, max_length=30)
    fingerprint: dict = Field(default_factory=lambda: {"components": []})


class FindingInput(Input):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=20000)
    system_id: UUID
    source_type: str = Field(default="human", max_length=40)


class PropertyInput(Input):
    system_id: UUID
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=8000)
    template_id: str | None = None
    definition: dict = Field(default_factory=dict)
    finding_id: UUID | None = None


class TargetInput(Input):
    system_id: UUID
    name: str = Field(min_length=1, max_length=120)
    adapter: Literal["http", "structured_trace", "mcp", "openai_compatible"]
    origin: str | None = None
    paths: list[str] = Field(default_factory=lambda: ["/"], max_length=20)
    methods: list[Literal["GET", "POST"]] = Field(default_factory=lambda: ["POST"], max_length=2)
    expires_at: datetime
    authorization_note: str = Field(min_length=10, max_length=4000)
    execution_class: Literal["DIGITAL_SANDBOX", "DIGITAL_STAGING"] = "DIGITAL_STAGING"
    # Current network adapters support one bearer credential. Reject additional
    # references instead of granting a worker secrets the adapter never uses.
    credential_reference_ids: list[UUID] = Field(default_factory=list, max_length=1)
    allowed_tools: list[str] = Field(default_factory=list, max_length=20)
    model: str | None = Field(default=None, max_length=200)


class RunInput(Input):
    system_id: UUID
    property_id: UUID
    target_id: UUID
    version: str = Field(default="fixed", max_length=120)
    trials: int = Field(default=5, ge=1, le=100)
    variant_count: int = Field(default=1, ge=1, le=5)
    baseline_id: UUID | None = None
    idempotency_key: str = Field(min_length=8, max_length=120)
    observation: dict | None = None
    stimulus: dict | None = None
    candidate: dict | None = None
    github: dict | None = None
    fingerprint: dict = Field(default_factory=lambda: {"components": []})
    observer_id: UUID | None = None
    qualification_case: Literal["KNOWN_PERMITTED", "KNOWN_PROHIBITED", "MISSING_OBSERVATION"] | None = None


class FixInput(Input):
    run_id: UUID
    verification_run_id: UUID
    description: str = Field(min_length=5, max_length=4000)


class GauntletInput(Input):
    system_id: UUID
    name: str = Field(min_length=1, max_length=120)
    scope: str = Field(min_length=10, max_length=4000)
    property_ids: list[UUID] = Field(default_factory=list, max_length=25)


class ImpactInput(Input):
    system_id: UUID
    previous: dict
    candidate: dict


class InviteInput(Input):
    email: str = Field(min_length=5, max_length=320)
    role: Literal["admin", "security", "developer", "viewer"]


class PilotInput(Input):
    trial_limit: int = Field(ge=0, le=100000)
    max_systems: int = Field(ge=1, le=100)
    reason: str = Field(min_length=10, max_length=1000)


class CredentialInput(Input):
    name: str = Field(min_length=1, max_length=120)
    secret_version: str = Field(min_length=1, max_length=500)


class LeadInput(Input):
    name: str = Field(min_length=1, max_length=120)
    email: str = Field(min_length=5, max_length=320)
    company: str = Field(min_length=1, max_length=160)
    message: str = Field(default="", max_length=2000)
    consent: Literal[True]
