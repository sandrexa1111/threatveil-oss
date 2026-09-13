"""Versioned autonomous-action contracts. Physical execution remains disabled.

Trusted receipt collection is a caller responsibility. A submitted document cannot
qualify its own witnesses: evaluators require an out-of-band source allowlist.
"""

import hashlib
import json
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator


def digest(value: Any) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    ).hexdigest()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def trial_correlation(run_id, variant_id, index):
    return str(uuid5(UUID(str(run_id)), f"{variant_id}:{index}"))


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"


class ActionPhase(StrEnum):
    ATTEMPTED = "ATTEMPTED"
    AUTHORIZED = "AUTHORIZED"
    DISPATCHED = "DISPATCHED"
    COMMITTED = "COMMITTED"
    DENIED = "DENIED"
    COMPENSATED = "COMPENSATED"


class Resource(Contract):
    type: str = Field(min_length=1, max_length=100)
    id: str = Field(min_length=1, max_length=300)
    tenant_id: str | None = None


class Principal(Contract):
    id: str
    tenant_id: str | None = None
    authority: tuple[str, ...] = ()
    delegation_parent: str | None = None


class Action(Contract):
    id: str = Field(default_factory=lambda: str(uuid4()))
    type: str = "DIGITAL_STATE_CHANGE"
    operation: str
    tool: str | None = None
    principal: Principal
    resource: Resource
    phase: ActionPhase
    trust_source: str = "UNKNOWN"
    approval_id: str | None = None
    approval_valid: bool | None = None
    authorized: bool | None = None
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None


class Receipt(Contract):
    id: str = Field(default_factory=lambda: str(uuid4()))
    correlation_id: str
    sequence: int = Field(ge=0)
    source_id: str
    source_version: str
    observed_at: datetime = Field(default_factory=utcnow)
    event_type: Literal[
        "agent_run",
        "tool_call",
        "resource_access",
        "external_action",
        "permission_check",
        "state_change",
    ]
    action: Action


class Witness(Contract):
    id: str
    source_type: str
    source_version: str
    authority: Literal["SELF_REPORTED", "INSTRUMENTED", "AUTHORITATIVE", "INDEPENDENT"]
    correlation_id: str
    complete: bool
    covered_operations: tuple[str, ...]
    boundary: str
    observed_at: datetime = Field(default_factory=utcnow)
    qualification_id: str | None = None
    failure_modes: tuple[str, ...] = ()


class ObservationContract(Contract):
    boundary: str
    required_witnesses: tuple[str, ...] = Field(min_length=1)
    required_operations: tuple[str, ...] = Field(min_length=1)
    max_age_seconds: int = Field(default=60, ge=1, le=86400)


class Predicate(Contract):
    kind: Literal[
        "missing_approval",
        "cross_tenant",
        "unauthorized_action",
        "untrusted_action",
        "forbidden_action",
        "forbidden_value",
    ]
    phases: tuple[ActionPhase, ...] = (ActionPhase.COMMITTED,)
    operations: tuple[str, ...] = Field(min_length=1)
    tools: tuple[str, ...] = ()
    resource_types: tuple[str, ...] = ()
    values: tuple[str, ...] = ()

    @model_validator(mode="after")
    def bounded_predicate(self):
        if not self.phases:
            raise ValueError("A predicate must specify at least one observed action phase")
        if self.kind == "forbidden_value" and not self.values:
            raise ValueError("A forbidden-value predicate requires values")
        return self


class LegitimateControl(Contract):
    operation: str
    resource_type: str
    expected_state: dict[str, Any] = Field(min_length=1)
    required_phase: ActionPhase = ActionPhase.COMMITTED


class PropertyDefinition(Contract):
    id: str
    version: int = Field(default=1, ge=1)
    title: str = Field(min_length=1, max_length=300)
    description: str = ""
    category: str = "AUTHORIZATION"
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"
    predicates: tuple[Predicate, ...] = Field(min_length=1)
    observation_contract: ObservationContract
    legitimate_task: str = ""
    legitimate_control: LegitimateControl | None = None
    tags: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    release_policy: Literal["WARN", "BLOCK"] = "WARN"


class FingerprintComponent(Contract):
    type: str = Field(min_length=1, max_length=100, pattern=r"^[^:]+$")
    id: str = Field(min_length=1, max_length=200)
    version: str | None = None
    digest: str | None = None
    provenance: Literal["DECLARED", "OBSERVED", "INFERRED", "UNKNOWN"] = "UNKNOWN"
    dependencies: tuple[str, ...] = ()


class SystemFingerprint(Contract):
    components: tuple[FingerprintComponent, ...] = ()

    @model_validator(mode="after")
    def unique_components(self):
        keys = [(c.type, c.id) for c in self.components]
        if len(keys) != len(set(keys)):
            raise ValueError("Duplicate fingerprint component identity")
        return self


class Observation(Contract):
    correlation_id: str
    receipts: tuple[Receipt, ...] = ()
    witnesses: tuple[Witness, ...] = ()
    boundary_mocked: bool = False
    execution_status: Literal["COMPLETED", "ERROR", "CANCELLED", "TIMEOUT"] = "COMPLETED"
    task_outcome: Literal["SUCCESS", "FAILURE", "UNKNOWN"] = "UNKNOWN"
    task_receipt_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    fingerprint: SystemFingerprint | None = None
    initial_state_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    attestations: dict[str, str] = Field(default_factory=dict)


class Candidate(Contract):
    type: str
    id: str
    version: str
    digest: str
    github_repository: str | None = None
    github_commit: str | None = None


class CredentialReference(Contract):
    id: str
    integration_id: str
    scopes: tuple[str, ...]
    version: str | None = None


class ReproductionCapsule(Contract):
    id: str
    identity: Principal
    fixture_references: tuple[str, ...]
    initial_state_digest: str
    fingerprint: SystemFingerprint
    boundary_under_test: str
    mocked_boundaries: tuple[str, ...] = ()
    reset_method: str
    allowed_effects: tuple[str, ...]
    required_witnesses: tuple[str, ...]
    credential_references: tuple[CredentialReference, ...] = ()
    execution_class: Literal[
        "DIGITAL_SANDBOX",
        "DIGITAL_STAGING",
        "SIMULATION",
        "HARDWARE_IN_THE_LOOP",
        "CONTROLLED_PHYSICAL_TEST",
        "PRODUCTION_OBSERVATION",
    ] = "DIGITAL_SANDBOX"
    environment_references: tuple[str, ...] = ()

    def ensure_launch_supported(self) -> None:
        if self.execution_class not in ("DIGITAL_SANDBOX", "DIGITAL_STAGING"):
            raise ValueError("This release only executes authorized digital fixtures or staging")


class ExperimentPlan(Contract):
    trials_per_variant: int = Field(default=5, ge=1, le=100)
    variant_count: int = Field(default=1, ge=1, le=5)
    independent_resets: bool = True
    confidence: float = Field(default=0.95, gt=0, lt=1)
    method: Literal["fixed_binomial"] = "fixed_binomial"

    @model_validator(mode="after")
    def bounded_plan(self):
        if self.trials_per_variant * self.variant_count > 500:
            raise ValueError("Experiment exceeds the bounded trial budget")
        return self


class EvidenceManifest(Contract):
    evaluator_version: str = "deterministic-v1"
    property_digest: str
    experiment_digest: str
    capsule_digest: str
    observation_digests: tuple[str, ...]
    limitations: tuple[str, ...] = ()
