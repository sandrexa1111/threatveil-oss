"""Bounded integration intake. Imported data proposes facts, never security truth.

These stateless parsers do not access networks, activate properties, qualify
witnesses, or transfer a historical verdict to a candidate. The caller owns
tenant authorization, retention and review before accepting fingerprint facts.
"""

import json
from datetime import datetime
from typing import Any, Literal

from pydantic import Field, field_validator

from threatveil.core.contracts import (
    Contract,
    Observation,
    SystemFingerprint,
    digest,
    utcnow,
)

MAX_BYTES = 4 * 1024 * 1024
MAX_ITEMS = 5000
FORMATS = ("otel_genai", "openai_agents", "anthropic_hooks", "mcp_tools", "cyclonedx", "sarif")


class IntakeContext(Contract):
    source_id: str = Field(default="import", min_length=1, max_length=150)
    source_version: str = Field(default="1", min_length=1, max_length=120)
    boundary: str = Field(default="imported", min_length=1, max_length=300)
    expected_correlation_id: str | None = Field(default=None, min_length=1, max_length=200)
    received_at: datetime = Field(default_factory=utcnow)

    @field_validator("received_at")
    @classmethod
    def aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Intake timestamp must include a timezone")
        return value


class TraceEdge(Contract):
    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    agent_id: str | None = None
    delegated_from: str | None = None
    delegated_to: str | None = None
    authority: Literal["UNVERIFIED"] = "UNVERIFIED"


class ImportedFinding(Contract):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=20000)
    source_type: Literal["sarif"] = "sarif"
    external_id: str
    scanner: str
    scanner_version: str | None = None
    rule_id: str | None = None
    level: Literal["none", "note", "warning", "error"] = "warning"
    locations: tuple[dict[str, Any], ...] = ()
    partial_fingerprints: dict[str, str] = Field(default_factory=dict)
    source_digest: str
    result_digest: str
    status: Literal["DRAFT"] = "DRAFT"
    baseline_state: str | None = None
    result_kind: str = "fail"
    suppressions: tuple[dict[str, Any], ...] = ()
    limitations: tuple[str, ...] = (
        "Scanner findings require human-reviewed property semantics and reproduction.",
    )


class NormalizedIntake(Contract):
    format: str
    normalizer_version: Literal["integration-intake-v1"] = "integration-intake-v1"
    source_digest: str
    fingerprint: SystemFingerprint = Field(default_factory=SystemFingerprint)
    observations: tuple[Observation, ...] = ()
    findings: tuple[ImportedFinding, ...] = ()
    trace_edges: tuple[TraceEdge, ...] = ()
    details: dict[str, Any] = Field(default_factory=dict)
    limitations: tuple[str, ...] = ()
    review_required: Literal[True] = True


def object_value(value: Any, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def array_value(value: Any, label: str, *, limit: int = MAX_ITEMS) -> list:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"{label} must be an array of at most {limit} items")
    return value


def text_value(value: Any, label: str, *, limit: int = 1000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{label} must be a nonempty string of at most {limit} characters")
    return value


def bounded_document(payload: Any) -> dict:
    """Reject ambiguous/non-JSON values before any normalization or hashing.

    Limits apply to the entire document, including fields a specific parser does
    not interpret. Unsupported data is never truncated into false equivalence.
    """
    object_value(payload, "Integration payload")
    pending, count = [(payload, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > 32 or count > 100000:
            raise ValueError("Integration document exceeds structural bounds")
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise ValueError("Integration JSON object keys must be strings")
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
        elif not isinstance(value, (str, int, float, bool, type(None))):
            raise ValueError("Integration document contains a non-JSON value")
    try:
        raw = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode()
    except (ValueError, OverflowError, UnicodeError) as exc:
        raise ValueError("Integration document is not finite valid JSON") from exc
    if len(raw) > MAX_BYTES:
        raise ValueError("Integration document exceeds 4 MiB")
    return payload


def component_id(value: str) -> str:
    # Hash long external identities; truncation would conflate distinct components.
    return value if len(value) <= 200 else f"sha256:{digest(value)}"


def normalize_integration(
    kind: str, payload: dict, *, context: IntakeContext | dict | None = None
) -> NormalizedIntake:
    from .composition_intake import normalize_cyclonedx, normalize_sarif
    from .mcp_discovery import normalize_mcp_tools
    from .telemetry_intake import normalize_anthropic_hooks, normalize_openai_agents, normalize_otel

    parsers = {
        "otel_genai": normalize_otel,
        "openai_agents": normalize_openai_agents,
        "anthropic_hooks": normalize_anthropic_hooks,
        "mcp_tools": normalize_mcp_tools,
        "cyclonedx": normalize_cyclonedx,
        "sarif": normalize_sarif,
    }
    if kind not in parsers:
        raise ValueError("Unsupported integration format")
    ctx = IntakeContext.model_validate(context or {})
    return parsers[kind](bounded_document(payload), ctx)
