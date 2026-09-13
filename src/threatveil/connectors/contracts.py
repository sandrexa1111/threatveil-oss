"""Public, versioned connector roles. No connector is a policy decision issuer."""

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


PROFILE = "connector/v1"
CONFORMANCE = "connector-conformance/v1"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Role(StrEnum):
    DISCOVER = "DISCOVER"
    CHANGE = "CHANGE"
    OBSERVE = "OBSERVE"
    VERIFY = "VERIFY"
    EXECUTE = "EXECUTE"
    ENFORCE = "ENFORCE"
    EXPORT = "EXPORT"
    CONSUME = "CONSUME"


class RoleContract(StrictModel):
    schema_version: Literal["connector/v1"] = PROFILE
    role: Role
    supported_versions: tuple[str, ...]
    permissions: tuple[str, ...]
    authority: Literal["READ", "WRITE", "LOCAL_READ"]
    facts: tuple[str, ...]
    qualification_assumptions: tuple[str, ...]
    freshness_seconds: int = Field(ge=1, le=86400)
    continuity: str
    pagination: str
    failures: tuple[str, ...]
    data_classification: Literal["PRIVATE_CUSTOMER_DATA"] = "PRIVATE_CUSTOMER_DATA"
    retention: str = "Organization retention/disclosure policy; no cross-customer use"
    limits: dict[str, int | str]
    conformance_version: Literal["connector-conformance/v1"] = CONFORMANCE
    implementation: str


class ConnectorManifest(StrictModel):
    schema_version: Literal["connector/v1"] = PROFILE
    id: str
    version: Literal["1.0.0"] = "1.0.0"
    name: str
    roles: tuple[RoleContract, ...]
    installation_roles: tuple[Role, ...]
    modes: tuple[Literal["IMPORT", "POLL", "PUSH"], ...]
    limitations: tuple[str, ...]


FAILURES = (
    "UNAVAILABLE", "UNAUTHORIZED", "EXPIRED", "RATE_LIMITED", "INVALID_RESPONSE",
    "PARTIAL", "CURSOR_GAP", "REORDERED", "CONFIGURATION_CHANGED",
)


def _role(role, versions, permissions, facts, *, implementation, authority="READ",
          freshness=300, pagination="One exact configured resource; no pagination",
          assumptions=(), continuity="Snapshot reconciliation only; intermediate changes unknown",
          requests=4):
    return RoleContract(
        role=role, supported_versions=tuple(versions), permissions=tuple(permissions),
        authority=authority, facts=tuple(facts),
        qualification_assumptions=(
            "Source identity describes acquisition, never system-wide assurance",
            "Running state, behavior and business effects require separate qualified evidence",
            *assumptions,
        ), freshness_seconds=freshness, continuity=continuity, pagination=pagination,
        failures=FAILURES,
        limits={"requests_per_collection": requests, "max_bytes": 4194304,
                "timeout_seconds": 60, "concurrency_per_installation": 1,
                "retry": "No automatic retries; next explicit collection reconciles",
                "cost": "No model execution; provider API rate/cost limits also apply",
                "minimum_collection_interval_seconds": 10},
        implementation=implementation,
    )


def manifests() -> dict[str, ConnectorManifest]:
    github = tuple(_role(
        role, ["GitHub REST 2022-11-28"], ["metadata:read", "contents:read"],
        ["repository_identity", "configured_git_ref"], implementation="github_read_snapshot",
    ) for role in (Role.DISCOVER, Role.CHANGE))
    github += (
        _role(Role.ENFORCE, ["GitHub REST 2022-11-28"], ["checks:write"],
              ["exact_sha_check_publication"], authority="WRITE",
              implementation="existing /v1/github-app release binding and publication outbox",
              assumptions=["Separate GitHub App approval/credential; read installations cannot invoke"],
              pagination="At most ten pages of 100 checks; ambiguous writes reconcile"),
        _role(Role.EXPORT, ["GitHub REST 2022-11-28", "ThreatVeil release receipt v1"],
              ["checks:write"], ["scoped_release_summary"], authority="WRITE",
              implementation="existing GitHub App exact-SHA check payload",
              assumptions=["Publishing a check does not prove a required gate was enforced"]),
    )
    result = {
        "github": ConnectorManifest(
            id="github", name="GitHub", roles=github,
            installation_roles=(Role.DISCOVER, Role.CHANGE), modes=("POLL",),
            limitations=("A repository revision is not a deployed state.",
                         "Canonical read installation is separate from the existing write binding.")),
        "mcp": ConnectorManifest(
            id="mcp", name="Bounded MCP", modes=("POLL", "IMPORT"),
            installation_roles=(Role.DISCOVER, Role.CHANGE),
            roles=tuple(_role(
                role,
                ["MCP 2026-07-28 stateless Streamable HTTP", "MCP 2025-11-25 Streamable HTTP"],
                ["verified target POST path", "server/discover", "tools/list",
                 "initialize (legacy era only)"],
                ["tool_catalog", "tool_contract", "declared_authorization",
                 "protocol_revision", "catalog_freshness"],
                implementation="version-aware MCP discovery over the authorized transport",
                pagination="At most 3 pages / 1000 tools / 4 MiB; repeated cursor aborts",
                assumptions=[
                    "Server tool descriptions and annotations remain unreviewed declarations",
                    "A server cache hint bounds re-read freshness, never evidence validity",
                    "The protocol era is established by an observed response, never assumed",
                ],
                requests=5,
            ) for role in (Role.DISCOVER, Role.CHANGE)),
            limitations=(
                "Catalog discovery never executes tools or verifies behavior.",
                "Legacy 2025-11-25 remains supported only for its deprecation window.",
                "Extensions, multi round-trip input and subscriptions are not implemented; "
                "see threatveil.integrations.mcp_protocol.FEATURE_SUPPORT for exact coverage.")),
        "otel": ConnectorManifest(
            id="otel", name="OpenTelemetry", modes=("PUSH", "IMPORT"),
            installation_roles=(Role.OBSERVE,),
            roles=(_role(Role.OBSERVE, ["OTLP JSON v1 / integration-intake-v1 GenAI subset"],
                         ["tenant API ingestion permission"],
                         ["recorded_invocation", "advertised_model", "instrumented_configuration"],
                         implementation="bounded authenticated OTLP JSON intake", requests=0,
                         pagination="Bounded batch, at most 5000 spans; no collector backfill",
                         continuity="Optional sequence/cursor detects gaps; sampling remains UNKNOWN",
                         assumptions=["Authenticated uploader is not an independent witness",
                                      "Success and finished spans do not prove committed effects"]),),
            limitations=("No telemetry absence/completeness claim or behavioral qualification.",
                         "Prompt bodies, arguments and outputs omitted from projection.")),
        "gcp_cloud_run": ConnectorManifest(
            id="gcp_cloud_run", name="GCP Cloud Run", modes=("POLL", "IMPORT"),
            installation_roles=(Role.DISCOVER, Role.CHANGE, Role.OBSERVE),
            roles=tuple(_role(
                role, ["Cloud Run Admin API v2", "google-cloud-run 0.x"],
                ["run.services.get", "run.services.getIamPolicy"],
                ["desired_configuration", "service_iam_policy", "control_plane_routing_status"],
                implementation="Google Cloud Run ServicesClient bounded read snapshot",
                assumptions=["Four reads compare service and policy etags; no cross-resource atomicity",
                             "Cloud control plane is not an independent running-code attestation",
                             "Service IAM omits inherited IAM, deny policies and effective access"],
            ) for role in (Role.DISCOVER, Role.CHANGE, Role.OBSERVE)),
            limitations=("Desired template and readiness never establish exact running system state.",
                         "One configured service only; no deployment/enforcement writes.")),
    }
    for name, label, version, facts in (
        ("openai_agents", "OpenAI Agents import", "integration-intake-v1 Agents export subset",
         ["recorded_invocation", "advertised_model"]),
        ("anthropic_hooks", "Anthropic hooks import", "integration-intake-v1 hooks subset",
         ["recorded_invocation", "advertised_model"]),
        ("cyclonedx", "CycloneDX import", "CycloneDX 1.5 / 1.6",
         ["declared_composition", "declared_dependencies"]),
        ("sarif", "SARIF import", "SARIF 2.1.0", ["unverified_finding"]),
    ):
        role = Role.OBSERVE if name in {"openai_agents", "anthropic_hooks"} else Role.DISCOVER
        result[name] = ConnectorManifest(
            id=name, name=label, modes=("IMPORT",), installation_roles=(role,),
            roles=(_role(role, [version], ["tenant API import permission"], facts,
                         implementation="existing integration-intake-v1 parser", authority="LOCAL_READ",
                         requests=0, pagination="One bounded 4 MiB document; external files not fetched",
                         continuity="Imported snapshot; live connectivity and continuity UNKNOWN"),),
            limitations=("Imported data is never a connected provider.",
                         "Imported facts and findings remain UNREVIEWED; no behavioral verdict."))
    result["agent_definition"] = ConnectorManifest(
        id="agent_definition", name="Agent definition import", modes=("IMPORT",),
        installation_roles=(Role.DISCOVER, Role.CHANGE),
        roles=tuple(_role(
            role, ["ThreatVeil agent manifest v1", "Claude Code settings.json", ".mcp.json",
                   "Claude subagent markdown", "langgraph.json", "CrewAI agents.yaml"],
            ["tenant API import permission"],
            ["declared_agents", "declared_tool_permissions", "declared_mcp_servers", "advertised_model"],
            implementation="deterministic agent-definition adapters (threatveil.agent_definitions)",
            authority="LOCAL_READ", requests=0,
            pagination="One bounded 256 KiB definition; referenced files are not fetched",
            continuity="Imported snapshot; live connectivity and continuity UNKNOWN",
            assumptions=["A definition file is declared configuration, not the running agent",
                         "Secret values are never retained; only names and digests"],
        ) for role in (Role.DISCOVER, Role.CHANGE)),
        limitations=("A definition file is declared configuration, never proof of the running agent.",
                     "Code-defined agents (OpenAI Agents SDK, LangGraph tools) are UNKNOWN; no code is "
                     "executed or parsed."))
    return result


class Snapshot(StrictModel):
    """Internal collector result; API clients cannot select acquisition or authority."""
    source_version: str
    mapping_version: str = PROFILE
    components: dict[str, dict[str, Any]] = Field(default_factory=dict)
    facts: dict[str, Any] = Field(default_factory=dict)
    complete: bool = False
    limitations: tuple[str, ...] = ()


class BatchInput(StrictModel):
    event_id: str = Field(min_length=8, max_length=120)
    payload: dict[str, Any]
    valid_at: datetime
    sequence: int | None = Field(default=None, ge=0, le=2**53 - 1)
    cursor: str | None = Field(default=None, min_length=1, max_length=2048)
    previous_cursor: str | None = Field(default=None, min_length=1, max_length=2048)

    @field_validator("valid_at")
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None:
            raise ValueError("Source valid time requires a timezone")
        return value
