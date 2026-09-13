"""OTLP/JSON GenAI, OpenAI Agents export, and Claude SDK hook projections.

Transport reports are instrumented invocation observations. They cannot prove
authorization, denial, durable mutation, task success, or observation completeness.
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from threatveil.core.contracts import (
    Action,
    ActionPhase,
    FingerprintComponent,
    Observation,
    Principal,
    Receipt,
    Resource,
    SystemFingerprint,
    Witness,
    digest,
)

from .intake import (
    MAX_ITEMS,
    IntakeContext,
    NormalizedIntake,
    TraceEdge,
    array_value,
    component_id,
    object_value,
    text_value,
)

TRACE_LIMITATIONS = (
    "Imported telemetry is unqualified instrumentation, not authoritative committed state.",
    "Sampling, missing spans and exporter failures prevent completeness claims.",
    "Model/tool output and success flags do not establish a legitimate-task result.",
    "Observed configuration is a partial fingerprint proposal requiring candidate review.",
    "Prompt bodies, tool arguments and outputs are omitted from the normalized projection.",
)


def _optional_text(value: Any, label: str) -> str | None:
    return None if value is None else text_value(value, label)


def _any_value(value: Any) -> Any:
    obj = object_value(value, "OTLP AnyValue")
    if len(obj) != 1:
        raise ValueError("OTLP AnyValue requires exactly one typed value")
    key, data = next(iter(obj.items()))
    if key == "stringValue" and isinstance(data, str):
        return data
    if key == "boolValue" and isinstance(data, bool):
        return data
    if key == "intValue" and not isinstance(data, bool):
        if isinstance(data, int) or (isinstance(data, str) and re.fullmatch(r"-?[0-9]+", data)):
            result = int(data)
            if -(2**63) <= result < 2**63:
                return result
    if key == "doubleValue" and isinstance(data, (float, int)) and not isinstance(data, bool):
        return data
    if key == "arrayValue":
        return [_any_value(v) for v in array_value(object_value(data, key).get("values", []), key)]
    if key == "kvlistValue":
        return _attributes(object_value(data, key).get("values", []))
    if key == "bytesValue" and isinstance(data, str):
        # Retain the wire value for hashing; do not interpret it as text or identity.
        return {"bytesValue": data}
    raise ValueError("Unsupported or malformed OTLP AnyValue")


def _attributes(value: Any) -> dict:
    attributes = {}
    for item in array_value(value, "OTLP attributes"):
        entry = object_value(item, "OTLP attribute")
        key = text_value(entry.get("key"), "OTLP attribute key")
        if key in attributes:
            raise ValueError("Duplicate OTLP attribute key")
        attributes[key] = _any_value(entry.get("value"))
    return attributes


def _otlp_time(value: Any) -> datetime:
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,20}", str(value)):
        raise ValueError("OTLP span timestamps must be unsigned nanoseconds")
    nanos = int(value)
    if nanos <= 0 or nanos >= 2**64:
        raise ValueError("OTLP span timestamp is outside the supported range")
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=nanos // 1000)


def _iso_time(value: Any, ctx: IntakeContext, limitations: set[str]) -> datetime:
    if value is None:
        limitations.add("Some events omit source timestamps; received time is not execution time.")
        return ctx.received_at
    timestamp = datetime.fromisoformat(text_value(value, "Event timestamp"))
    if timestamp.tzinfo is None:
        raise ValueError("Event timestamps must include a timezone")
    return timestamp


class _Projection:
    def __init__(self, kind: str, payload: dict, ctx: IntakeContext):
        self.kind, self.payload, self.ctx = kind, payload, ctx
        self.groups: dict[str, list[Receipt]] = defaultdict(list)
        self.errors: set[str] = set()
        self.edges: list[TraceEdge] = []
        self.seen: set[tuple[str, str]] = set()
        self.components: dict[tuple[str, str], FingerprintComponent] = {}
        self.limitations = set(TRACE_LIMITATIONS)

    def component(self, kind: str, identity: str, data: Any, version: str | None = None):
        key = kind, component_id(identity)
        component = FingerprintComponent(
            type=key[0],
            id=key[1],
            version=version,
            digest=digest(data) if data is not None else None,
            provenance="OBSERVED" if data is not None else "UNKNOWN",
        )
        if key in self.components and self.components[key] != component:
            component = FingerprintComponent(type=key[0], id=key[1], provenance="UNKNOWN")
            self.limitations.add(
                "Conflicting observed component versions cannot define one candidate."
            )
        self.components[key] = component

    def event(
        self,
        *,
        trace: str,
        identity: str,
        operation: str,
        timestamp: datetime,
        phase: ActionPhase = ActionPhase.ATTEMPTED,
        tool: str | None = None,
        agent: str | None = None,
        parent: str | None = None,
        delegated_from: str | None = None,
        delegated_to: str | None = None,
        failed: bool = False,
    ):
        trace = text_value(trace, "Trace/session identity", limit=200)
        identity = text_value(identity, "Event identity", limit=500)
        if self.ctx.expected_correlation_id and trace != self.ctx.expected_correlation_id:
            raise ValueError("Imported correlation does not match the requested correlation")
        key = trace, identity
        if key in self.seen:
            raise ValueError("Duplicate imported event identity")
        self.seen.add(key)
        if len(self.seen) > MAX_ITEMS:
            raise ValueError("Telemetry import exceeds 5000 events")
        self.edges.append(
            TraceEdge(
                trace_id=trace,
                span_id=identity,
                parent_span_id=parent,
                agent_id=agent,
                delegated_from=delegated_from,
                delegated_to=delegated_to,
            )
        )
        if failed:
            self.errors.add(trace)
            self.limitations.add(
                "A source reported an execution error; this is not a security verdict."
            )
        event_id = digest(
            {
                "source": self.ctx.source_id,
                "format": self.kind,
                "trace": trace,
                "event": identity,
                "payload": digest(self.payload),
            }
        )
        receipt = Receipt(
            id=event_id,
            correlation_id=trace,
            sequence=len(self.groups[trace]),
            source_id=self.ctx.source_id,
            source_version=self.ctx.source_version,
            observed_at=timestamp,
            event_type="tool_call" if tool else "agent_run",
            action=Action(
                id=event_id,
                type="RECORDED_INVOCATION",
                operation=operation,
                tool=tool,
                principal=Principal(id=agent or "UNKNOWN"),
                resource=Resource(
                    type="tool" if tool else "agent_workflow", id=component_id(tool or trace)
                ),
                phase=phase,
                trust_source="UNKNOWN",
            ),
        )
        self.groups[trace].append(receipt)

    def finish(self) -> NormalizedIntake:
        limitations = tuple(sorted(self.limitations))
        observations = []
        fingerprint = SystemFingerprint(
            components=tuple(self.components[k] for k in sorted(self.components))
        )
        for trace, receipts in sorted(self.groups.items()):
            witness = Witness(
                id=self.ctx.source_id,
                source_type=self.kind,
                source_version=self.ctx.source_version,
                authority="INSTRUMENTED",
                correlation_id=trace,
                complete=False,
                covered_operations=tuple(sorted({r.action.operation for r in receipts})),
                boundary=self.ctx.boundary,
                observed_at=max(r.observed_at for r in receipts),
                failure_modes=("unqualified_import", "incomplete_coverage", "no_committed_state"),
            )
            observations.append(
                Observation(
                    correlation_id=trace,
                    receipts=tuple(receipts),
                    witnesses=(witness,),
                    boundary_mocked=True,
                    fingerprint=fingerprint,
                    task_outcome="UNKNOWN",
                    execution_status="ERROR" if trace in self.errors else "COMPLETED",
                    limitations=limitations,
                )
            )
        if not observations:
            limitations += ("No supported invocation observations were present.",)
        return NormalizedIntake(
            format=self.kind,
            source_digest=digest(self.payload),
            fingerprint=fingerprint,
            observations=tuple(observations),
            trace_edges=tuple(self.edges),
            limitations=limitations,
        )


def normalize_otel(payload: dict, ctx: IntakeContext) -> NormalizedIntake:
    """Parse OTLP/JSON ExportTraceServiceRequest using GenAI span attributes."""
    projection = _Projection("otel_genai", payload, ctx)
    seen_spans = set()
    count = 0
    for resource_group in array_value(payload.get("resourceSpans"), "resourceSpans"):
        group = object_value(resource_group, "ResourceSpans")
        resource = _attributes(
            object_value(group.get("resource", {}), "resource").get("attributes", [])
        )
        for scope_group in array_value(group.get("scopeSpans", []), "scopeSpans"):
            scope = object_value(scope_group, "ScopeSpans")
            for raw in array_value(scope.get("spans", []), "spans"):
                count += 1
                if count > MAX_ITEMS:
                    raise ValueError("OTLP import exceeds 5000 spans")
                span = object_value(raw, "Span")
                attrs = _attributes(span.get("attributes", []))
                trace, identity = span.get("traceId"), span.get("spanId")
                if (
                    not isinstance(trace, str)
                    or not re.fullmatch(r"[0-9a-fA-F]{32}", trace)
                    or int(trace, 16) == 0
                    or not isinstance(identity, str)
                    or not re.fullmatch(r"[0-9a-fA-F]{16}", identity)
                    or int(identity, 16) == 0
                ):
                    raise ValueError("OTLP requires nonzero hexadecimal traceId and spanId")
                trace, identity = trace.lower(), identity.lower()
                if (trace, identity) in seen_spans:
                    raise ValueError("Duplicate OTLP span identity")
                seen_spans.add((trace, identity))
                parent = span.get("parentSpanId") or None
                if parent is not None:
                    if not isinstance(parent, str) or not re.fullmatch(r"[0-9a-fA-F]{16}", parent):
                        raise ValueError("Invalid OTLP parentSpanId")
                    parent = parent.lower() if int(parent, 16) else None
                operation = attrs.get("gen_ai.operation.name")
                if operation is None:
                    projection.limitations.add(
                        "Non-GenAI spans were omitted from invocation projection."
                    )
                    continue
                operation = text_value(operation, "GenAI operation")
                started = _otlp_time(span.get("startTimeUnixNano"))
                ended = _otlp_time(span["endTimeUnixNano"]) if span.get("endTimeUnixNano") else None
                if ended and ended < started:
                    raise ValueError("OTLP span ends before it starts")
                provider = (
                    _optional_text(
                        attrs.get("gen_ai.provider.name", attrs.get("gen_ai.system")), "Provider"
                    )
                    or "UNKNOWN"
                )
                model = _optional_text(attrs.get("gen_ai.request.model"), "Model")
                slot = f"{ctx.source_id}:{provider}:{model or 'unknown'}"
                if model:
                    projection.component(
                        "model", slot, {"provider": provider, "model": model}, model
                    )
                    config = {k: v for k, v in attrs.items() if k.startswith("gen_ai.request.")}
                    projection.component("model_config", slot, config)
                if "gen_ai.tool.definitions" in attrs:
                    projection.component("toolset", slot, attrs["gen_ai.tool.definitions"])
                if "gen_ai.system_instructions" in attrs:
                    projection.component("prompt", slot, attrs["gen_ai.system_instructions"])
                tool = _optional_text(attrs.get("gen_ai.tool.name"), "Tool name")
                if operation == "execute_tool" and tool is None:
                    projection.limitations.add("An execute_tool span omitted the tool name.")
                agent = _optional_text(attrs.get("gen_ai.agent.id"), "Agent identity")
                if agent:
                    projection.component(
                        "agent",
                        agent,
                        {k: v for k, v in attrs.items() if k.startswith("gen_ai.agent.")},
                    )
                if resource.get("service.version"):
                    service = text_value(
                        resource.get("service.name", ctx.source_id), "Service name"
                    )
                    version = text_value(resource["service.version"], "Service version")
                    projection.component("application", service, {"version": version}, version)
                if any(
                    span.get(k, 0)
                    for k in ("droppedAttributesCount", "droppedEventsCount", "droppedLinksCount")
                ):
                    projection.limitations.add("The exporter reported dropped span data.")
                status = object_value(span.get("status", {}), "Span status")
                projection.event(
                    trace=trace,
                    identity=identity,
                    operation=tool or operation,
                    timestamp=ended or started,
                    tool=tool,
                    agent=agent,
                    parent=parent,
                    phase=ActionPhase.DISPATCHED if ended and tool else ActionPhase.ATTEMPTED,
                    failed=status.get("code") in (2, "STATUS_CODE_ERROR"),
                )
    return projection.finish()


def normalize_openai_agents(payload: dict, ctx: IntakeContext) -> NormalizedIntake:
    """Import Python Agents SDK Span.export() records, wrapped in {spans:[...]}."""
    projection = _Projection("openai_agents", payload, ctx)
    for value in array_value(payload.get("spans"), "OpenAI spans"):
        span = object_value(value, "OpenAI span")
        data = object_value(span.get("span_data"), "OpenAI span_data")
        kind = text_value(data.get("type"), "OpenAI span type")
        if kind not in (
            "agent",
            "function",
            "generation",
            "response",
            "handoff",
            "guardrail",
            "custom",
            "mcp_tools",
        ):
            projection.limitations.add(
                "Unsupported OpenAI span types were retained only by source digest."
            )
            continue
        trace = text_value(span.get("trace_id"), "OpenAI trace_id", limit=200)
        identity = text_value(span.get("id"), "OpenAI span id", limit=200)
        parent = _optional_text(span.get("parent_id"), "OpenAI parent_id")
        ended = span.get("ended_at")
        timestamp = _iso_time(ended or span.get("started_at"), ctx, projection.limitations)
        if ended and span.get("started_at"):
            if timestamp < _iso_time(span["started_at"], ctx, projection.limitations):
                raise ValueError("OpenAI span ends before it starts")
        tool = text_value(data.get("name"), "Function name") if kind == "function" else None
        model = data.get("model")
        if kind == "response":
            response = data.get("response")
            if isinstance(response, dict):
                model = response.get("model")
            if not model:
                projection.component("model", f"{ctx.source_id}:response", None)
                projection.limitations.add(
                    "Responses span export omits model/configuration details."
                )
        if kind == "mcp_tools":
            server = _optional_text(data.get("server"), "MCP server") or "UNKNOWN"
            projection.component("mcp", f"{ctx.source_id}:{server}", None)
            projection.component("toolset", f"{ctx.source_id}:{server}", data.get("result"))
            projection.limitations.add(
                "Agents MCP span lists tool names only; full contracts require tools/list capture."
            )
        if model:
            model = text_value(model, "OpenAI model")
            slot = f"{ctx.source_id}:{model}"
            projection.component("model", slot, {"model": model}, model)
            projection.component("model_config", slot, data.get("model_config"))
        if kind == "agent":
            name = text_value(data.get("name"), "Agent name")
            projection.component("agent", f"{ctx.source_id}:{name}", data)
        projection.event(
            trace=trace,
            identity=identity,
            operation=tool or f"agent.{kind}",
            timestamp=timestamp,
            tool=tool,
            parent=parent,
            phase=ActionPhase.DISPATCHED if ended and tool else ActionPhase.ATTEMPTED,
            delegated_from=_optional_text(data.get("from_agent"), "Handoff source")
            if kind == "handoff"
            else None,
            delegated_to=_optional_text(data.get("to_agent"), "Handoff destination")
            if kind == "handoff"
            else None,
            failed=bool(span.get("error")),
        )
    return projection.finish()


def normalize_anthropic_hooks(payload: dict, ctx: IntakeContext) -> NormalizedIntake:
    """Import Claude Agent SDK hook inputs, wrapped in {events:[...]}.

    A sender may add observed_at and tool_use_id from its callback arguments.
    Input tool_result/tool_response text is never promoted to state evidence.
    """
    projection = _Projection("anthropic_hooks", payload, ctx)
    supported = {"PreToolUse", "PostToolUse", "PostToolUseFailure", "SubagentStart", "SubagentStop"}
    for raw in array_value(payload.get("events"), "Anthropic hook events"):
        event = object_value(raw, "Anthropic hook input")
        hook = text_value(event.get("hook_event_name"), "hook_event_name")
        if hook not in supported:
            projection.limitations.add(
                "Unsupported Claude hooks were retained only by source digest."
            )
            continue
        trace = text_value(event.get("session_id"), "Claude session_id", limit=200)
        tool = text_value(event.get("tool_name"), "Claude tool_name") if "ToolUse" in hook else None
        agent = _optional_text(event.get("agent_id"), "Claude agent_id")
        call_id = text_value(
            event.get("tool_use_id") if tool else agent, "Hook event identity", limit=200
        )
        timestamp = _iso_time(event.get("observed_at"), ctx, projection.limitations)
        projection.event(
            trace=trace,
            identity=f"{hook}:{call_id}",
            tool=tool,
            agent=agent,
            operation=tool or f"agent.{hook}",
            timestamp=timestamp,
            phase=ActionPhase.DISPATCHED
            if hook in ("PostToolUse", "PostToolUseFailure")
            else ActionPhase.ATTEMPTED,
            failed=hook == "PostToolUseFailure",
        )
    return projection.finish()
