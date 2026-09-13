import json

from threatveil.core.contracts import Observation

from .base import Adapter, AdapterCapabilities, AdapterContext, AuthorizedTransport, Stimulus


class HTTPAgentAdapter(Adapter):
    capabilities = AdapterCapabilities(
        id="http-agent",
        version="1.0",
        input_modalities=("structured_input",),
        action_types=("DIGITAL_TOOL_ACTION",),
        state_sources=("customer_instrumentation",),
        reset_capability="CUSTOMER_RESET",
        side_effect_class="DIGITAL_ONLY",
        observation_coverage=("customer_declared",),
        execution_mode="DIGITAL_STAGING",
        authority_model="Customer identity; run-scoped broker credentials",
    )

    def __init__(self, transport: AuthorizedTransport):
        self.transport = transport
        self.context: AdapterContext | None = None
        self._observation: Observation | None = None

    async def prepare(self, context: AdapterContext) -> None:
        if context.execution_mode != "DIGITAL_STAGING":
            raise ValueError(
                "HTTP adapter requires an explicitly authorized digital staging target"
            )
        self.context, self._observation = context, None

    async def stimulate(self, stimulus: Stimulus) -> None:
        if self.context is None or stimulus.correlation_id != self.context.correlation_id:
            raise ValueError("Adapter must be prepared with the same correlation ID")
        if stimulus.type != "structured_input":
            raise ValueError("HTTP adapter expects structured_input")
        body = json.dumps(
            {
                "schema_version": "1.0",
                "correlation_id": stimulus.correlation_id,
                "input": stimulus.payload,
            },
            allow_nan=False,
        ).encode()
        if len(body) > 262144:
            raise ValueError("Stimulus exceeds 256 KiB")
        response = await self.transport.request(
            "POST",
            self.context.endpoint_url,
            body=body,
            headers={"Content-Type": "application/json"},
        )
        if response.status_code < 200 or response.status_code >= 300:
            raise RuntimeError(f"Target request returned HTTP {response.status_code}")
        if len(response.body) > 1048576:
            raise ValueError("Observation exceeds 1 MiB")
        self._observation = Observation.model_validate_json(response.body)
        if self._observation.correlation_id != self.context.correlation_id:
            raise ValueError("Target returned unrelated observation")

    async def observe(self) -> Observation:
        if self._observation is None:
            raise ValueError("No observation has been collected")
        return self._observation

    async def cleanup(self) -> None:
        self.context, self._observation = None, None
