"""Recorded trace import cannot claim current-system verification."""

from threatveil.core.contracts import Observation

from .base import Adapter, AdapterCapabilities, AdapterContext, Stimulus


class StructuredTraceAdapter(Adapter):
    capabilities = AdapterCapabilities(
        id="structured-trace",
        version="1.0",
        input_modalities=("structured_input",),
        action_types=("RECORDED_ACTION",),
        state_sources=("imported_receipts",),
        reset_capability="NONE",
        side_effect_class="RECORDED_ONLY",
        observation_coverage=("recorded_receipts",),
        execution_mode="RECORDED_REPLAY",
        authority_model="Imported sources require separate qualification",
    )

    def __init__(self):
        self.context: AdapterContext | None = None
        self._observation: Observation | None = None

    async def prepare(self, context: AdapterContext) -> None:
        if context.execution_mode != "RECORDED_REPLAY":
            raise ValueError("Trace adapter only re-evaluates recorded observations")
        self.context = context

    async def stimulate(self, stimulus: Stimulus) -> None:
        if self.context is None or stimulus.correlation_id != self.context.correlation_id:
            raise ValueError("Unprepared or unrelated trace")
        raw = Observation.model_validate(stimulus.payload)
        if raw.correlation_id != self.context.correlation_id:
            raise ValueError("Trace correlation mismatch")
        self._observation = raw.model_copy(
            update={
                "boundary_mocked": True,
                "limitations": raw.limitations
                + ("Recorded observations do not test a current live boundary.",),
            }
        )

    async def observe(self) -> Observation:
        if self._observation is None:
            raise ValueError("No trace imported")
        return self._observation

    async def cleanup(self) -> None:
        self.context, self._observation = None, None
