"""Model API adapter: generated tool requests are not executed or called side effects."""

import json

from threatveil.core.contracts import Observation

from .base import AdapterCapabilities, Stimulus
from .http import HTTPAgentAdapter


class OpenAICompatibleAdapter(HTTPAgentAdapter):
    capabilities = AdapterCapabilities(
        id="openai-compatible",
        version="1.0",
        input_modalities=("chat_messages",),
        action_types=("MODEL_OUTPUT",),
        state_sources=("provider_response",),
        reset_capability="FRESH_SESSION",
        side_effect_class="DIGITAL_ONLY",
        observation_coverage=("model_output_only",),
        execution_mode="DIGITAL_STAGING",
        authority_model="Run-scoped provider credential; no tools executed",
    )

    def __init__(self, transport, model: str):
        super().__init__(transport)
        self.model = model
        self.model_response: dict | None = None

    async def stimulate(self, stimulus: Stimulus) -> None:
        if self.context is None or stimulus.correlation_id != self.context.correlation_id:
            raise ValueError("Unprepared or unrelated model stimulus")
        if stimulus.type != "chat_messages" or set(stimulus.payload) - {"messages", "temperature"}:
            raise ValueError("Only bounded chat messages and temperature are supported")
        messages = stimulus.payload.get("messages")
        if not isinstance(messages, list) or not 1 <= len(messages) <= 50:
            raise ValueError("Require between 1 and 50 messages")
        body = json.dumps(
            {
                "model": self.model,
                "messages": messages,
                "temperature": stimulus.payload.get("temperature", 0),
                "stream": False,
                "max_tokens": 2048,
            },
            allow_nan=False,
        ).encode()
        if len(body) > 262144:
            raise ValueError("Model stimulus exceeds 256 KiB")
        response = await self.transport.request(
            "POST",
            self.context.endpoint_url,
            body=body,
            headers={"Content-Type": "application/json"},
        )
        if response.status_code != 200 or len(response.body) > 1048576:
            raise RuntimeError("Provider response failed or exceeds bounds")
        self.model_response = json.loads(response.body)
        if not isinstance(self.model_response.get("choices"), list):
            raise ValueError("Provider response has no choices")
        self._observation = Observation(
            correlation_id=stimulus.correlation_id,
            limitations=(
                "Provider response is self-report; no authoritative tool/state witness.",
                "Model-generated tool requests are never automatically executed.",
            ),
        )

    async def cleanup(self) -> None:
        await super().cleanup()
        self.model_response = None
