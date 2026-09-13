"""Autonomous-system adapter interfaces, not prompt-specific transports."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Literal, Mapping, Protocol

from pydantic import Field

from threatveil.core.contracts import Contract, Observation, Receipt


class AdapterCapabilities(Contract):
    id: str
    version: str
    input_modalities: tuple[str, ...]
    action_types: tuple[str, ...]
    state_sources: tuple[str, ...]
    reset_capability: Literal["FRESH_SESSION", "CUSTOMER_RESET", "NONE"]
    side_effect_class: Literal["DIGITAL_ONLY", "RECORDED_ONLY"]
    observation_coverage: tuple[str, ...]
    execution_mode: Literal["DIGITAL_SANDBOX", "DIGITAL_STAGING", "RECORDED_REPLAY"]
    authority_model: str


class Stimulus(Contract):
    type: Literal["structured_input", "tool_call", "chat_messages"]
    payload: dict[str, Any]
    correlation_id: str = Field(min_length=1, max_length=200)


@dataclass(frozen=True)
class TransportResponse:
    status_code: int
    body: bytes
    headers: Mapping[str, str]


class AuthorizedTransport(Protocol):
    """Caller enforces DNS pinning, target scope, expiry, quotas and deadlines.

    The adapter never creates a network client, follows redirects, resolves URLs,
    fetches secrets, or derives a destination from model output.
    """

    async def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> TransportResponse: ...


@dataclass(frozen=True)
class AdapterContext:
    endpoint_url: str
    execution_mode: Literal["DIGITAL_SANDBOX", "DIGITAL_STAGING", "RECORDED_REPLAY"]
    correlation_id: str
    # Credentials are injected by the broker transport; never a target dictionary.


class Adapter(ABC):
    capabilities: AdapterCapabilities

    @abstractmethod
    async def prepare(self, context: AdapterContext) -> None: ...

    @abstractmethod
    async def stimulate(self, stimulus: Stimulus) -> None: ...

    @abstractmethod
    async def observe(self) -> Observation: ...

    async def collect_tool_trace(self) -> tuple[Receipt, ...]:
        return (await self.observe()).receipts

    async def collect_state(self) -> tuple[dict, ...]:
        return tuple(
            r.action.after for r in (await self.observe()).receipts if r.action.after is not None
        )

    @abstractmethod
    async def cleanup(self) -> None: ...
