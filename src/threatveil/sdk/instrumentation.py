"""Small instrumentation SDK. Emitting receipts does not qualify their source."""

from uuid import uuid4

from threatveil.core.contracts import Action, Observation, Receipt, Witness


class Trace:
    def __init__(
        self, source_id: str, source_version: str, boundary: str, correlation_id: str | None = None
    ):
        self.source_id, self.source_version, self.boundary = source_id, source_version, boundary
        self.correlation_id = correlation_id or str(uuid4())
        self.receipts: list[Receipt] = []

    def _record(self, event_type: str, action: Action | dict) -> Receipt:
        receipt = Receipt(
            correlation_id=self.correlation_id,
            sequence=len(self.receipts),
            source_id=self.source_id,
            source_version=self.source_version,
            event_type=event_type,
            action=Action.model_validate(action),
        )
        self.receipts.append(receipt)
        return receipt

    def agent_run(self, action: Action | dict):
        return self._record("agent_run", action)

    def tool_call(self, action: Action | dict):
        return self._record("tool_call", action)

    def resource_access(self, action: Action | dict):
        return self._record("resource_access", action)

    def external_action(self, action: Action | dict):
        return self._record("external_action", action)

    def permission_check(self, action: Action | dict):
        return self._record("permission_check", action)

    def state_change(self, action: Action | dict):
        return self._record("state_change", action)

    def observation(self, *, complete: bool = False) -> Observation:
        witness = Witness(
            id=self.source_id,
            source_type="sdk_instrumentation",
            source_version=self.source_version,
            authority="INSTRUMENTED",
            correlation_id=self.correlation_id,
            complete=complete,
            covered_operations=tuple(sorted({r.action.operation for r in self.receipts})),
            boundary=self.boundary,
        )
        return Observation(
            correlation_id=self.correlation_id,
            receipts=tuple(self.receipts),
            witnesses=(witness,),
            limitations=("SDK collection requires independent witness qualification.",),
        )
