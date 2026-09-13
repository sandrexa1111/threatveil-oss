import json
from uuid import uuid4

import httpx
import pytest

from threatveil.sdk import ThreatVeilClient


def test_sdk_sends_stable_idempotency_and_scoped_auth():
    seen = []
    run_id = str(uuid4())

    def handle(request):
        seen.append(request)
        return httpx.Response(
            202, json={"id": run_id, "status": "COMPLETED", "release_action": "BLOCK"}
        )

    http_client = httpx.Client(transport=httpx.MockTransport(handle))
    observer_id = str(uuid4())
    with ThreatVeilClient(
        "https://control.example", "synthetic-test-token", http_client=http_client
    ) as client:
        result = client.create_run(
            system_id=str(uuid4()),
            property_id=str(uuid4()),
            target_id=str(uuid4()),
            version="candidate",
            observer_id=observer_id,
            candidate={
                "type": "application_version",
                "id": "agent",
                "version": "candidate",
                "digest": "a" * 64,
            },
            stimulus={"path": "/verify", "payload": {"fixture": "reviewed"}},
            idempotency_key="ci-build-42",
        )
        assert result["id"] == run_id
        assert client.wait_run(run_id)["release_action"] == "BLOCK"
    assert seen[0].headers["Authorization"] == "Bearer synthetic-test-token"
    assert json.loads(seen[0].content)["idempotency_key"] == "ci-build-42"
    assert json.loads(seen[0].content)["observer_id"] == observer_id
    assert json.loads(seen[0].content)["stimulus"]["path"] == "/verify"
    assert len(seen) == 2
    assert not http_client.is_closed
    http_client.close()


def test_sdk_rejects_insecure_remote_and_path_injection():
    with pytest.raises(ValueError):
        ThreatVeilClient("http://remote.example")
    with pytest.raises(ValueError):
        ThreatVeilClient("https://secret@example.com")
    with ThreatVeilClient("http://127.0.0.1:8000") as client:
        with pytest.raises(ValueError):
            client.get_run("../billing")
