import json

from fastapi import FastAPI
from fastapi.testclient import TestClient

from threatveil.observability import SafeErrorBoundary, event


def test_exception_response_and_logs_do_not_export_payload_or_credentials(capsys):
    app = FastAPI()
    app.add_middleware(SafeErrorBoundary)

    @app.post("/fixture/{record_id}")
    def fails(record_id: str):
        raise RuntimeError("credential-secret and customer-evidence")

    with TestClient(app) as client:
        result = client.post(
            "/fixture/sensitive-id?token=credential-secret",
            json={"secret": "customer-evidence"},
            headers={"Authorization": "Bearer credential-secret"},
        )
    assert result.status_code == 500
    assert result.json()["request_id"] == result.headers["x-request-id"]
    output = capsys.readouterr().out
    assert "credential-secret" not in output + result.text
    assert "customer-evidence" not in output + result.text
    assert "sensitive-id" not in output
    events = [json.loads(line) for line in output.splitlines()]
    assert any(
        row["event"] == "service.exception" and row["error_type"] == "RuntimeError"
        for row in events
    )


def test_operational_field_allowlist_drops_untrusted_payload(capsys):
    event(
        "run.finished",
        run_id="opaque-run-id",
        unexpected_field="never-export",
        payload={"secret": "never-export"},
    )
    output = json.loads(capsys.readouterr().out)
    assert output == {"event": "run.finished", "severity": "INFO", "run_id": "opaque-run-id"}
