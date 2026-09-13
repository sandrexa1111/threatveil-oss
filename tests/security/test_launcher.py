"""Dispatcher time budgets avoid losing maintenance responses under normal load."""

from unittest.mock import MagicMock

import pytest

from threatveil import launcher


@pytest.mark.parametrize(
    ("path", "expected"),
    [("/internal/reconcile", 300), ("/internal/pending", 30), ("/internal/prepare-dispatch", 30)],
)
def test_only_reconcile_has_extended_broker_timeout(monkeypatch, path, expected):
    import google.oauth2.id_token

    monkeypatch.setenv("TV_BROKER_URL", "https://broker.example.invalid")
    monkeypatch.setattr(google.oauth2.id_token, "fetch_id_token", lambda *_: "synthetic")
    client = MagicMock()
    monkeypatch.setattr(launcher.httpx, "Client", client)
    client.return_value.__enter__.return_value.post.return_value.json.return_value = {"ok": True}
    assert launcher.broker(path) == {"ok": True}
    client.assert_called_once_with(timeout=expected, trust_env=False, follow_redirects=False)


def test_dispatch_budget_preserves_unstarted_outbox_items(monkeypatch):
    from google.cloud import run_v2

    clock = iter([0, 0, 181])
    monkeypatch.setattr(launcher.time, "monotonic", lambda: next(clock))
    monkeypatch.setenv("TV_RUNNER_JOB", "projects/test/locations/test/jobs/test")
    calls = []

    def broker(path, payload=None):
        calls.append((path, payload))
        if path == "/internal/pending":
            return {"items": [{"id": "first"}, {"id": "second"}]}
        if path == "/internal/prepare-dispatch":
            return {"run_id": "synthetic-run", "bootstrap_token": "synthetic-bootstrap"}
        return {}

    monkeypatch.setattr(launcher, "broker", broker)
    jobs = MagicMock()
    monkeypatch.setattr(run_v2, "JobsClient", lambda: jobs)
    assert launcher.dispatch_pending() == {"dispatched": ["synthetic-run"]}
    assert calls == [
        ("/internal/pending", None),
        ("/internal/prepare-dispatch", {"id": "first"}),
        ("/internal/dispatched", {"outbox_id": "first"}),
    ]
    jobs.run_job.assert_called_once()
    assert jobs.run_job.call_args.kwargs["timeout"] == 30
    assert jobs.run_job.call_args.kwargs["retry"] is None
