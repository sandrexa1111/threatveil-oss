"""Trusted dispatcher: broker-scoped run preparation and shared Cloud Run Job launch."""

import os
import time
import httpx
from .observability import SafeErrorBoundary

from fastapi import FastAPI, Request, HTTPException

app = FastAPI(title="ThreatVeil launcher", docs_url=None, redoc_url=None)


def authorize(request):
    from google.auth.transport.requests import Request as GoogleRequest
    from google.oauth2.id_token import verify_oauth2_token

    token = request.headers.get("authorization", "").removeprefix("Bearer ")
    try:
        claims = verify_oauth2_token(
            token,
            GoogleRequest(),
            audience=os.environ.get("TV_LAUNCHER_AUDIENCE", "threatveil-launcher"),
        )
        allowed = {os.environ.get("TV_TASKS_IDENTITY"), os.environ.get("TV_SCHEDULER_IDENTITY")} - {
            None,
            "",
        }
        if claims.get("email") not in allowed or claims.get("email_verified") is not True:
            raise ValueError()
    except Exception:
        raise HTTPException(401, "Trusted dispatch identity required") from None


def broker(path, payload=None):
    from google.auth.transport.requests import Request
    from google.oauth2.id_token import fetch_id_token

    token = fetch_id_token(Request(), os.environ.get("TV_BROKER_AUDIENCE", "threatveil-broker"))
    # Reconciliation can perform ten bounded, sequential external deliveries.
    timeout = 300 if path == "/internal/reconcile" else 30
    with httpx.Client(timeout=timeout, trust_env=False, follow_redirects=False) as client:
        response = client.post(
            os.environ["TV_BROKER_URL"].rstrip("/") + path,
            json=payload or {},
            headers={"Authorization": "Bearer " + token},
        )
        response.raise_for_status()
        return response.json()


def dispatch_pending():
    from google.cloud import run_v2

    deadline = time.monotonic() + 180
    items = broker("/internal/pending")["items"]
    dispatched = []
    client = run_v2.JobsClient()
    for item in items:
        # Leave untouched outbox items pending for the next delivery/reconciliation.
        # Finish an already-started item; never repeat an uncertain launch here.
        if time.monotonic() >= deadline:
            break
        prepared = broker("/internal/prepare-dispatch", item)
        client.run_job(
            request=run_v2.RunJobRequest(
                name=os.environ["TV_RUNNER_JOB"],
                overrides=run_v2.RunJobRequest.Overrides(
                    task_count=1,
                    container_overrides=[
                        run_v2.RunJobRequest.Overrides.ContainerOverride(
                            env=[
                                {"name": "TV_RUN_ID", "value": prepared["run_id"]},
                                {
                                    "name": "TV_BOOTSTRAP_TOKEN",
                                    "value": prepared["bootstrap_token"],
                                },
                            ]
                        )
                    ],
                ),
            ),
            timeout=30,
            retry=None,
        )
        broker("/internal/dispatched", {"outbox_id": item["id"]})
        dispatched.append(prepared["run_id"])
    return {"dispatched": dispatched}


@app.post("/internal/dispatch")
def dispatch(request: Request):
    authorize(request)
    return dispatch_pending()


@app.post("/internal/reconcile")
def reconcile(request: Request):
    authorize(request)
    broker("/internal/reconcile")
    return dispatch_pending()


app.add_middleware(SafeErrorBoundary)
