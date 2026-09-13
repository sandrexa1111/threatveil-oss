"""Operational events deliberately exclude exception text, payloads and request URLs."""

import json
import re
import time
from uuid import uuid4

from starlette.responses import JSONResponse

FIELDS = frozenset(
    {
        "request_id",
        "run_id",
        "organization_id",
        "status_code",
        "duration_ms",
        "route",
        "error_type",
        "security_verdict",
        "execution_status",
        "partial_response",
    }
)


def event(name, severity="INFO", **fields):
    if not re.fullmatch(r"[a-z_.]{1,80}", name) or severity not in {"INFO", "WARNING", "ERROR"}:
        raise ValueError("Invalid operational event")
    data = {"event": name, "severity": severity}
    for key, value in fields.items():
        if key in FIELDS and isinstance(value, (str, int, bool)):
            data[key] = value[:200] if isinstance(value, str) else value
    print(json.dumps(data, separators=(",", ":")), flush=True)


class SafeErrorBoundary:
    """Stop framework traceback logging from serializing secret-bearing DB parameters."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request_id, started, status, began = str(uuid4()), False, 500, time.monotonic()
        scope["tv_request_id"] = request_id

        async def tracked_send(message):
            nonlocal started, status
            if message["type"] == "http.response.start":
                started, status = True, message["status"]
                message["headers"] = [
                    (k, v) for k, v in message.get("headers", []) if k.lower() != b"x-request-id"
                ] + [(b"x-request-id", request_id.encode())]
            await send(message)

        try:
            await self.app(scope, receive, tracked_send)
        except Exception as error:
            # An incomplete stream is never given the export's 'complete' trailer.
            event(
                "service.exception",
                "ERROR",
                request_id=request_id,
                error_type=type(error).__name__,
                partial_response=started,
                duration_ms=round((time.monotonic() - began) * 1000),
            )
            if not started:
                await JSONResponse(
                    {"detail": "Service could not complete the request", "request_id": request_id},
                    status_code=500,
                    headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
                )(scope, receive, tracked_send)
            else:
                await send({"type": "http.response.body", "body": b"", "more_body": False})
        if status >= 400:
            event(
                "http.failed",
                "ERROR" if status >= 500 else "WARNING",
                request_id=request_id,
                status_code=status,
                route=getattr(scope.get("route"), "path", "unmatched"),
                duration_ms=round((time.monotonic() - began) * 1000),
            )
