"""Bound request bytes before JSON/model parsing, including chunked requests."""

from starlette.responses import JSONResponse


class BodyLimitMiddleware:
    def __init__(self, app, maximum=2_000_000):
        self.app, self.maximum = app, maximum

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        buffered = bytearray()
        while True:
            event = await receive()
            if event["type"] == "http.disconnect":
                return
            body = event.get("body", b"")
            if len(buffered) + len(body) > self.maximum:
                response = JSONResponse(
                    {"detail": "Request exceeds the bounded execution limit"}, status_code=413
                )
                return await response(scope, receive, send)
            buffered.extend(body)
            if not event.get("more_body", False):
                break
        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(buffered), "more_body": False}
            return await receive()

        await self.app(scope, bounded_receive, send)
