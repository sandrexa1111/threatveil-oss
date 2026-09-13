import asyncio

import pytest

from threatveil.http_limits import BodyLimitMiddleware


def exchange(events, maximum=16, scope_type="http"):
    received, sent = [], []
    pending = iter(events)
    async def receive():
        return next(pending)
    async def send(event):
        sent.append(event)
    async def app(scope, receive, send):
        received.append(await receive())
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})
    scope = {"type": scope_type, "method": "POST", "headers": []}
    asyncio.run(BodyLimitMiddleware(app, maximum)(scope, receive, send))
    return received, sent


@pytest.mark.parametrize("length", [0, 15, 16, 17])
def test_request_limit_applies_before_application_parsing_at_exact_boundary(length):
    received, sent = exchange([{"type": "http.request", "body": b"x" * length}])
    assert sent[0]["status"] == (413 if length > 16 else 204)
    assert len(received) == (0 if length > 16 else 1)


def test_chunked_bytes_are_aggregated_and_oversize_stops_before_next_read():
    events = [{"type": "http.request", "body": b"x" * 8, "more_body": True},
              {"type": "http.request", "body": b"x" * 9, "more_body": True}]
    received, sent = exchange(events)
    assert not received and sent[0]["status"] == 413


def test_empty_chunks_do_not_change_body_semantics():
    events = [{"type": "http.request", "body": b"", "more_body": True} for _ in range(5000)]
    events.append({"type": "http.request", "body": b"valid"})
    received, sent = exchange(events)
    assert sent[0]["status"] == 204 and received[0]["body"] == b"valid"


def test_disconnected_body_never_reaches_application():
    received, sent = exchange([{"type": "http.request", "body": b"partial", "more_body": True},
                               {"type": "http.disconnect"}])
    assert received == sent == []


def test_non_http_protocol_is_not_buffered_as_http():
    event = {"type": "websocket.connect"}
    received, _ = exchange([event], scope_type="websocket")
    assert received == [event]
