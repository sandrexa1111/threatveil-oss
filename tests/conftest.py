"""Each simulated client has its own peer, as independent customers do in practice.

This leaves the real PostgreSQL rate limiter enabled. Tests that exercise a shared
peer can pass an explicit client tuple and deliberately hit the same bucket.
"""

from uuid import uuid4

import pytest
from starlette.testclient import TestClient


@pytest.fixture(autouse=True)
def distinct_test_client_peers(monkeypatch):
    original = TestClient.__init__

    def initialize(self, *args, **kwargs):
        from threatveil.api import app

        if (args[0] if args else kwargs.get("app")) is app:
            octets = uuid4().bytes[:3]
            kwargs.setdefault("client", ("127." + ".".join(str(v) for v in octets), 50000))
        original(self, *args, **kwargs)

    monkeypatch.setattr(TestClient, "__init__", initialize)
