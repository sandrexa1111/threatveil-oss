from uuid import uuid4

from fastapi.testclient import TestClient

from threatveil.api import app


def test_random_session_cookies_cannot_bypass_login_rate_limit():
    with TestClient(app, client=(f"rate-test-{uuid4()}", 50000)) as client:
        for index in range(21):
            client.cookies.set("tv_session", str(uuid4()))
            response = client.post("/v1/auth/local", json={"unknown": "field"})
            assert response.status_code == (422 if index < 20 else 429)
