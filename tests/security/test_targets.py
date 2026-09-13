import asyncio
import socket
from types import SimpleNamespace

import pytest

from threatveil import targets


@pytest.mark.parametrize("origin", ["http://example.com", "https://user:pass@example.com",
    "https://example.com:8443", "https://example.com/path", "https://example.com?x=1",
    "https://example.com#fragment", "https://example.com%2f.attacker.invalid", "https://example.com\\@evil.invalid"])
def test_target_origin_rejects_routing_ambiguity(origin):
    with pytest.raises(ValueError):
        targets.origin_parts(origin)


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
    "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1",  # noqa: S104 - prohibited destination fixture
    "fc00::1", "::ffff:127.0.0.1"])
def test_any_prohibited_dns_answer_rejects_the_entire_target(monkeypatch, address):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))])
    with pytest.raises(ValueError):
        targets.public_addresses("registered.example", 443)


def test_pinned_connection_connects_only_validated_ip_and_preserves_tls_hostname(monkeypatch):
    captured = {}
    raw = object()

    def connection(address, timeout):
        captured["address"] = address
        return raw

    def wrap(sock, server_hostname):
        assert sock is raw
        captured["server_hostname"] = server_hostname
        return SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(socket, "create_connection", connection)
    conn = targets.PinnedHTTPS("registered.example", "8.8.8.8")
    conn._context = SimpleNamespace(wrap_socket=wrap)
    conn.connect()
    assert captured == {"address": ("8.8.8.8", 443), "server_hostname": "registered.example"}
    conn.close()


@pytest.fixture
def fake_transport(monkeypatch):
    calls = []
    dns_calls = []
    response = SimpleNamespace(status=200, headers={}, body=b'{"ok":true}', delivered=False)

    def resolve(host, port):
        dns_calls.append((host, port))
        return ["8.8.8.8"]

    class Response:
        @property
        def status(self):
            return response.status

        def getheader(self, key, default=None):
            return response.headers.get(key, default)

        def getheaders(self):
            return list(response.headers.items())

        def read1(self, _size):
            if response.delivered:
                return b""
            response.delivered = True
            return response.body

    class Connection:
        sock = None

        def __init__(self, host, address):
            calls.append({"host": host, "address": address})

        def request(self, method, path, body=None, headers=None):
            calls[-1].update(method=method, path=path, body=body, headers=headers)

        def getresponse(self):
            return Response()

        def close(self):
            pass
    monkeypatch.setattr(targets, "public_addresses", resolve)
    monkeypatch.setattr(targets, "PinnedHTTPS", Connection)
    return response, calls, dns_calls


def test_bounded_transport_resolves_once_and_ignores_proxy_environment(fake_transport, monkeypatch):
    response, calls, dns = fake_transport
    monkeypatch.setenv("HTTPS_PROXY", "http://169.254.169.254:8080")
    result = targets.bounded_request("https://registered.example", "/test", body={"input": "fixture"},
                                     allowed_paths=["/test"], allowed_methods=["POST"])
    assert result["body"] == response.body
    assert len(calls) == len(dns) == 1
    assert calls[0]["address"] == "8.8.8.8"
    assert calls[0]["headers"]["Accept-Encoding"] == "identity"


@pytest.mark.parametrize("headers", [{"Host": "metadata.google.internal"}, {"Connection": "upgrade"},
                                    {"Authorization": "safe\r\nHost: evil"}, {"X-Forwarded-Host": "evil"}])
def test_routing_header_injection_is_rejected(fake_transport, headers):
    with pytest.raises(ValueError):
        targets.bounded_request("https://registered.example", "/test", headers=headers)
    assert not fake_transport[1]


@pytest.mark.parametrize("case", ["redirect", "compressed", "length", "stream"])
def test_redirect_compression_and_response_bounds(fake_transport, case):
    response, calls, _ = fake_transport
    if case == "redirect":
        response.status, response.headers = 302, {"Location": "http://169.254.169.254"}
    elif case == "compressed":
        response.headers = {"Content-Encoding": "gzip"}
    elif case == "length":
        response.headers = {"Content-Length": str(targets.MAX_RESPONSE+1)}
    else:
        response.body = b"x"*(targets.MAX_RESPONSE+1)
    with pytest.raises(ValueError):
        targets.bounded_request("https://registered.example", "/test")
    assert len(calls) == 1


def test_scope_and_credentials_cannot_be_broadened_by_adapter(fake_transport):
    transport = targets.SafeTransport({"origin": "https://registered.example", "paths": ["/test"], "methods": ["POST"]},
                                      headers={"Authorization": "synthetic-run-token"})

    async def scenario():
        for url, headers in (("https://other.example/test", {}), ("/admin", {}),
                              ("/test", {"Authorization": "adapter-invented-token"})):
            with pytest.raises(ValueError):
                await transport.request("POST", url, headers=headers)
        result = await transport.request("POST", "/test", body=b"{}", headers={"Content-Type": "application/json"})
        assert result.status_code == 200
    asyncio.run(scenario())
    assert fake_transport[1][0]["headers"]["Authorization"] == "synthetic-run-token"
