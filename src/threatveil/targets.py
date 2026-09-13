"""Bounded HTTPS transport: resolve once, validate every address, connect to a pinned IP."""

import http.client
import ipaddress
import json
import socket
import ssl
import time
import threading
from urllib.parse import urlsplit


MAX_RESPONSE = 2_000_000
MAX_REQUEST = 512_000
# Protocol routing metadata an adapter may mirror from the body it is already
# sending. Credentials are added by the broker transport, never by an adapter.
ADAPTER_HEADERS = frozenset(
    {"content-type", "accept", "mcp-protocol-version", "mcp-session-id", "mcp-method", "mcp-name"}
)
CREDENTIAL_HEADERS = frozenset({"authorization", "x-api-key"})


def public_addresses(host: str, port: int):
    if not host or host.lower().rstrip(".") in {"localhost", "metadata.google.internal"}:
        raise ValueError("Target hostname is prohibited")
    addresses = {item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    if not addresses:
        raise ValueError("Target DNS has no addresses")
    for value in addresses:
        address = ipaddress.ip_address(value)
        if not address.is_global or address.is_multicast or address.is_unspecified:
            raise ValueError("Target resolved to a prohibited address")
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            if not address.ipv4_mapped.is_global:
                raise ValueError("Mapped address is prohibited")
    return sorted(addresses)


def origin_parts(origin: str):
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or "%" in parsed.netloc
        or "\\" in origin
        or parsed.port not in {None, 443}
    ):
        raise ValueError(
            "Targets require an HTTPS origin on port 443 without path, credentials or query"
        )
    return parsed


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address, timeout=15):
        super().__init__(host, 443, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        sock = socket.create_connection((self.address, 443), timeout=self.timeout)
        self.sock = sock
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def bounded_request(
    origin, path, method="POST", body=None, headers=None, allowed_paths=None, allowed_methods=None
):
    parsed = origin_parts(origin)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "\\" in path
        or "\r" in path
        or "\n" in path
        or "#" in path
        or urlsplit(path).scheme
        or ".." in path.split("/")
    ):
        raise ValueError("Invalid target path")
    if allowed_paths is not None and path not in allowed_paths:
        raise ValueError("Path is outside authorized scope")
    if method not in (allowed_methods or ["GET", "POST"]):
        raise ValueError("Method is outside authorized scope")
    encoded = (
        body
        if isinstance(body, bytes)
        else json.dumps(body, allow_nan=False).encode()
        if body is not None
        else None
    )
    if encoded and len(encoded) > MAX_REQUEST:
        raise ValueError("Request exceeds limit")
    address = public_addresses(parsed.hostname, 443)[0]
    safe_headers = {
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "Content-Type": "application/json",
    }
    for k, v in (headers or {}).items():
        if (
            k.lower() not in (CREDENTIAL_HEADERS | ADAPTER_HEADERS)
            or len(v) > 2048
            or "\r" in v
            or "\n" in v
        ):
            raise ValueError("Only broker-supplied credential headers are accepted")
        safe_headers[k] = v
    start = time.monotonic()
    connection = PinnedHTTPS(parsed.hostname, address)
    active_socket = []

    def stop_io():
        sock = active_socket[0] if active_socket else connection.sock
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        connection.close()

    deadline = threading.Timer(20, stop_io)
    deadline.daemon = True
    deadline.start()
    try:
        connection.request(method, path, body=encoded, headers=safe_headers)
        active_socket.append(connection.sock)
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise ValueError("Target redirects are prohibited")
        if response.getheader("Content-Encoding", "identity").lower() not in {"identity", ""}:
            raise ValueError("Compressed target responses are prohibited")
        length = response.getheader("Content-Length")
        if length and (not length.isdigit() or int(length) > MAX_RESPONSE):
            raise ValueError("Response exceeds limit")
        chunks = []
        size = 0
        while True:
            if time.monotonic() - start > 20:
                raise TimeoutError("Target execution deadline exceeded")
            chunk = response.read1(min(65536, MAX_RESPONSE - size + 1))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_RESPONSE:
                raise ValueError("Response exceeds limit")
        if time.monotonic() - start >= 20:
            raise TimeoutError("Target execution deadline exceeded")
        return {
            "status_code": response.status,
            "body": b"".join(chunks),
            "peer": address,
            "headers": dict(response.getheaders()),
        }
    finally:
        deadline.cancel()
        connection.close()


class SafeTransport:
    def __init__(self, target, headers=None):
        self.target = target
        self.headers = headers or {}

    async def request(self, method, url=None, **kwargs):
        import asyncio
        from .adapters.base import TransportResponse

        if url and url.startswith("https://"):
            parts = urlsplit(url)
            origin = f"{parts.scheme}://{parts.netloc}"
            if origin.rstrip("/") != self.target["origin"].rstrip("/"):
                raise ValueError("Origin outside registered target")
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
        else:
            path = url or kwargs.pop("path", "/")
        adapter_headers = kwargs.get("headers") or {}
        if any(k.lower() not in ADAPTER_HEADERS for k in adapter_headers):
            raise ValueError("Adapter cannot supply credentials or routing headers")
        result = await asyncio.to_thread(
            bounded_request,
            self.target["origin"],
            path,
            method,
            kwargs.get("json", kwargs.get("body")),
            {**adapter_headers, **self.headers},
            self.target["paths"],
            self.target["methods"],
        )
        return TransportResponse(result["status_code"], result["body"], result["headers"])
