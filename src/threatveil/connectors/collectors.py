"""Bounded read adapters and conservative mappings onto the shared source model."""

import asyncio
import json
import re
import time
from urllib.parse import quote

import httpx

from ..core.contracts import digest
from ..integrations.intake import IntakeContext, bounded_document, normalize_integration
from .contracts import Snapshot


class SourceFailure(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def imported_snapshot(kind, payload, source_identity, valid_at):
    """Reuse frozen parser semantics without copying imported provenance as authority."""
    bounded_document(payload)
    if kind == "gcp_cloud_run":
        return cloud_run_snapshot(payload)
    if kind == "agent_definition":
        from ..agent_definitions import snapshot

        return snapshot(payload, source_identity)
    format_name = {"otel": "otel_genai", "mcp": "mcp_tools"}.get(kind, kind)
    if kind == "mcp":
        payload = {**payload, "server_id": source_identity}
    normalized = normalize_integration(
        format_name, payload,
        context=IntakeContext(source_id=source_identity, received_at=valid_at),
    )
    components = {
        f"{item.type}:{item.id}": {
            "type": item.type, "id": item.id, "version": item.version,
            "digest": item.digest, "dependencies": list(item.dependencies),
        }
        for item in normalized.fingerprint.components
    }
    for component in components.values():
        if component["type"] == "model":
            component["identity_basis"] = "ADVERTISED_CONFIGURATION"
            component["behavioral_revision"] = None
    facts = {
        "source_digest": normalized.source_digest,
        "observation_count": len(normalized.observations),
        "finding_count": len(normalized.findings),
        "trace_edge_count": len(normalized.trace_edges),
        "task_outcome": "UNKNOWN", "committed_effect": "UNKNOWN",
        "running_state_proven": False,
    }
    if normalized.observations:
        facts["invocations"] = [
            {"correlation_id": observation.correlation_id,
             "source_event_id": receipt.id, "observed_at": receipt.observed_at.isoformat(),
             "operation": receipt.action.operation, "tool": receipt.action.tool,
             "phase": receipt.action.phase.value,
             "authorized": "UNKNOWN", "committed_effect": "UNKNOWN"}
            for observation in normalized.observations for receipt in observation.receipts
        ]
        facts["trace_edges"] = [item.model_dump(mode="json") for item in normalized.trace_edges]
    if normalized.findings:
        facts["finding_references"] = [
            {"external_id": item.external_id, "scanner": item.scanner,
             "scanner_version": item.scanner_version, "result_digest": item.result_digest,
             "level": item.level, "status": "UNVERIFIED"}
            for item in normalized.findings
        ]
    complete = False
    source_version = {
        "otel": "OTLP JSON v1; supplied semantic convention revision UNKNOWN",
        "openai_agents": "Agents export; SDK revision UNKNOWN unless supplied",
        "anthropic_hooks": "Claude hooks; SDK revision UNKNOWN unless supplied",
        "cyclonedx": str(payload.get("specVersion", "UNKNOWN")),
        "sarif": str(payload.get("version", "UNKNOWN")),
    }.get(kind, "UNKNOWN")
    if kind == "mcp":
        from ..integrations.mcp_protocol import ERAS, SUPPORTED_PROTOCOLS

        catalog = normalized.details["snapshot"]
        source_version = "MCP " + catalog["protocol_version"]
        complete = catalog["complete"] and catalog["protocol_version"] in SUPPORTED_PROTOCOLS
        facts["catalog_digest"] = catalog["catalog_digest"]
        facts["tool_names"] = [item["name"] for item in catalog["tools"]]
        facts["protocol_version"] = catalog["protocol_version"]
        facts["protocol_era"] = ERAS.get(catalog["protocol_version"], "UNKNOWN")
        facts["supported_versions"] = catalog.get("supported_versions") or []
        # Server freshness hint, retained beside the catalog and never as validity.
        facts["catalog_cache_ttl_ms"] = catalog.get("cache_ttl_ms")
        facts["catalog_cache_scope"] = catalog.get("cache_scope")
        # Structured, bounded facts so a later change can be named exactly: which
        # declared authorization field moved, which interface appeared, or which
        # other catalog part changed. None means authorization was not captured.
        from ..integrations.intake import component_id
        from ..source_semantics import bounded_authorization

        facts["authorization"] = bounded_authorization(catalog.get("authorization"))
        facts["catalog_parts"] = {
            "protocol_version": catalog["protocol_version"],
            "server_info": digest(catalog.get("server_info") or {}),
            "capabilities": digest(catalog.get("capabilities") or {}),
            "catalog_metadata": digest(catalog.get("catalog_metadata") or {}),
        }
        facts["tool_components"] = {
            "tool:" + component_id(f"{catalog['server_id']}:{item['name']}"): item["name"]
            for item in catalog["tools"]
        }
    # Sensitive raw arguments, messages, tool output and span bodies are never retained here.
    return Snapshot(
        source_version=source_version, mapping_version=normalized.normalizer_version,
        components=components,
        facts=facts, complete=complete, limitations=normalized.limitations,
    )


def _strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise SourceFailure("INVALID_RESPONSE")
            result[key] = value
        return result

    try:
        return bounded_document(json.loads(raw, object_pairs_hook=pairs))
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise SourceFailure("INVALID_RESPONSE") from None


def github_snapshot(configuration, token, *, client=None):
    """Read exactly one repository/ref with a pre-existing read token, never mint writes."""
    repository = configuration["repository"]
    repository_id = configuration["repository_id"]
    ref = configuration["ref"]
    own = client is None
    client = client or httpx.Client(timeout=10, trust_env=False, follow_redirects=False)
    started = time.monotonic()

    def get(path):
        try:
            with client.stream("GET", "https://api.github.com" + path, headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/vnd.github+json",
                "Accept-Encoding": "identity", "X-GitHub-Api-Version": "2022-11-28",
            }) as response:
                if response.status_code in {401, 403}:
                    raise SourceFailure("UNAUTHORIZED")
                if response.status_code == 429:
                    raise SourceFailure("RATE_LIMITED")
                if response.status_code != 200:
                    raise SourceFailure("UNAVAILABLE")
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > 2_000_000 or time.monotonic() - started > 40:
                        raise SourceFailure("INVALID_RESPONSE")
                    chunks.append(chunk)
                return _strict_json(b"".join(chunks))
        except httpx.HTTPError:
            raise SourceFailure("UNAVAILABLE") from None

    try:
        repo = get("/repos/" + repository)
        if str(repo.get("id")) != repository_id or repo.get("full_name") != repository:
            raise SourceFailure("INVALID_RESPONSE")
        # Git refs are not sequential event cursors. Read twice to reject a moving ref.
        path = "/repos/" + repository + "/git/ref/" + quote(ref.removeprefix("refs/"), safe="/")
        first, second = get(path), get(path)
        if digest(first) != digest(second):
            raise SourceFailure("PARTIAL")
        obj = first.get("object") or {}
        sha = obj.get("sha")
        if first.get("ref") != ref or obj.get("type") != "commit" or not isinstance(sha, str):
            raise SourceFailure("INVALID_RESPONSE")
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha) or not sha.strip("0"):
            raise SourceFailure("INVALID_RESPONSE")
        return Snapshot(
            source_version="GitHub REST 2022-11-28",
            components={f"git_commit:{repository_id}": {
                "type": "git_commit", "id": repository_id, "version": sha, "digest": sha,
                "dependencies": [],
            }},
            facts={"repository_id": repository_id, "repository": repository, "ref": ref,
                   "sha": sha, "running_state_proven": False}, complete=True,
            limitations=("Only the configured ref was reconciled; intermediate changes may be missed.",
                         "A Git revision does not identify the deployed system."),
        )
    finally:
        if own:
            client.close()


def cloud_run_snapshot(payload):
    """Control-plane facts are kept separate from a qualified deployment observation."""
    bounded_document(payload)
    service, policy = payload.get("service"), payload.get("iam_policy")
    if not isinstance(service, dict) or not isinstance(policy, dict):
        raise SourceFailure("INVALID_RESPONSE")
    name = service.get("name")
    if not isinstance(name, str) or not re.fullmatch(
        r"projects/[a-zA-Z0-9-]+/locations/[a-z0-9-]+/services/[a-z][a-z0-9-]{0,62}", name
    ):
        raise SourceFailure("INVALID_RESPONSE")
    template = service.get("template", {})
    if not isinstance(template, dict):
        raise SourceFailure("INVALID_RESPONSE")
    containers = template.get("containers", [])
    if not isinstance(containers, list) or len(containers) > 100:
        raise SourceFailure("INVALID_RESPONSE")
    images = [item.get("image") for item in containers if isinstance(item, dict)]
    if len(images) != len(containers) or any(not isinstance(item, str) for item in images):
        raise SourceFailure("INVALID_RESPONSE")
    routing = service.get("trafficStatuses", [])
    if not isinstance(routing, list) or len(routing) > 100:
        raise SourceFailure("INVALID_RESPONSE")
    status = {
        key: service.get(key) for key in (
            "generation", "observedGeneration", "reconciling", "latestReadyRevision",
            "latestCreatedRevision", "trafficStatuses", "terminalCondition",
        )
    }
    # Unknown fields remain part of aggregate digests, so unsupported changes cannot disappear.
    configuration = {
        key: value for key, value in service.items()
        if key not in {"updateTime", "createTime", "deleteTime", "expireTime", "etag", "uid", *status}
    }
    components = {}
    for kind, content in (
        ("cloud_configuration", configuration), ("permissions", policy),
        ("identity", {"serviceAccount": template.get("serviceAccount")}),
        ("deployment", status),
    ):
        components[f"{kind}:{name}"] = {
            "type": kind, "id": name, "digest": digest(content), "version": None,
            "dependencies": [],
        }
    complete = bool(
        service.get("etag") and policy.get("etag")
        and service.get("reconciling") is False
        and str(service.get("generation")) == str(service.get("observedGeneration"))
        and service.get("generation") is not None
    )
    return Snapshot(
        source_version="Cloud Run Admin API v2", components=components, complete=complete,
        facts={"service": name, "desired_images": images,
               "service_account": template.get("serviceAccount"),
               "service_etag": service.get("etag"), "iam_etag": policy.get("etag"),
               "control_plane_status": status, "running_state_proven": False,
               "service_iam_digest": digest(policy), "effective_permissions": "UNKNOWN"},
        limitations=(
            "Desired configuration and Cloud Run status do not prove exact running system state.",
            "Service IAM excludes inherited IAM, deny policies and effective resource authorization.",
            "Reads compare etags but are not an atomic transaction across service and IAM.",
            "Environment values and raw IAM members are retained only as digests.",
        ),
    )


def collect_cloud_run(configuration, token, *, client=None):
    from google.api_core.exceptions import (
        Forbidden, NotFound, ResourceExhausted, Unauthorized, GoogleAPICallError,
    )
    from google.cloud import run_v2
    from google.oauth2.credentials import Credentials
    from google.protobuf.json_format import MessageToDict

    own = client is None
    # Explicit pinned credential reference supplied by the service, never ambient ADC.
    client = client or run_v2.ServicesClient(
        credentials=Credentials(token),
        client_options={"api_endpoint": "run.googleapis.com"}, transport="rest",
    )
    resource = configuration["service"]
    try:
        def read():
            service = client.get_service(request={"name": resource}, retry=None, timeout=10)
            policy = client.get_iam_policy(
                request={"resource": resource, "options": {"requested_policy_version": 3}},
                retry=None, timeout=10,
            )
            return (
                MessageToDict(run_v2.Service.pb(service)),
                MessageToDict(policy),
            )

        before, after = read(), read()
        if before[0].get("name") != resource or after[0].get("name") != resource:
            raise SourceFailure("INVALID_RESPONSE")
        if (not before[0].get("etag") or not before[1].get("etag")
                or before[0].get("etag") != after[0].get("etag")
                or before[1].get("etag") != after[1].get("etag")):
            raise SourceFailure("PARTIAL")
        # Proto JSON omits default false; retain the server's typed boolean explicitly.
        # Equality of full snapshots catches movement not represented by a particular etag.
        if digest(before) != digest(after):
            raise SourceFailure("PARTIAL")
        after[0].setdefault("reconciling", False)
        return cloud_run_snapshot({"service": after[0], "iam_policy": after[1]})
    except (Forbidden, Unauthorized):
        raise SourceFailure("UNAUTHORIZED") from None
    except ResourceExhausted:
        raise SourceFailure("RATE_LIMITED") from None
    except (NotFound, GoogleAPICallError):
        raise SourceFailure("UNAVAILABLE") from None
    finally:
        if own:
            client.transport.close()


async def collect_mcp(target, *, source_identity, headers, recheck):
    from ..adapters.base import AdapterContext
    from ..adapters.mcp import MCPAdapter
    from ..integrations.mcp_discovery import discover_mcp_tools
    from ..targets import SafeTransport

    # Read-only surface for both eras. Every other method, including any tools/call,
    # is rejected before the authorized transport is reached.
    READ_METHODS = frozenset(
        {"server/discover", "tools/list", "initialize", "notifications/initialized"}
    )

    class ReadTransport(SafeTransport):
        async def request(self, method, url=None, **kwargs):
            await asyncio.to_thread(recheck)
            message = _strict_json(kwargs.get("body", b"{}"))
            if method != "POST" or message.get("method") not in READ_METHODS:
                raise SourceFailure("UNAUTHORIZED")
            return await super().request(method, url, **kwargs)

    # The adapter requires a tool allowlist, but this transport rejects every tools/call.
    adapter = MCPAdapter(ReadTransport(target, headers), ("__discovery_only__",))
    endpoint = target["origin"].rstrip("/") + target["discovery_path"]
    await adapter.prepare(AdapterContext(endpoint, "DIGITAL_STAGING", source_identity))
    try:
        async with asyncio.timeout(60):
            captured = await discover_mcp_tools(adapter, server_id=source_identity, max_pages=3)
        payload = captured.model_dump(mode="json", exclude={
            "schema_version", "fingerprint", "catalog_digest", "limitations",
        })
        # Preserve the negotiated freshness hint through the shared normalization path.
        if captured.cache_ttl_ms is not None:
            payload["ttlMs"] = captured.cache_ttl_ms
        if captured.cache_scope is not None:
            payload["cacheScope"] = captured.cache_scope
        from ..db import now
        return imported_snapshot("mcp", payload, source_identity, now())
    finally:
        await adapter.cleanup()
