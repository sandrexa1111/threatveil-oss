"""Deterministic agent-definition intelligence.

Parses a declared agent definition into the bounded source shape every source
uses: components, and a declared authorization block that source semantics can
compare. Adapters are pure and deterministic. They never execute code, never
fetch anything and never call a model. Anything a format does not declare as data
(for example tools defined in code) is reported as UNKNOWN, never guessed. Secret
values (environment variables, headers, tokens) are never retained: only their
names, or a digest.
"""

import re
from pathlib import PurePosixPath

import yaml

from .connectors.contracts import Snapshot
from .core.contracts import digest

PROFILE = "agent-definition/v1"
MAX_ITEMS = 500
MAX_TEXT = 262_144
MAX_YAML_EVENTS = 20_000
ITEM = re.compile(r"^[^\x00-\x1f]{1,200}$")
FORMATS = ("manifest", "claude_settings", "mcp_json", "claude_subagent", "langgraph", "crewai", "openai_agents")
CODE_DEFINED = "Tools, permissions and routing for this format are defined in code; ThreatVeil does not execute or parse code."


class DefinitionError(ValueError):
    """A safe, content-free explanation of why a definition cannot be parsed."""


def load_yaml(text):
    """Safe YAML: one document, no anchors or aliases, bounded size and event count."""
    if not isinstance(text, str) or len(text) > MAX_TEXT:
        raise DefinitionError("The YAML document must be text of at most 256 KiB")
    try:
        for count, event in enumerate(yaml.parse(text, Loader=yaml.SafeLoader)):
            if count > MAX_YAML_EVENTS:
                raise DefinitionError("The YAML document exceeds ThreatVeil's structural bound")
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                raise DefinitionError("YAML anchors and aliases are not accepted")
        return yaml.safe_load(text)
    except yaml.YAMLError:
        raise DefinitionError("The YAML document could not be parsed") from None


def _document(value, *, mapping=True):
    if isinstance(value, str):
        value = load_yaml(value)
    if mapping and not isinstance(value, dict):
        raise DefinitionError("The definition must be a mapping")
    return value


def _names(value, field):
    if value is None:
        return []
    items = [v.strip() for v in value.split(",")] if isinstance(value, str) else value
    if not isinstance(items, list) or len(items) > MAX_ITEMS:
        raise DefinitionError(f"{field} must be a list of at most {MAX_ITEMS} names")
    result = set()
    for item in items:
        if not isinstance(item, str) or not ITEM.fullmatch(item.strip()):
            raise DefinitionError(f"{field} must contain short names")
        result.add(item.strip())
    return sorted(result)


def _text_digest(value):
    return digest(value) if isinstance(value, str) and value else None


def _flag(value, field):
    if value is None or isinstance(value, bool):
        return value
    raise DefinitionError(f"{field} must be true or false")


def _mapping(value, field):
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > MAX_ITEMS:
        raise DefinitionError(f"{field} must be a mapping of at most {MAX_ITEMS} entries")
    for key in value:
        if not isinstance(key, str) or not ITEM.fullmatch(key):
            raise DefinitionError(f"{field} must use short names")
    return value


def _server(spec):
    """Connection facts for one MCP server, without any secret value."""
    spec = spec if isinstance(spec, dict) else {}
    url = spec.get("url")
    host = re.sub(r"^[a-z]+://([^/@]*@)?([^/:?#]+).*$", r"\2", url) if isinstance(url, str) else None
    return {"transport": str(spec.get("type") or spec.get("transport") or ("http" if url else "stdio"))[:20],
            "host": host[:200] if host else None,
            "command": digest([spec.get("command"), spec.get("args")]) if spec.get("command") else None,
            "env_names": sorted(str(k)[:100] for k in (spec.get("env") or {}))[:100],
            "header_names": sorted(str(k)[:100] for k in (spec.get("headers") or {}))[:100]}


def _definition(**values):
    base = {"agents": {}, "authorization": None, "servers": {}, "graphs": {}, "policies": {}, "unknown": [],
            "ignored_fields": [], "complete": True, "settings_model": None}
    base.update(values)
    return base


def manifest(document):
    """ThreatVeil's generic agent manifest (JSON or YAML)."""
    document = _document(document)
    agents, authorization, ignored = {}, {"agents": {}, "tools": {}}, []
    known = {"model", "instructions", "tools", "denied_tools", "requires_approval", "mcp_servers", "delegates_to",
             "resources", "allow_delegation", "description"}
    for name, spec in _mapping(document.get("agents"), "agents").items():
        spec = _mapping(spec, f"agent {name}")
        ignored += [f"agents.{name}.{key}" for key in spec if key not in known]
        grants = {"allow_delegation": _flag(spec.get("allow_delegation"), "allow_delegation")}
        authorization["agents"][name] = {
            "tools": _names(spec.get("tools"), "tools"), "denied_tools": _names(spec.get("denied_tools"), "denied_tools"),
            "mcp_servers": _names(spec.get("mcp_servers"), "mcp_servers"),
            "delegates_to": _names(spec.get("delegates_to"), "delegates_to"),
            "resources": _names(spec.get("resources"), "resources"),
            **{k: v for k, v in grants.items() if v is not None}}
        for tool in _names(spec.get("requires_approval"), "requires_approval"):
            authorization["tools"].setdefault(tool, {})["approval_required"] = True
        agents[name] = {"model": str(spec["model"])[:200] if spec.get("model") else None,
                        "instructions": _text_digest(spec.get("instructions")),
                        "description": _text_digest(spec.get("description"))}
    for tool, conditions in _mapping(document.get("tools"), "tools").items():
        conditions = _mapping(conditions, f"tool {tool}")
        authorization["tools"].setdefault(tool, {}).update(conditions)
    servers = {name: _server(spec) for name, spec in _mapping(document.get("mcp_servers"), "mcp_servers").items()}
    ignored += [key for key in document if key not in {"schema", "agents", "tools", "mcp_servers"}]
    return _definition(agents=agents, authorization=authorization, servers=servers, ignored_fields=sorted(ignored))


def claude_settings(document):
    """Claude Code settings.json: permission rules, MCP enablement, hooks and model."""
    document = _document(document)
    permissions = _mapping(document.get("permissions"), "permissions")
    authorization = {"permissions": {
        "allow": _names(permissions.get("allow"), "permissions.allow"),
        "deny": _names(permissions.get("deny"), "permissions.deny"),
        "ask": _names(permissions.get("ask"), "permissions.ask"),
        "additional_directories": _names(permissions.get("additionalDirectories"), "additionalDirectories")}}
    if permissions.get("defaultMode") is not None:
        authorization["permissions"]["default_mode"] = str(permissions["defaultMode"])[:40]
    mcp = {"enabled_servers": _names(document.get("enabledMcpjsonServers"), "enabledMcpjsonServers"),
           "disabled_servers": _names(document.get("disabledMcpjsonServers"), "disabledMcpjsonServers")}
    enable_all = _flag(document.get("enableAllProjectMcpServers"), "enableAllProjectMcpServers")
    if enable_all is not None:
        mcp["enable_all_project_servers"] = enable_all
    servers = {name: _server(spec) for name, spec in _mapping(document.get("mcpServers"), "mcpServers").items()}
    if servers:
        mcp["servers"] = sorted(servers)
    authorization["mcp"] = mcp
    policies = {"hooks": digest(document["hooks"])} if document.get("hooks") else {}
    known = {"permissions", "enabledMcpjsonServers", "disabledMcpjsonServers", "enableAllProjectMcpServers",
             "mcpServers", "hooks", "model", "$schema"}
    return _definition(authorization=authorization, servers=servers, policies=policies,
                       settings_model=str(document["model"])[:200] if document.get("model") else None,
                       ignored_fields=sorted(k for k in document if k not in known))


def mcp_json(document):
    """A project .mcp.json: which MCP servers the agent may connect to."""
    document = _document(document)
    servers = {name: _server(spec) for name, spec in _mapping(document.get("mcpServers"), "mcpServers").items()}
    return _definition(authorization={"mcp": {"servers": sorted(servers)}}, servers=servers,
                       ignored_fields=sorted(k for k in document if k != "mcpServers"))


def claude_subagent(document):
    """A Claude subagent markdown file: YAML frontmatter plus instructions."""
    if not isinstance(document, str) or len(document) > MAX_TEXT:
        raise DefinitionError("A subagent definition must be markdown text of at most 256 KiB")
    match = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n?(.*)$", document, re.S)
    if not match:
        raise DefinitionError("A subagent definition must begin with YAML frontmatter")
    front = _document(match.group(1))
    name = front.get("name")
    if not isinstance(name, str) or not ITEM.fullmatch(name):
        raise DefinitionError("A subagent definition requires a short name")
    # Omitting tools inherits every tool of the parent: recorded as such, never as an empty list.
    tools = "INHERITED_ALL" if front.get("tools") is None else _names(front.get("tools"), "tools")
    return _definition(
        agents={name: {"model": str(front["model"])[:200] if front.get("model") else None,
                       "instructions": _text_digest(match.group(2).strip()),
                       "description": _text_digest(front.get("description"))}},
        authorization={"agents": {name: {"tools": tools}}},
        ignored_fields=sorted(k for k in front if k not in {"name", "description", "tools", "model"}))


def langgraph(document):
    """langgraph.json declares graph entry points only; tools live in code."""
    document = _document(document)
    graphs = {name: digest(str(target)) for name, target in _mapping(document.get("graphs"), "graphs").items()}
    return _definition(graphs=graphs, complete=False, unknown=[CODE_DEFINED])


def crewai(document):
    """CrewAI agents.yaml: agents, their tools and delegation flags."""
    document = _document(document)
    agents, authorization = {}, {"agents": {}}
    for name, spec in _mapping(document, "agents").items():
        spec = _mapping(spec, f"agent {name}")
        entry = {"tools": _names(spec.get("tools"), "tools")}
        for flag in ("allow_delegation", "allow_code_execution"):
            value = _flag(spec.get(flag), flag)
            if value is not None:
                entry[flag] = value
        authorization["agents"][name] = entry
        agents[name] = {"model": str(spec["llm"])[:200] if spec.get("llm") else None,
                        "instructions": digest([spec.get("role"), spec.get("goal"), spec.get("backstory")]),
                        "description": None}
    return _definition(agents=agents, authorization=authorization)


def openai_agents(_document_value):
    raise DefinitionError("OpenAI Agents SDK definitions are code. Export a ThreatVeil agent manifest to evaluate them.")


ADAPTERS = {"manifest": manifest, "claude_settings": claude_settings, "mcp_json": mcp_json,
            "claude_subagent": claude_subagent, "langgraph": langgraph, "crewai": crewai,
            "openai_agents": openai_agents}


def infer_format(path):
    """Best-effort format from a file path, for the CLI. Returns None when unknown."""
    item = PurePosixPath(str(path).replace("\\", "/"))
    name = item.name.lower()
    if name in {"settings.json", "settings.local.json"} and ".claude" in item.parts:
        return "claude_settings"
    if name == ".mcp.json":
        return "mcp_json"
    if name.endswith(".md") and "agents" in item.parts and ".claude" in item.parts:
        return "claude_subagent"
    if name == "langgraph.json":
        return "langgraph"
    if name in {"agents.yaml", "agents.yml"}:
        return "crewai"
    if "threatveil" in name and name.endswith((".json", ".yaml", ".yml")):
        return "manifest"
    return None


# Structural signatures. A candidate must also parse under its adapter, so a key that
# merely looks familiar never selects a format on its own.
_CLAUDE_SETTINGS_KEYS = {"permissions", "enabledMcpjsonServers", "disabledMcpjsonServers",
                         "enableAllProjectMcpServers", "hooks"}
_LANGGRAPH_KEYS = {"$schema", "graphs", "dependencies", "env", "python_version", "node_version", "dockerfile_lines",
                   "pip_config_file", "store", "auth", "http", "checkpointer", "image_distro"}
_MANIFEST_KEYS = {"schema", "agents", "tools", "mcp_servers"}
_CREW_KEYS = {"role", "goal", "backstory"}
_FILENAMES = {"settings.json": "claude_settings", "settings.local.json": "claude_settings", ".mcp.json": "mcp_json",
              "langgraph.json": "langgraph", "agents.yaml": "crewai", "agents.yml": "crewai"}
MCP_CATALOG = "mcp_tools"


def parse_text(value):
    """Uploaded or pasted text as a document: markdown frontmatter stays text, the rest is JSON or safe YAML."""
    if not isinstance(value, str):
        return value
    if re.match(r"^\ufeff?\s*---\r?\n", value):
        return value
    try:
        import json

        return json.loads(value)
    except ValueError:
        return load_yaml(value)


def _structural(document):
    if isinstance(document, str):
        match = re.match(r"^\ufeff?\s*---\r?\n(.*?)\r?\n---", document, re.S)
        try:
            front = load_yaml(match.group(1)) if match else None
        except DefinitionError:
            front = None
        return ["claude_subagent"] if isinstance(front, dict) and isinstance(front.get("name"), str) else []
    if not isinstance(document, dict) or not document:
        return []
    keys = set(document)
    found = []
    if keys & _CLAUDE_SETTINGS_KEYS:
        found.append("claude_settings")
    if isinstance(document.get("mcpServers"), dict) and not keys - {"mcpServers", "$schema"}:
        found.append("mcp_json")
    if isinstance(document.get("graphs"), dict) and keys <= _LANGGRAPH_KEYS:
        found.append("langgraph")
    if isinstance(document.get("agents"), dict) and keys <= _MANIFEST_KEYS:
        found.append("manifest")
    if all(isinstance(v, dict) and set(v) & _CREW_KEYS for v in document.values()):
        found.append("crewai")
    if isinstance(document.get("tools"), list) and ({"protocol_version", "server_info"} & keys):
        found.append(MCP_CATALOG)
    return found


def _parses(fmt, document):
    if fmt == MCP_CATALOG:
        return True  # validated by the MCP catalog parser when previewed or imported
    try:
        ADAPTERS[fmt](document)
        return True
    except (DefinitionError, ValueError, TypeError, KeyError, RecursionError):
        return False


def detect_format(document, filename=None):
    """Deterministic format detection for an uploaded or pasted definition.

    Structure decides, and every candidate must also parse under its own adapter. A file
    name only settles a tie between candidates that already fit; it never selects a
    format by itself. When two formats fit and the name does not settle it, the result is
    AMBIGUOUS and the caller must ask. Nothing about the content is returned.
    """
    try:
        document = parse_text(document)
    except DefinitionError:
        return {"status": "UNSUPPORTED", "format": None, "candidates": [],
                "basis": "The file is neither JSON, YAML nor subagent markdown."}
    candidates = [fmt for fmt in _structural(document) if _parses(fmt, document)]
    name = PurePosixPath(str(filename or "").replace("\\", "/")).name.lower()
    by_name = _FILENAMES.get(name) or ("claude_subagent" if name.endswith(".md") else None) \
        or ("manifest" if "threatveil" in name else None)
    if len(candidates) == 1:
        return {"status": "DETECTED", "format": candidates[0], "candidates": candidates,
                "basis": "Structure matches exactly one supported format."}
    if len(candidates) > 1 and by_name in candidates:
        return {"status": "DETECTED", "format": by_name, "candidates": candidates,
                "basis": "Structure fits more than one format; the file name settles which."}
    if candidates:
        return {"status": "AMBIGUOUS", "format": None, "candidates": candidates,
                "basis": "Structure fits more than one supported format."}
    hint = None
    if isinstance(document, dict) and isinstance(document.get("spans"), list):
        hint = "OPENAI_AGENTS_TRACE"
    elif isinstance(document, dict) and isinstance(document.get("events"), list):
        hint = "AGENT_SDK_HOOK_EVENTS"
    return {"status": "UNSUPPORTED", "format": None, "candidates": [], "hint": hint,
            "basis": "No supported definition format matches this structure."}


def _component(kind, identifier, value, version=None):
    return {"type": kind, "id": identifier, "version": version, "digest": digest(value), "dependencies": []}


def snapshot(payload, source_identity):
    """The bounded source snapshot for one agent definition."""
    from .source_semantics import bounded_authorization

    if not isinstance(payload, dict) or payload.get("format") not in ADAPTERS:
        raise DefinitionError("Unsupported agent-definition format; supported: " + ", ".join(FORMATS))
    fmt = payload["format"]
    definition = ADAPTERS[fmt](payload.get("document"))
    authorization = definition["authorization"]
    components = {}
    if authorization is not None:
        components[f"permissions:{source_identity}"] = _component("permissions", source_identity, authorization)
    for name, agent in definition["agents"].items():
        if agent.get("model"):
            components[f"model:{name}"] = {**_component("model", name, agent["model"], agent["model"]),
                                           "identity_basis": "ADVERTISED_CONFIGURATION", "behavioral_revision": None}
        if agent.get("instructions"):
            components[f"prompt:{name}"] = _component("prompt", name, agent["instructions"])
        components[f"agent:{name}"] = _component("agent", name, agent.get("description"))
    if definition["settings_model"]:
        components["model:settings"] = {**_component("model", "settings", definition["settings_model"],
                                                     definition["settings_model"]),
                                        "identity_basis": "ADVERTISED_CONFIGURATION", "behavioral_revision": None}
    for name, server in definition["servers"].items():
        components[f"mcp:{name}"] = _component("mcp", name, server)
    for name, target in definition["graphs"].items():
        components[f"graph:{name}"] = _component("graph", name, target)
    for name, value in definition["policies"].items():
        components[f"policy:{name}"] = _component("policy", name, value)
    tools = sorted({tool for agent in ((authorization or {}).get("agents") or {}).values()
                    for tool in (agent.get("tools") if isinstance(agent.get("tools"), list) else [])}
                   | set(((authorization or {}).get("tools") or {}).keys())
                   | set(((authorization or {}).get("permissions") or {}).get("allow", [])))
    limitations = ["An agent definition is declared configuration; it does not prove the running agent uses it.",
                   *definition["unknown"]]
    if definition["ignored_fields"]:
        limitations.append(f"{len(definition['ignored_fields'])} field(s) have no reviewed semantics and were not compared.")
    facts = {
        "definition_format": fmt, "definition_parts": {"format": fmt, "agents": sorted(definition["agents"]),
                                                       "ignored_fields": definition["ignored_fields"][:100]},
        "authorization": bounded_authorization(authorization), "tool_names": tools[:MAX_ITEMS],
        "mcp_servers": sorted(definition["servers"]), "unknown": definition["unknown"],
        "task_outcome": "UNKNOWN", "committed_effect": "UNKNOWN", "running_state_proven": False,
    }
    return Snapshot(source_version=f"{fmt} ({PROFILE})", mapping_version=PROFILE, components=components,
                    facts=facts, complete=definition["complete"], limitations=tuple(limitations))
