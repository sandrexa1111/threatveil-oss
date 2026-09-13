# Agent-definition intelligence

Most agents are not described by a repository revision. They are described by a settings file,
an MCP configuration, a subagent markdown file or a crew definition — and those files change
far more often than the code around them.

ThreatVeil parses them deterministically into the same bounded source shape every other source
produces, so a change to `.claude/settings.json` is interpreted by exactly the same semantics
as a change to a live MCP catalogue.

## Supported formats

| Format | File | What it declares | Completeness |
|---|---|---|---|
| `manifest` | your own `threatveil-agent.yaml` / `.json` | agents, tools, per-tool conditions, MCP servers, delegation | complete |
| `claude_settings` | `.claude/settings.json` | permission `allow` / `deny` / `ask`, default mode, additional directories, MCP enablement, hooks, model | complete |
| `mcp_json` | `.mcp.json` | which MCP servers the agent may connect to | complete |
| `claude_subagent` | `.claude/agents/<name>.md` | name, description, tools (or inheritance), model, instructions | complete |
| `langgraph` | `langgraph.json` | graph entry points only | **incomplete**: tools and permissions are in code |
| `crewai` | `agents.yaml` | agents, tools, delegation and code-execution flags | complete |
| OpenAI Agents SDK | code | — | refused with a clear message: export a manifest instead |

"Complete" means the format declares its authority as data. Where it does not, ThreatVeil says
`UNKNOWN` and records the reason; it never guesses and it never parses or executes code.

## What is retained, and what is not

Retained: component identities and digests (tools, MCP servers, subagents, model identifiers,
instruction digests, hook digests), and a bounded flattened authorization block.

Never retained: environment variable values, header values, tokens, URLs beyond the host,
command arguments beyond a digest, or instruction text. A test asserts that a configuration
containing `Bearer …` and an `API_KEY` value yields a snapshot containing neither.

## The semantics a change gets

The shared authority vocabulary now covers the fields these formats actually use:

| Vocabulary | Fields | Direction |
|---|---|---|
| Scope lists | `allow`, `tools`, `allowed_tools`, `scopes`, `permissions`, `resources`, `roles`, `tenants`, `servers`, `enabled_servers`, `mcp_servers`, `additional_directories`, `delegates_to` | adding an item **expands** |
| Denial lists | `deny`, `ask`, `denied_tools`, `disallowed_tools`, `disabled_servers` | removing an item **expands**; adding one **contracts** |
| Restrictions | `approval_required`, `tenant_bound`, `read_only`, `dual_control`, `mfa_required`, … | relaxing **expands** |
| Grant flags | `allow_delegation`, `allow_code_execution`, `enable_all_project_servers` | enabling **expands**; a flag absent on one side is `UNKNOWN` |
| Ordered modes | `default_mode`: `plan` < `default` < `acceptEdits` < `bypassPermissions` | a value outside the list is `UNKNOWN` |

Everything else stays `UNKNOWN_IMPACT`. A subagent that omits `tools` inherits every parent
tool; ThreatVeil records `INHERITED_ALL` rather than an empty list, and a later change from
inheritance to an explicit list is `UNKNOWN` rather than a guessed contraction.

## Bounds

256 KiB per document. YAML is parsed with the safe loader, one document only, and **anchors and
aliases are refused** (the classic YAML expansion bomb). Event count, depth, item counts and
name lengths are all bounded. A parse failure returns a content-free 422: ThreatVeil never
echoes your configuration back in an error.

## Using it

Create a source with connector `agent_definition` in `IMPORT` mode, then:

```bash
threatveil propose-change $SYSTEM_ID --installation $INSTALLATION_ID --file .claude/settings.json
```

Import it for real when you want it watched, and replay its history to see what past changes
would have meant:

```bash
threatveil replay-config-history $SYSTEM_ID --installation $INSTALLATION_ID \
  --path .claude/settings.json --limit 5
```

Replayed results are labelled `REPLAYED` and never count as activation.

## Limitations

- A definition file is declared configuration. It is not proof that the running agent uses it.
- Code-defined tools (LangGraph nodes, Agents SDK code) stay `UNKNOWN`. That is a true answer,
  and a manifest is the way to make it knowable.
- Fields with no reviewed semantics are counted and reported, not silently ignored.
