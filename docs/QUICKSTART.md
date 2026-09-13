# Quickstart: connect your own agent

**Goal: a real answer about your own system in under fifteen minutes.** Not a demo. At the
end you will have asked ThreatVeil "what would this change break?" about a change you are
actually considering, and got an answer bound to your own declared configuration.

You do not need a live connection, a test harness or an observer to start. Those raise what
ThreatVeil can *prove*; this quickstart is about getting a true answer quickly.

> **Running it.** There is no hosted ThreatVeil. Start one locally with
> `docker compose up --build` and open `http://127.0.0.1:3000` (see the
> [README](../README.md#quick-start)). Where this guide shows
> `https://your-deployment.example/api/backend`, use `http://127.0.0.1:8000` instead.

---

## Before you start

You need one of these files from the agent you want to protect:

| You have | Format to use |
|---|---|
| A Claude Code project | `.claude/settings.json` (`claude_settings`) or `.mcp.json` (`mcp_json`) |
| A subagent definition | `.claude/agents/<name>.md` (`claude_subagent`) |
| An MCP tool gateway | the `tools/list` catalogue JSON (no format needed) |
| A LangGraph app | `langgraph.json` (`langgraph`) — tools are in code, so most of it stays UNKNOWN |
| A CrewAI crew | `agents.yaml` (`crewai`) |
| None of the above | write a ThreatVeil agent manifest (`manifest`); see §6 |

Secrets are never read from these files. Environment variable values, headers and tokens are
dropped; only their names and digests are retained.

---

## 1. Create the workspace (2 minutes)

Sign in and choose **Import a definition**, then **Upload configuration** (or **Paste
definition**). You do not pick a format: ThreatVeil detects it from the file's structure, and if
a file fits more than one format it asks which one it is. **ThreatVeil found** lists what it
established — the detected stack, advertised models, tools, MCP servers, permissions and agents —
before anything is created, and then asks only for what no file declares.

**GitHub** and **MCP** are also offered as connection methods. A live GitHub source needs a read
credential reference registered by an owner; until one exists the screen says *Configuration
required* rather than pretending to connect.

Name the system after the workflow it performs, not the repository: *"Support refund agent"*,
not *"support-svc"*. Then declare the environment you are protecting: staging first. A staging
boundary gives you real answers without touching production. **Connect system** creates the
system, its environment and the definition source, and imports the file as a first observation.

No definition file? **Advanced manual setup** on the same screen takes the details by hand.

## 2. Import the definition (3 minutes)

If you imported the file in step 1, this is done. To import later or from CI, create a source
of type **Agent definition import**, then import the file:

```bash
export TV_API_URL=https://your-deployment.example/api/backend
export TV_API_TOKEN=...   # Settings → Developer → API tokens

threatveil propose-change $SYSTEM_ID \
  --installation $INSTALLATION_ID \
  --file .claude/settings.json
```

The first import is a first observation: it establishes what ThreatVeil has seen, and it
invalidates nothing. ThreatVeil now knows which tools are allowed, which are denied, which
MCP servers are enabled and which model is configured.

## 3. Declare one claim (4 minutes)

Open the system's **Security claims** tab and use the claim builder: pick a pattern (for example
APPROVAL REQUIRED), say what it
governs, and edit every line so it is true for your system. Then declare the dependency it
relies on, for example `permissions:approval`.

Your claim is now `NOT_YET_VERIFIED`. That is the honest state: ThreatVeil holds no evidence
for it, and it will never report it as supported. What it *can* do from here is tell you
which changes reach it.

## 4. Map the fact that controls it (2 minutes)

Open the system's **Evidence** tab and expand **Dependency mapping**. ThreatVeil lists the facts
your source actually reported and
suggests correspondences with the reason for each — a tool name match, a declared approval
field, a permission scope. Approve the ones that are right.

Only an approved mapping narrows anything. Until one exists, every change stays conservative:
ThreatVeil tells you that every claim it could reach needs review.

## 5. Ask what your next change would break (3 minutes)

Edit the configuration you are about to ship — add a tool to `allow`, remove a `deny`, relax
an approval — and ask:

```bash
threatveil propose-change $SYSTEM_ID \
  --installation $INSTALLATION_ID \
  --file /tmp/settings-proposed.json \
  --reference-type PULL_REQUEST --reference "#128"
```

You get a claim-level answer: which claims this change reaches, which stay untouched, which
way authority moved, and what is not mapped. Current clearance does not change: the
assessment is recorded as **PROPOSED · NON-ACTIVE · NOT CURRENT STATE**.

Then tell ThreatVeil whether it was right. The **Was this right?** control records your
judgement beside the consequence, and never changes the consequence.

## 6. If you have no definition file

Write a manifest. This is the whole format:

```yaml
schema: threatveil-agent-manifest/v1
agents:
  support-agent:
    model: claude-opus-5
    tools: [ticket.update, refund.issue]
    denied_tools: [account.delete]
    requires_approval: [refund.issue]
    mcp_servers: [billing]
tools:
  refund.issue:
    approval_required: true
    tenant_bound: true
    max_amount: 500
mcp_servers:
  billing: {url: https://billing.internal.example/mcp, transport: http}
```

Import it the same way, with `--format manifest`.

---

## What you have, and what you do not

**You have:** a named system, a declared authority boundary, one claim in business language,
one reviewed mapping, and a true claim-level answer about a real proposed change — plus the
record of who declared and approved what.

**You do not have yet:** evidence. A declared claim is not a verified claim. To get from
`NOT_YET_VERIFIED` to `CURRENT` you need an approved executable check and a qualified
business-effect observer (`docs/BUSINESS_EFFECT_OBSERVER.md`). ThreatVeil will keep saying
so on every screen until you do, because that difference is the product.

## Next

1. Connect the source live instead of importing it, so ThreatVeil sees changes you forget to
   send (`docs/CONNECTOR_CONTRACT.md`).
2. Declare an observer contract and qualify it against the harness.
3. Install the Assurance Gate in WARN in your pipeline (`docs/ASSURANCE_GATE.md`).
4. Replay your real configuration history to see what past changes would have meant:
   `threatveil replay-config-history $SYSTEM_ID --installation $INSTALLATION_ID --path .claude/settings.json`.
