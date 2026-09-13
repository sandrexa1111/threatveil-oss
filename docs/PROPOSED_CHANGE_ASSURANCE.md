# Proposed-change assurance: what would this change break?

The ordinary flow waits for a change to happen and then tells you what it meant. A proposed
change asks the same question before you ship: given the claims you hold today, what would
this configuration do to them?

This is the fastest honest path to value on a customer's own system, because it needs no
natural change to occur and nothing is faked: the proposal is the customer's own.

## What it is, exactly

`POST /v1/systems/{system_id}/proposed-changes`

```json
{
  "installation_id": "…",
  "payload": {"format": "claude_settings", "document": {"permissions": {"allow": ["Read", "Write"]}}},
  "reference": {"type": "PULL_REQUEST", "id": "#128", "url": "https://github.com/acme/agent/pull/128"},
  "idempotency_key": "pr-128-settings-json"
}
```

ThreatVeil parses the proposal with the **same** deterministic parser a real import uses,
compares it against what it last observed from that source, and runs the same semantics: which
facts changed, which way declared authority moved, which reviewed dependencies are touched,
which claims those reach.

## The guarantees

| Guarantee | How it holds |
|---|---|
| **Read-only for clearance** | No source batch, system state, decision, status event or evidence record is written. The only write is one `proposed_change_assessment`. A test asserts no other record kind grows |
| **Labelled** | Every assessment carries `PROPOSED · NON-ACTIVE · NOT CURRENT STATE`, `active: false`, `current_state: false` |
| **Auditable** | Append-only, with the reference, the source, the baseline batch it compared against, and the digest of the request |
| **Bounded** | One source, a 256 KiB document bound by the shared document limits, 30 evaluations per organization per minute, plus the global per-route limit |
| **Tenant-scoped** | The system, the source and the environment must all belong to the caller's organization |
| **Idempotent** | The same key with the same content returns the same recorded answer; the same key with different content is a 409 |

The `reference` is a label for people. The URL must be `https`, is bounded, is never a path,
and **ThreatVeil never fetches it**.

## The answers it can give

| Effect | Meaning |
|---|---|
| `WOULD_REQUIRE_REPROOF` | Named claims this change reaches would need fresh evidence |
| `NO_CLAIM_AFFECTED` | Scoped by reviewed mappings to dependencies no claim relies on: ship it |
| `DECLARED_CLAIMS_AFFECTED` | It reaches claims you declared but have not verified. Now prove them |
| `NO_DECLARED_CLAIM_AFFECTED` | No declared claim depends on what this touches |
| `NO_CHANGE` | Identical to the last observation |
| `NO_BASELINE` | Nothing has been observed from this source yet, so there is nothing to compare |
| `NO_CLAIMS` | No claims exist for this system |

It also reports what clearance *is* (unchanged) and what it **would become** if the change were
applied and nothing else changed — two different statements, never merged.

## In a pull request

```yaml
- uses: actions/checkout@v4
- uses: ./integrations/github-change-assurance
  with:
    api-url: ${{ vars.THREATVEIL_API_URL }}
    api-token: ${{ secrets.THREATVEIL_API_TOKEN }}
    system-id: ${{ vars.THREATVEIL_SYSTEM_ID }}
    installation-id: ${{ vars.THREATVEIL_INSTALLATION_ID }}
    file: .claude/settings.json
    # fail-on: never (default) | reproof | unknown
```

The check is called **THREATVEIL — CHANGE ASSURANCE**. It publishes `success` for a no-impact
answer and `neutral` otherwise; it **never** publishes `failure` and never fails the build
unless you set `fail-on` yourself. A security check that blocks every pull request by default
is a security check that gets removed in week two.

Outputs: `effect`, `conclusion`, `assessment-id`.

## On the command line

```bash
threatveil propose-change $SYSTEM_ID --installation $INSTALLATION_ID \
  --file .claude/settings.json --reference-type PULL_REQUEST --reference '#128'
```

## Replaying real history

The same evaluation can be pointed at the past:

```bash
threatveil replay-config-history $SYSTEM_ID --installation $INSTALLATION_ID \
  --path .claude/settings.json --limit 5
```

This reads the **local** git history, sends each revision, and shows what each change would
have meant judged by today's claims and mappings. Every result is recorded with mode
`REPLAYED` and is **never** counted as activation, because the customer did not experience it
at the time.

## Limitations stated on every result

- A dry run compares declared configuration. It does not execute the agent, a tool or a test.
- It changes no clearance, evidence or authority; the result is not current state.
- Unmapped subjects stay conservative: every claim they could reach is listed.
- A proposal is not a deployment. ThreatVeil cannot know whether you actually shipped it.

## Time to value

Two instrumented moments, both reported per organization in
`/v1/measurements/business` → `time_to_wow`:

- `seconds_to_first_proposed_consequence` — signup to the first determinate answer about a
  proposed change on a real system.
- `seconds_to_first_confirmed_consequence` — signup to business activation.

`NO_BASELINE`, `NO_CHANGE` and `NO_CLAIMS` do not count as a wow, because they are not answers
about claims.
