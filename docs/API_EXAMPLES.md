# API and SDK examples

Every example below uses a scoped API token (workspace settings → API tokens). A token
carries the role of the member who issued it; a read-only role can read, never write.

```bash
export TV_API_URL=https://your-deployment.example/api/backend
export TV_API_TOKEN=tv_...
export SYSTEM_ID=...      # a protected system
export INSTALLATION_ID=... # one of its sources
```

Machine callers should send `X-ThreatVeil-Consumer: <label>` so reliance is attributable;
the label is bounded (`[a-z0-9][a-z0-9_.-]{0,39}`) and never free text.

---

## 1. Is this system still cleared to act? (the Assurance Gate)

```bash
curl -sS "$TV_API_URL/v1/systems/$SYSTEM_ID/assurance/current?action=refund.issue" \
  -H "Authorization: Bearer $TV_API_TOKEN" \
  -H "X-ThreatVeil-Consumer: deploy-pipeline"
```

```python
from threatveil.sdk.client import ThreatVeilClient

with ThreatVeilClient(API_URL, TOKEN) as client:
    gate = client.current_assurance(SYSTEM_ID, action="refund.issue", consumer="deploy-pipeline")
    if not client.is_cleared(gate):          # fail closed: UNKNOWN is never cleared
        raise SystemExit(f"Not cleared: {gate['status']} — {gate['why']}")
```

```ts
import { ThreatVeilClient } from '@threatveil/sdk';

const tv = new ThreatVeilClient(process.env.TV_API_URL!, process.env.TV_API_TOKEN!);
const gate = await tv.currentAssurance(systemId, { action: 'refund.issue', consumer: 'deploy-pipeline' });
if (!ThreatVeilClient.isCleared(gate)) process.exit(1);   // fail closed
```

```bash
threatveil assurance-current "$SYSTEM_ID" --require-cleared   # exits non-zero unless CURRENT + ALLOW
```

`UNKNOWN` never means cleared. Your policy decides what to do when ThreatVeil cannot answer.

---

## 2. What would this change break? (proposed-change dry run)

```bash
curl -sS -X POST "$TV_API_URL/v1/systems/$SYSTEM_ID/proposed-changes" \
  -H "Authorization: Bearer $TV_API_TOKEN" -H 'Content-Type: application/json' \
  -H "X-ThreatVeil-Consumer: github-actions" \
  -d '{
    "installation_id": "'"$INSTALLATION_ID"'",
    "payload": {"format": "claude_settings", "document": {"permissions": {"allow": ["Read", "Write"]}}},
    "reference": {"type": "PULL_REQUEST", "id": "#128", "url": "https://github.com/acme/agent/pull/128"},
    "idempotency_key": "pr-128-settings-json"
  }'
```

```python
result = client.propose_change(
    SYSTEM_ID, installation_id=INSTALLATION_ID,
    payload={"format": "claude_settings", "document": proposed},
    reference={"type": "PULL_REQUEST", "id": "#128"})
print(result["summary"]["effect"], result["clearance"])   # clearance is unchanged, always
```

```bash
threatveil propose-change "$SYSTEM_ID" --installation "$INSTALLATION_ID" \
  --file .claude/settings.json --reference-type PULL_REQUEST --reference '#128'
```

In CI, use the action instead (`integrations/github-change-assurance`). It publishes the
answer as a job summary and never fails the build unless you set `fail-on`.

---

## 3. Was that consequence right? (feedback)

```bash
curl -sS -X POST "$TV_API_URL/v1/systems/$SYSTEM_ID/consequences/$CONSEQUENCE_ID/feedback" \
  -H "Authorization: Bearer $TV_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"verdict": "CORRECT", "comment": "The approval field is exactly what gates this.",
       "idempotency_key": "review-2026-09-12-a"}'
```

```python
client.confirm_consequence(SYSTEM_ID, CONSEQUENCE_ID, verdict="PARTIALLY_CORRECT",
                           comment="Right claim, wrong severity for us.")
```

Verdicts: `CORRECT`, `PARTIALLY_CORRECT`, `INCORRECT`, `NOT_SURE`. Feedback is append-only
and never changes the consequence, the claim or the clearance.

---

## 4. What do we claim, and how far has each claim got?

```bash
curl -sS "$TV_API_URL/v1/systems/$SYSTEM_ID/claims" -H "Authorization: Bearer $TV_API_TOKEN"
curl -sS "$TV_API_URL/v1/systems/$SYSTEM_ID/guidance" -H "Authorization: Bearer $TV_API_TOKEN"
```

```python
ladder = client.claims(SYSTEM_ID)
print({level: ladder["counts"][level] for level in ladder["levels"]})
for item in client.guidance(SYSTEM_ID)["items"]:
    print(item["code"], "→ ThreatVeil will not claim:", item["not_claimed"])
```

`DECLARED`, `NOT_YET_VERIFIED`, `QUALIFIED` and `CURRENT` are four different states and are
never merged.

---

## 5. Did the business effect actually commit? (qualified observer)

```bash
curl -sS "$TV_API_URL/v1/observer-definitions/$DEFINITION_ID/effects?correlation_value=refund-9" \
  -H "Authorization: Bearer $TV_API_TOKEN"
```

```python
effect = client.observed_effect(DEFINITION_ID, "refund-9")
assert effect["effect"] in {"COMMITTED", "COMMITTED_THEN_COMPENSATED", "DENIED",
                            "NO_EFFECT_OBSERVED", "UNKNOWN"}
```

`UNKNOWN` is not "no effect", and `COMMITTED_THEN_COMPENSATED` still means it committed.

---

## 6. A passport for someone outside your organization

```bash
# 1. issue (STANDARD disclosure withholds internal identifiers and resource names)
curl -sS -X POST "$TV_API_URL/v1/systems/$SYSTEM_ID/passports" \
  -H "Authorization: Bearer $TV_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"audience": "Acme vendor security review", "valid_days": 30}'

# 2. review exactly what would leave your organization
curl -sS "$TV_API_URL/v1/passports/$PASSPORT_ID/disclosure-preview" \
  -H "Authorization: Bearer $TV_API_TOKEN"

# 3. share, confirming that disclosure
curl -sS -X POST "$TV_API_URL/v1/passports/$PASSPORT_ID/share" \
  -H "Authorization: Bearer $TV_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"label": "Acme review", "valid_days": 14, "confirm_disclosure": true}'
```

Offline verification, with no ThreatVeil account and no network call to us:

```bash
threatveil verify-passport passport.json --directory trust-keys.json
```

```python
from threatveil.sdk.passports import verify_passport_with_directory

statement = verify_passport_with_directory(envelope, directory,
                                           passport_id=passport_id,
                                           system_reference=document["system"]["reference"])
```

Authenticity and current status are separate by design: a passport stays authentic after
your system changes, and its status check is what says it no longer describes today.

---

## 7. Measurement and provenance

```bash
curl -sS "$TV_API_URL/v1/measurements/business"   -H "Authorization: Bearer $TV_API_TOKEN"
curl -sS "$TV_API_URL/v1/measurements/activation" -H "Authorization: Bearer $TV_API_TOKEN"
curl -sS "$TV_API_URL/v1/measurements/ai-usage"   -H "Authorization: Bearer $TV_API_TOKEN"
curl -sS "$TV_API_URL/v1/build-info"              -H "Authorization: Bearer $TV_API_TOKEN"
```

Every consequence carries a provenance: `SYNTHETIC`, `CUSTOMER`, `LIVE`, `IMPORTED`,
`PROPOSED` or `REPLAYED`. Synthetic and replayed activity is shown and never counted.

---

## 8. Take your data with you

```bash
curl -sS "$TV_API_URL/v1/memory/export" -H "Authorization: Bearer $TV_API_TOKEN" > memory.ndjson
```

See `docs/DATA_EXPORT.md` for the record kinds, the one deliberate exclusion, and how to read
the stream.

---

## Errors, limits and idempotency

| Status | Meaning |
|---|---|
| 401 | No valid session or token. |
| 403 | The role does not permit this action, or a boundary refused it. |
| 404 | Not found **or** not yours. ThreatVeil does not distinguish the two. |
| 409 | A conflict you must resolve: a reused idempotency key with different content, a revoked observer, a qualification for a different contract. |
| 413 | The request body exceeds 2 MB. |
| 422 | Input refused: out of bounds, unparseable, or a control character. |
| 429 | Rate limited. Retry after the stated window. |

Every write takes an `idempotency_key`. Replaying the same key with the same content returns
the same record (`duplicate: true`); replaying it with different content is a 409. Keys are
tenant-scoped: two organizations can use the same key without colliding.
