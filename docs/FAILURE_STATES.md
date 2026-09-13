# Failure states: what ThreatVeil refuses to claim, and what to do

Most security products go quiet when they cannot answer. ThreatVeil names the situation, states
what it will not claim because of it, and gives the next step. `GET /v1/systems/{id}/guidance`
returns exactly that, and the workspace renders it on the system overview.

Each item carries a severity:

| Severity | Meaning |
|---|---|
| `BLOCKING_VALUE` | ThreatVeil cannot do its job here yet |
| `LIMITS_SCOPE` | It works, but the answer is narrower than it looks |
| `INFORMATIONAL` | Worth knowing; nothing is blocked |

---

| Code | Severity | It means | ThreatVeil will not claim | Next step |
|---|---|---|---|---|
| `NO_LIVE_SOURCE` | LIMITS_SCOPE | every source is an import, so changes are seen only when you send them | that it is watching this system | connect a source it can read itself, or keep importing on a schedule you control |
| `SOURCE_OUTAGE` | LIMITS_SCOPE | a connected source reported a gap, a partial snapshot, an expiry or nothing recently | that a gap means "nothing changed" | reconcile the source, then re-establish the claims its facts support |
| `BASELINE_MISSING` | BLOCKING_VALUE | no qualified verification has produced a state for this environment | anything about what a change invalidated | run the approved verification once |
| `UNMAPPED_CHANGE` | LIMITS_SCOPE | part of what changed is not mapped to a reviewed dependency | that an unnamed fact is harmless | review the mapping suggestions and approve the ones that are right |
| `NO_QUALIFIED_OBSERVER` | BLOCKING_VALUE | no observer for this environment has passed qualification | that missing evidence means no effect | declare an observer contract and qualify it against the harness |
| `CLAIM_NOT_EXECUTABLE` | LIMITS_SCOPE | claims are declared but no approved executable check is bound | that a declared claim is supported | now prove it: bind an approved claim with a qualified observer |
| `EVIDENCE_STALE` | BLOCKING_VALUE | evidence behind a claim was produced for an earlier state | that a historical pass is a current pass | re-establish the affected claims against the current state |
| `CLEARANCE_EXPIRED` | BLOCKING_VALUE | the reviewed boundary or the last clearance has expired | that an expired clearance speaks for today | review the authority boundary and re-establish clearance |
| `PASSPORT_AUTHENTIC_BUT_SUPERSEDED` | INFORMATIONAL | a passport you issued is still authentic but no longer describes today | that authenticity is current status | issue a fresh passport, or let the recipient's status check show it |

Each item also carries the records that evidence it, so the claim is checkable.

## The empty states this replaces

Every screen that could be empty says why it is empty and what to do, instead of showing a
zero:

| Screen | Empty state |
|---|---|
| Systems | the two-choice onboarding: connect my own agent, or explore an example |
| Claims | "No claim has been stated for this system yet" plus the claim builder |
| What changed | "Nothing has changed since this boundary was established" — or that earlier changes are covered by later verification |
| What still holds | claim-by-claim currency, with `UNKNOWN` stated as `UNKNOWN` |
| Dependency mapping | "Nothing is mapped for this source yet, so every change it reports stays conservative" |
| What would break | "Connect or import a source first. A dry run compares a proposal against what ThreatVeil last observed" |
| Review queue | "Nothing is waiting for review" |
| Passport | issuance form plus the disclosure preview before any link exists |
| Guidance | "Nothing is limiting this answer" — and what that statement depends on |

## The rule behind all of it

An honest limitation is a feature. A customer who knows exactly what ThreatVeil is not saying
can act on what it is saying; a customer who discovers the gap later stops believing the rest
of it.
