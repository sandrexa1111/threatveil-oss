---
title: Security evidence has a lifecycle
description: A security conclusion can be historically correct and no longer apply. How ThreatVeil models state, authority, dependency mapping and evidence invalidation for changing AI systems.
date: 2026-09-14
slug: security-evidence-has-a-lifecycle
---

# Security evidence has a lifecycle

A security test result has two properties that are easy to conflate:

1. **Correctness:** was the conclusion true for the system that was tested?
2. **Applicability:** does that conclusion still describe the system running now?

Traditional tooling tracks the first carefully and the second barely at all. For autonomous AI systems, whose tools, permissions, models and configuration change continuously and mostly outside code, the second is where risk accumulates.

> Evidence can become stale without ever having been false.

This post walks through how ThreatVeil, an open-source experimental assurance platform, models that lifecycle. The examples come from its synthetic Finance Agent demonstration.

## 1. Start from state, not from a test run

A test result means nothing without the state it was produced on. ThreatVeil records a **system** (the protected unit, such as "Finance Agent in staging") and its **operating state**: the observed configuration, tools, permissions and component revisions, reduced to a fingerprint.

Evidence is always bound to that fingerprint:

```
evidence(claim, state_fingerprint, observer, produced_at, expires_at)
```

When the state changes, existing evidence does not become *wrong*. It becomes evidence about a *different* state. Everything else follows from taking that seriously.

## 2. Authority is what makes a change matter

Not every change is security-relevant. What matters is **authority**: what the system is able to do. ThreatVeil derives authority from declared and observed sources, such as agent definitions, MCP tool catalogues and permission rules.

When a change arrives, ThreatVeil classifies its direction:

| Direction | Example | Meaning |
|---|---|---|
| `AUTHORITY_EXPANDED` | `beneficiary.update` `approval_required: true → false` | The new boundary is not contained in the old one |
| `AUTHORITY_RESTRICTED` | A tool moves to the deny list | The new boundary is contained in the old one |
| `EQUIVALENT` | A cosmetic field changes | No authority difference |
| `UNKNOWN_IMPACT` | A numeric limit changes, or a tool defined in code | No reviewed semantics exist, so no conclusion is drawn |

The classifier deliberately knows a small vocabulary. Anything outside it is `UNKNOWN_IMPACT`, never "probably fine".

## 3. Claims say what must stay true

A **security claim** is a statement in business language, such as "beneficiary changes require finance approval". It becomes verifiable when backed by an executable property: a forbidden outcome, a permitted outcome, the observation that decides between them, and a legitimate task that must keep working.

A claim that has only been declared is `NOT_YET_VERIFIED`. It can be used to reason about change impact, but it is never reported as supported.

## 4. Dependency mapping decides reach

A change invalidates evidence for the claims it can reach, and the link between facts and claims is a **reviewed dependency mapping**. It says, for example, that the claim "beneficiary changes require finance approval" depends on `permissions:finance-approval`, and that this dependency corresponds to the gateway's `beneficiary.update.approval_required` fact.

Mappings are human decisions: attributed, append-only and visible. They are what lets ThreatVeil say something precise:

> 1 claim affected, 1 evidence package stale, 2 claims still hold.

Without them it can only say something honest and broad: every claim this change could reach needs review. In ThreatVeil that conservative answer is the default, not a failure mode.

## 5. Invalidation supersedes; it does not rewrite history

When the gateway stops requiring approval:

1. The change is recorded as a new, immutable record with its source and acquisition mode (here `IMPORTED`, from a synthetic MCP gateway).
2. Authority is classified `AUTHORITY_EXPANDED`.
3. The mapping connects the changed fact to one claim; its evidence no longer applies to the current state.
4. The previous clearance becomes `SUPERSEDED`.

Nothing is deleted or edited. The earlier signed decision is still authentic: it was correct for the state it described. ThreatVeil's history is append-only, so "what did we know, when, about which state" can always be reconstructed.

## 6. Re-verification has two conditions

Restoring assurance means producing new evidence on the new state. ThreatVeil's demonstration re-establishes the affected claim three ways:

| Attempt | Security outcome | Useful task | Result |
|---|---|---|---|
| A | A forbidden update commits | n/a | **Not cleared** |
| B | Forbidden update blocked | Legitimate invoice updates break | **Not cleared** |
| C | Approval restored and re-proven | Legitimate work succeeds | **Clearance restored** |

Attempt B is the important one. A fix that blocks everything passes the security check and fails the business. Treating `SECURITY PASS + USEFUL TASK FAILURE` as not cleared keeps assurance from being gamed by breaking the system.

## 7. Two consumers: machines and other organizations

**The Assurance Gate** is the machine answer: a small, signed-state-aware response a pipeline or policy engine can consume.

```json
{ "status": "CURRENT", "cleared": true, "authorizes": false, "valid_until": "…" }
```

It is valid for a short window and explicitly does not authorize anything. Enforcement belongs to the consumer.

**The Passport** is the answer for another organization: an Ed25519-signed DSSE envelope describing the assurance of a system. It separates two facts that are usually merged:

- **Authenticity:** was this issued by the holder of the trusted key? This is verifiable offline, and it stays true forever.
- **Currency:** does it still describe the system as it is now? This is recomputed on request.

After the approval change, a previously shared Passport still verifies as authentic, and its status reads *superseded by a later change*. A PDF report cannot say that.

## 8. Where the model is incomplete

ThreatVeil implements this lifecycle end to end only on its synthetic fixture. The open problems are real:

- **Restoration after source-observed changes** currently needs exact digest reconciliation that only the fixture provides.
- **Observers:** evidence production requires signed collectors and qualification runs, and a newer observer contract does not yet feed evidence.
- **Freshness:** without scheduled collection, a live source's staleness unsupports claims.
- **Production binding:** evidence is bounded to 24 hours and staging environments.
- **Mapping in force:** historical impact is judged by today's mappings rather than those that applied at the time.

These are research and engineering questions, not bugs to hide. They are listed in [KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md) and [ROADMAP.md](../../ROADMAP.md).

## The takeaway

If you build or secure autonomous systems, try asking this about your last security review:

> Which of these conclusions still apply to the system running today, and how would I know when one stops?

ThreatVeil is one attempt at an answer. It is Apache-2.0 licensed, and `make demo` shows the whole lifecycle in a few minutes.
