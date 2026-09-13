---
title: Why we open-sourced ThreatVeil
description: ThreatVeil started as a company-building experiment around one question about autonomous AI systems. The research and engineering are more useful in the open.
date: 2026-09-14
slug: why-we-open-sourced-threatveil
---

# Why we open-sourced ThreatVeil

ThreatVeil began as an attempt to build a company around a simple question:

> When an autonomous AI system changes, how do we know the security conclusions we previously relied on are still true?

We spent 2026 building a substantial experimental architecture around that question. It covers authority tracking, security claims, evidence applicability, change impact, signed assurance records, a machine-readable Assurance Gate and externally verifiable Passports. Today we are releasing all of it under the Apache License 2.0, together with an unedited internal audit of what works and what does not.

This post explains the problem, what we built, what we learned, and why we think open source is the right next phase.

## The problem: security evidence quietly expires

The usual security workflow for software is familiar:

```
TEST → PASS → SHIP
```

Autonomous AI systems break the last arrow. An agent that issues refunds or updates payment details is tested, and it passes. Then the system keeps changing, and most of those changes are not code:

- a tool gateway stops requiring approval for one operation;
- someone adds an MCP server with a new tool;
- a permission rule in `.claude/settings.json` is relaxed;
- the model behind the agent is swapped;
- a prompt, a limit or a tenant binding changes.

```
TEST → PASS → MODEL / TOOL / PERMISSION / CONFIG CHANGES → ?
```

The old test result is still *true*: the system you tested did pass. What nobody can easily say is whether it still *applies* to the system running now. Most organizations answer that question with a calendar ("re-test quarterly") or not at all.

## What we built

ThreatVeil models the whole chain explicitly:

```
System → Authority → Security claims → Evidence → Change
       → Evidence invalidation → Re-verification → Current assurance → Gate / Passport
```

A few ideas carry most of the weight.

**Evidence is bound to a state.** A passing check is recorded against the exact configuration and authority it was produced on, and it expires. It supports a claim only while that state holds.

**Changes invalidate evidence selectively.** When a change arrives, ThreatVeil classifies which way authority moved (expanded, restricted, unknown). Human-reviewed dependency mappings then determine which claims the change reaches. In the synthetic demonstration, relaxing an approval requirement makes exactly one of three claims lose its evidence, while the other two keep theirs. Without a reviewed mapping, ThreatVeil stays conservative: everything the change could reach needs review.

**Blocking useful work is not a fix.** Re-verification checks both that the bad outcome is prevented and that the legitimate task still works. `SECURITY PASS + USEFUL TASK FAILURE = NOT CLEARED`.

**Authentic is not the same as current.** A Passport is a signed statement that an external party can verify offline. Its signature stays valid forever, but its *current status* is recomputed on request. After a later change the Passport is still authentic, and it now reads *superseded*.

**Declared is not verified.** Importing an agent definition and declaring claims gives an immediate, useful answer to "what would this change reach?". It never produces evidence. The product keeps those two answers visibly separate.

## What works, and what does not

We want this release to be judged on the truth, so here it is.

**Working today:** the append-only assurance kernel with tenant isolation and signed records; deterministic parsing of Claude Code settings, `.mcp.json`, subagent files, MCP tool catalogues, CrewAI and a ThreatVeil manifest; authority-direction classification; reviewed dependency mapping; proposed-change dry runs; the Assurance Gate; signed Passports with offline verification; and a full end-to-end demonstration. About 700 Python tests run against real PostgreSQL, including row-level security and signature checks.

**Not working, or only on the synthetic fixture:**

- Regaining assurance after a source-observed change works only for the demonstration fixture. On other systems two passing re-verifications still leave the Gate not cleared.
- There are two observer concepts, and the newer one produces no evidence.
- Nothing schedules collection from "live" sources, so a connected source degrades clearance within minutes.
- Evidence lives at most 24 hours, and production environments cannot be cleared.
- ThreatVeil was never accepted in a cloud deployment or used by a real customer.

All of this is in [KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md), and the audit that found it is in the repository.

## What we learned

**The hard part is not detection; it is applicability.** Diffing configuration is easy, and large language models are getting good at explaining diffs. Knowing which earlier *evidence* a diff invalidates, and proving that nothing else was affected, requires a model of claims, dependencies and state that most tools do not have.

**Conservatism has to be designed in.** Every shortcut we were tempted by (inferring dependencies, trusting imported traces, treating a declaration as a check) would have produced a friendlier product that sometimes said "fine" when it did not know. The Gate never reported a false clearance in any audited scenario, and that was the result of saying UNKNOWN a lot.

**The last mile is evidence production.** Getting a real system to produce qualified, state-bound evidence repeatedly is harder than modelling it. That is where the open problems are.

## Why open source

A company needs a narrow, sellable loop and a customer who pays for it now. The research question underneath ThreatVeil is broader and earlier than that. It touches agent frameworks, MCP, deployment platforms, identity systems and security testing. It deserves to be tested and argued with by people who work on those systems.

The architecture is substantial enough to be worth studying and extending. It is honest enough about its gaps that contributors can see exactly where to start. Keeping it private would mean nobody learns from it.

## Where you can help

- **Generic restoration:** re-establish assurance after a source change on any system, not just the fixture.
- **Observer unification:** one observer concept that yields evidence.
- **Scheduled collection:** make "watching" true.
- **Framework adapters:** LangGraph and OpenAI Agents SDK, where tools are defined in code.
- **Authority semantics:** numeric limits, schema bounds and MCP annotations.
- **Research:** can evidence applicability be measured? What would a portable assurance record look like?

Start with the [roadmap](../../ROADMAP.md) and the [contributing guide](../../CONTRIBUTING.md), run `make demo`, and tell us where the model breaks.
