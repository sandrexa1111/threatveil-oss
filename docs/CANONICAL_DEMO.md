# The canonical five-minute demonstration

**The autonomous system changed. ThreatVeil knew exactly which previous security conclusion no longer held.**

> **SYNTHETIC DEMONSTRATION.** The demonstration uses the existing Finance Agent only. It runs in a labelled SANDBOX: three claims, committed synthetic SQL effects in a SQLite ledger, and a synthetic MCP tool gateway imported as a source (never presented as live). No customer system, provider or money is touched. It shows the assurance model working on a prepared fixture; it does **not** show that ThreatVeil works on other systems. Restoration after a source change and the one-click orchestration are fixture-specific; see [known limitations §9](KNOWN_LIMITATIONS.md#9-synthetic-fixture-boundaries).

## Reset and preparation

Every run uses a fresh local organization. Nothing is deleted and there is no fixture backdoor; local sign-in is refused by configuration outside local/test.

With Docker (no host toolchain), against the running `docker compose up` stack:

```
make demo          # docker compose --profile demo run --rm demo
make demo-live     # same, with --stop-at cleared
```

On a host development setup, against a running local API:

```
uv run python scripts/canonical_demo.py --trusted-public-key <independently exported pem> --stop-at cleared
```

This prints an email address. Sign in with it at `/login` and continue live. Without `--stop-at`, the script performs and verifies all six steps and writes `summary.json`, the timings and the signed artifacts.

Alternatively, in the product: open **Protection journey** under Advanced, tick the synthetic scope, choose **Prepare finance example**, then open **Systems**.

## Script

| Step | In the product | What the prospect sees |
|---|---|---|
| 1 · Current | Systems → **Establish baseline** | "Finance Agent · Current clearance **Cleared** · 3 of 3 critical claims · consequential powers: Beneficiary update, Invoice update". Open **System map** and **What it can do**. |
| 2 · Change outside code | **Relax beneficiary approval** | The tool gateway, not a repository, stopped requiring approval for `beneficiary.update`. |
| 3 · Consequence | **What changed** / **What it can do** | "**Beneficiary update authority expanded**". Before: `approval_required = true, tenant_bound = true`; after: `approval_required = false`. 1 claim affected, 1 evidence package stale, 2 still hold, previous clearance **SUPERSEDED**. The explanation names the claim, the dependency (`permissions:finance-approval`) and the reviewed mapping, then says what to re-establish. |
| 4 · Re-establish | **Re-establish** → A, B, C | A: a forbidden beneficiary update committed → **Security failed: not cleared.** B: security passed but invoice updates broke → **Security held, but useful work broke: not cleared.** C: approval restored and re-proven → **Clearance restored.** |
| 5 · Machine | **Clearance** | The Assurance Gate: `CURRENT`, `cleared: true`, `authorizes: false`, valid for 60 seconds, plus the `curl` a CI job would run and the status table. |
| 6 · External party | **Passport** → Issue → **Create a share link** → open it in a private window → **Verify authenticity in this browser** | "Authentic: signed by key …" and "Current status: Still current". Then relax approval again and reload the link: still **authentic**, now **Superseded by a later change**. |

Optional contrast: **Expose an unreviewed payment tool**. Nothing maps that new interface, so every claim needs fresh evidence and "payment.execute" appears outside the declared boundary. Unknown stays unknown.

## What to say

- "A historical pass is not a current pass. Security evidence has a shelf life."
- "Nothing here guessed. The claim depends on that permission because your reviewer said so, and you can see the record."
- "Blocking useful work is not a fix. ThreatVeil clears only when the bad outcome is prevented *and* the good outcome still works."
- "Your customer can verify this without an account, and can see the moment it stops being current."

## Acceptance

`scripts/canonical_demo.py` asserts every step and verifies each signed record against an independently supplied key, and against the published trust directory. `apps/web/tests/assurance-intelligence.spec.ts` drives the same six steps in a browser, including external verification in a separate browser context.
