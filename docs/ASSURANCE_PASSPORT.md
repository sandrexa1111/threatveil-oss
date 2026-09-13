# Current Assurance Passport

A Current Assurance Passport is a **portable, signed representation of one bounded current assurance case**. An AI-native vendor can send it to an enterprise customer during a security review, procurement, renewal or technical evaluation.

It is **not** a certification, a compliance attestation, a trust score, or a statement that the system is safe. The document itself says so, under `not_claims`.

## What it communicates

| Section | Content |
|---|---|
| System, environment, state | Named system, environment and purpose; exact state digest; whether that state was established by qualified test execution |
| Consequential authority | Each declared action in plain language (for example "Beneficiary update"), with whether evidence currently supports it; interfaces a source reported outside the declared boundary; `grants_permissions: false` |
| Clearance at issue | Cleared, Needs reassessment, Not cleared, Revoked or No clearance yet, with the decision identifier |
| Claims | Four groups: supported by current evidence / needs fresh evidence / failed / not yet supported (including business-language definitions that are not yet executable) |
| Evidence status | Per claim: its currency in plain language, when it was produced, and its security and useful-task outcomes |
| Status check | Where current status can be checked; semantics of each status |
| Verification | Trust directory location, predicate type, tools |
| Limitations and non-claims | Explicit |

Internal machinery (ProofScopes, receipts, fingerprints, observation contracts, support-digest mechanics) is not exported. A buyer does not need to understand it.

## Three outputs

1. **Human-readable view** — in the workspace (`/app/passport`) and on the shared public page `/passport/{token}`, which needs no account.
2. **Machine-readable JSON** — the predicate, with schema [`schemas/assurance-passport-v1.schema.json`](../schemas/assurance-passport-v1.schema.json).
3. **Signed record** — a DSSE/in-toto statement. Predicate type `https://threatveil.com/attestation/assurance-passport/v1`, subject = system ID and state digest, signed with the same Ed25519 key published in `/v1/trust/keys`. It reuses the existing signing profile; it is not a new cryptographic system.

## Authenticity is not current clearance

A passport stays **authentic** forever: it is an immutable, signed historical statement. Its **current status** is recomputed on each check:

| Status | When |
|---|---|
| `CURRENT` | The system is still in the passport's state, and what the passport described (its clearance, or the support it described) still holds. |
| `SUPERSEDED` | The system changed after issue: a later state, or an observed change that moved the described support. |
| `REASSESS` | The support behind it moved without an observed change. |
| `EXPIRED` | Past the passport's own validity window (1–90 days; 30 by default). |
| `REVOKED` | The issuer withdrew it. |

A passport issued while the system already needed reassessment describes that honestly, and it stays `CURRENT` until the system moves again.

## Sharing

`POST /v1/passports/{id}/share` creates a capability link for one external party. The token is shown once.

- It is an HMAC-authenticated binding of organization, passport, share and expiry. The HMAC key is derived by HKDF from the signing key, so the attestation key never signs capability tokens.
- It exposes only that passport and its recomputed status.
- It can be revoked independently (`/v1/passports/shares/{id}/revoke`), and revoking the passport revokes its meaning.
- Public checks are rate-limited per share, and recorded at most once per hour as `passport.status_checked`. This is the external-verification history.
- ThreatVeil never sends the link to anyone.

## Independent verification

- **Browser:** the shared page includes "Verify authenticity in this browser". It checks the DSSE pre-authentication encoding with WebCrypto Ed25519 against the published trust directory, including the key's status and validity window.
- **Offline:** `threatveil verify-passport passport.json --directory trust.json`, or `--public-key key.pem`.
- **Library:** `threatveil.sdk.passports.verify_passport_with_directory()`.

Each of these establishes authenticity at issue time only. Rotation and revocation follow [trust distribution](TRUST_DISTRIBUTION.md): a retired key still verifies what it signed inside its window, and a revoked key verifies nothing.

## Sales use

Send the buyer the share link and, if they prefer, the signed JSON. The canonical demonstration shows the property that matters: after the system changes, the passport is still cryptographically authentic, and its status reads `SUPERSEDED`. See [canonical demo](CANONICAL_DEMO.md).
