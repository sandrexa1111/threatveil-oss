# Trust distribution for ThreatVeil records

A signed decision is durable evidence only if someone who is not a ThreatVeil customer can resolve the key that signed it, years later, without asking ThreatVeil for permission. That resolution is what this document specifies. It is a prerequisite for the first hosted customer record, because retrofitting trust distribution onto records that have already been issued is the expensive version of this work.

## What is published

`GET /v1/trust/keys` is unauthenticated, cacheable and carries no tenant data. It returns a `threatveil-trust-directory/v1` document: an issuer, and one entry per verification key.

| Field | Meaning |
|---|---|
| `keyid` | SHA-256 over the raw Ed25519 public key. This is the same identifier the DSSE signature block carries. |
| `algorithm` / `signature_profile` | `Ed25519` and `dsse-in-toto-ed25519/v1`. Unknown algorithms are refused rather than assumed. |
| `status` | `ACTIVE`, `RETIRED` or `REVOKED`. |
| `valid_from` / `valid_until` | The window in which this key was authorized to sign. |
| `revoked_at` / `revocation_reason` | Present exactly when the status is `REVOKED`. |
| `public_key_pem` | The public half only. |
| `supersedes` | The `keyid` this key replaced, where applicable. |

The identifier is derived from the key material and re-derived on load, so a directory cannot rename a key or substitute material under an existing identifier. A document containing private key material is refused. At most one key may be `ACTIVE`.

## Rotation semantics

These are the whole point of the directory, so they are stated once and enforced in `threatveil.sdk.trust_directory`:

- **ACTIVE** — may sign new records; verifies records signed inside its window.
- **RETIRED** — must not sign new records; **still verifies** records that were signed inside its window. Rotation therefore never invalidates history.
- **REVOKED** — the private key is considered compromised. Genuine and forged signatures can no longer be distinguished, so **nothing** signed by it verifies, whatever its date.

A record whose `not_before` falls outside its key's validity window is refused even when the signature is arithmetically valid: the key was not authorized to make that statement at that time.

## What the directory does not establish

A directory establishes which key signed a record. It does not establish that the record's decision is still current — that is the record's own `status_uri`, and it is deliberately a separate check. Offline verification is a historical statement; current status requires a fresh online read. Nothing here attests that the underlying security conclusion was correct, only that the statement is authentic and was made under an authorized key.

## Verification paths

Two are implemented and both belong to the SDK, not the service:

- `verify_change_record(envelope, public_key, ...)` — the caller supplies a key it already trusts. This remains the primitive and the strongest posture.
- `verify_change_record_with_directory(envelope, directory, ...)` — the caller trusts a directory obtained out of band, and resolution, status and window checks are applied before the signature is checked.

Neither requires privileged access to the ThreatVeil backend. That is what makes an exported record an asset rather than a report.

## Operating requirements

Outside local development, an operator-managed directory must be configured through `TV_TRUST_DIRECTORY_PATH`, holding the full rotation history. The service refuses to publish a directory that does not list its own signer as `ACTIVE`, because publishing one would produce unverifiable records for as long as the mistake went unnoticed.

Without that configuration the service derives a single-key directory from the running signing key and labels it `DERIVED` or `LOCAL_DEMONSTRATION`. A derived directory is explicitly not a rotation history, and the read-only activation preflight fails its `trust_directory` check until an operator-provisioned one exists with at least thirty days before the active key expires.

## Not implemented

One algorithm profile. No transparency log, so third-party verification still depends on obtaining this directory rather than on an independent witness. No keyless or identity-based signing. No automated rotation schedule: rotation is an operator action, and the directory records its result. `signature_profile` is a versioned extension seam, not implemented post-quantum support; a second profile should be added when a customer or standard requires it, since a seam is only proven by its second occupant.
