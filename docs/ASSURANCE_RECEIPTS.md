# Assurance receipts

ThreatVeil release receipts use an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) carried in a [DSSE envelope](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md). The signing primitive is Ed25519 from the `cryptography` library. The verifier is in `src/threatveil/sdk/receipts.py`; it requires no database, hosted UI, credentials, or network. The public schema is `schemas/assurance-receipt-v1.schema.json`.

The statement's subject is the SHA-256 digest of the candidate's complete system fingerprint. The predicate also carries the native exact candidate, including a Git SHA where applicable. A Git object digest is never mislabeled as SHA-256. The signed predicate includes the organization, system, decision ID, policy, per-property outcomes, evaluation time, exception snapshots, limitations and any additional lineage fields supplied by the control plane.

`release_action` is the effective policy result. `underlying_action` preserves the result before an exception or rollout policy. A signed exception does not rewrite a property FAIL or turn it into a security PASS. The signing library validates the envelope and required release metadata; authorization and evidence evaluation belong to the server, which must provide the already-authorized immutable decision snapshot.

## Offline verification

Obtain the issuer's public key through a trusted configuration channel. Do not trust a key supplied alongside an untrusted receipt. Obtain the expected organization and candidate fingerprint independently from your deployment inputs.

```sh
python -m threatveil.sdk.receipts release.dsse.json \
  --public-key trusted-release-key.pem \
  --candidate-fingerprint "$EXPECTED_FINGERPRINT_SHA256" \
  --organization "$EXPECTED_ORGANIZATION_ID" \
  --system "$EXPECTED_SYSTEM_ID"
```

The verifier returns a verified historical decision and exits nonzero for an invalid signature, ambiguous JSON, unsupported predicate, malformed receipt, or scope mismatch. Optional `--decision` binds a specific decision ID; `--require-action ALLOW` additionally requires that recorded action. An authentic historical ALLOW is not a fresh deployment authorization: this offline command does not re-evaluate current evidence validity, key revocations or exception expiry, and explicitly returns `current_deployment_authorized: false`.

The standard signature covers DSSE pre-authentication encoding of `application/vnd.in-toto+json` and the exact serialized statement bytes. JSON order does not need to be normalized by an external verifier: verify the decoded payload bytes before parsing. Both standard and URL-safe base64 are accepted. Duplicate JSON keys, non-finite numbers, unexpected envelope fields, oversized envelopes and malformed signatures are rejected. The `keyid` is SHA-256 of the public key's DER SubjectPublicKeyInfo; it is a key selection hint, never a source of trust.

## Key and transparency boundaries

Keep the release signing key in the control plane's managed secret boundary, separately from observer keys, runtime targets and runner identities. Configure a stable trusted public key for consumers and retain old public keys for historical verification. The library generates no fallback signing key and embeds no private key in a receipt.

The current implementation is a key-based DSSE profile. It does not claim Fulcio keyless signing, Rekor inclusion, a trusted signing timestamp, Sigstore bundle validation, independent certification or production deployment. [Sigstore verification](https://docs.sigstore.dev/cosign/verifying/verify/) adds certificate identity and transparency requirements that must be implemented and tested before those claims are made. Publishing customer security predicates into a public transparency log additionally requires an explicit data-handling decision; it is not performed by this verifier.

Local security tests cover independent standard Ed25519 verification, deterministic signing, native SHA binding, tenant/system/candidate/decision mismatch, untrusted keys, tampering, duplicate-key parsing, base64 variants, malformed metadata, exception preservation and CLI exit semantics. Live issuer configuration, managed key rotation, external consumer acceptance and transparency-log acceptance remain separate deployment criteria.
