export type VerificationResult = {ok: boolean; detail: string; keyid?: string; keyStatus?: string};

const decode = (value: string) => {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
  return bytes;
};
const encode = (value: string) => new TextEncoder().encode(value);
const hex = (buffer: ArrayBuffer) => Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
function concat(...parts: Uint8Array[]) {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}
const OFFLINE = 'This browser cannot verify Ed25519 signatures. Use the offline verifier: threatveil verify-passport.';

/**
 * Verify a DSSE/in-toto envelope against a published trust directory, in the browser.
 * This establishes authenticity at issue time only. It never establishes current status.
 */
export async function verifyEnvelope(envelope: unknown, directory: Record<string, unknown>): Promise<VerificationResult> {
  const value = envelope as {payloadType?: string; payload?: string; signatures?: {keyid?: string; sig?: string}[]} | null;
  const signature = value?.signatures?.[0];
  if (!value?.payload || !value.payloadType || value.signatures?.length !== 1 || !signature?.keyid || !signature.sig) {
    return {ok: false, detail: 'This is not a single-signature DSSE envelope.'};
  }
  const keys = Array.isArray(directory.keys) ? directory.keys as Record<string, unknown>[] : [];
  const entry = keys.find(key => key.keyid === signature.keyid);
  if (!entry) return {ok: false, detail: 'The signing key is not listed in the published trust directory.'};
  const keyStatus = String(entry.status);
  if (keyStatus === 'REVOKED') return {ok: false, detail: 'The signing key is revoked; nothing it signed is trusted.', keyid: signature.keyid, keyStatus};
  if (!globalThis.crypto?.subtle) return {ok: false, detail: OFFLINE};
  const der = decode(String(entry.public_key_pem || '').replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''));
  if (hex(await crypto.subtle.digest('SHA-256', der.slice(der.length - 32))) !== signature.keyid) {
    return {ok: false, detail: 'The directory key does not match the signature key identifier.'};
  }
  let key: CryptoKey;
  try { key = await crypto.subtle.importKey('spki', der, {name: 'Ed25519'}, false, ['verify']); }
  catch { return {ok: false, detail: OFFLINE}; }
  const payload = decode(value.payload);
  const type = encode(value.payloadType);
  const pae = concat(encode(`DSSEv1 ${type.length} `), type, encode(` ${payload.length} `), payload);
  if (!await crypto.subtle.verify({name: 'Ed25519'}, key, decode(signature.sig), pae)) {
    return {ok: false, detail: 'The signature does not match this record. It may have been altered.', keyid: signature.keyid, keyStatus};
  }
  try {
    const predicate = JSON.parse(new TextDecoder().decode(payload))?.predicate ?? {};
    const signedAt = Date.parse(predicate.issued_at ?? predicate.not_before);
    const from = Date.parse(String(entry.valid_from));
    const until = entry.valid_until ? Date.parse(String(entry.valid_until)) : Infinity;
    if (!(signedAt >= from && signedAt < until)) {
      return {ok: false, detail: 'The record was signed outside this key’s validity window.', keyid: signature.keyid, keyStatus};
    }
  } catch { return {ok: false, detail: 'The signed statement is unreadable.'}; }
  return {ok: true, detail: 'Authentic', keyid: signature.keyid, keyStatus};
}
