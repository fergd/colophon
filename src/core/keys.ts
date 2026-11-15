// Checking a seal's signature (SPEC §7.1): ECDSA P-256 (what a Secure Enclave or a TPM holds) and Ed25519 (a key in
// software), both through WebCrypto. Nothing here says whose key it is.

import { hex, unbase64url } from './bytes.ts';
import type { KeyRef } from './entries.ts';
import { sha256 } from './hash.ts';

/** A key's fingerprint: SHA-256 of its public bytes, in hex. Null when `pub` isn't base64url. */
export async function fingerprint(key: KeyRef): Promise<string | null> {
  const pub = unbase64url(key.pub);
  return pub ? hex(await sha256(pub)) : null;
}

/** Whether `sig` (64 bytes) is `key`'s signature over `message`. False for anything malformed or unsupported. */
export async function verifySignature(key: KeyRef, message: Uint8Array<ArrayBuffer>, sig: Uint8Array<ArrayBuffer>): Promise<boolean> {
  const pub = unbase64url(key.pub);
  if (!pub || sig.length !== 64) return false;
  try {
    if (key.alg === 'ecdsa-p256-sha256') {
      if (pub.length !== 65 || pub[0] !== 4) return false;
      const k = await crypto.subtle.importKey('raw', pub, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k, sig, message);
    }
    if (key.alg === 'ed25519') {
      if (pub.length !== 32) return false;
      const k = await crypto.subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']);
      return await crypto.subtle.verify({ name: 'Ed25519' }, k, sig, message);
    }
  } catch { /* an unsupported or malformed key verifies nothing */ }
  return false;
}
