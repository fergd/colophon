// SHA-256 and HMAC-SHA-256 through WebCrypto, which browsers and Node both have. Version 0 names one hash
// algorithm, "sha-256" (SPEC §5.1).

import { hex, utf8 } from './bytes.ts';

export const HASH = 'sha-256';

export async function sha256(bytes: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

/** The entry hash of a line (SPEC §2): SHA-256 of its bytes, without the line feed, in hex. */
export async function entryHash(line: string): Promise<string> {
  return hex(await sha256(utf8(line)));
}

export async function hmacSha256(key: Uint8Array<ArrayBuffer>, message: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, message));
}
