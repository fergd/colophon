// What a host supplies (SPEC and the brief's ground rules): the core touches no file, key, network or clock itself.
// Each port is small enough to implement over a file, the Keychain, a fetch, or a test double.

import type { KeyAlg } from './core/entries.ts';

/** One chain's lines. Only ever appended to; a host never rewrites what is there. */
export interface Storage {
  /** Everything stored so far, as text ('' when nothing is). */
  read(): Promise<string>;
  /** Add `text` to the end, durably, in one write. */
  append(text: string): Promise<void>;
}

/** The device's signing key. The private half never leaves the signer. */
export interface Signer {
  alg: KeyAlg;
  /** The public key: 65 bytes (0x04 ‖ X ‖ Y) for P-256, 32 for Ed25519. */
  publicKey(): Promise<Uint8Array>;
  /** The signature over `message`: 64 bytes (`r ‖ s` for P-256). */
  sign(message: Uint8Array): Promise<Uint8Array>;
}

/** An outside timestamp service. It is sent a bare hash and nothing else. */
export interface AnchorService {
  scheme: string;
  /** Where the request goes (kept in the record as `via`); optional. */
  via?: string;
  /** A receipt for `hash` (32 bytes), as the scheme's proof bytes. May reject: nothing is recorded then. */
  submit(hash: Uint8Array): Promise<Uint8Array>;
}

export interface Clock {
  /** Milliseconds since 1970 on the computer's clock. */
  now(): number;
  /** Milliseconds on a clock that never goes back and doesn't follow changes to the computer's clock. */
  monotonic(): number;
}

/** Random bytes (identifiers, secrets). Default: WebCrypto's. */
export type Random = (length: number) => Uint8Array;
