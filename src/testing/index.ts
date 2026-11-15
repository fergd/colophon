// Stand-ins for the ports, for tests and examples: storage in memory, a key in software, an anchor that issues
// receipts no verifier accepts, and a clock that is set by hand. Not for a real record.

import { concat, utf8 } from '../core/bytes.ts';
import type { KeyAlg } from '../core/entries.ts';
import type { AnchorService, Clock, Random, Signer, Storage } from '../ports.ts';

export class MemoryStorage implements Storage {
  text: string;
  /** Set to make the next writes fail. */
  failing = false;
  constructor(text = '') { this.text = text; }
  read(): Promise<string> { return Promise.resolve(this.text); }
  append(more: string): Promise<void> {
    if (this.failing) return Promise.reject(new Error('the storage is failing'));
    this.text += more;
    return Promise.resolve();
  }
  /** The stored lines, without the final empty one. */
  get lines(): string[] { return this.text.split('\n').filter(Boolean); }
}

/** A key held in memory. `softwareSigner('ed25519')` or `softwareSigner('ecdsa-p256-sha256')`. */
export async function softwareSigner(alg: KeyAlg = 'ed25519'): Promise<Signer> {
  const params = alg === 'ed25519' ? { name: 'Ed25519' } : { name: 'ECDSA', namedCurve: 'P-256' };
  const pair = await crypto.subtle.generateKey(params, false, ['sign', 'verify']) as CryptoKeyPair;
  const pub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  return {
    alg,
    publicKey: () => Promise.resolve(pub),
    sign: async (message) => new Uint8Array(await crypto.subtle.sign(alg === 'ed25519' ? { name: 'Ed25519' } : { name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new Uint8Array(message))),
  };
}

/** A clock set by hand: `advance(ms)` moves both clocks; `set(t)` moves only the computer's (a clock changed). */
export class TestClock implements Clock {
  private wall: number;
  private mono = 1_000;
  constructor(start = Date.UTC(2026, 0, 5, 9, 0, 0)) { this.wall = start; }
  now(): number { return this.wall; }
  monotonic(): number { return this.mono; }
  advance(ms: number): void { this.wall += ms; this.mono += ms; }
  set(t: number): void { this.wall = t; }
}

/** An anchor that answers with bytes naming the hash and its own clock: a scheme ("test") no verifier checks. */
export class FakeAnchor implements AnchorService {
  scheme = 'test';
  via = 'test:fake';
  submitted: Uint8Array[] = [];
  /** Set to make requests fail, as a service that can't be reached. */
  down = false;
  private readonly clock: Clock;
  constructor(clock: Clock) { this.clock = clock; }
  submit(hash: Uint8Array): Promise<Uint8Array> {
    if (this.down) return Promise.reject(new Error('the service cannot be reached'));
    this.submitted.push(hash);
    return Promise.resolve(concat(utf8(`test-receipt:${this.clock.now()}:`), hash));
  }
}

/** Random bytes from a seed, so a test's identifiers are the same on every run. */
export function seededRandom(seed = 1): Random {
  let s = seed >>> 0 || 1;
  return (length) => {
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i++) { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; out[i] = s & 0xff; }
    return out;
  };
}
