// Checking an OpenTimestamps receipt (SPEC §8.3): a path of hash operations from the anchored hash to the Merkle
// root of a Bitcoin block. The path is checked here, offline. The last step — that the block of that height has
// that Merkle root, and when it was mined — needs the block's header, which the caller may supply; without it the
// result says exactly what is left to compare. It reads untrusted input.

import { concat, equal, hex } from '../bytes.ts';
import { sha256 } from '../hash.ts';

/** What a Bitcoin block header says, as far as a receipt needs. */
export interface BlockHeader {
  /** The Merkle root as block explorers show it (hex, the byte order reversed from the header's). */
  merkleRoot: string;
  /** The block's time, in seconds since 1970. */
  time: number;
}
/** A source of Bitcoin block headers by height; null when it has none for that height. */
export type Headers = (height: number) => Promise<BlockHeader | null>;

export type OtsResult =
  | { status: 'held'; time: number; height: number }
  | { status: 'failed'; reason: string }
  /** The path checks out; one comparison is left for the reader. */
  | { status: 'needs-header'; height: number; merkleRoot: string }
  | { status: 'pending'; calendars: string[] }
  | { status: 'unchecked'; reason: string };

const MAGIC = Uint8Array.of(0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94);
const BITCOIN = '0588960d73d71901';
const PENDING = '83dfe30d2ef90c8e';
/** Limits on what is read: a message never grows past this, a proof never has more steps or branches than these. */
const MAX_MESSAGE = 4096;
const MAX_STEPS = 10_000;

class Malformed extends Error {}
class Unsupported extends Error {}

class Reader {
  at = 0;
  readonly bytes: Uint8Array<ArrayBuffer>;
  constructor(bytes: Uint8Array<ArrayBuffer>) { this.bytes = bytes; }
  get done() { return this.at >= this.bytes.length; }
  byte(): number {
    if (this.at >= this.bytes.length) throw new Malformed('cut short');
    return this.bytes[this.at++]!;
  }
  take(n: number): Uint8Array<ArrayBuffer> {
    if (n < 0 || this.at + n > this.bytes.length) throw new Malformed('cut short');
    const out = this.bytes.subarray(this.at, this.at + n);
    this.at += n;
    return out;
  }
  varint(): number {
    let value = 0;
    let shift = 1;
    for (let i = 0; i < 8; i++) {
      const b = this.byte();
      value += (b & 0x7f) * shift;
      if (!(b & 0x80)) return value;
      shift *= 128;
    }
    throw new Malformed('a number too large');
  }
  varbytes(max = MAX_MESSAGE): Uint8Array<ArrayBuffer> {
    const n = this.varint();
    if (n > max) throw new Malformed('too long');
    return this.take(n);
  }
}

interface Attestation { kind: 'bitcoin'; height: number; message: Uint8Array }
/** A calendar's promise still to be kept: ask `calendar` about `commitment`; its answer continues the path. */
export interface PendingRequest {
  calendar: string;
  /** The message the path reaches at the pending attestation: what the calendar committed to. */
  commitment: Uint8Array<ArrayBuffer>;
  /** The operations from the anchored hash to the commitment, serialized as in a receipt. */
  path: Uint8Array<ArrayBuffer>;
}
interface Found { bitcoin: Attestation[]; pending: string[]; requests: PendingRequest[]; steps: number }

function varint(n: number): Uint8Array<ArrayBuffer> {
  const out: number[] = [];
  do { let b = n % 128; n = Math.floor(n / 128); if (n) b |= 0x80; out.push(b); } while (n);
  return Uint8Array.from(out);
}

/** Walk a timestamp from `message`, applying each operation, and collect what it attests. */
async function walk(r: Reader, message: Uint8Array<ArrayBuffer>, found: Found, path: Uint8Array<ArrayBuffer> = new Uint8Array(0)): Promise<void> {
  // (a timestamp is one or more branches: every branch but the last is marked 0xff)
  for (;;) {
    if (++found.steps > MAX_STEPS) throw new Malformed('too many steps');
    let tag = r.byte();
    const more = tag === 0xff;
    if (more) tag = r.byte();
    if (tag === 0x00) {
      const kind = hex(r.take(8));
      const payload = new Reader(r.varbytes(8192));
      if (kind === BITCOIN) found.bitcoin.push({ kind: 'bitcoin', height: payload.varint(), message });
      else if (kind === PENDING) {
        const calendar = new TextDecoder().decode(payload.varbytes(1000)).replace(/[^\x21-\x7e]/g, '');
        found.pending.push(calendar);
        found.requests.push({ calendar, commitment: message, path });
      }
      // (an attestation of a kind this verifier doesn't know is passed over)
    } else {
      let next: Uint8Array<ArrayBuffer>;
      let op: Uint8Array<ArrayBuffer>;
      if (tag === 0x08) { next = await sha256(message); op = Uint8Array.of(0x08); }
      else if (tag === 0xf0 || tag === 0xf1) {
        const arg = r.varbytes();
        next = tag === 0xf0 ? concat(message, arg) : concat(arg, message);
        op = concat(Uint8Array.of(tag), varint(arg.length), arg);
      }
      else throw new Unsupported('the receipt uses an operation this verifier does not handle');
      if (next.length > MAX_MESSAGE) throw new Malformed('too long');
      await walk(r, next, found, concat(path, op));
    }
    if (!more) return;
  }
}

/** A `.ots` file's digest and its timestamp bytes (what a record stores as the proof); null when it isn't one for SHA-256. */
export function splitOtsFile(file: Uint8Array<ArrayBuffer>): { digest: Uint8Array<ArrayBuffer>; proof: Uint8Array<ArrayBuffer> } | null {
  try {
    const r = new Reader(file);
    if (!equal(r.take(MAGIC.length), MAGIC) || r.varint() !== 1 || r.byte() !== 0x08) return null;
    const digest = r.take(32);
    return { digest, proof: file.subarray(r.at) };
  } catch { return null; }
}

/**
 * Check a receipt for `hash` (32 bytes). `proof` is the serialized timestamp: its operations and attestations,
 * without a `.ots` file's header and digest.
 */
export async function verifyOpenTimestamps(proof: Uint8Array<ArrayBuffer>, hash: Uint8Array<ArrayBuffer>, headers?: Headers): Promise<OtsResult> {
  const found: Found = { bitcoin: [], pending: [], requests: [], steps: 0 };
  try {
    const r = new Reader(proof);
    await walk(r, hash, found);
    if (!r.done) return { status: 'failed', reason: 'the receipt cannot be read' };
  } catch (e) {
    if (e instanceof Unsupported) return { status: 'unchecked', reason: e.message };
    return { status: 'failed', reason: 'the receipt cannot be read' };
  }
  // The earliest block wins: it is the strongest statement the receipt makes.
  const blocks = found.bitcoin.filter((a) => a.message.length === 32).sort((a, b) => a.height - b.height);
  if (!blocks.length) {
    return found.pending.length ? { status: 'pending', calendars: found.pending } : { status: 'unchecked', reason: 'the receipt attests nothing this verifier knows' };
  }
  let first: OtsResult | null = null;
  for (const b of blocks) {
    // (a header holds the root in the opposite byte order from the one people read)
    const merkleRoot = hex(Uint8Array.from(b.message).reverse());
    const header = headers ? await headers(b.height).catch(() => null) : null;
    if (!header) { first ??= { status: 'needs-header', height: b.height, merkleRoot }; continue; }
    if (header.merkleRoot.toLowerCase() !== merkleRoot) return { status: 'failed', reason: `the receipt does not match Bitcoin block ${b.height}` };
    return { status: 'held', time: header.time * 1000, height: b.height };
  }
  return first!;
}

/**
 * A pending receipt's open requests (SPEC §8.1, `replaces`): for each calendar that promised to reach Bitcoin, what to
 * ask it about. Empty when there are none, or the receipt can't be read.
 */
export async function pendingRequests(proof: Uint8Array<ArrayBuffer>, hash: Uint8Array<ArrayBuffer>): Promise<PendingRequest[]> {
  const found: Found = { bitcoin: [], pending: [], requests: [], steps: 0 };
  try {
    const r = new Reader(proof);
    await walk(r, hash, found);
    return r.done ? found.requests : [];
  } catch { return []; }
}

/**
 * The completed receipt: the path to a pending request's commitment followed by the calendar's answer (its timestamp
 * from the commitment). Null unless the result reaches a Bitcoin block: an answer that is still pending, or that
 * doesn't read, completes nothing. The completed receipt carries only this calendar's branch.
 */
export async function completeOpenTimestamps(request: PendingRequest, answer: Uint8Array<ArrayBuffer>, hash: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer> | null> {
  const proof = concat(request.path, answer);
  const r = await verifyOpenTimestamps(proof, hash);
  return r.status === 'needs-header' || r.status === 'held' ? proof : null;
}
