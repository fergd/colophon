// Writing one device's chain (SPEC §2–§9): each entry a canonical line that names the hash of the line before it.
// A chain is only ever appended to. Everything a platform does (the file, the key, the clock, the timestamp
// service) comes in through the ports; a failure of any of them rejects the call and leaves the chain as it was.

import { base64url, hex, unhex, utf8 } from './bytes.ts';
import { canonical, parseLine, type Json } from './canonical.ts';
import {
  sealMessage, STEP_MS, VERSION,
  type Activity, type ActivityRow, type Anchor, type Body, type ChainStart, type Change, type Checkpoint, type Extension,
  type Gap, type KeyChange, type KeyRef, type RecordStart, type Sees, type SessionEnd, type SessionStart,
} from './entries.ts';
import { entryHash, HASH } from './hash.ts';
import { merkleRoot } from './merkle.ts';
import type { AnchorService, Clock, Random, Signer, Storage } from '../ports.ts';

export interface ChainPorts {
  storage: Storage;
  clock: Clock;
  /** The device's key; without one the chain is unsigned and `seal` does nothing. */
  signer?: Signer;
  random?: Random;
}

/** An entry as it was written. */
export interface Written {
  seq: number;
  hash: string;
  line: string;
}

const webRandom: Random = (length) => crypto.getRandomValues(new Uint8Array(length));
/** A new identifier for a record or a chain: 128 random bits in hex (SPEC §4). */
export const newId = (random: Random = webRandom): string => hex(random(16));
/** A new secret for a chain's part salts: 32 random bytes (SPEC §6.3). It never goes in the record. */
export const newSecret = (random: Random = webRandom): Uint8Array => random(32);

async function keyRef(signer: Signer | undefined): Promise<KeyRef | undefined> {
  return signer ? { alg: signer.alg, pub: base64url(await signer.publicKey()) } : undefined;
}

type StartOf<T> = Omit<T, 'type' | 'record' | 'chain' | 'hash' | 'key'>;

export class Chain {
  readonly record: string;
  readonly chain: string;
  private readonly ports: ChainPorts;
  private seq: number;
  private prev: string | null;
  private signer: Signer | undefined;
  /** The monotonic clock at this session's start; null outside a session. */
  private sessionAt: number | null = null;
  /** Appends run one after another. */
  private queue: Promise<unknown> = Promise.resolve();

  private constructor(ports: ChainPorts, ids: { record: string; chain: string }, head: { seq: number; prev: string | null }) {
    this.ports = ports;
    this.record = ids.record;
    this.chain = ids.chain;
    this.seq = head.seq;
    this.prev = head.prev;
    this.signer = ports.signer;
  }

  /** A record's founding chain: its first entry says how the book began (SPEC §5.1). The storage must be empty. */
  static async begin(ports: ChainPorts, start: StartOf<RecordStart> & { record?: string }): Promise<Chain> {
    if (await ports.storage.read()) throw new Error('this chain has entries already');
    const { record, ...rest } = start;
    const c = new Chain(ports, { record: record ?? newId(ports.random), chain: newId(ports.random) }, { seq: 0, prev: null });
    const key = await keyRef(ports.signer);
    await c.append({ type: 'record.start', record: c.record, chain: c.chain, hash: HASH, ...(key ? { key } : {}), ...rest });
    return c;
  }

  /** Another chain of an existing record: another device, or this one beginning again (SPEC §5.2). */
  static async join(ports: ChainPorts, start: StartOf<ChainStart> & { record: string }): Promise<Chain> {
    if (await ports.storage.read()) throw new Error('this chain has entries already');
    const { record, ...rest } = start;
    const c = new Chain(ports, { record, chain: newId(ports.random) }, { seq: 0, prev: null });
    const key = await keyRef(ports.signer);
    await c.append({ type: 'chain.start', record, chain: c.chain, hash: HASH, ...(key ? { key } : {}), ...rest });
    return c;
  }

  /**
   * A chain already in storage, ready for more. A write that was cut short is closed with a line feed and recorded
   * as a gap (SPEC §9); nothing already written is changed. Throws when the chain can't be read: the host then
   * begins a new chain (`join`, why "unreadable") and leaves this one as it is.
   */
  static async open(ports: ChainPorts): Promise<Chain> {
    const stored = await ports.storage.read();
    if (!stored) throw new Error('there is no chain here yet');
    const lines = stored.split('\n');
    const fragment = lines.pop()!; // ('' when the text ends with a line feed)
    let head: { seq: number; hash: string } | null = null;
    let ids: { record: string; chain: string } | null = null;
    let afterHead: string | null = null; // (the last line after the head that isn't an entry)
    for (const line of lines) {
      const e = parseLine(line);
      const ok = e && e.v === VERSION && typeof e.seq === 'number' && typeof e.type === 'string' && e.seq === (head ? head.seq + 1 : 0);
      if (!ok) { afterHead = line; continue; }
      if (e.seq === 0) {
        if (typeof e.record !== 'string' || typeof e.chain !== 'string') throw new Error('the chain’s first entry can’t be read');
        ids = { record: e.record, chain: e.chain };
      }
      head = { seq: e.seq as number, hash: await entryHash(line) };
      afterHead = null;
    }
    if (!head || !ids) throw new Error('the chain’s first entry can’t be read');
    const c = new Chain(ports, ids, { seq: head.seq + 1, prev: head.hash });
    const torn = fragment || afterHead;
    if (torn !== null && torn !== '') {
      if (fragment) await ports.storage.append('\n');
      await c.append({ type: 'gap', why: 'torn', torn: await entryHash(torn) });
    }
    return c;
  }

  /** The last entry written: where the chain stands. */
  get head(): { seq: number; hash: string } {
    if (this.prev === null) throw new Error('the chain has no entries');
    return { seq: this.seq - 1, hash: this.prev };
  }

  /** A reference to this chain's head, for another chain's `sees` (SPEC §4). */
  get seen(): Sees {
    return { chain: this.chain, ...this.head };
  }

  /** Add an entry of any type. The envelope (version, position, previous hash, times) is filled in here. */
  append(body: Body | Extension): Promise<Written> {
    const run = this.queue.then(() => this.write(body));
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async write(body: Body | Extension): Promise<Written> {
    const { clock, storage } = this.ports;
    const entry: { [k: string]: unknown } = { ...body, v: VERSION, seq: this.seq, t: clock.now() };
    if (this.prev !== null) entry.prev = this.prev;
    if (this.sessionAt !== null) entry.m = Math.max(0, Math.round(clock.monotonic() - this.sessionAt));
    const line = canonical(entry as Json);
    const hash = await entryHash(line);
    await storage.append(`${line}\n`);
    const written = { seq: this.seq, hash, line };
    this.seq++;
    this.prev = hash;
    return written;
  }

  sessionStart(start: Omit<SessionStart, 'type'>): Promise<Written> {
    return this.enqueue(async () => {
      this.sessionAt = this.ports.clock.monotonic();
      return this.write({ type: 'session.start', ...start });
    });
  }

  sessionEnd(why: SessionEnd['why']): Promise<Written> {
    return this.enqueue(async () => {
      const w = await this.write({ type: 'session.end', why });
      this.sessionAt = null;
      return w;
    });
  }

  /** Counts for one or more intervals (SPEC §5.4). `from` is the first interval's start. */
  activity(from: number, rows: ActivityRow[], ctx?: string): Promise<Written> {
    const a: Activity = { type: 'activity', step: STEP_MS, from: Math.floor(from / STEP_MS) * STEP_MS, rows, ...(ctx ? { ctx } : {}) };
    return this.append(a);
  }

  change(change: Omit<Change, 'type'>): Promise<Written> {
    return this.append({ type: 'change', ...change });
  }

  gap(gap: Omit<Gap, 'type'>): Promise<Written> {
    return this.append({ type: 'gap', ...gap });
  }

  /**
   * A checkpoint (SPEC §6): the saved file's hash and, when the host cuts the manuscript into parts, the root over
   * their leaf hashes (`partLeaf`; a host may cache the leaves of parts that haven't changed).
   */
  async checkpoint(at: { file: Uint8Array; words: number; leaves?: Uint8Array[]; changed?: number }): Promise<Written> {
    const root = at.leaves ? await merkleRoot(at.leaves) : null;
    const c: Checkpoint = {
      type: 'checkpoint', file: hex(at.file), words: at.words,
      ...(at.leaves ? { parts: at.leaves.length } : {}), ...(root ? { root: hex(root) } : {}),
      ...(at.changed !== undefined ? { changed: at.changed } : {}),
    };
    return this.append(c);
  }

  /** A seal (SPEC §7.2): this device's signature over the chain so far. Null when the chain has no key. */
  seal(): Promise<Written | null> {
    return this.enqueue(() => this.sealWith(this.signer, false));
  }

  private async sealWith(signer: Signer | undefined, named: boolean): Promise<Written | null> {
    if (!signer || this.prev === null) return null;
    const { clock } = this.ports;
    // (the times are read once: what is signed is exactly what is written)
    const t = clock.now();
    const m = this.sessionAt !== null ? Math.max(0, Math.round(clock.monotonic() - this.sessionAt)) : undefined;
    const key = named ? hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(await signer.publicKey())))) : undefined;
    const sig = await signer.sign(utf8(sealMessage({ prev: this.prev, seq: this.seq, t, m, key })));
    if (sig.length !== 64) throw new Error('a signature is 64 bytes');
    const entry: { [k: string]: Json } = { type: 'seal', sig: base64url(sig), v: VERSION, seq: this.seq, t, prev: this.prev };
    if (m !== undefined) entry.m = m;
    if (key) entry.key = key;
    const line = canonical(entry);
    const hash = await entryHash(line);
    await this.ports.storage.append(`${line}\n`);
    const written = { seq: this.seq, hash, line };
    this.seq++;
    this.prev = hash;
    return written;
  }

  /**
   * A time anchor (SPEC §8): the hash of `target` (default: the head) goes to the service, and its receipt is
   * stored. Entries may be written while the request is out. Rejects, writing nothing, when the service does.
   */
  async anchor(service: AnchorService, target: { seq: number; hash: string } = this.head, replaces?: number): Promise<Written> {
    const bytes = unhex(target.hash);
    if (!bytes || bytes.length !== 32) throw new Error('an anchor’s target is an entry hash');
    const proof = await service.submit(bytes);
    const a: Anchor = {
      type: 'anchor', scheme: service.scheme, target: { seq: target.seq, hash: target.hash }, proof: base64url(proof),
      ...(service.via ? { via: service.via } : {}), ...(replaces !== undefined ? { replaces } : {}),
    };
    return this.append(a);
  }

  /**
   * A change of key (SPEC §7.3): the new key is named, the old key signs the change (when it still can), then the
   * new key signs. From here the chain's seals are the new key's.
   */
  keyChange(next: Signer, why: KeyChange['why'], oldSigns = true): Promise<Written> {
    return this.enqueue(async () => {
      const old = this.signer;
      const w = await this.write({ type: 'key.change', key: (await keyRef(next))!, why });
      if (oldSigns && old) await this.sealWith(old, true);
      this.signer = next;
      await this.sealWith(next, false);
      return w;
    });
  }

  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn);
    this.queue = run.catch(() => undefined);
    return run;
  }
}
