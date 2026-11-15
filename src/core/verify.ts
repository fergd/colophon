// Verification (SPEC §10): read a record's lines as untrusted, rebuild its chains from the hashes, check every
// seal and receipt, work out what the outside timestamps bound, add up what the record claims, and say what was
// checked, what held, what failed and where, and what could not be checked. A structured result, never a verdict.

import { base64url, hex, unbase64url, unhex, utf8 } from './bytes.ts';
import { isCanonical, parseLine, type Json } from './canonical.ts';
import { sealMessage, VERSION, type KeyRef } from './entries.ts';
import { entryHash, sha256 } from './hash.ts';
import { fingerprint, verifySignature } from './keys.ts';
import { verifyOpenTimestamps, type Headers } from './anchors/opentimestamps.ts';
import { verifyRfc3161 } from './anchors/rfc3161.ts';
import { rootBytes } from './anchors/roots.ts';

export const VERIFIER = '0.1.0';
/** How far a claimed time may lie outside its anchored bounds before it is reported (SPEC §8.4). */
export const CLOCK_TOLERANCE_MS = 5 * 60_000;
/** How far a Bitcoin block's time may be from the time it was mined. */
export const BLOCK_SLACK_MS = 2 * 60 * 60_000;

export type Status = 'held' | 'failed' | 'unchecked' | 'note';

/** One thing found: what, how it stands, and where. `code` is stable; the sentence for it is in `describe`. */
export interface Finding {
  status: Status;
  code: string;
  chain?: string;
  seq?: number;
  file?: string;
  line?: number;
  data?: { [k: string]: string | number };
}

export interface ChainReport {
  chain: string;
  record: string;
  /** `record.start` (with how the book began) or `chain.start` (with why this chain began). */
  began: { type: string; how?: string; why?: string; words: number };
  entries: number;
  /** Claimed times of the first and last entries. */
  first: number;
  last: number;
  /** The hash of the last entry. */
  head: string;
  /** Seals that checked out, and the entries after the last of them. */
  seals: number;
  unsealed: number;
  keys: { fingerprint: string; alg: string; from: number }[];
  /** Entries after the target of the last verified anchor. */
  unanchored: number;
}

export interface AnchorReport {
  chain: string;
  seq: number;
  target: number;
  scheme: string;
  status: 'held' | 'failed' | 'unchecked' | 'pending' | 'needs-header';
  /** The receipt's time (ms), when it gives one. */
  time?: number;
  authority?: string;
  detail?: string;
  height?: number;
  merkleRoot?: string;
}

export interface GapReport { chain: string; seq: number; why: string; from?: number; to?: number; n?: number }

export interface Result {
  /** Set when the record uses a version this verifier doesn't know: nothing else was checked. */
  refused?: { version: number; supported: number };
  format: { versions: number[]; verifier: string };
  record: string | null;
  chains: ChainReport[];
  anchors: AnchorReport[];
  time: {
    /** By the computer's clock. */
    claimedFrom: number | null;
    claimedTo: number | null;
    /** From verified receipts. */
    anchoredFrom: number | null;
    anchoredTo: number | null;
    /** The longest stretch of claimed time with no verified anchor inside it. */
    longestUnanchored: { ms: number; from: number; to: number; chain: string } | null;
    disagreements: { chain: string; seq: number; ms: number }[];
  };
  totals: {
    /** Words added and removed by each source, as the record claims. */
    sources: { [source: string]: [number, number] };
    pastes: { count: number; words: number; largest: number; sizes: number[] };
    changes: { [op: string]: { count: number; added: number; removed: number } };
    sessions: number;
    /** True when a chain failed part-way: the totals cover only what came before. */
    partial: boolean;
  };
  gaps: GapReport[];
  manuscript: { given: false } | { given: true; match: 'last' | 'earlier' | 'none'; chain?: string; seq?: number; t?: number; noLaterThan?: number };
  unknown: { [type: string]: number };
  findings: Finding[];
  failed: boolean;
}

export interface VerifyInput {
  files: { name: string; text: string }[];
  /** The manuscript file's bytes, to compare with the checkpoints. */
  manuscript?: Uint8Array<ArrayBuffer>;
  /** An entry hash the reader was given earlier: the record should contain it. */
  expectHead?: string;
  /** A key fingerprint the reader was given: the record should be signed by it. */
  expectKey?: string;
  /** A source of Bitcoin block headers, to finish checking OpenTimestamps receipts. */
  bitcoin?: Headers;
  /** Timestamp authorities' root certificates (DER). Default: this verifier's list. */
  roots?: Uint8Array<ArrayBuffer>[];
}

type Obj = { [k: string]: Json };
interface Line { file: string; n: number; text: string; hash: string; entry: Obj | null }
interface E extends Line { entry: Obj; seq: number; t: number; type: string; prev: string | null; chain?: string }

const CORE = new Set(['record.start', 'chain.start', 'session.start', 'session.end', 'activity', 'change', 'checkpoint', 'seal', 'anchor', 'gap', 'key.change']);
const HEX64 = /^[0-9a-f]{64}$/;
const ID = /^[0-9a-f]{32}$/;
const int = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v);
const count = (v: unknown): number => (int(v) && v >= 0 ? v : 0);
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);
const obj = (v: unknown): Obj | null => (v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : null);
/** A name from the record, safe to show: short, printable. */
const label = (v: unknown): string => (typeof v === 'string' ? v.replace(/[^\x21-\x7e]/g, '').slice(0, 64) : '');

function keyOf(v: unknown): KeyRef | null {
  const k = obj(v);
  return k && (k.alg === 'ecdsa-p256-sha256' || k.alg === 'ed25519') && typeof k.pub === 'string' ? { alg: k.alg, pub: k.pub } : null;
}

function empty(): Result {
  return {
    format: { versions: [], verifier: VERIFIER }, record: null, chains: [], anchors: [],
    time: { claimedFrom: null, claimedTo: null, anchoredFrom: null, anchoredTo: null, longestUnanchored: null, disagreements: [] },
    totals: { sources: {}, pastes: { count: 0, words: 0, largest: 0, sizes: [] }, changes: {}, sessions: 0, partial: false },
    gaps: [], manuscript: { given: false }, unknown: {}, findings: [], failed: false,
  };
}

export async function verify(input: VerifyInput): Promise<Result> {
  const r = empty();
  const find = (f: Finding) => { r.findings.push(f); };

  // ── 1. Lines ──
  const lines: Line[] = [];
  const seen = new Set<string>();
  for (const file of input.files) {
    const parts = file.text.split('\n');
    const fragment = parts.pop()!;
    if (fragment) find({ status: 'note', code: 'incomplete-last-line', file: file.name, line: parts.length + 1 });
    for (let i = 0; i < parts.length; i++) {
      const text = parts[i]!;
      if (!text) { find({ status: 'failed', code: 'not-an-entry', file: file.name, line: i + 1 }); continue; }
      const hash = await entryHash(text);
      if (seen.has(hash)) continue; // (the same line supplied twice, in two files)
      seen.add(hash);
      lines.push({ file: file.name, n: i + 1, text, hash, entry: parseLine(text) });
    }
  }

  // ── 2. Versions: anything this verifier doesn't know stops everything ──
  const versions = new Set<number>();
  for (const l of lines) if (l.entry && int(l.entry.v)) versions.add(l.entry.v);
  r.format.versions = [...versions].sort((a, b) => a - b);
  const unknownVersion = r.format.versions.find((v) => v !== VERSION);
  if (unknownVersion !== undefined) {
    r.refused = { version: unknownVersion, supported: VERSION };
    r.failed = true;
    return r;
  }

  // ── 3. Entries, and the chains they form ──
  const entries: E[] = [];
  const others: Line[] = [];
  for (const l of lines) {
    const e = l.entry;
    const prev = e ? str(e.prev) ?? null : null;
    const ok = e && e.v === VERSION && typeof e.type === 'string' && int(e.seq) && e.seq >= 0 && int(e.t)
      && (e.seq === 0 ? e.prev === undefined : !!prev && HEX64.test(prev));
    if (ok) entries.push({ ...l, entry: e, seq: e.seq as number, t: e.t as number, type: e.type as string, prev });
    else others.push(l);
  }
  const children = new Map<string, E[]>();
  for (const e of entries) if (e.prev) children.set(e.prev, [...(children.get(e.prev) ?? []), e]);
  const reached = new Set<E>();
  const chains: E[][] = [];
  for (const start of entries.filter((e) => e.seq === 0)) {
    const chain = [start];
    reached.add(start);
    for (let cur = start; ;) {
      const kids = children.get(cur.hash) ?? [];
      if (!kids.length) break;
      if (kids.length > 1) {
        find({ status: 'failed', code: 'fork', seq: cur.seq, file: kids[1]!.file, line: kids[1]!.n });
        // (the other continuations, and what follows them, are part of the fork: not reported again as broken)
        const stack = kids.slice(1);
        while (stack.length) { const x = stack.pop()!; reached.add(x); stack.push(...(children.get(x.hash) ?? [])); }
      }
      const next = kids[0]!;
      if (next.seq !== cur.seq + 1) find({ status: 'failed', code: 'out-of-step', seq: next.seq, file: next.file, line: next.n });
      chain.push(next);
      reached.add(next);
      cur = next;
    }
    chains.push(chain);
  }
  // Entries that follow nothing given: where a chain was altered, or a stretch is missing.
  const entryHashes = new Set(entries.map((e) => e.hash));
  let detached = 0;
  for (const e of entries) {
    if (reached.has(e) || (e.prev && entryHashes.has(e.prev))) continue;
    find({ status: 'failed', code: 'broken', seq: e.seq, file: e.file, line: e.n });
    detached++;
  }
  if (detached || r.findings.some((f) => f.code === 'fork')) r.totals.partial = true;
  // Lines that aren't entries: a write cut short is named by the gap that follows it; anything else is a failure.
  const torn = new Set(entries.filter((e) => e.type === 'gap' && e.entry.why === 'torn').map((e) => str(e.entry.torn)));
  for (const l of others) if (!torn.has(l.hash)) find({ status: 'failed', code: 'not-an-entry', file: l.file, line: l.n });
  for (const e of entries) if (!isCanonical(e.text)) find({ status: 'note', code: 'not-canonical', file: e.file, line: e.n });

  // ── 4. Each chain ──
  const all = new Map<string, E[]>(); // (by chain id)
  const checkpoints: { chain: string; e: E; file: string }[] = [];
  const knownFiles = new Set<string>();
  const sees: { from: E; chain: string; seq: number; hash: string }[] = [];
  const verified: { chain: string; time: number; slack: number; target: number; seq: number }[] = [];
  const roots = input.roots ?? rootBytes();

  for (const chain of chains) {
    const start = chain[0]!;
    const s = start.entry;
    const id = str(s.chain);
    const record = str(s.record);
    if ((start.type !== 'record.start' && start.type !== 'chain.start') || !id || !ID.test(id) || !record || !ID.test(record)) {
      find({ status: 'failed', code: 'bad-start', file: start.file, line: start.n });
      r.totals.partial = true;
      continue;
    }
    if (s.hash !== 'sha-256') find({ status: 'unchecked', code: 'unknown-hash', chain: id, data: { hash: label(s.hash) } });
    if (all.has(id)) { find({ status: 'failed', code: 'fork', chain: id, seq: 0, file: start.file, line: start.n }); continue; }
    all.set(id, chain);
    for (const e of chain) e.chain = id;
    r.record ??= record;
    if (record !== r.record) { find({ status: 'note', code: 'other-record', chain: id }); continue; }

    const keys: { key: KeyRef; fp: string; from: number }[] = [];
    const addKey = async (k: KeyRef | null, from: number) => {
      const fp = k ? await fingerprint(k) : null;
      if (k && fp) keys.push({ key: k, fp, from });
      return fp;
    };
    await addKey(keyOf(s.key), 0);
    let seals = 0;
    let lastSeal = -1;
    let change: { seq: number; old: string | null; endorsed: boolean } | null = null;
    let session: E | null = null;
    let words: number | null = count(s.words);
    if (str(s.file)) knownFiles.add(s.file as string);
    if (start.type === 'chain.start' && s.why !== 'device') r.gaps.push({ chain: id, seq: 0, why: `chain-${label(s.why) || 'began'}` });

    for (const e of chain) {
      const b = e.entry;
      for (const ref of Array.isArray(b.sees) ? b.sees : []) {
        const o = obj(ref);
        if (o && str(o.chain) && int(o.seq) && str(o.hash)) sees.push({ from: e, chain: o.chain as string, seq: o.seq, hash: o.hash as string });
      }
      switch (e.type) {
        case 'record.start': case 'chain.start': break;
        case 'session.start': {
          if (session) r.gaps.push({ chain: id, seq: session.seq, why: 'session-not-ended', from: session.t });
          session = e;
          r.totals.sessions++;
          words = count(b.words);
          break;
        }
        case 'session.end': session = null; break;
        case 'activity': {
          for (const row of Array.isArray(b.rows) ? b.rows : []) {
            const w = obj(obj(row)?.w);
            for (const [source, d] of Object.entries(w ?? {})) {
              if (!Array.isArray(d)) continue;
              const name = label(source) || 'unnamed';
              const sum = (r.totals.sources[name] ??= [0, 0]);
              sum[0] += count(d[0]); sum[1] += count(d[1]);
              if (!b.ctx && words !== null) words += count(d[0]) - count(d[1]);
            }
            for (const size of Array.isArray(obj(row)?.pastes) ? (obj(row)!.pastes as Json[]) : []) {
              const n = count(size);
              r.totals.pastes.sizes.push(n);
            }
          }
          break;
        }
        case 'change': {
          const op = label(b.op) || 'unnamed';
          const d = Array.isArray(b.w) ? b.w : [];
          const sum = (r.totals.changes[op] ??= { count: 0, added: 0, removed: 0 });
          sum.count++; sum.added += count(d[0]); sum.removed += count(d[1]);
          // (a change made outside is already in the words the session opened on)
          if (words !== null && op !== 'outside') words += count(d[0]) - count(d[1]);
          if (op === 'outside') { r.gaps.push({ chain: id, seq: e.seq, why: 'changed-outside', from: e.t, n: count(d[0]) + count(d[1]) }); }
          break;
        }
        case 'checkpoint': {
          const file = str(b.file);
          if (file && HEX64.test(file)) { checkpoints.push({ chain: id, e, file }); knownFiles.add(file); }
          else find({ status: 'failed', code: 'bad-checkpoint', chain: id, seq: e.seq, file: e.file, line: e.n });
          if (words !== null && int(b.words) && b.words !== words) find({ status: 'note', code: 'counts-disagree', chain: id, seq: e.seq, data: { by: b.words - words } });
          words = count(b.words);
          break;
        }
        case 'seal': {
          const sig = unbase64url(str(b.sig) ?? '!');
          const named = str(b.key);
          const k = named ? keys.find((x) => x.fp === named) : keys[keys.length - 1];
          const message = utf8(sealMessage({ prev: e.prev!, seq: e.seq, t: e.t, m: int(b.m) ? b.m : undefined, key: named }));
          if (!k) { find({ status: keys.length || named ? 'failed' : 'unchecked', code: 'seal-without-key', chain: id, seq: e.seq, file: e.file, line: e.n }); break; }
          // (the signature's text must be exactly its bytes' encoding: no second spelling of the same signature)
          if (!sig || base64url(sig) !== b.sig || !(await verifySignature(k.key, message, sig))) { find({ status: 'failed', code: 'bad-signature', chain: id, seq: e.seq, file: e.file, line: e.n }); break; }
          seals++;
          lastSeal = e.seq;
          if (change && named && named === change.old && !change.endorsed && e.seq === change.seq + 1) change.endorsed = true;
          else if (named && keys[keys.length - 1]!.fp !== named) find({ status: 'note', code: 'old-key-used', chain: id, seq: e.seq });
          break;
        }
        case 'key.change': {
          if (change) find({ status: 'note', code: change.endorsed ? 'key-changed-endorsed' : 'key-changed-unendorsed', chain: id, seq: change.seq });
          const old = keys.length ? keys[keys.length - 1]!.fp : null;
          if (!(await addKey(keyOf(b.key), e.seq))) find({ status: 'failed', code: 'bad-key', chain: id, seq: e.seq, file: e.file, line: e.n });
          change = { seq: e.seq, old, endorsed: false };
          break;
        }
        case 'gap': {
          r.gaps.push({ chain: id, seq: e.seq, why: label(b.why) || 'unnamed', ...(int(b.from) ? { from: b.from } : { from: e.t }), ...(int(b.to) ? { to: b.to } : {}), ...(int(b.n) ? { n: b.n } : {}) });
          break;
        }
        case 'anchor': {
          const target = obj(b.target);
          const tSeq = target && int(target.seq) ? target.seq : -1;
          const tHash = target ? str(target.hash) : undefined;
          const scheme = label(b.scheme) || 'unnamed';
          const report: AnchorReport = { chain: id, seq: e.seq, target: tSeq, scheme, status: 'unchecked' };
          r.anchors.push(report);
          const at = tSeq >= 0 && tSeq < e.seq ? chain[tSeq] : undefined;
          if (!at || at.seq !== tSeq || at.hash !== tHash) {
            report.status = 'failed';
            report.detail = 'not-in-record';
            find({ status: 'failed', code: 'anchor-elsewhere', chain: id, seq: e.seq, file: e.file, line: e.n });
            break;
          }
          const proof = unbase64url(str(b.proof) ?? '!');
          const hash = unhex(at.hash)!;
          if (!proof) { report.status = 'failed'; report.detail = 'the receipt cannot be read'; find({ status: 'failed', code: 'bad-receipt', chain: id, seq: e.seq, file: e.file, line: e.n, data: { why: report.detail } }); break; }
          if (scheme === 'rfc3161') {
            const v = await verifyRfc3161(proof, hash, roots);
            report.status = v.status;
            if (v.status === 'held') { report.time = v.time; report.authority = v.authority; verified.push({ chain: id, time: v.time, slack: 0, target: tSeq, seq: e.seq }); }
            else { report.detail = v.reason; if (v.status === 'unchecked') report.authority = v.authority; }
          } else if (scheme === 'opentimestamps') {
            const v = await verifyOpenTimestamps(proof, hash, input.bitcoin);
            report.status = v.status;
            if (v.status === 'held') { report.time = v.time; report.height = v.height; report.authority = 'Bitcoin'; verified.push({ chain: id, time: v.time, slack: BLOCK_SLACK_MS, target: tSeq, seq: e.seq }); }
            else if (v.status === 'needs-header') { report.height = v.height; report.merkleRoot = v.merkleRoot; }
            else if (v.status === 'pending') report.detail = v.calendars.join(' ');
            else report.detail = v.reason;
          } else report.detail = 'a scheme this verifier does not know';
          if (report.status === 'failed') find({ status: 'failed', code: 'bad-receipt', chain: id, seq: e.seq, file: e.file, line: e.n, data: { why: report.detail ?? '' } });
          break;
        }
        default: {
          if (CORE.has(e.type)) break;
          const name = label(e.type) || 'unnamed';
          r.unknown[name] = (r.unknown[name] ?? 0) + 1;
        }
      }
    }
    if (session) r.gaps.push({ chain: id, seq: session.seq, why: 'session-not-ended', from: session.t });
    if (change) find({ status: 'note', code: change.endorsed ? 'key-changed-endorsed' : 'key-changed-unendorsed', chain: id, seq: change.seq });
    const last = chain[chain.length - 1]!;
    r.chains.push({
      chain: id, record,
      began: { type: start.type, ...(str(s.how) ? { how: label(s.how) } : {}), ...(str(s.why) ? { why: label(s.why) } : {}), words: count(s.words) },
      entries: chain.length, first: start.t, last: last.t, head: last.hash,
      seals, unsealed: last.seq - lastSeal, keys: keys.map((k) => ({ fingerprint: k.fp, alg: k.key.alg, from: k.from })),
      unanchored: 0,
    });
    if (!keys.length) find({ status: 'unchecked', code: 'not-signed', chain: id });
    else if (last.seq > lastSeal) find({ status: 'note', code: 'unsealed-tail', chain: id, seq: lastSeal + 1, data: { n: last.seq - lastSeal, since: chain[lastSeal + 1]?.t ?? last.t } });
  }

  // A session that opened on a manuscript no checkpoint produced, with no entry accounting for it.
  for (const [id, chain] of all) for (const e of chain) {
    if (e.type !== 'session.start') continue;
    const file = str(e.entry.file);
    if (!file || knownFiles.has(file)) continue;
    const end = chain.findIndex((x, i) => i > e.seq && (x.type === 'session.end' || x.type === 'session.start'));
    const within = chain.slice(e.seq + 1, end < 0 ? undefined : end);
    if (!within.some((x) => x.type === 'change' && x.entry.op === 'outside')) find({ status: 'note', code: 'unaccounted-change', chain: id, seq: e.seq });
  }
  // Lines of one chain out of their order in a file: harmless to the chain (it is rebuilt from hashes), and said.
  const lastSeq = new Map<string, number>();
  for (const e of entries) {
    if (!e.chain) continue;
    const key = `${e.file}\n${e.chain}`;
    if (e.seq < (lastSeq.get(key) ?? -1)) find({ status: 'note', code: 'out-of-order', chain: e.chain, seq: e.seq, file: e.file, line: e.n });
    lastSeq.set(key, Math.max(e.seq, lastSeq.get(key) ?? -1));
  }

  // ── 5. What one chain says it saw of another ──
  for (const s of sees) {
    const other = all.get(s.chain);
    if (!other) { find({ status: 'note', code: 'chain-not-supplied', chain: s.from.chain, seq: s.from.seq }); continue; }
    const at = other[s.seq];
    if (!at) find({ status: 'failed', code: 'chain-cut-short', chain: s.chain, seq: s.seq, data: { has: other.length } });
    else if (at.hash !== s.hash) find({ status: 'failed', code: 'chain-differs', chain: s.chain, seq: s.seq });
  }

  // ── 6. Time ──
  const disagree = (chain: string, seq: number, ms: number) => { r.time.disagreements.push({ chain, seq, ms }); };
  for (const [id, chain] of all) {
    const mine = verified.filter((v) => v.chain === id);
    const report = r.chains.find((c) => c.chain === id);
    if (!report) continue;
    const first = chain[0]!.t;
    const last = chain[chain.length - 1]!.t;
    r.time.claimedFrom = Math.min(r.time.claimedFrom ?? first, first);
    r.time.claimedTo = Math.max(r.time.claimedTo ?? last, last);
    report.unanchored = chain.length - 1 - Math.max(-1, ...mine.map((v) => v.target));
    for (const v of mine) {
      r.time.anchoredFrom = Math.min(r.time.anchoredFrom ?? v.time, v.time);
      r.time.anchoredTo = Math.max(r.time.anchoredTo ?? v.time, v.time);
    }
    // Each entry against the receipts around it: written no later than the next anchor over it, and after every receipt before it.
    let worst: { seq: number; ms: number } | null = null;
    const note = (seq: number, ms: number) => { if (ms > CLOCK_TOLERANCE_MS && (!worst || ms > worst.ms)) worst = { seq, ms }; };
    for (const e of chain) {
      let upper = Infinity;
      let lower = -Infinity;
      for (const v of mine) {
        if (v.target >= e.seq) upper = Math.min(upper, v.time + v.slack);
        if (v.seq < e.seq) lower = Math.max(lower, v.time - v.slack);
      }
      note(e.seq, e.t - upper);
      note(e.seq, lower - e.t);
    }
    if (worst) disagree(id, (worst as { seq: number }).seq, (worst as { ms: number }).ms);
    // The computer's clock against itself: going backwards, or falling behind its own monotonic clock.
    let back = 0;
    let sessionStart: E | null = null;
    let jump = 0;
    for (let i = 1; i < chain.length; i++) {
      const e = chain[i]!;
      if (e.t < chain[i - 1]!.t) back++;
      if (e.type === 'session.start') sessionStart = e;
      else if (sessionStart && int(e.entry.m) && e.entry.m - (e.t - sessionStart.t) > CLOCK_TOLERANCE_MS) jump = Math.max(jump, e.entry.m - (e.t - sessionStart.t));
      if (e.type === 'session.end') sessionStart = null;
    }
    if (back) find({ status: 'note', code: 'clock-went-back', chain: id, data: { n: back } });
    if (jump) find({ status: 'note', code: 'clock-set-back', chain: id, data: { ms: jump } });
    // The longest stretch of claimed time with no verified anchor inside it.
    const points = [first, ...mine.map((v) => chain[v.target]!.t).sort((a, b) => a - b), last];
    for (let i = 1; i < points.length; i++) {
      const ms = points[i]! - points[i - 1]!;
      if (!r.time.longestUnanchored || ms > r.time.longestUnanchored.ms) r.time.longestUnanchored = { ms, from: points[i - 1]!, to: points[i]!, chain: id };
    }
  }
  for (const d of r.time.disagreements) find({ status: 'note', code: 'clock-disagrees', chain: d.chain, seq: d.seq, data: { ms: d.ms } });
  if (all.size && !verified.length) find({ status: 'unchecked', code: 'no-anchors' });

  // ── 7. Totals ──
  const sizes = r.totals.pastes.sizes.sort((a, b) => b - a);
  r.totals.pastes = { count: sizes.length, words: sizes.reduce((a, b) => a + b, 0), largest: sizes[0] ?? 0, sizes: sizes.slice(0, 50) };

  // ── 8. The manuscript, and what the reader expected ──
  if (input.manuscript) {
    const file = hex(await sha256(input.manuscript));
    const lastOf = [...all.keys()].map((id) => checkpoints.filter((c) => c.chain === id).pop()).filter((c): c is NonNullable<typeof c> => !!c).sort((a, b) => b.e.t - a.e.t)[0];
    const hit = lastOf?.file === file ? lastOf : checkpoints.filter((c) => c.file === file).pop();
    if (!hit) { r.manuscript = { given: true, match: 'none' }; find({ status: 'note', code: 'manuscript-no-match' }); }
    else {
      const bound = verified.filter((v) => v.chain === hit.chain && v.target >= hit.e.seq).map((v) => v.time + v.slack).sort((a, b) => a - b)[0];
      r.manuscript = { given: true, match: hit === lastOf ? 'last' : 'earlier', chain: hit.chain, seq: hit.e.seq, t: hit.e.t, ...(bound !== undefined ? { noLaterThan: bound } : {}) };
      find({ status: hit === lastOf ? 'held' : 'note', code: hit === lastOf ? 'manuscript-matches' : 'manuscript-earlier', chain: hit.chain, seq: hit.e.seq });
    }
  }
  if (input.expectHead) {
    const e = entries.find((x) => x.hash === input.expectHead && x.chain);
    if (!e) find({ status: 'failed', code: 'head-missing' });
    else find({ status: 'held', code: all.get(e.chain!)!.length - 1 === e.seq ? 'head-is-last' : 'head-present', chain: e.chain, seq: e.seq });
  }
  if (input.expectKey) {
    const has = r.chains.some((c) => c.keys.some((k) => k.fingerprint === input.expectKey));
    find({ status: has ? 'held' : 'failed', code: has ? 'key-expected' : 'key-not-expected' });
  }

  // ── 9. What held ──
  for (const c of r.chains) {
    const bad = r.findings.some((f) => f.status === 'failed' && (f.chain === c.chain || f.chain === undefined) && ['broken', 'fork', 'out-of-step', 'not-an-entry'].includes(f.code));
    if (!bad) find({ status: 'held', code: 'chain-intact', chain: c.chain, data: { n: c.entries } });
    if (c.seals && !r.findings.some((f) => f.chain === c.chain && (f.code === 'bad-signature' || f.code === 'seal-without-key'))) find({ status: 'held', code: 'signed', chain: c.chain, data: { n: c.seals, keys: c.keys.length } });
  }
  if (!all.size) find({ status: 'failed', code: 'no-record' });
  r.failed = r.findings.some((f) => f.status === 'failed');
  return r;
}

/** The command-line verifier's exit status (SPEC §10.2). */
export function exitStatus(r: Result): 0 | 1 | 2 {
  if (r.refused || r.findings.some((f) => f.code === 'no-record')) return 2;
  return r.failed ? 1 : 0;
}
