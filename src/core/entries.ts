// The entries of format version 0 (SPEC §3, §5–§9), as types. An entry on disk is one canonical JSON line; these
// say what a writer may put in one. A verifier reads lines as untrusted and never relies on these types.

export const VERSION = 0;

/** Members every entry has (SPEC §3). */
export interface Envelope {
  v: number;
  type: string;
  seq: number;
  /** Entry hash of the previous entry; absent when `seq` is 0. */
  prev?: string;
  /** Milliseconds since 1970 on the computer's clock: a claim. */
  t: number;
  /** Milliseconds on the monotonic clock since this session's start. */
  m?: number;
}

export type KeyAlg = 'ecdsa-p256-sha256' | 'ed25519';
/** A signing key as a record names it: `pub` is base64url (SPEC §7.1). */
export interface KeyRef { alg: KeyAlg; pub: string }
/** A reference to an entry on a chain (SPEC §4). */
export interface Sees { chain: string; seq: number; hash: string }

export type How = 'new' | 'imported' | 'opened' | 'copied' | 'continued';
export interface Source { kind: 'word' | 'markdown' | 'text'; sha256?: string }

export interface RecordStart {
  type: 'record.start';
  record: string;
  chain: string;
  hash: 'sha-256';
  key?: KeyRef;
  how: How;
  unit: 'words';
  words: number;
  file?: string;
  source?: Source;
  from?: { record: string; chain: string; seq: number; hash: string };
  prior?: { kind: string; sha256: string; entries: number; first: number; last: number };
}

export interface ChainStart {
  type: 'chain.start';
  record: string;
  chain: string;
  hash: 'sha-256';
  key?: KeyRef;
  why: 'device' | 'reset' | 'unreadable' | 'key-lost';
  words: number;
  file?: string;
  sees?: Sees[];
}

export interface SessionStart {
  type: 'session.start';
  app: { name: string; version: string };
  platform: string;
  profile?: string;
  file?: string;
  words: number;
  sees?: Sees[];
}
export interface SessionEnd { type: 'session.end'; why: 'closed' | 'quit' | 'switched' }

/** Words added and removed. */
export type Delta = [added: number, removed: number];
export type ActivitySource = 'typed' | 'pasted' | 'moved' | 'replaced' | 'spelling' | 'system' | 'undo' | 'redo';
export interface ActivityRow {
  /** The interval is `from + i × step` to `from + (i + 1) × step`. */
  i: number;
  w: { [source: string]: Delta };
  /** The size in words of each paste from outside in this interval, largest first, at most 50. */
  pastes?: number[];
}
export interface Activity {
  type: 'activity';
  step: number;
  from: number;
  rows: ActivityRow[];
  ctx?: string;
}

export type ChangeOp = 'import' | 'sprint' | 'restore' | 'rewrite' | 'park' | 'unpark' | 'move' | 'remove' | 'outside';
export interface Change {
  type: 'change';
  /** One of `ChangeOp`, or another name: the set is open. */
  op: ChangeOp | (string & {});
  w: Delta;
  parts?: number;
  source?: Source;
  recorded?: boolean;
  file?: string;
  taken?: boolean;
}

export interface Checkpoint {
  type: 'checkpoint';
  file: string;
  words: number;
  parts?: number;
  root?: string;
  changed?: number;
}

export interface Seal { type: 'seal'; sig: string; key?: string }

export interface Anchor {
  type: 'anchor';
  scheme: 'rfc3161' | 'opentimestamps' | (string & {});
  target: { seq: number; hash: string };
  proof: string;
  via?: string;
  replaces?: number;
}

export interface Gap {
  type: 'gap';
  why: 'torn' | 'failed' | 'interrupted' | 'off' | (string & {});
  from?: number;
  to?: number;
  n?: number;
  torn?: string;
}

export interface KeyChange { type: 'key.change'; key: KeyRef; why: 'rotated' | 'exposed' | 'replaced' }

/** An entry of a type this document doesn't define: `domain:name` (SPEC §5). */
export interface Extension { type: `${string}:${string}`; [member: string]: unknown }

export type Body = RecordStart | ChainStart | SessionStart | SessionEnd | Activity | Change | Checkpoint | Seal | Anchor | Gap | KeyChange;
export type Entry = Envelope & Body;

/** The interval activity is counted in (SPEC §5.4). */
export const STEP_MS = 60_000;
/** Pastes listed one by one in a row, at most. */
export const PASTES_LISTED = 50;

/** What a seal signs (SPEC §7.2): the chain so far, and where in it the seal stands. ASCII. */
export function sealMessage(seal: { prev: string; seq: number; t: number; m?: number; key?: string }): string {
  return `provenance-seal-v0:${seal.prev}:${seal.seq}:${seal.t}:${seal.m ?? ''}:${seal.key ?? ''}`;
}
