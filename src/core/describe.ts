// The verifier's sentences (SPEC §10.3), for a reader who isn't technical. They say only what the record can show:
// "existed no later than", "the computer's clock said", "the record says". Never a verdict, a score or a "proves".

import type { Finding, Result, Status } from './verify.ts';

export interface Sentence { status: Status; text: string }

const n = (x: number) => x.toLocaleString('en-GB');
const DATE = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' });
const when = (t: number) => `${DATE.format(t)} UTC`;
const many = (count: number, one: string, more = `${one}s`) => `${n(count)} ${count === 1 ? one : more}`;

/** A length of time, in the largest unit that fits. */
export function span(ms: number): string {
  const minutes = Math.round(ms / 60_000);
  if (minutes < 90) return many(Math.max(1, minutes), 'minute');
  const hours = Math.round(minutes / 60);
  if (hours < 48) return many(hours, 'hour');
  return many(Math.round(hours / 24), 'day');
}

const SOURCES: { [source: string]: string } = {
  typed: 'typed', pasted: 'pasted from outside the app', moved: 'moved within the app', replaced: 'changed by find and replace',
  spelling: 'changed by spelling corrections', system: 'put in whole by the operating system (dictation, text replacement or system writing tools: the record cannot tell which)',
  undo: 'taken back by undo', redo: 'put back by redo',
};
const CHANGES: { [op: string]: string } = {
  import: 'imported from a file', sprint: 'placed from a timed sprint', restore: 'restored from the app’s history', rewrite: 'put in place from a rewrite',
  park: 'set aside', unpark: 'brought back from being set aside', move: 'reordered', remove: 'deleted with a scene or chapter', outside: 'changed outside the app',
};
const GAPS: { [why: string]: string } = {
  torn: 'a write was cut short', failed: 'the recorder could not write', interrupted: 'the app stopped with activity not yet written', off: 'recording was switched off',
  'changed-outside': 'the manuscript was changed outside the app', 'session-not-ended': 'a session was not closed normally',
  'chain-reset': 'the record began again on the same computer', 'chain-unreadable': 'the earlier record could not be read', 'chain-key-lost': 'the signing key was lost',
};

const where = (f: Finding) => (f.file !== undefined && f.line !== undefined ? `line ${n(f.line)} of ${f.file}` : f.seq !== undefined ? `entry ${n(f.seq)}` : 'the record');

function sentence(f: Finding, r: Result): string | null {
  const d = f.data ?? {};
  switch (f.code) {
    // held
    case 'chain-intact': return `Chain intact: all ${many(+d.n!, 'entry', 'entries')} follow one another without alteration.`;
    case 'signed': return `Signed: ${many(+d.n!, 'signature')} by ${+d.keys! === 1 ? 'one key' : `${n(+d.keys!)} keys`}, all valid. Nothing in the record shows whose ${+d.keys! === 1 ? 'key this is' : 'keys these are'}.`;
    case 'manuscript-matches': return `The manuscript you supplied is, byte for byte, the one saved at the record’s last checkpoint${r.manuscript.given && r.manuscript.t ? ` (${when(r.manuscript.t)} by the computer’s clock${r.manuscript.noLaterThan ? `; existed no later than ${when(r.manuscript.noLaterThan)}` : '; no outside timestamp covers it yet'})` : ''}.`;
    case 'head-is-last': return 'The entry you were told to expect is the last one in this record.';
    case 'head-present': return 'The entry you were told to expect is in this record, which has grown since.';
    case 'key-expected': return 'The record is signed by the key you were told to expect.';
    // failed
    case 'broken': return `Altered: ${where(f)} does not follow the line before it. An entry was changed, removed, inserted or moved at or just before this point. Everything after it is unverified.`;
    case 'not-an-entry': return `Altered or damaged: ${where(f)} is not an entry, and nothing in the record accounts for it.`;
    case 'out-of-step': return `Altered: ${where(f)} is out of step with the entry before it.`;
    case 'fork': return `This chain continues in two different ways after entry ${n(f.seq ?? 0)}. Two versions of this record exist.`;
    case 'bad-start': return `${where(f)} begins a chain but is not a valid first entry.`;
    case 'bad-signature': return `Signature invalid at ${where(f)}.`;
    case 'seal-without-key': return f.status === 'failed' ? `A signature at ${where(f)} is by a key the record never named.` : `A signature at ${where(f)} could not be checked: the record names no key.`;
    case 'bad-key': return `A key named at ${where(f)} cannot be read.`;
    case 'bad-checkpoint': return `A checkpoint at ${where(f)} cannot be read.`;
    case 'anchor-elsewhere': return `A receipt at ${where(f)} is for an entry that is not in this record. The record was changed after that receipt was issued.`;
    case 'bad-receipt': return `A receipt at ${where(f)} is not valid: ${d.why}.`;
    case 'chain-cut-short': return `Another device’s chain says it saw entry ${n(f.seq ?? 0)} of this chain, but this copy stops before it. This copy is shorter than the record once was.`;
    case 'chain-differs': return `Another device’s chain saw a different entry ${n(f.seq ?? 0)} on this chain than the one here. Two versions of this record exist.`;
    case 'head-missing': return 'The record you were told to expect ends at an entry this copy does not contain: it is shorter, or different.';
    case 'key-not-expected': return 'The record is not signed by the key you were told to expect.';
    case 'no-record': return 'No record was found in what you supplied.';
    // not checked, and limits
    case 'unsealed-tail': return `The last ${many(+d.n!, 'entry', 'entries')} (since ${when(+d.since!)} by the computer’s clock) ${+d.n! === 1 ? 'is' : 'are'} not covered by a signature. ${+d.n! === 1 ? 'It' : 'They'} could be changed without it showing.`;
    case 'not-signed': return 'This chain is not signed.';
    case 'no-anchors': return 'No outside timestamps were verified. Every time in this record is the computer’s own claim. Nothing shows when any of it was written.';
    case 'clock-disagrees': return `The computer’s clock disagrees with an outside timestamp at entry ${n(f.seq ?? 0)} by ${span(+d.ms!)}.`;
    case 'clock-went-back': return `The computer’s clock went backwards ${many(+d.n!, 'time')} between entries.`;
    case 'clock-set-back': return `The computer’s clock fell behind its own steady clock by ${span(+d.ms!)} during a session: it was set back, or it is unreliable.`;
    case 'incomplete-last-line': return `The last line of ${f.file} is incomplete: the app was interrupted while writing, or the file was cut. It was ignored.`;
    case 'not-canonical': return `${where(f)} is not in canonical form: written by software that does not follow the format.`;
    case 'out-of-order': return `${where(f)} is out of its place in the file. The chain itself is unaffected.`;
    case 'counts-disagree': return `At entry ${n(f.seq ?? 0)} the manuscript’s size differs by ${many(Math.abs(+d.by!), 'word')} from what the entries before it add up to.`;
    case 'unaccounted-change': return `The session at entry ${n(f.seq ?? 0)} opened on a manuscript no earlier checkpoint produced, and no entry accounts for the difference.`;
    case 'key-changed-endorsed': return `The key was changed at entry ${n(f.seq ?? 0)}. The old key signed the change.`;
    case 'key-changed-unendorsed': return `From entry ${n(f.seq ?? 0)} the record is signed by a different key, and nothing ties it to the earlier one. This is what a lost key looks like. It is also what someone without the original key would produce.`;
    case 'old-key-used': return `A retired key signed again at entry ${n(f.seq ?? 0)}.`;
    case 'chain-not-supplied': return 'The record refers to another device’s chain that was not supplied.';
    case 'other-record': return 'One of the chains supplied belongs to a different record. It was not included.';
    case 'unknown-hash': return `A chain names a hash algorithm this verifier does not know (${d.hash}).`;
    case 'manuscript-earlier': return `The manuscript you supplied does not match the last checkpoint. It matches the checkpoint at entry ${n(f.seq ?? 0)}.`;
    case 'manuscript-no-match': return 'The manuscript you supplied matches no checkpoint: it was changed after the record ends, or it is a different text.';
    default: return null;
  }
}

/** The result as sentences: what held, what failed, what was not checked, then what the record says. */
export function describe(r: Result): Sentence[] {
  if (r.refused) {
    return [{ status: 'failed', text: `This record uses format version ${r.refused.version}. This verifier understands versions up to ${r.refused.supported}. Nothing was checked. Use a newer verifier.` }];
  }
  const out: Sentence[] = [];
  const order: Status[] = ['failed', 'held', 'unchecked', 'note'];
  for (const status of order) for (const f of r.findings) {
    if (f.status !== status) continue;
    const text = sentence(f, r);
    if (text && !out.some((s) => s.text === text)) out.push({ status, text });
  }
  if (!r.chains.length) return out;
  if (r.chains.length > 1) out.push({ status: 'note', text: `This record was written on ${n(r.chains.length)} devices.` });

  // Time: the computer's claim beside the outside evidence.
  const held = r.anchors.filter((a) => a.status === 'held');
  if (held.length) {
    const services = [...new Set(held.map((a) => a.authority ?? a.scheme))].join(', ');
    const one = r.time.anchoredFrom === r.time.anchoredTo;
    out.push({ status: 'held', text: `Timestamped from outside: ${many(held.length, 'receipt')} from ${services}, ${held.length === 1 ? 'valid' : 'all valid'}. ${one ? `Its time is ${when(r.time.anchoredTo!)}` : `The earliest is ${when(r.time.anchoredFrom!)}; the latest is ${when(r.time.anchoredTo!)}`}. Everything ${one ? 'it' : 'the latest'} covers existed no later than that.` });
  }
  if (r.time.claimedFrom !== null && r.time.claimedTo !== null) {
    out.push({ status: 'note', text: `The computer’s clock says this record covers ${when(r.time.claimedFrom)} to ${when(r.time.claimedTo)}.${r.time.anchoredFrom !== null ? ` Outside evidence covers ${when(r.time.anchoredFrom)} to ${when(r.time.anchoredTo!)}.` : ''}${r.time.longestUnanchored ? ` The longest stretch with no outside timestamp is ${span(r.time.longestUnanchored.ms)}, from ${when(r.time.longestUnanchored.from)} to ${when(r.time.longestUnanchored.to)}.` : ''}` });
  }
  const unanchored = r.chains.reduce((s, c) => s + c.unanchored, 0);
  if (held.length && unanchored) out.push({ status: 'note', text: `${many(unanchored, 'entry', 'entries')} at the end ${unanchored === 1 ? 'has' : 'have'} no outside timestamp yet: there is no outside evidence of when ${unanchored === 1 ? 'it was' : 'they were'} written.` });
  for (const a of r.anchors) {
    if (a.status === 'needs-header') out.push({ status: 'unchecked', text: `A receipt at entry ${n(a.seq)} needs one outside check: Bitcoin block ${n(a.height!)} must have Merkle root ${a.merkleRoot}. The time is that block’s time.` });
    else if (a.status === 'pending') out.push({ status: 'unchecked', text: `A receipt at entry ${n(a.seq)} is not yet final, and shows nothing until it is.` });
    else if (a.status === 'unchecked') out.push({ status: 'unchecked', text: `A receipt at entry ${n(a.seq)} could not be checked: ${a.detail ?? 'unknown reason'}.` });
  }

  // What the record says: the app's own counts.
  const parts: string[] = [];
  for (const [source, [added, removed]] of Object.entries(r.totals.sources)) {
    parts.push(`${many(added, 'word')} ${SOURCES[source] ?? `from a source this verifier does not know (${source})`}${removed ? ` (${n(removed)} removed)` : ''}`);
  }
  for (const [op, c] of Object.entries(r.totals.changes)) {
    parts.push(`${many(c.count, 'time')} text was ${CHANGES[op] ?? `changed in a way this verifier does not know (${op})`} (${n(c.added)} words in, ${n(c.removed)} out)`);
  }
  if (parts.length) {
    const p = r.totals.pastes;
    out.push({ status: 'note', text: `The record says: ${parts.join('; ')}.${p.count ? ` Pastes from outside: ${many(p.count, 'paste')}, ${many(p.words, 'word')}, the largest ${many(p.largest, 'word')}.` : ''} These are the writing app’s own counts. A verifier cannot check them.${r.totals.partial ? ' The record failed part-way, so these cover only the entries that could be verified.' : ''}` });
  }
  if (r.gaps.length) {
    out.push({ status: 'note', text: `The record cannot vouch for ${many(r.gaps.length, 'stretch', 'stretches')}: ${r.gaps.map((g) => `${GAPS[g.why] ?? g.why}${g.from ? ` (${when(g.from)} by the computer’s clock)` : ''}`).join('; ')}.` });
  }
  const unknown = Object.entries(r.unknown);
  if (unknown.length) out.push({ status: 'note', text: `${many(unknown.reduce((s, [, c]) => s + c, 0), 'entry', 'entries')} of kinds this verifier does not know: ${unknown.map(([t]) => t).join(', ')}. They are part of the chain and were not interpreted.` });
  if (!r.manuscript.given) out.push({ status: 'unchecked', text: 'No manuscript was supplied, so nothing was compared with the record’s checkpoints.' });
  out.push({ status: 'note', text: 'A record that ends early looks the same as a complete one. Compare it with the manuscript, or with an entry hash you were given earlier.' });
  return out;
}
