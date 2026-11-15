// Makes the test records in fixtures/v0. RUN ONCE PER FORMAT VERSION: once a version is released its fixtures are
// frozen and never made again (SPEC §12); a test fails if any of them changes. Version 0 is not released yet.
//
//   node packages/provenance/scripts/make-fixtures.ts
//
// This is the only code in the package that uses the network: it asks FreeTSA for two genuine RFC 3161 receipts and
// an OpenTimestamps calendar for one pending receipt, each for a bare hash of a test entry.

import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Chain, canonical, concat, exitStatus, hex, parseLine, partLeaf, sha256, utf8, verify, type Part } from '../src/index.ts';
import { children, parseDer } from '../src/core/anchors/der.ts';
import { FakeAnchor, MemoryStorage, seededRandom, softwareSigner, TestClock } from '../src/testing/index.ts';
import type { AnchorService } from '../src/ports.ts';

const OUT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'v0');
const MIN = 60_000;

/** A genuine RFC 3161 receipt from FreeTSA for a hash: the TimeStampToken, with the authority's certificate inside. */
const freeTsa: AnchorService = {
  scheme: 'rfc3161',
  via: 'https://freetsa.org/tsr',
  async submit(hash) {
    const sha256Alg = Uint8Array.of(0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00);
    const imprint = concat(Uint8Array.of(0x30, 0x31), sha256Alg, Uint8Array.of(0x04, 0x20), hash);
    const req = concat(Uint8Array.of(0x30, 3 + imprint.length + 3, 0x02, 0x01, 0x01), imprint, Uint8Array.of(0x01, 0x01, 0xff));
    const res = await fetch('https://freetsa.org/tsr', { method: 'POST', headers: { 'Content-Type': 'application/timestamp-query' }, body: req });
    if (!res.ok) throw new Error(`FreeTSA answered ${res.status}`);
    const [, token] = children(parseDer(new Uint8Array(await res.arrayBuffer())));
    if (!token) throw new Error('FreeTSA gave no receipt');
    return token.raw;
  },
};

/** A genuine pending OpenTimestamps receipt from a public calendar. It becomes final hours later; this one never will be upgraded. */
const calendar: AnchorService = {
  scheme: 'opentimestamps',
  via: 'https://alice.btc.calendar.opentimestamps.org',
  async submit(hash) {
    const res = await fetch('https://alice.btc.calendar.opentimestamps.org/digest', { method: 'POST', headers: { Accept: 'application/vnd.opentimestamps.v1' }, body: new Uint8Array(hash) });
    if (!res.ok) throw new Error(`the calendar answered ${res.status}`);
    return new Uint8Array(await res.arrayBuffer());
  },
};

/** A manuscript of placeholder text in `n` parts; `edit` changes one part's text. */
function manuscript(n: number, edits: { [part: number]: string } = {}): { file: Uint8Array<ArrayBuffer>; parts: Part[]; words: number } {
  const parts: Part[] = [];
  for (let i = 0; i < n; i++) parts.push({ id: `scene${String(i + 1).padStart(2, '0')}`, content: utf8(`## Part ${i + 1}\n\n${edits[i] ?? 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'}\n\n`) });
  const file = concat(...parts.map((p) => p.content));
  return { file, parts, words: new TextDecoder().decode(file).split(/\s+/).filter(Boolean).length };
}

const SECRET = new Uint8Array(32).fill(7);
async function checkpoint(chain: Chain, m: ReturnType<typeof manuscript>, changed?: number) {
  return chain.checkpoint({ file: await sha256(m.file), words: m.words, leaves: await Promise.all(m.parts.map((p) => partLeaf(SECRET, p))), changed });
}

const APP = { name: 'Example Writer', version: '1.0.0' };
const written: { [name: string]: string | Uint8Array } = {};
const put = (name: string, content: string | Uint8Array) => { written[name] = content; };

/** One session of writing: activity, a checkpoint, a seal. Returns the manuscript as saved. */
async function session(chain: Chain, clock: TestClock, before: ReturnType<typeof manuscript>, text: string, opts: { anchors?: AnchorService[]; paste?: number } = {}) {
  await chain.sessionStart({ app: APP, platform: 'darwin', profile: 'example-parts-1', file: hex(await sha256(before.file)), words: before.words });
  clock.advance(3 * MIN);
  const after = manuscript(before.parts.length + 1, { [before.parts.length]: text });
  const grew = after.words - before.words;
  const paste = opts.paste ?? 0;
  await chain.activity(clock.now() - 3 * MIN, [
    { i: 0, w: { typed: [Math.ceil((grew - paste) / 2) + 4, 4] } },
    { i: 2, w: { typed: [Math.floor((grew - paste) / 2), 0], ...(paste ? { pasted: [paste, 0] } : {}) }, ...(paste ? { pastes: [paste] } : {}) },
  ]);
  await checkpoint(chain, after, 1);
  const seal = await chain.seal();
  for (const a of opts.anchors ?? []) await chain.anchor(a, seal!);
  clock.advance(MIN);
  await chain.sessionEnd('closed');
  await chain.seal();
  return after;
}

async function main() {
  // ── clean: one device, two sessions, signed, with genuine receipts; ends on a seal ──
  // (the first session's three minutes end at the real present, so the genuine receipts agree with the claimed times)
  const clock = new TestClock(Date.now() - 3 * MIN);
  const EMPTY = hex(await sha256(new Uint8Array(0)));
  const random = seededRandom(20261112);
  const storage = new MemoryStorage();
  const signer = await softwareSigner('ecdsa-p256-sha256');
  const chain = await Chain.begin({ storage, clock, signer, random }, { how: 'new', unit: 'words', words: 0, file: EMPTY });
  let m = manuscript(0);
  m = await session(chain, clock, m, 'Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium.', { anchors: [freeTsa, calendar] });
  clock.advance(8 * MIN);
  m = await session(chain, clock, m, 'Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt neque porro quisquam est.', { paste: 12 });
  const clean = storage.text;
  const lines = storage.lines;
  put('clean.jsonl', clean);
  put('clean.manuscript.md', m.file);
  put('clean.secret.hex', `${hex(SECRET)}\n`);
  put('clean.head.txt', `${chain.head.hash}\n`);

  // ── the tampering attacks of the threat model, each made from the clean record ──
  // 1. Edited: one count changed in an activity entry (entry 2), nothing else.
  const at = lines.findIndex((l) => l.includes('"type":"activity"'));
  put('edited.jsonl', `${lines.map((l, i) => (i === at ? l.replace('"typed":[', '"typed":[9') : l)).join('\n')}\n`);
  // 1. Reordered: two lines swapped. The chain is rebuilt from hashes, so this is harmless, and said.
  const swapped = [...lines];
  [swapped[3], swapped[4]] = [swapped[4]!, swapped[3]!];
  put('reordered.jsonl', `${swapped.join('\n')}\n`);
  // 1. Spliced: an entry removed from the middle.
  put('spliced.jsonl', `${lines.filter((_, i) => i !== at).join('\n')}\n`);
  // 2. Truncated: the second session cut off, at the end of a line. A valid, shorter record: only the manuscript
  //    or the expected head shows it.
  const firstEnd = lines.findIndex((l, i) => i > at && l.includes('"type":"seal"') && lines[i - 1]!.includes('"session.end"'));
  put('truncated.jsonl', `${lines.slice(0, firstEnd + 1).join('\n')}\n`);
  // A torn last line: the app stopped mid-write.
  put('torn.jsonl', `${clean}${lines[lines.length - 1]!.slice(0, 41)}`);
  // 9 / wrong key: the last seal replaced by one from a key the record never named.
  {
    const other = await softwareSigner('ecdsa-p256-sha256');
    const s2 = new MemoryStorage(`${lines.slice(0, -1).join('\n')}\n`);
    const c2 = await Chain.open({ storage: s2, clock, signer: other });
    await c2.seal();
    put('wrong-key.jsonl', s2.text);
  }
  // 4. Forked: two continuations of the same point, both signed by the record's own key.
  {
    const base = `${lines.slice(0, firstEnd + 1).join('\n')}\n`;
    const b = new MemoryStorage(base);
    const cb = await Chain.open({ storage: b, clock, signer });
    const fm = manuscript(1, { 0: 'Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium.' });
    await cb.sessionStart({ app: APP, platform: 'darwin', file: hex(await sha256(fm.file)), words: fm.words });
    await cb.activity(clock.now(), [{ i: 0, w: { typed: [600, 0] } }]);
    await cb.sessionEnd('closed');
    await cb.seal();
    put('forked.jsonl', clean + b.text.slice(base.length));
  }
  // 3. Backdated: a whole record made now, its clock set six months back, with a genuine receipt from today.
  {
    const old = new TestClock(Date.now() - 182 * 24 * 60 * MIN);
    const s = new MemoryStorage();
    const c = await Chain.begin({ storage: s, clock: old, signer: await softwareSigner('ed25519'), random }, { how: 'new', unit: 'words', words: 0, file: EMPTY });
    let bm = manuscript(0);
    for (let day = 0; day < 4; day++) { bm = await session(c, old, bm, `Day ${day + 1}: quis autem vel eum iure reprehenderit qui in ea voluptate velit esse.`); old.advance(45 * 24 * 60 * MIN); }
    await c.anchor(freeTsa);
    put('backdated.jsonl', s.text);
  }

  // ── two devices: each its own chain, the second seeing the first ──
  {
    const c1 = new TestClock(Date.UTC(2026, 2, 3, 9, 0, 0));
    const a = new MemoryStorage();
    const ca = await Chain.begin({ storage: a, clock: c1, signer: await softwareSigner('ecdsa-p256-sha256'), random }, { how: 'imported', unit: 'words', words: manuscript(1).words, file: hex(await sha256(manuscript(1).file)), source: { kind: 'word', sha256: hex(await sha256(utf8('an imported file'))) } });
    let dm = manuscript(1);
    dm = await session(ca, c1, dm, 'Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit.', { anchors: [new FakeAnchor(c1)] });
    c1.advance(26 * 60 * MIN);
    const b = new MemoryStorage();
    const cb = await Chain.join({ storage: b, clock: c1, signer: await softwareSigner('ed25519'), random }, { record: ca.record, why: 'device', words: dm.words, file: hex(await sha256(dm.file)), sees: [ca.seen] });
    dm = await session(cb, c1, dm, 'Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil.');
    put('two-devices.jsonl', a.text + b.text);
    // The first device's chain cut back after the second saw it: the second chain shows it.
    put('two-devices-cut.jsonl', `${a.lines.slice(0, 3).join('\n')}\n${b.text}`);
  }

  // ── a gap: a write cut short and mended, a stretch the recorder couldn't write, a change made outside ──
  {
    const c1 = new TestClock(Date.UTC(2026, 4, 9, 14, 0, 0));
    const s = new MemoryStorage();
    const signerG = await softwareSigner('ed25519');
    let c = await Chain.begin({ storage: s, clock: c1, signer: signerG, random }, { how: 'opened', unit: 'words', words: manuscript(2).words, file: hex(await sha256(manuscript(2).file)) });
    let gm = manuscript(2);
    await c.sessionStart({ app: APP, platform: 'darwin', file: hex(await sha256(gm.file)), words: gm.words });
    c1.advance(2 * MIN);
    await c.activity(c1.now(), [{ i: 0, w: { typed: [31, 2], spelling: [1, 1] } }]);
    s.text += '{"m":180000,"rows":[{"i":0,"w":{"ty'; // (the app stopped here, mid-write)
    c1.advance(60 * MIN);
    c = await Chain.open({ storage: s, clock: c1, signer: signerG });
    await c.gap({ why: 'failed', from: c1.now() - 30 * MIN, to: c1.now(), n: 4 });
    const outside = manuscript(3, { 2: 'Text that arrived from another program entirely, unseen.' });
    await c.sessionStart({ app: APP, platform: 'darwin', file: hex(await sha256(outside.file)), words: outside.words });
    await c.change({ op: 'outside', w: [outside.words - gm.words, 0], file: hex(await sha256(outside.file)), taken: true });
    gm = outside;
    await checkpoint(c, gm, 1);
    await c.sessionEnd('quit');
    await c.seal();
    put('gap.jsonl', s.text);
  }

  // ── entries of a type the verifier doesn't know; a system-tool insertion; a key change ──
  {
    const c1 = new TestClock(Date.UTC(2026, 6, 1, 8, 0, 0));
    const s = new MemoryStorage();
    const c = await Chain.begin({ storage: s, clock: c1, signer: await softwareSigner('ecdsa-p256-sha256'), random }, { how: 'new', unit: 'words', words: 0 });
    await c.sessionStart({ app: APP, platform: 'linux', words: 0 });
    await c.append({ type: 'example.org:beat-placed', beats: 3, kind: 'midpoint' });
    c1.advance(MIN);
    await c.activity(c1.now(), [{ i: 0, w: { typed: [20, 0], system: [6, 0], 'example.org:dictated': [5, 0] } }]);
    await c.append({ type: 'example.org:beat-placed', beats: 4, kind: 'climax' });
    await c.keyChange(await softwareSigner('ed25519'), 'rotated');
    await c.sessionEnd('closed');
    await c.seal();
    put('unknown-type.jsonl', s.text);
    // A later format version: refused whole.
    const future = parseLine(s.lines[1]!)!;
    put('unknown-version.jsonl', `${s.lines[0]}\n${canonical({ ...future, v: 7 })}\n`);
  }

  // ── write them, with what the verifier of this day says about each ──
  rmSync(OUT, { recursive: true, force: true });
  mkdirSync(OUT, { recursive: true });
  for (const [name, content] of Object.entries(written)) writeFileSync(path.join(OUT, name), content);
  const expected: { [name: string]: unknown } = {};
  for (const name of Object.keys(written).filter((x) => x.endsWith('.jsonl')).sort()) {
    const text = readFileSync(path.join(OUT, name), 'utf8');
    const withManuscript = name === 'clean.jsonl' || name === 'truncated.jsonl';
    const r = await verify({ files: [{ name, text }], ...(withManuscript ? { manuscript: new Uint8Array(readFileSync(path.join(OUT, 'clean.manuscript.md'))) } : {}), ...(name === 'truncated.jsonl' ? { expectHead: String(written['clean.head.txt']).trim() } : {}) });
    expected[name] = {
      exit: exitStatus(r),
      failed: r.findings.filter((f) => f.status === 'failed').map((f) => `${f.code}${f.line !== undefined ? `@line${f.line}` : f.seq !== undefined ? `@${f.seq}` : ''}`).sort(),
      notes: [...new Set(r.findings.filter((f) => f.status !== 'failed' && f.status !== 'held').map((f) => f.code))].sort(),
      anchors: r.anchors.map((a) => `${a.scheme}:${a.status}`),
      chains: r.chains.length,
    };
  }
  writeFileSync(path.join(OUT, 'EXPECTED.json'), `${JSON.stringify(expected, null, 2)}\n`);
  const manifest: { [name: string]: string } = {};
  for (const name of readdirSync(OUT).sort()) manifest[name] = createHash('sha256').update(readFileSync(path.join(OUT, name))).digest('hex');
  writeFileSync(path.join(OUT, '..', 'v0.manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  console.warn(`wrote ${Object.keys(manifest).length} files to ${OUT}`);
}

await main();
