import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { Chain, describe as say, entryHash, exitStatus, isCanonical, parseLine, sha256, utf8, verify, type ActivityRow } from '../src/index.ts';
import { FakeAnchor, MemoryStorage, seededRandom, softwareSigner, TestClock } from '../src/testing/index.ts';
import { failed, MIN, record, runs } from './helpers.ts';

const check = (text: string, more: object = {}) => verify({ files: [{ name: 'record.jsonl', text }], ...more });

describe('writing a chain (SPEC §2–§9)', () => {
  it('every line is canonical, carries the version, and names the hash of the line before it', async () => {
    const { storage } = await record();
    const lines = storage.lines;
    expect(storage.text.endsWith('\n')).toBe(true);
    for (let i = 0; i < lines.length; i++) {
      const e = parseLine(lines[i]!)!;
      expect(isCanonical(lines[i]!)).toBe(true);
      expect(e.v).toBe(0);
      expect(e.seq).toBe(i);
      expect(e.prev).toBe(i ? await entryHash(lines[i - 1]!) : undefined);
    }
    expect(parseLine(lines[0]!)).toMatchObject({ type: 'record.start', how: 'new', hash: 'sha-256', unit: 'words' });
  });

  it('a record written then verified passes: intact, signed, its counts added up, the manuscript matched', async () => {
    const { storage, chain, lastFile } = await record(3);
    const r = await check(storage.text, { manuscript: lastFile, expectHead: chain.head.hash });
    expect(failed(r)).toEqual([]);
    expect(exitStatus(r)).toBe(0);
    expect(r.chains).toHaveLength(1);
    expect(r.chains[0]).toMatchObject({ entries: storage.lines.length, seals: 6, unsealed: 0, head: chain.head.hash });
    expect(r.totals.sources).toEqual({ typed: [123, 9], pasted: [15, 0] });
    expect(r.totals.pastes).toMatchObject({ count: 3, words: 15, largest: 5 });
    expect(r.totals.sessions).toBe(3);
    expect(r.manuscript).toMatchObject({ given: true, match: 'last' });
    expect(r.findings.map((f) => f.code)).toEqual(expect.arrayContaining(['chain-intact', 'signed', 'manuscript-matches', 'head-is-last', 'no-anchors']));
    expect(r.findings.some((f) => f.code === 'counts-disagree')).toBe(false);
  });

  it('holds no prose: only the members the format names', async () => {
    const { storage } = await record();
    const allowed = new Set(['v', 'type', 'seq', 'prev', 't', 'm', 'record', 'chain', 'hash', 'key', 'how', 'unit', 'words', 'app', 'platform', 'step', 'from', 'rows', 'file', 'parts', 'root', 'sig', 'why']);
    for (const line of storage.lines) for (const k of Object.keys(parseLine(line)!)) expect(allowed.has(k), k).toBe(true);
  });

  it('a storage that fails rejects the call and leaves the chain where it was; the next entry follows the last one written', async () => {
    const { storage, chain } = await record(1);
    const head = chain.head;
    storage.failing = true;
    await expect(chain.gap({ why: 'failed' })).rejects.toThrow();
    await expect(chain.seal()).rejects.toThrow();
    expect(chain.head).toEqual(head);
    storage.failing = false;
    await chain.gap({ why: 'failed', n: 2 });
    await chain.seal();
    const r = await check(storage.text);
    expect(failed(r)).toEqual([]);
    expect(r.gaps).toEqual([expect.objectContaining({ why: 'failed', n: 2 })]);
  });

  it('a write cut short is closed and recorded as a gap, never rewritten; the chain goes on', async () => {
    const { storage, clock, signer } = await record(1);
    const before = storage.text;
    storage.text += '{"m":120000,"rows":[{"i":0,"w":{"ty';
    const chain = await Chain.open({ storage, clock, signer });
    expect(storage.text.startsWith(`${before}{"m":120000,"rows":[{"i":0,"w":{"ty\n`)).toBe(true);
    await chain.seal();
    const r = await check(storage.text);
    expect(failed(r)).toEqual([]);
    expect(r.gaps).toEqual([expect.objectContaining({ why: 'torn' })]);
    // Without the gap that names it, the same stray line is a failure, at its line.
    const lines = storage.lines;
    const stray = lines.findIndex((l) => l.endsWith('"ty'));
    const r2 = await check(`${lines.slice(0, stray + 1).join('\n')}\n`);
    expect(r2.findings).toEqual(expect.arrayContaining([expect.objectContaining({ status: 'failed', code: 'not-an-entry', line: stray + 1 })]));
  });

  it('opening a chain that can’t be read throws, and changes nothing', async () => {
    for (const text of ['', 'nonsense\n', '{"v":0,"type":"activity","seq":4,"t":1}\n']) {
      const storage = new MemoryStorage(text);
      await expect(Chain.open({ storage, clock: new TestClock() })).rejects.toThrow();
      expect(storage.text).toBe(text);
    }
    await expect(Chain.begin({ storage: new MemoryStorage('x\n'), clock: new TestClock() }, { how: 'new', unit: 'words', words: 0 })).rejects.toThrow();
  });

  it('an unsigned chain is said to be unsigned; a chain reopened goes on from its head', async () => {
    const clock = new TestClock();
    const storage = new MemoryStorage();
    const a = await Chain.begin({ storage, clock }, { how: 'opened', unit: 'words', words: 900 });
    expect(await a.seal()).toBeNull();
    const b = await Chain.open({ storage, clock });
    expect(b.head).toEqual(a.head);
    expect(b.record).toBe(a.record);
    await b.gap({ why: 'off' });
    const r = await check(storage.text);
    expect(failed(r)).toEqual([]);
    expect(r.findings).toEqual(expect.arrayContaining([expect.objectContaining({ status: 'unchecked', code: 'not-signed' })]));
    expect(r.chains[0]!.began).toMatchObject({ type: 'record.start', how: 'opened', words: 900 });
  });

  it('a key change: the old key signs it, then the new; left unsigned by the old, it is said', async () => {
    for (const oldSigns of [true, false]) {
      const { storage, chain } = await record(1, 'ecdsa-p256-sha256');
      await chain.keyChange(await softwareSigner('ed25519'), 'rotated', oldSigns);
      await chain.gap({ why: 'off' });
      await chain.seal();
      const r = await check(storage.text);
      expect(failed(r)).toEqual([]);
      expect(r.chains[0]!.keys.map((k) => k.alg)).toEqual(['ecdsa-p256-sha256', 'ed25519']);
      expect(r.findings.map((f) => f.code)).toContain(oldSigns ? 'key-changed-endorsed' : 'key-changed-unendorsed');
    }
  });

  it('an anchor stores the service’s receipt for an earlier entry; a service that can’t be reached writes nothing', async () => {
    const { storage, chain, clock } = await record(1);
    const service = new FakeAnchor(clock);
    const target = chain.head;
    await chain.gap({ why: 'off' });
    await chain.anchor(service, target);
    expect(service.submitted).toHaveLength(1);
    expect(service.submitted[0]).toHaveLength(32);
    const lines = storage.lines.length;
    service.down = true;
    await expect(chain.anchor(service)).rejects.toThrow();
    expect(storage.lines).toHaveLength(lines);
    const r = await check(storage.text);
    expect(failed(r)).toEqual([]);
    // (a scheme the verifier doesn't know is passed over and said: it bounds nothing)
    expect(r.anchors).toEqual([expect.objectContaining({ scheme: 'test', status: 'unchecked', target: target.seq })]);
    expect(r.time.anchoredFrom).toBeNull();
    // A receipt naming an entry that isn't there: the record was changed after it was issued.
    const moved = storage.text.replace(`"seq":${target.seq}},"type":"anchor"`, `"seq":${target.seq - 1}},"type":"anchor"`);
    expect(moved).not.toBe(storage.text);
    expect(failed(await check(moved))).toContain('anchor-elsewhere');
  });

  it('two devices: a chain each, no line of one ever in the other; the second sees the first, and a first cut short shows', async () => {
    const clock = new TestClock();
    const random = seededRandom(3);
    const a = new MemoryStorage();
    const ca = await Chain.begin({ storage: a, clock, signer: await softwareSigner(), random }, { how: 'new', unit: 'words', words: 0 });
    await ca.gap({ why: 'off' });
    await ca.seal();
    const b = new MemoryStorage();
    const cb = await Chain.join({ storage: b, clock, signer: await softwareSigner('ecdsa-p256-sha256'), random }, { record: ca.record, why: 'device', words: 0, sees: [ca.seen] });
    await cb.seal();
    await ca.gap({ why: 'off' });
    await ca.seal();
    const r = await verify({ files: [{ name: 'a.jsonl', text: a.text }, { name: 'b.jsonl', text: b.text }] });
    expect(failed(r)).toEqual([]);
    expect(r.chains.map((c) => c.began.type).sort()).toEqual(['chain.start', 'record.start']);
    expect(r.record).toBe(ca.record);
    // One file holding both, in any order, is the same record.
    const joined = await check(b.text + a.text);
    expect(failed(joined)).toEqual([]);
    expect(joined.chains).toHaveLength(2);
    // The first chain cut back to before what the second saw.
    const cut = await verify({ files: [{ name: 'a.jsonl', text: `${a.lines.slice(0, 2).join('\n')}\n` }, { name: 'b.jsonl', text: b.text }] });
    expect(cut.findings).toEqual(expect.arrayContaining([expect.objectContaining({ status: 'failed', code: 'chain-cut-short', chain: ca.chain })]));
    // A chain of another record is left out, and said.
    const stranger = await record(1);
    const mixed = await verify({ files: [{ name: 'a.jsonl', text: a.text }, { name: 'x.jsonl', text: stranger.storage.text }] });
    expect(mixed.findings.map((f) => f.code)).toContain('other-record');
  });
});

describe('round trip: any sequence of valid entries, written then verified, passes', () => {
  const row = fc.record({ i: fc.nat(4), typed: fc.nat(400), cut: fc.nat(50), pasted: fc.nat(3000) });
  const op = fc.oneof(
    fc.record({ kind: fc.constant('activity' as const), rows: fc.array(row, { minLength: 1, maxLength: 5 }) }),
    fc.record({ kind: fc.constant('checkpoint' as const), text: fc.string({ maxLength: 40 }), parts: fc.nat(9) }),
    fc.record({ kind: fc.constant('seal' as const) }),
    fc.record({ kind: fc.constant('change' as const), op: fc.constantFrom('import', 'sprint', 'restore', 'rewrite', 'park', 'unpark', 'move', 'remove', 'outside'), added: fc.nat(5000), removed: fc.nat(5000) }),
    fc.record({ kind: fc.constant('gap' as const), why: fc.constantFrom('failed', 'interrupted', 'off') }),
    fc.record({ kind: fc.constant('session' as const) }),
    fc.record({ kind: fc.constant('extension' as const), n: fc.integer() }),
    fc.record({ kind: fc.constant('anchor' as const) }),
    fc.record({ kind: fc.constant('key' as const), old: fc.boolean() }),
    fc.record({ kind: fc.constant('wait' as const), ms: fc.integer({ min: 0, max: 86_400_000 }) }),
  );

  it('with either kind of key, or none', async () => {
    const keys = [await softwareSigner('ed25519'), await softwareSigner('ecdsa-p256-sha256'), undefined];
    const spare = await softwareSigner('ed25519');
    await fc.assert(fc.asyncProperty(fc.array(op, { maxLength: 30 }), fc.nat(2), async (ops, which) => {
      const clock = new TestClock();
      const storage = new MemoryStorage();
      const signer = keys[which];
      const chain = await Chain.begin({ storage, clock, signer }, { how: 'new', unit: 'words', words: 0 });
      const anchor = new FakeAnchor(clock);
      let open = false;
      let last = utf8('');
      for (const o of ops) {
        clock.advance(1000);
        if (o.kind === 'activity') {
          const rows: ActivityRow[] = o.rows.map((x, i) => ({ i: i + x.i, w: { typed: [x.typed, x.cut], ...(x.pasted ? { pasted: [x.pasted, 0] } : {}) }, ...(x.pasted ? { pastes: [x.pasted] } : {}) }));
          await chain.activity(clock.now(), rows);
        } else if (o.kind === 'checkpoint') {
          last = utf8(o.text);
          await chain.checkpoint({ file: await sha256(last), words: o.text.length, leaves: await Promise.all(Array.from({ length: o.parts }, (_, i) => sha256(utf8(`${o.text}${i}`)))) });
        } else if (o.kind === 'seal') await chain.seal();
        else if (o.kind === 'change') await chain.change({ op: o.op, w: [o.added, o.removed] });
        else if (o.kind === 'gap') await chain.gap({ why: o.why, from: clock.now() - MIN, to: clock.now() });
        else if (o.kind === 'session') { await (open ? chain.sessionEnd('closed') : chain.sessionStart({ app: { name: 'T', version: '1' }, platform: 'darwin', words: 0 })); open = !open; }
        else if (o.kind === 'extension') await chain.append({ type: 'example.org:thing', n: o.n });
        else if (o.kind === 'anchor') await chain.anchor(anchor);
        else if (o.kind === 'key' && signer) await chain.keyChange(spare, 'rotated', o.old);
        else if (o.kind === 'wait') clock.advance(o.ms);
      }
      await chain.seal();
      const r = await check(storage.text, { manuscript: last, expectHead: chain.head.hash });
      expect(failed(r)).toEqual([]);
      expect(exitStatus(r)).toBe(0);
      expect(r.chains[0]!.entries).toBe(storage.lines.length);
      expect(r.chains[0]!.unsealed).toBe(signer ? 0 : storage.lines.length);
      expect(r.findings.map((f) => f.code)).toContain('chain-intact');
      // (every sentence is made without throwing, and none claims more than the record can show)
      for (const s of say(r)) expect(s.text).not.toMatch(/\bproves?\b|authentic|verified human|\bscore\b|%/i);
    }), runs(150));
  });
});
