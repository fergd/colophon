// The test records of format version 0 (fixtures/v0, each described in its README). Once version 0 is released
// they are frozen: a verifier of any later day must read them and say what the verifier of their day said.
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { auditPath, describe as say, exitStatus, hex, merkleRoot, parseLine, partLeaf, partSalt, unhex, utf8, verify, verifyDisclosure, type Part } from '../src/index.ts';
import { fixture, fixtureBytes, ROOT } from './helpers.ts';

const DIR = path.join(ROOT, 'fixtures', 'v0');
const expected = JSON.parse(fixture('EXPECTED.json')) as { [name: string]: { exit: number; failed: string[]; notes: string[]; anchors: string[]; chains: number } };
const manuscript = () => fixtureBytes('v0/clean.manuscript.md');
const head = fixture('clean.head.txt').trim();

describe('the fixtures of format version 0', () => {
  it('are frozen: no file added, removed or changed', () => {
    const manifest = JSON.parse(readFileSync(path.join(ROOT, 'fixtures', 'v0.manifest.json'), 'utf8')) as { [name: string]: string };
    const now = Object.fromEntries(readdirSync(DIR).filter((n) => n !== 'README.md').sort().map((n) => [n, createHash('sha256').update(readFileSync(path.join(DIR, n))).digest('hex')]));
    expect(now).toEqual(manifest);
  });

  for (const name of Object.keys(expected)) {
    it(`${name}: what the verifier of its day said`, async () => {
      const r = await verify({
        files: [{ name, text: fixture(name) }],
        ...(name === 'clean.jsonl' || name === 'truncated.jsonl' ? { manuscript: manuscript() } : {}),
        ...(name === 'truncated.jsonl' ? { expectHead: head } : {}),
      });
      expect({
        exit: exitStatus(r),
        failed: r.findings.filter((f) => f.status === 'failed').map((f) => `${f.code}${f.line !== undefined ? `@line${f.line}` : f.seq !== undefined ? `@${f.seq}` : ''}`).sort(),
        notes: [...new Set(r.findings.filter((f) => f.status !== 'failed' && f.status !== 'held').map((f) => f.code))].sort(),
        anchors: r.anchors.map((a) => `${a.scheme}:${a.status}`),
        chains: r.chains.length,
      }).toEqual(expected[name]);
      for (const s of say(r)) expect(s.text).not.toMatch(/\bproves?\b|authentic|verified human|\bscore\b/i);
    });
  }

  it('clean: intact, signed, its manuscript matched, a genuine receipt verified, its head the one expected', async () => {
    const r = await verify({ files: [{ name: 'clean.jsonl', text: fixture('clean.jsonl') }], manuscript: manuscript(), expectHead: head });
    expect(r.failed).toBe(false);
    expect(r.manuscript).toMatchObject({ given: true, match: 'last' });
    expect(r.findings.map((f) => f.code)).toEqual(expect.arrayContaining(['chain-intact', 'signed', 'manuscript-matches', 'head-is-last']));
    expect(r.anchors[0]).toMatchObject({ scheme: 'rfc3161', status: 'held', authority: 'www.freetsa.org' });
    expect(r.time.anchoredFrom).toBe(r.anchors[0]!.time);
    expect(r.time.disagreements).toEqual([]);
  });

  it('clean: one part of its last checkpoint can be shown without the others', async () => {
    const secret = unhex(fixture('clean.secret.hex').trim())!;
    const text = new TextDecoder().decode(manuscript());
    const parts: Part[] = text.split(/(?=## Part )/).map((t, i) => ({ id: `scene${String(i + 1).padStart(2, '0')}`, content: utf8(t) }));
    const leaves = await Promise.all(parts.map((p) => partLeaf(secret, p)));
    const last = fixture('clean.jsonl').split('\n').filter(Boolean).map((l) => parseLine(l)!).filter((e) => e.type === 'checkpoint').pop()!;
    expect(hex((await merkleRoot(leaves))!)).toBe(last.root);
    expect(last.parts).toBe(parts.length);
    const d = { part: parts[1]!, salt: await partSalt(secret, parts[1]!.id), index: 1, parts: parts.length, path: await auditPath(leaves, 1) };
    expect(await verifyDisclosure(d, unhex(last.root as string)!)).toBe(true);
  });

  it('backdated: it verifies, and its times come out as the anchor’s, not the clock’s — and the output says so', async () => {
    const r = await verify({ files: [{ name: 'backdated.jsonl', text: fixture('backdated.jsonl') }] });
    expect(r.failed).toBe(false);
    const day = (t: number) => new Date(t).toISOString().slice(0, 10);
    // The computer's clock claims six months; the only outside evidence is one receipt, from the day it was made.
    expect(day(r.time.claimedFrom!)).toBe('2026-05-23');
    expect(day(r.time.anchoredFrom!)).toBe('2026-11-21');
    expect(r.time.anchoredTo).toBe(r.time.anchoredFrom);
    expect(r.time.longestUnanchored!.ms).toBeGreaterThan(100 * 86_400_000);
    const said = say(r).map((s) => s.text).join('\n');
    expect(said).toContain('The computer’s clock says this record covers 23 May 2026');
    expect(said).toContain('Outside evidence covers 21 November 2026');
    expect(said).toMatch(/The longest stretch with no outside timestamp is 1\d\d days/);
  });

  it('a record with no anchor at all says that every time in it is the computer’s own claim', async () => {
    const said = say(await verify({ files: [{ name: 'gap.jsonl', text: fixture('gap.jsonl') }] })).map((s) => s.text).join('\n');
    expect(said).toContain('Every time in this record is the computer’s own claim');
  });

  it('gap: each stretch the record can’t vouch for is listed, never passed over', async () => {
    const r = await verify({ files: [{ name: 'gap.jsonl', text: fixture('gap.jsonl') }] });
    expect(r.failed).toBe(false);
    expect(r.gaps.map((g) => g.why).sort()).toEqual(['changed-outside', 'failed', 'session-not-ended', 'torn']);
    expect(r.totals.changes.outside).toMatchObject({ count: 1 });
  });

  it('unknown-type: entries of a kind the verifier doesn’t know are chained, counted and passed over', async () => {
    const r = await verify({ files: [{ name: 'unknown-type.jsonl', text: fixture('unknown-type.jsonl') }] });
    expect(r.failed).toBe(false);
    expect(r.unknown).toEqual({ 'example.org:beat-placed': 2 });
    expect(r.totals.sources).toMatchObject({ typed: [20, 0], system: [6, 0], 'example.org:dictated': [5, 0] });
    expect(r.chains[0]!.entries).toBe(fixture('unknown-type.jsonl').split('\n').filter(Boolean).length);
    // Changing one of them breaks the chain like any other entry.
    const changed = fixture('unknown-type.jsonl').replace('"beats":3', '"beats":4');
    expect((await verify({ files: [{ name: 'x', text: changed }] })).failed).toBe(true);
  });

  it('unknown-version: refused whole, with a plain message, and nothing else claimed', async () => {
    const r = await verify({ files: [{ name: 'unknown-version.jsonl', text: fixture('unknown-version.jsonl') }] });
    expect(r.refused).toEqual({ version: 7, supported: 0 });
    expect(exitStatus(r)).toBe(2);
    expect(r.chains).toEqual([]);
    expect(say(r)).toEqual([{ status: 'failed', text: 'This record uses format version 7. This verifier understands versions up to 0. Nothing was checked. Use a newer verifier.' }]);
  });

  it('truncated: valid on its own; shown only by the manuscript and the head a reader holds', async () => {
    const alone = await verify({ files: [{ name: 'truncated.jsonl', text: fixture('truncated.jsonl') }] });
    expect(alone.failed).toBe(false);
    const withBoth = await verify({ files: [{ name: 'truncated.jsonl', text: fixture('truncated.jsonl') }], manuscript: manuscript(), expectHead: head });
    expect(withBoth.findings.map((f) => f.code)).toEqual(expect.arrayContaining(['head-missing', 'manuscript-no-match']));
  });
});
