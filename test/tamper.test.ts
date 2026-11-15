// Tampering (THREAT_MODEL attacks 1–4): what each change to a valid record makes the verifier say, and where.
// The limits are tested as limits: a record cut at the end of a line is a valid shorter record, and shows only
// against something outside it (SPEC §15, item 4).
import { beforeAll, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { verify, type Result } from '../src/index.ts';
import { failed, record, runs } from './helpers.ts';

let text = '';
let lines: string[] = [];
let head = '';
let lastFile = new Uint8Array(0);
beforeAll(async () => {
  const r = await record(2);
  text = r.storage.text;
  lines = r.storage.lines;
  head = r.chain.head.hash;
  lastFile = r.lastFile;
});
const check = (t: string, more: object = {}) => verify({ files: [{ name: 'r.jsonl', text: t }], ...more });
const lineOf = (index: number) => text.slice(0, index).split('\n').length; // (1-based)
const reportedAt = (r: Result) => r.findings.filter((f) => f.status === 'failed' && f.line !== undefined).map((f) => f.line!);
const CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}[]":,.-_ \\\n';

describe('a valid record, changed', () => {
  it('is valid to begin with, and ends on a seal', async () => {
    expect(failed(await check(text, { expectHead: head, manuscript: lastFile }))).toEqual([]);
    expect(lines[lines.length - 1]).toContain('"type":"seal"');
  });

  it('any single character changed is reported, at its line or the next', async () => {
    await fc.assert(fc.asyncProperty(fc.nat(text.length - 1), fc.nat(CHARS.length - 1), async (at, c) => {
      const to = CHARS[c]!;
      fc.pre(text[at] !== to);
      const r = await check(text.slice(0, at) + to + text.slice(at + 1));
      const line = lineOf(at);
      if (r.refused) return; // (the version itself was changed: refused whole, nothing claimed)
      // In the last line, the one change a signature can't catch turns the seal into another kind of entry: it is
      // then reported as an entry no signature covers.
      const uncovered = line >= lines.length && r.findings.some((f) => f.code === 'unsealed-tail');
      expect(failed(r).length > 0 || uncovered, `changed ${JSON.stringify(text[at])} to ${JSON.stringify(to)} at ${at} (line ${line})`).toBe(true);
      if (!uncovered) expect(reportedAt(r).some((n) => n === line || n === line + 1 || n === line - 1), `reported at ${reportedAt(r)} for line ${line}`).toBe(true);
    }), runs(600));
  });

  it('any line removed is reported at the line that followed it; the last line removed shows against the head a reader holds', async () => {
    for (let i = 0; i < lines.length; i++) {
      const cut = `${lines.filter((_, j) => j !== i).join('\n')}\n`;
      const r = await check(cut, { expectHead: head });
      if (i === 0) expect(failed(r)).toContain('broken'); // (no first entry: nothing left to follow)
      else if (i < lines.length - 1) expect(r.findings).toEqual(expect.arrayContaining([expect.objectContaining({ status: 'failed', code: 'broken', line: i + 1 })]));
      else {
        expect(failed(r)).toEqual(['head-missing']);
        // Without something outside the record, a shorter record is only a record whose last entries aren't sealed.
        const alone = await check(cut);
        expect(failed(alone)).toEqual([]);
        expect(alone.findings.map((f) => f.code)).toContain('unsealed-tail');
        expect(alone.chains[0]!.head).not.toBe(head);
      }
    }
  });

  it('any two lines swapped: the chain is rebuilt from the hashes and holds, and the line out of place is said', async () => {
    await fc.assert(fc.asyncProperty(fc.nat(lines.length - 1), fc.nat(lines.length - 1), async (a, b) => {
      fc.pre(a < b);
      const swapped = [...lines];
      [swapped[a], swapped[b]] = [swapped[b]!, swapped[a]!];
      const r = await check(`${swapped.join('\n')}\n`, { expectHead: head });
      expect(failed(r)).toEqual([]);
      expect(r.chains[0]!.head).toBe(head);
      const out = r.findings.filter((f) => f.code === 'out-of-order').map((f) => f.line);
      expect(out).toContain(b + 1); // (the earlier entry, now sitting after later ones)
    }), runs(100));
  });

  it('cut at any point: a broken last line is said; a clean cut is a shorter record, shown by the head, the manuscript, or nothing', async () => {
    await fc.assert(fc.asyncProperty(fc.integer({ min: 1, max: text.length - 1 }), async (at) => {
      const cut = text.slice(0, at);
      const r = await check(cut, { expectHead: head, manuscript: lastFile });
      expect(failed(r)).toContain('head-missing');
      const alone = await check(cut);
      if (!cut.endsWith('\n')) expect(alone.findings).toEqual(expect.arrayContaining([expect.objectContaining({ code: 'incomplete-last-line', line: lineOf(at) })]));
      // What a cut can never do: leave a record that still ends where the whole one did.
      expect(alone.chains[0]?.head).not.toBe(head);
    }), runs(300));
    // A cut right after the first session's last seal: nothing inside the record shows it.
    const firstEnd = lines.findIndex((l, i) => i > 0 && l.includes('"type":"seal"') && lines[i - 1]!.includes('"session.end"'));
    const short = `${lines.slice(0, firstEnd + 1).join('\n')}\n`;
    const alone = await check(short);
    expect(failed(alone)).toEqual([]);
    expect(alone.findings.map((f) => f.code)).not.toContain('unsealed-tail');
    // …the manuscript does: it is not the one this record ends on.
    const withBook = await check(short, { manuscript: lastFile });
    expect(withBook.manuscript).toMatchObject({ given: true, match: 'none' });
  });

  it('a line put in, a line repeated, a line from another record: each breaks the chain there', async () => {
    const other = (await record(1)).storage.lines;
    const changed = lines[2]!.replace('"typed":[40', '"typed":[41');
    expect(changed).not.toBe(lines[2]);
    for (const extra of [changed, other[2]!]) {
      const r = await check(`${[...lines.slice(0, 4), extra, ...lines.slice(4)].join('\n')}\n`);
      expect(failed(r).length).toBeGreaterThan(0);
      expect(reportedAt(r)).toContain(5);
    }
    // (the very same line twice is the same entry twice: nothing is added by it)
    expect(failed(await check(`${[...lines.slice(0, 4), lines[3], ...lines.slice(4)].join('\n')}\n`))).toEqual([]);
  });

  it('a whole chain rewritten by someone without the key: every seal fails', async () => {
    const { storage } = await record(1);
    const mine = storage.lines;
    const forged = (await record(1)).storage.lines; // (another key's record, with this record's first entry's key claimed)
    const r = await check(`${[mine[0], ...forged.slice(1)].join('\n')}\n`);
    expect(failed(r).length).toBeGreaterThan(0);
  });

  it('two continuations of one point: a fork, said as two versions', async () => {
    const a = await record(1);
    const base = a.storage.text;
    await a.chain.gap({ why: 'off' });
    await a.chain.seal();
    const one = a.storage.text;
    a.storage.text = base;
    const again = await (await import('../src/index.ts')).Chain.open({ storage: a.storage, clock: a.clock, signer: a.signer });
    await again.gap({ why: 'failed' });
    await again.seal();
    const r = await check(one + a.storage.text.slice(base.length));
    expect(failed(r)).toContain('fork');
  });
});
