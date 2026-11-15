import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Chain, hex, partLeaf, sha256, utf8, type Part } from '../src/index.ts';
import { MemoryStorage, seededRandom, softwareSigner, TestClock } from '../src/testing/index.ts';

export const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
export const fixture = (name: string) => readFileSync(path.join(ROOT, 'fixtures', 'v0', name), 'utf8');
export const fixtureBytes = (name: string) => new Uint8Array(readFileSync(path.join(ROOT, 'fixtures', name)));
export const runs = (fallback: number) => ({ numRuns: Number(process.env.FC_RUNS) || fallback, seed: Number(process.env.FC_SEED) || undefined });
export const MIN = 60_000;
export const SECRET = new Uint8Array(32).fill(3);

export function parts(n: number, salt = ''): Part[] {
  return Array.from({ length: n }, (_, i) => ({ id: `p${i}`, content: utf8(`part ${i} ${salt}`) }));
}

/** A small signed record ending on a seal: its storage, its chain, its clock. */
export async function record(sessions = 2, alg: 'ed25519' | 'ecdsa-p256-sha256' = 'ed25519') {
  const clock = new TestClock();
  const storage = new MemoryStorage();
  const signer = await softwareSigner(alg);
  const chain = await Chain.begin({ storage, clock, signer, random: seededRandom(7) }, { how: 'new', unit: 'words', words: 0 });
  let words = 0;
  for (let s = 0; s < sessions; s++) {
    await chain.sessionStart({ app: { name: 'Test', version: '1' }, platform: 'darwin', words });
    clock.advance(2 * MIN);
    await chain.activity(clock.now(), [{ i: 0, w: { typed: [40 + s, 3] } }, { i: 1, w: { pasted: [5, 0] }, pastes: [5] }]);
    words += 42 + s;
    const file = utf8(`manuscript after session ${s}`);
    await chain.checkpoint({ file: await sha256(file), words, leaves: await Promise.all(parts(3, String(s)).map((p) => partLeaf(SECRET, p))) });
    await chain.seal();
    clock.advance(MIN);
    await chain.sessionEnd('closed');
    await chain.seal();
    clock.advance(600 * MIN);
  }
  return { storage, chain, clock, signer, words, lastFile: utf8(`manuscript after session ${sessions - 1}`) };
}

export const failed = (r: { findings: { status: string; code: string }[] }) => r.findings.filter((f) => f.status === 'failed').map((f) => f.code);
export { hex };
