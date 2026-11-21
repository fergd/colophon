// What the recorder costs (the brief): appending an activity entry, and a checkpoint on a 150,000-word book in
// 400 scenes. Phase 2 holds these against the save pipeline's 52 ms. Storage is memory: a real append adds one
// write and sync.
//
//   node packages/colophon/scripts/bench.ts [path to a large manuscript]

import { readFileSync } from 'node:fs';
import { Chain, partLeaf, sha256, utf8, type Part } from '../src/index.ts';
import { MemoryStorage, softwareSigner, TestClock } from '../src/testing/index.ts';

const WORDS = 150_000;
const SCENES = 400;
const source = process.argv[2] ? readFileSync(process.argv[2], 'utf8') : 'lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua '.repeat(20_000);
const words = source.split(/\s+/).filter(Boolean);
while (words.length < WORDS) words.push(...words.slice(0, WORDS - words.length));
const per = Math.ceil(WORDS / SCENES);
const parts: Part[] = Array.from({ length: SCENES }, (_, i) => ({ id: `scene${i}`, content: utf8(words.slice(i * per, (i + 1) * per).join(' ')) }));
const file = utf8(parts.map((p) => new TextDecoder().decode(p.content)).join('\n\n'));
const secret = new Uint8Array(32).fill(9);

async function time(label: string, runs: number, fn: () => Promise<unknown>) {
  const samples: number[] = [];
  for (let i = 0; i < runs; i++) { const t = performance.now(); await fn(); samples.push(performance.now() - t); }
  samples.sort((a, b) => a - b);
  const at = (q: number) => samples[Math.min(samples.length - 1, Math.floor(q * samples.length))]!;
  process.stdout.write(`${label.padEnd(64)} median ${at(0.5).toFixed(2)} ms   p95 ${at(0.95).toFixed(2)} ms\n`);
}

for (const alg of ['ed25519', 'ecdsa-p256-sha256'] as const) {
  const clock = new TestClock();
  const chain = await Chain.begin({ storage: new MemoryStorage(), clock, signer: await softwareSigner(alg) }, { how: 'new', unit: 'words', words: 0 });
  await chain.sessionStart({ app: { name: 'bench', version: '0' }, platform: 'darwin', words: 0 });
  process.stdout.write(`\n${alg} · ${(file.length / 1024).toFixed(0)} KB manuscript, ${words.length.toLocaleString()} words, ${SCENES} scenes\n`);
  await time('append an activity entry (5 rows)', 500, () => chain.activity(clock.now(), [0, 1, 2, 3, 4].map((i) => ({ i, w: { typed: [40, 3] as [number, number] } }))));
  await time('seal', 300, () => chain.seal());
  let leaves = await Promise.all(parts.map((p) => partLeaf(secret, p)));
  await time('checkpoint, every scene hashed afresh (the first save)', 30, async () => {
    leaves = await Promise.all(parts.map((p) => partLeaf(secret, p)));
    await chain.checkpoint({ file: await sha256(file), words: WORDS, leaves });
  });
  await time('checkpoint, one scene changed (leaves kept by the host)', 100, async () => {
    leaves[17] = await partLeaf(secret, parts[17]!);
    await chain.checkpoint({ file: await sha256(file), words: WORDS, leaves, changed: 1 });
  });
  await time('…of which the file’s hash alone', 100, () => sha256(file));
  await time('checkpoint + seal, one scene changed', 100, async () => {
    leaves[17] = await partLeaf(secret, parts[17]!);
    await chain.checkpoint({ file: await sha256(file), words: WORDS, leaves, changed: 1 });
    await chain.seal();
  });
}
