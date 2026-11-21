// The package stands alone (the brief's ground rules): it imports nothing outside itself, its core uses nothing a
// browser lacks, and the whole verifier runs where there is no Node at all. (That an app using it reaches only its
// entry is the app's own test to keep: Baretext's is app/main/test/colophon-boundary.test.ts.)
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
import { build } from 'esbuild';
import { describe, expect, it } from 'vitest';
import { fixture, ROOT } from './helpers.ts';

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = path.join(dir, n);
    return statSync(p).isDirectory() ? (n === 'node_modules' ? [] : files(p)) : n.endsWith('.ts') ? [p] : [];
  });
}
const imports = (file: string) => [...readFileSync(file, 'utf8').matchAll(/(?:^|\n)\s*(?:import|export)[^'"\n]*?from\s+['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)/g)].map((m) => m[1] ?? m[2]!);

describe('the package imports nothing outside itself', () => {
  it('every relative import stays inside the package; nothing names another package of this repository', () => {
    for (const file of files(ROOT)) for (const spec of imports(file)) {
      if (spec.startsWith('.')) expect(path.resolve(path.dirname(file), spec).startsWith(ROOT + path.sep), `${file} imports ${spec}`).toBe(true);
      else expect(spec, `${file} imports ${spec}`).toMatch(/^(node:[a-z/_]+|vitest(\/config)?|fast-check|esbuild)$/);
    }
  });

  it('the core, the ports and the stand-ins use only what a browser has: no Node module, global or API', () => {
    for (const file of files(path.join(ROOT, 'src'))) {
      const text = readFileSync(file, 'utf8').replace(/\/\/.*$/gm, ''); // (what the code does, not what its comments say)
      for (const spec of imports(file)) expect(spec.startsWith('.'), `${file} imports ${spec}`).toBe(true);
      expect(text, file).not.toMatch(/\b(Buffer|process|require|__dirname|__filename|globalThis\.process|setImmediate)\b(?!['’])/);
    }
  });
});

describe('the verifier runs with no Node', () => {
  it('bundled for a browser and run where only web globals exist, it checks a record and reads a genuine receipt', async () => {
    const out = await build({ entryPoints: [path.join(ROOT, 'src', 'index.ts')], bundle: true, format: 'iife', globalName: 'colophon', platform: 'browser', target: 'es2022', write: false });
    // A fresh realm: the language's own objects, plus the five web globals the core uses. No process, Buffer or require.
    const context = vm.createContext({ crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob });
    expect(vm.runInContext('typeof process + typeof Buffer + typeof require + typeof module', context)).toBe('undefinedundefinedundefinedundefined');
    vm.runInContext(out.outputFiles[0]!.text, context);
    context.text = fixture('clean.jsonl');
    const r = JSON.parse(await vm.runInContext('colophon.verify({ files: [{ name: "clean.jsonl", text }] }).then((r) => JSON.stringify({ failed: r.failed, anchors: r.anchors.map((a) => a.status), codes: r.findings.map((f) => f.code), said: colophon.describe(r).length }))', context) as string) as { failed: boolean; anchors: string[]; codes: string[]; said: number };
    expect(r.failed).toBe(false);
    expect(r.anchors).toEqual(['held', 'pending']);
    expect(r.codes).toEqual(expect.arrayContaining(['chain-intact', 'signed']));
    expect(r.said).toBeGreaterThan(4);
  });
});
