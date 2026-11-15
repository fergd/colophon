// The two verifiers anyone can run: the command line, and one HTML file that works offline.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { webPage } from '../scripts/build-web.ts';
import { fixture, ROOT } from './helpers.ts';

const cli = (...args: string[]) => spawnSync(process.execPath, [path.join(ROOT, 'verify', 'cli', 'verify.ts'), ...args], { encoding: 'utf8', cwd: path.join(ROOT, 'fixtures', 'v0') });

describe('verify <record> [manuscript]', () => {
  it('nothing failed: exit 0, with what was checked and what was not', () => {
    const r = cli('clean.jsonl', 'clean.manuscript.md', '--head', fixture('clean.head.txt').trim());
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('held         Chain intact: all 15 entries');
    expect(r.stdout).toContain('The manuscript you supplied is, byte for byte');
    expect(r.stdout).toContain('not checked  A receipt at entry 6 is not yet final');
    expect(r.stdout).not.toMatch(/FAILED/);
  });

  it('something failed: exit 1, and where', () => {
    const r = cli('edited.jsonl');
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('FAILED       Altered: line 4 of edited.jsonl does not follow the line before it.');
  });

  it('could not be checked but nothing failed: exit 0 with the limits said', () => {
    const r = cli('gap.jsonl');
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('not checked  No outside timestamps were verified.');
    expect(r.stdout).toContain('not checked  No manuscript was supplied');
  });

  it('an unknown version, a file that isn’t a record, no file: exit 2', () => {
    expect(cli('unknown-version.jsonl').status).toBe(2);
    expect(cli('unknown-version.jsonl').stdout).toContain('Nothing was checked');
    expect(cli('clean.manuscript.md').status).toBe(2);
    expect(cli('no-such-file.jsonl').status).toBe(2);
    expect(cli().status).toBe(2);
  });

  it('--json gives the structured result', () => {
    const r = cli('two-devices.jsonl', '--json');
    const result = JSON.parse(r.stdout) as { chains: unknown[]; failed: boolean };
    expect(result.chains).toHaveLength(2);
    expect(result.failed).toBe(false);
  });
});

describe('the web verifier: one file, no network', () => {
  const html = readFileSync(path.join(ROOT, 'verify', 'web', 'verify.html'), 'utf8');

  it('is what its sources build (run scripts/build-web.ts after changing the core)', async () => {
    expect(html).toBe(await webPage());
  });

  it('its policy allows nothing but its own script and style, named by their hashes', () => {
    const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html)![1]!;
    const script = /<script>([\s\S]*)<\/script>/.exec(html)![1]!;
    const style = /<style>([\s\S]*?)<\/style>/.exec(html)![1]!;
    const sha = (t: string) => createHash('sha256').update(t).digest('base64');
    expect(csp).toBe(`default-src 'none'; script-src 'sha256-${sha(script)}'; style-src 'sha256-${sha(style)}'; base-uri 'none'; form-action 'none'`);
    // (default-src 'none' covers connect-src, img-src, font-src, frame-src…: no request of any kind can leave the page)
    expect(csp).not.toMatch(/connect-src|https?:|\*|unsafe/);
  });

  it('is self-contained: no other file, no address, nothing that asks the network', () => {
    expect(html).not.toMatch(/<link|<img|<iframe|<script[^>]+src|@import|url\(/i);
    const script = /<script>([\s\S]*)<\/script>/.exec(html)![1]!;
    expect(script).not.toMatch(/\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts|\bimport\s*\(|new\s+Worker|\.src\s*=|location\s*(\.href)?\s*=/);
    // The only addresses in it are text: none (the trusted roots are certificates, not places).
    expect(html.match(/https?:\/\/[^\s"'<)]+/g) ?? []).toEqual([]);
    expect(html.length).toBeLessThan(200_000);
  });
});
