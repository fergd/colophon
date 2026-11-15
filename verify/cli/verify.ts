#!/usr/bin/env node
// verify <record>… [manuscript] [--head <entry hash>] [--key <fingerprint>] [--json]
//
// Prints what was checked, what held, what failed and where, and what could not be checked (SPEC §10).
// Exit status: 0 nothing failed (there may be things not checked); 1 something failed; 2 the record could not be
// read, or is in a format version this verifier doesn't know. Reads files; uses no network.

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, exitStatus, parseLine, verify, VERIFIER } from '../../src/index.ts';

const LABEL = { held: 'held       ', failed: 'FAILED     ', unchecked: 'not checked', note: 'note       ' } as const;

function usage(): never {
  process.stderr.write('usage: verify <record.jsonl>… [manuscript] [--head <entry hash>] [--key <fingerprint>] [--json]\n');
  process.exit(2);
}

/** A file is part of a record when its first line is an entry; anything else is taken as the manuscript. */
function isRecord(bytes: Uint8Array): string | null {
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { return null; }
  const first = parseLine(text.slice(0, text.indexOf('\n') < 0 ? undefined : text.indexOf('\n')));
  return first && typeof first.type === 'string' && typeof first.v === 'number' ? text : null;
}

async function main(argv: string[]): Promise<number> {
  const files: { name: string; text: string }[] = [];
  let manuscript: Uint8Array<ArrayBuffer> | undefined;
  let expectHead: string | undefined;
  let expectKey: string | undefined;
  let json = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--json') json = true;
    else if (a === '--head') expectHead = argv[++i] ?? usage();
    else if (a === '--key') expectKey = argv[++i] ?? usage();
    else if (a.startsWith('--')) usage();
    else {
      let bytes: Uint8Array<ArrayBuffer>;
      try { bytes = new Uint8Array(readFileSync(a)); } catch { process.stderr.write(`cannot read ${a}\n`); return 2; }
      const text = isRecord(bytes);
      if (text !== null) files.push({ name: path.basename(a), text });
      else if (!manuscript) manuscript = bytes;
      else { process.stderr.write(`${a} is not a record, and a manuscript was already given\n`); return 2; }
    }
  }
  if (!files.length) usage();
  const result = await verify({ files, manuscript, expectHead, expectKey });
  if (json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  else {
    process.stdout.write(`Record check (verifier ${VERIFIER})\n\n`);
    for (const s of describe(result)) process.stdout.write(`${LABEL[s.status]}  ${s.text}\n`);
  }
  return exitStatus(result);
}

process.exitCode = await main(process.argv.slice(2));
