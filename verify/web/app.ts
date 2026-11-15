// The page's own code: files dropped on it are read in the page and checked there. It makes no network request
// (the page's Content-Security-Policy allows none), and it writes what it read as text, never as markup.

import { describe, parseLine, verify, VERIFIER, type Sentence } from '../../src/index.ts';

const LABEL: { [status in Sentence['status']]: string } = { held: 'Held', failed: 'Failed', unchecked: 'Not checked', note: 'Note' };
const $ = (id: string) => document.getElementById(id)!;

function isRecord(bytes: Uint8Array): string | null {
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { return null; }
  const end = text.indexOf('\n');
  const first = parseLine(end < 0 ? text : text.slice(0, end));
  return first && typeof first.type === 'string' && typeof first.v === 'number' ? text : null;
}

async function check(list: File[]) {
  const out = $('result');
  out.replaceChildren();
  const files: { name: string; text: string }[] = [];
  let manuscript: Uint8Array<ArrayBuffer> | undefined;
  const names: string[] = [];
  for (const f of list) {
    const bytes = new Uint8Array(await f.arrayBuffer());
    const text = isRecord(bytes);
    if (text !== null) { files.push({ name: f.name, text }); names.push(`${f.name} (record)`); }
    else if (!manuscript) { manuscript = bytes; names.push(`${f.name} (manuscript)`); }
    else names.push(`${f.name} (ignored: a manuscript was already given)`);
  }
  $('given').textContent = names.join(' · ');
  if (!files.length) { line(out, 'failed', 'None of these files is a record.'); return; }
  const head = ($('head') as HTMLInputElement).value.trim() || undefined;
  const result = await verify({ files, manuscript, expectHead: head });
  for (const s of describe(result)) line(out, s.status, s.text);
}

function line(out: HTMLElement, status: Sentence['status'], text: string) {
  const row = document.createElement('li');
  row.dataset.status = status;
  const label = document.createElement('span');
  label.className = 'status';
  label.textContent = LABEL[status];
  const body = document.createElement('span');
  body.textContent = text;
  row.append(label, body);
  out.append(row);
}

$('version').textContent = VERIFIER;
const drop = $('drop');
const input = $('files') as HTMLInputElement;
input.addEventListener('change', () => { void check([...(input.files ?? [])]); });
for (const type of ['dragenter', 'dragover']) drop.addEventListener(type, (e) => { e.preventDefault(); drop.dataset.over = 'true'; });
drop.addEventListener('dragleave', () => { delete drop.dataset.over; });
drop.addEventListener('drop', (e) => {
  e.preventDefault();
  delete drop.dataset.over;
  void check([...(e.dataTransfer?.files ?? [])]);
});
