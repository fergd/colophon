// Builds verify/web/verify.html: one file holding the whole verifier, which checks a dropped record in the page.
// Its Content-Security-Policy names the hashes of its own script and style and allows nothing else: no network.
//
//   node packages/provenance/scripts/build-web.ts

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const WEB = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'verify', 'web');
const b64 = (text: string) => createHash('sha256').update(text).digest('base64');

/** The page, built from its sources. */
export async function webPage(): Promise<string> {
  const out = await build({ entryPoints: [path.join(WEB, 'app.ts')], bundle: true, format: 'iife', platform: 'browser', target: 'es2022', minify: true, write: false, legalComments: 'none' });
  // (a closing script tag inside the script would end it early)
  const js = out.outputFiles[0]!.text.replace(/<\/script/gi, '<\\/script');
  const css = readFileSync(path.join(WEB, 'style.css'), 'utf8');
  return readFileSync(path.join(WEB, 'template.html'), 'utf8')
    .replace('__SCRIPT__', () => b64(js)).replace('__STYLE__', () => b64(css))
    .replace('__CSS__', () => css).replace('__JS__', () => js);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  writeFileSync(path.join(WEB, 'verify.html'), await webPage());
  process.stderr.write('wrote verify/web/verify.html\n');
}
