# Colophon

*Colophon: in a book, the note that says how it was made. Format version 0 is a draft: it is not frozen and has not had an outside security review. Nothing here should be used to make a public claim.*

A writing app can keep a **record** of how a text was written: when it was worked on, how the words arrived (typed, pasted, imported, moved, cut), and a fingerprint of the manuscript at each save. This package is that record's format, a library that writes and checks it, and two verifiers anyone can run.

- **The format** is in [`docs/SPEC.md`](docs/SPEC.md).
- **What a record is evidence of, and what it is not,** is in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Read it before relying on a record for anything.

## What a record shows

- **That it has not been altered** since it was written. Each entry names the hash of the one before; signatures cover the chain.
- **That it existed no later than certain moments.** Receipts from outside timestamp services are stored in the record. This is the only hard evidence in it.
- **What the writing app wrote down at the time:** counts and times. Never the text.

## What it cannot show

- That a person composed the words. Typing out text from elsewhere is recorded as typing.
- Who wrote it. A record is tied to a key, not a person.
- That the software writing it was honest.
- That it is complete. A record cut short looks like a whole one; compare it with the manuscript.

There is no score and no verdict. The verifier says what held, what failed and where, and what it could not check.

## Checking a record

Command line (Node 22.18 or later, no install step, no network):

```
node verify/cli/verify.ts record.jsonl manuscript.md
node verify/cli/verify.ts record.jsonl --head <entry hash you were given> --json
```

Exit status: `0` nothing failed, `1` something failed, `2` the record could not be read or is in a version this verifier does not know.

In a browser: open [`verify/web/verify.html`](verify/web/verify.html) and drop the files on it. It is one file, works from disk, and its Content-Security-Policy allows no network request of any kind.

By hand, the chain itself: `sed -n 56p record.jsonl | tr -d '\n' | shasum -a 256` prints the `prev` of line 57.

## Writing a record

```ts
import { Chain, partLeaf, sha256 } from './src/index.ts';

const chain = await Chain.begin({ storage, clock, signer }, { how: 'new', unit: 'words', words: 0 });
await chain.sessionStart({ app: { name: 'My Editor', version: '1.0' }, platform: 'darwin', words: 0 });
await chain.activity(Date.now(), [{ i: 0, w: { typed: [38, 4] } }]);
await chain.checkpoint({ file: await sha256(savedBytes), words: 34, leaves });
await chain.seal();
await chain.anchor(timestampService);
```

The host supplies four small things ([`src/ports.ts`](src/ports.ts)): **storage** (append text, read it back), a **signer** (ECDSA P-256 or Ed25519), an **anchor service** (send a hash, get a receipt) and a **clock**. The core touches no file, key, network or clock itself and runs anywhere WebCrypto does. `src/testing` has stand-ins for all four.

Two rules for a host:

- **A record failure must never block, delay or fail a save.** Write the record after the manuscript is safely saved; if the record cannot be written, write a `gap` when it can.
- **Never put prose in a record:** no text, no titles, no file names (SPEC §13).

## Layout

| | |
|---|---|
| `src/core/` | Canonical form, hashing, entries, the Merkle tree, writing a chain, verifying, the verifier's sentences, receipt verification (`anchors/`). |
| `src/ports.ts` | What a host supplies. |
| `src/testing/` | In-memory storage, a software signer, a fake anchor, a clock set by hand. |
| `verify/cli`, `verify/web` | The two verifiers. |
| `fixtures/v0/` | Test records, frozen once version 0 is released. `fixtures/receipts/` holds genuine receipts. |
| `scripts/` | `build-web.ts` (rebuild the page after changing the core), `bench.ts`, `make-fixtures.ts` (once per format version; the only code here that uses the network). |

## Dependencies

None at run time. Hashing, signatures and RSA/ECDSA verification are the platform's WebCrypto. The readers for RFC 3161 receipts (ASN.1 DER, CMS, X.509) and OpenTimestamps proofs are written here, because no small, audited JavaScript library for either was found; they are the first thing an outside review should read. Development uses `vitest`, `fast-check` and `esbuild`.

## Licence

Code: Apache-2.0 ([`LICENSE`](LICENSE)). The documents in `docs/`: CC BY 4.0.

## Patents

Apache-2.0 includes a patent licence for the code in this repository. So that you can also write your own implementation of the format from the specification alone, without using this code, the specification is offered under the Open Web Foundation's **Final Specification Agreement, OWFa 1.0 (Patent and Copyright Grants)**, signed by its author: [`OWFa-1.0.md`](OWFa-1.0.md).

In short, and the agreement itself is what counts: the author promises not to assert any patent claims they hold, now or later, against anyone implementing the specification; the promise covers an implementation that implements all of the specification's required parts, and only those parts; it ends for anyone who sues claiming that implementing the specification infringes their patents. It says nothing about patents held by others.

## The name

"Colophon" is this format's name. The licences cover the code and the documents, not the name. Implement the format, fork it, adapt it: all welcome. Saying that your software "writes Colophon records" or "checks Colophon records" when it follows the specification is welcome too. Please don't call a changed version of the format "Colophon", or suggest that this project endorses your software, without asking first.
