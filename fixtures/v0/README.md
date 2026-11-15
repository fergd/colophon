# Test records, format version 0

Each `.jsonl` here is a record. `EXPECTED.json` holds what the verifier of the day said about each (exit status, failures and where, notes, receipts). `../v0.manifest.json` holds every file's SHA-256: **once version 0 is released these files are frozen**, and a test fails if one changes. Until then they may be made again with `scripts/make-fixtures.ts`.

The text in them is placeholder Latin. The app named in them, "Example Writer", does not exist.

| File | What it is | What a verifier says |
|---|---|---|
| `clean.jsonl` | One device, two sessions, signed with ECDSA P-256, ending on a seal. Holds a **genuine RFC 3161 receipt** from FreeTSA and a genuine, still pending, OpenTimestamps receipt. | Intact, signed, one receipt valid, one not yet final. |
| `clean.manuscript.md` | The manuscript that record ends on. | Matches the last checkpoint. |
| `clean.head.txt` | The record's last entry hash, as a reader might have been given it. | |
| `clean.secret.hex` | The secret its part salts come from. A real one never leaves the writer; this one is here so a test can open one part. | |
| `edited.jsonl` | Attack 1: one count changed in one entry. | Fails at the next line. |
| `reordered.jsonl` | Attack 1: two lines swapped. The chain is rebuilt from hashes, so it holds. | A note: a line out of place. |
| `spliced.jsonl` | Attack 1: one entry removed from the middle. | Fails at the line that followed it. |
| `truncated.jsonl` | Attack 2: the second session cut off at the end of a line. **Valid on its own.** | Shown only by the manuscript (no match) and the expected head (missing). |
| `torn.jsonl` | The app stopped mid-write: an incomplete last line. | A note; the line is ignored. |
| `backdated.jsonl` | Attack 3: a whole record made in one go, its clock set six months back, with a genuine receipt from the day it was made. | Verifies. Claimed span: May to November. Outside evidence: one day. |
| `forked.jsonl` | Attack 4: two signed continuations of one point. | Fails: two versions exist. |
| `wrong-key.jsonl` | Attack 9 in reverse: the last seal made by a key the record never named. | Signature invalid. |
| `two-devices.jsonl` | Two chains in one file, the second seeing the first. Ed25519 and P-256. | Two devices, intact. |
| `two-devices-cut.jsonl` | The first device's chain cut back after the second saw it. | Fails: this copy is shorter than the record once was. |
| `gap.jsonl` | A write cut short and mended, a stretch the recorder could not write, a change made outside the app, a session never closed. | No failure; four stretches it cannot vouch for. |
| `unknown-type.jsonl` | Entries of a type, and a source, the verifier does not know; a key change signed by the old key. | Chained, counted, passed over. |
| `unknown-version.jsonl` | An entry in format version 7. | Refused whole. |
