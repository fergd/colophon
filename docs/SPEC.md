# The record format, version 0

*Draft for review, 10 November 2026. Its name is **Colophon** (chosen 21 November 2026): in a book, the colophon is the note that says how it was made. Licensed CC BY 4.0. Read `THREAT_MODEL.md` first: it says what a record is evidence of. This document says how one is built and checked.*

**Status:** version 0 is not frozen. It freezes on the day a build that writes it reaches any writer. From then on, nothing in this document may change in a way that alters how a version 0 record is read.

## 1. The format on one page

A **record** describes how one book was written. It is one or more plain text files. Each line is one **entry**, written as JSON. A typical few lines, shortened:

```
{"type":"session.start","seq":812,"t":1794000000000,"prev":"9f2c…","v":0, …}
{"type":"activity","seq":813,"t":1794000300000,"prev":"41ab…","v":0,"rows":[{"i":0,"w":{"typed":[38,4]}}, …], …}
{"type":"checkpoint","seq":814,"t":1794000301000,"prev":"c07e…","v":0,"file":"5d1e…","root":"88a0…","words":151234, …}
{"type":"seal","seq":815,"t":1794000301050,"prev":"77b3…","v":0,"sig":"MEUC…"}
```

Five ideas carry the whole design:

1. **A chain.** Every entry contains `prev`, the SHA-256 hash of the exact bytes of the line before it. Changing, removing or reordering any line breaks the next one. Anyone can check this with a standard hashing tool.
2. **Counts, never words.** An **activity** entry says how many words arrived in each minute and by what route: typed, pasted, moved and so on. No entry of any kind holds the writer's text, a title or a file name.
3. **Checkpoints.** At a save, a **checkpoint** entry records a hash of the manuscript file and one hash summarising all its scenes. Later, the writer can show that a file, or a single scene, is the one a checkpoint committed to, without revealing anything else.
4. **Seals.** A **seal** entry is a digital signature, by the device's key, over the chain so far.
5. **Anchors.** An **anchor** entry stores a receipt from an outside timestamp service for an earlier entry's hash. It shows that the chain up to that entry existed no later than the receipt's time. This is the only time in a record that does not rest on the writer's own computer.

A book written on several computers has one **chain per device**, each written only by that device, so syncing the files between computers can never produce a conflict. A verifier reads all the chains and reports on them together.

A **verifier** reads a record (and, optionally, the manuscript) and reports what it checked, what held, what failed and where, what it could not check, the time bounds, the totals by source, and the gaps. It gives no verdict and no score.

The sections below make each of these exact. The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 2. Lines, encoding and the canonical form

**Decision: JSON Lines; canonical form RFC 8785 (JCS) with integers only; hashes are taken over the line's bytes, not over a re-serialization.**

- A record file is UTF-8 without a byte order mark. Each entry is one line, ended by a single line feed (0x0A). No blank lines. A line is at most 1,048,576 bytes.
- Each line is a JSON object in the canonical form of RFC 8785: members sorted by key, no insignificant white space, strings escaped as that RFC says.
- **Numbers are integers** between −(2^53 − 1) and 2^53 − 1, written as plain decimal digits. No fractions, no exponents. This removes the one hard part of RFC 8785 (floating-point formatting), so a canonical writer is a few dozen lines in any language.
- Member names in entries defined here are lower-case ASCII.
- Binary values are base64url without padding (RFC 4648 §5). Hashes are lower-case hexadecimal.

**The entry hash** of a line is the SHA-256 of its bytes, excluding the line feed. It is the entry's identity everywhere in this format: in `prev`, in references between chains, in what is sealed and in what is anchored.

*Why hash the bytes and not the parsed entry.* The usual design stores a hash inside each entry and recomputes it by removing that field and serializing again. That makes the chain's validity depend on every verifier, forever, serializing exactly as the writer did. Here the canonical form is a rule for **writers**; the chain is checked from bytes alone. Consequences:

- The chain can be checked by hand: `sed -n 56p record.jsonl | tr -d '\n' | shasum -a 256` gives the `prev` of line 57.
- An entry of a type the verifier has never seen is chained and checked exactly like any other.
- A line that is valid JSON but not canonical does not break the chain. The verifier reports it ("line N is not in canonical form: written by software that does not follow the format"), as a warning.
- There is no hash of an entry inside itself. The last line of a chain is therefore covered by nothing until another entry follows it. See §10 and attack 1 in the threat model.

## 3. The envelope

Every entry has these members:

| Member | Type | Meaning |
|---|---|---|
| `v` | integer | Format version. `0` here. |
| `type` | string | Entry type (§5). |
| `seq` | integer | Position in its chain, from 0, increasing by 1. |
| `prev` | string, 64 hex | Entry hash of the previous entry in the chain. **Absent when `seq` is 0.** |
| `t` | integer | Milliseconds since 1970-01-01T00:00:00Z on the computer's clock when the entry was written. **A claim.** |
| `m` | integer, optional | Milliseconds on the computer's monotonic clock since this session's `session.start`. Present on entries written inside a session. |

All other members belong to the entry's type. A type MUST NOT redefine an envelope member. A verifier MUST ignore members it does not know (they are still covered by the chain, because the chain covers bytes).

`t` is never refused or corrected by a writer. A clock that runs backwards produces entries whose `t` decreases; the verifier reports it.

No time zone is recorded. A verifier shows times in UTC or in the reader's own zone.

## 4. Records, chains and files

**Decision: a record is a set of per-device chains. A chain is found by following `prev`, not by what file a line is in.**

- A **chain** is a sequence of entries with `seq` 0, 1, 2, … each naming the one before in `prev`. Exactly one device appends to a chain.
- A **record** is every chain that carries the same `record` identifier in its first entry.
- The first entry of a record's founding chain is `record.start`. The first entry of every other chain is `chain.start`. These are the only entries without `prev`.
- Identifiers `record` and `chain` are 32 hexadecimal characters from 128 random bits. They are not derived from the device, the user or the book.

**Files are only containers.** A verifier is given one or more files, takes all their lines as one collection, and rebuilds the chains by `prev`. So:

- A chain MAY be stored as several files (for example one per month, so that finished files never change and sync cheaply). Concatenating them in order gives the chain.
- Several chains MAY be concatenated into one file for sending. `cat` is a valid export.
- Within a file, lines SHOULD appear in chain order.

What the verifier reports from the rebuilt structure:

- **A fork:** two entries with the same `prev`. "Chain X continues in two different ways after entry N."
- **A missing stretch:** an entry whose `prev` matches no line given. "Entries before N in chain X are missing."
- **An orphan chain:** a chain whose first entry names a different `record`. Reported and not merged.

**How chains are tied together.** Three things connect one device's chain to another's, in increasing strength:

1. The shared `record` identifier (anyone can copy it; weak).
2. **Content continuity:** a session that opens on a manuscript whose file hash equals a checkpoint on another chain.
3. **`sees` references:** an entry MAY list the latest entry it could see on each other chain, as `{"chain": …, "seq": …, "hash": …}`. This fixes an order between chains (the entry holding the reference was written after the one referred to) and commits one chain's history into another's, so cutting or rewriting the first shows in the second.

**Merging for a report** is by `t`, labelled as claimed, with the order corrected wherever anchors or `sees` references prove a different one.

A second device joins by reading the `record` identifier from the chain files it finds beside the book. Where those files live is outside the format.

## 5. Entry types

**Decision: an open set. Core types have no colon. Extension types are `domain:name`. A verifier chains and counts types it does not know and passes over them.**

- Core types are defined in this document: `record.start`, `chain.start`, `session.start`, `session.end`, `activity`, `change`, `checkpoint`, `seal`, `anchor`, `gap`, `key.change`.
- An extension type is `<a domain its definer controls>:<name>`, for example `baretext.ink:beat-placed`. Extensions MUST obey every rule of §2, §3 and §13 (no prose).
- An extension cannot change the meaning of a core entry. Something every verifier must understand needs a new format version (§12).
- A verifier lists unknown types by name with a count: "214 entries of kinds this verifier does not know: `baretext.ink:beat-placed`."

### 5.1 `record.start`

First entry of the founding chain.

| Member | Meaning |
|---|---|
| `record`, `chain` | Identifiers (§4). |
| `hash` | Hash algorithm for this chain. `"sha-256"` in version 0. |
| `key` | Optional. The chain's signing key (§7): `{"alg": …, "pub": …}`. |
| `how` | How the book began, as far as this record knows. See below. |
| `unit` | What the counts count. `"words"` in version 0, as the writing app counts them. |
| `words` | Words in the manuscript at this moment. |
| `file` | SHA-256 of the manuscript file at this moment, if there is one. |
| `source` | For `imported`: `{"kind": "word" \| "markdown" \| "text", "sha256": …}`, the hash of the imported file. Never its name. |
| `from` | For `copied`: `{"record": …, "chain": …, "seq": …, "hash": …}`, the last entry of the record this book was copied from. |
| `prior` | For `continued`: `{"kind": …, "sha256": …, "entries": …, "first": …, "last": …}`, an earlier record in another format (§14). |

`how` is one of:

- `new`: created empty in the app.
- `imported`: created by importing a file from another program. The record begins at the import.
- `opened`: an existing manuscript with no record. The record begins now and says nothing about how the `words` already there were written.
- `copied`: a copy (Save As) of a book that has a record.
- `continued`: an existing manuscript with an earlier record in a different format.

### 5.2 `chain.start`

First entry of every later chain: `record`, `chain`, `hash`, `key` as above, and:

- `why`: `device` (another computer), `reset` (the same computer began again), `unreadable` (the old chain file could not be read), `key-lost` (the old key is unavailable, so it could not make a `key.change`).
- `words`, `file`: the manuscript as this chain first found it.
- `sees`: optional references to other chains (§4).

To change the hash algorithm, a device starts a new chain with a different `hash` and a `sees` reference to its old chain's last entry.

### 5.3 `session.start` and `session.end`

A session is one stretch of a book being open in the app.

`session.start`: `app` (`{"name": …, "version": …}`), `platform` (the operating system's family only: `"darwin"`, `"win32"`, `"linux"`), `profile` (how checkpoints cut the manuscript into parts, §6), `file` and `words` (the manuscript as opened), and optional `sees`.

`session.end`: `why` (`closed`, `quit`, `switched`).

A session with no `session.end` was interrupted. The verifier reports it and does not treat it as a failure.

### 5.4 `activity`

Counts of text edits made in the editor, in coarse intervals.

**Decision: 60-second intervals. Counts of words per source. No per-key timings.**

| Member | Meaning |
|---|---|
| `step` | Interval length in milliseconds. `60000`. |
| `from` | Start of the first interval, in ms, a multiple of `step`. |
| `rows` | One row per interval that had activity. |
| `ctx` | Optional. Where the editing happened if not in the manuscript: `"sprint"`. |

A row is `{"i": n, "w": {source: [added, removed], …}, "pastes": [size, …]}`:

- `i`: the interval is `from + i × step` to `from + (i + 1) × step`.
- `w`: for each source that did anything, words added and words removed.
- `pastes`: optional. The size in words of each paste from outside the app in this interval, largest first, at most 50; any beyond that are only in the total. A report can then treat small and large pastes differently without the format taking a view on what "small" means.

An `activity` entry MAY carry several consecutive rows. A writer SHOULD write one before every checkpoint and at session end, so that a checkpoint always follows the activity that led to it. (Writing one entry per interval is also valid and costs more; see §11.)

**Sources in `activity`:**

| Source | Meaning |
|---|---|
| `typed` | Entered at the keyboard, including through an input method. |
| `pasted` | Pasted or dropped from outside the app. |
| `moved` | Cut, copied or dragged from within the app (this book, its notes, its parked scenes, another book in the same app). Not pasting. |
| `replaced` | Changed by find and replace. |
| `spelling` | Changed by accepting a spelling correction. |
| `system` | Put in whole by the operating system rather than key by key: dictation, text replacement, system writing tools. **The record cannot tell these apart.** |
| `undo`, `redo` | Text put back or taken out by undo or redo. |

These match the meanings already used in `packages/editor/src/word-delta.ts` and `provenance.ts`: the measure is the change in word count of the lines an edit touches; a paste counts the pasted words themselves.

### 5.5 `change`

One event that altered the manuscript other than by editing in place.

Members: `op`, `w` (`[added, removed]` in words, as it affected the manuscript), and optionally `parts` (how many scenes were affected) and members specific to the `op`.

| `op` | Meaning | Extra members |
|---|---|---|
| `import` | Text brought in from a file. | `source` as in `record.start`. |
| `sprint` | Text written in a timed sprint, placed in the book. | `recorded`: whether its writing appears as `activity` with `ctx: "sprint"`. |
| `restore` | An earlier state restored from the app's history. | `file`: hash of the state restored. |
| `rewrite` | A rewrite written beside a chapter or scene put in its place. | |
| `park`, `unpark` | A scene moved out to, or back from, set-aside storage. | |
| `move` | Scenes or chapters reordered. No words change. | |
| `remove` | A scene or chapter deleted. | |
| `outside` | The manuscript file differed from the last checkpoint when opened: it was changed outside the app. | `file`: hash found. `taken`: whether that version became the working one. |

Unknown `op` values are listed by name. `outside` is also listed by the verifier among the gaps (§9); its `w` is the difference from the last checkpoint, which the session's opening `words` already includes.

Every source named in the brief maps to exactly one place: typed, pasted, moved, find and replace, spelling, system tool, undo and redo are `activity` sources; imported, sprint, History restore, rewrite, Cold Storage and changed-outside are `change` ops.

### 5.6 `checkpoint`, `seal`, `anchor`, `gap`, `key.change`

Defined in §6, §7, §8, §9 and §7.

## 6. Checkpoints

**Decision: a checkpoint holds the unsalted hash of the saved file and a Merkle root over salted per-scene hashes. Salts come from one secret per chain that never enters the record. Checkpoints are made at a save, but not at every save.**

| Member | Meaning |
|---|---|
| `file` | SHA-256 of the manuscript file's bytes exactly as saved. |
| `words` | Words in the manuscript. |
| `parts` | Number of parts (scenes) under `root`. |
| `root` | Merkle root over the parts. Optional: absent if the host supplies no parts. |
| `changed` | Optional. How many parts' hashes differ from the previous checkpoint on this chain. |

### 6.1 When

A writing app may save many times a minute. (Baretext's existing recorder wrote 2,588 entries in 298 minutes of writing, one per save: 8.7 a minute.) A checkpoint at each would multiply the record's size for no gain in evidence. A writer SHOULD write a checkpoint:

- at the first save after 5 minutes of activity since the last checkpoint;
- at the last save of a session;
- whenever the app keeps a snapshot of the manuscript, so that every snapshot the writer still has matches a checkpoint;
- immediately before and after any `change`.

### 6.2 The file hash

Unsalted on purpose: its job is to let anyone holding a manuscript confirm it is the one the record ends on. It reveals nothing to someone who does not already have the file.

### 6.3 Parts and the tree

The host cuts the manuscript into an ordered list of **parts**, each with a stable identifier (1 to 64 ASCII characters) and its bytes. How it cuts is the host's **profile**, named in `session.start` (for example `"baretext-md-1"`: one part per scene, in manuscript order). The profile must be published so that others can recompute it. The file hash covers every byte whether or not parts do.

- Salt for a part: `HMAC-SHA-256(secret, "colophon-part-v0:" ‖ id)`, 32 bytes, where `secret` is 32 random bytes belonging to the chain.
- Leaf data: `salt ‖ len(id) as one byte ‖ id ‖ content bytes`.
- The tree is the Merkle Tree Hash of RFC 6962 §2.1 over the leaf data in manuscript order: leaves are hashed with a 0x00 prefix, inner nodes with 0x01, and an odd-sized list splits at the largest power of two below its size. An empty list has no `root`.

*Why salted.* Without a salt, showing one scene means handing over the hashes of its neighbours in the tree, and a short neighbour (an empty scene, a one-line scene) could be guessed from its hash.

*Why the salt depends on the part and not on the checkpoint.* An unchanged scene then has the same leaf in every checkpoint. The app can cache leaves and rehash only what changed, which matters for the save path. The cost: someone given proofs for the same scene at two checkpoints can see which neighbouring branches of the tree changed in between (not what they contain).

*Where the secret lives.* With the writer, outside the record, one per chain so that it never needs to travel between devices. It is never included when a record is sent to someone. Where exactly is the host's decision (phase 2).

- **If the secret is lost:** no single-scene proof can be made for that chain's checkpoints. The file hash still works.
- **If the secret leaks:** someone who also holds a proof could test guesses for the neighbouring scenes in that proof. Nothing in the record itself is exposed.

### 6.4 Showing one scene

A **disclosure** is a small separate document, made by the writer when they choose: the checkpoint's chain and entry hash, the part's identifier and index, the number of parts, the part's salt, the RFC 6962 audit path, and the part's content. A verifier recomputes the root and compares. The disclosure format is fixed here so that the commitment is usable; producing one is a later phase.

### 6.5 What can be shown when the snapshot is gone

The app keeps a limited history (Baretext: the last 10 point-in-time and 30 daily snapshots). For a checkpoint whose manuscript the writer no longer has:

- **Shown:** that a file with that hash, of that many words in that many parts, existed no later than the anchor that follows.
- **Not shown:** anything about what it said. The hash cannot be turned back into text, and the writer cannot recreate the exact bytes.
- **One exception, and it is useful:** any scene that has not changed since. The writer can take the scene from the finished book, with its salt, and show that this exact scene was already under a checkpoint two years old. Scenes that changed later cannot be shown at their earlier state.

So how much of a book's past can be opened depends on how many states the writer keeps. That is a decision for the app (§15, item 7).

## 7. Keys, seals and key changes

**Decision: signatures are their own entries (seals), each signing the chain so far. ECDSA P-256 and Ed25519. No claim about whose key it is.**

### 7.1 Keys

`key` is `{"alg": …, "pub": …}`:

| `alg` | Public key in `pub` | Signature in `sig` |
|---|---|---|
| `ecdsa-p256-sha256` | Uncompressed point, 65 bytes (0x04 ‖ X ‖ Y) | `r ‖ s`, 64 bytes, each 32 bytes big-endian |
| `ed25519` | 32 bytes (RFC 8032) | 64 bytes (RFC 8032) |

A verifier MUST support both. P-256 is what the Mac's Secure Enclave and most TPMs can hold; Ed25519 is the usual choice for a key held in software. Hardware that returns DER-encoded ECDSA signatures must convert them to `r ‖ s`. Either value of `s` is accepted.

A key's **fingerprint** is the SHA-256 of its `pub` bytes, in hex.

A chain MAY have no key. Its entries are then chained and may be anchored, and the verifier reports "not signed".

### 7.2 `seal`

Members: `sig`, and optionally `key` (a fingerprint; default: the chain's current key). A seal has no other members.

The signature is over the ASCII bytes of

`colophon-seal-v0:` *prev* `:` *seq* `:` *t* `:` *m* `:` *key*

where each part is the seal's own member as written (decimal for numbers; empty for an absent `m` or `key`). Because `prev` commits to every earlier entry, one seal covers the whole chain before it; because its own position and times are signed too, a seal that is the last line of a record cannot be altered without it showing. `sig` must be the one base64url spelling of its bytes.

A writer SHOULD write a seal after each checkpoint, as the last entry of a session (after `session.end`), and immediately before requesting an anchor, so that what gets anchored is a signed state.

*Why a seal is a separate entry and not a field of the checkpoint.* A signature inside an entry has to be computed over that entry with the signature removed, which brings back the re-serialization that §2 avoids. A separate entry signs a hash and nothing else. It also lets a session end on a signature, which leaves no unsigned tail after a clean close.

### 7.3 `key.change`

Members: `key` (the new key) and `why` (`rotated`, `exposed`, `replaced`).

After this entry the chain's current key is the new one. The writer SHOULD follow it with a seal by the **old** key (naming it in `key`), showing that the old key's holder accepted the new one, then a seal by the new key.

### 7.4 What a verifier says about keys

- Every seal checks against the key current at that point: "Signed 9,412 times by one key (fingerprint 3fa9…), first seen at the start of this record."
- A key change sealed by the old key: "The key was changed at entry N. The old key signed the change."
- A key change not sealed by the old key, or a `chain.start` with `why: "key-lost"`: "From entry N the record is signed by a different key, and nothing ties it to the earlier one. This is what a lost key looks like. It is also what someone without the original key would produce."
- In every case, unless the reader supplied a fingerprint to compare: "Nothing in the record shows whose key this is or what software held it."
- A seal that does not check is a failure, at that entry.

Version 0 has no attestation and no revocation.

## 8. Time anchors

**Decision: support both RFC 3161 and OpenTimestamps from version 0, because they fail in different ways. The scheme is named in each anchor, so others can be added.**

### 8.1 `anchor`

| Member | Meaning |
|---|---|
| `scheme` | `"rfc3161"` or `"opentimestamps"`. Others are passed over and reported as not checked. |
| `target` | `{"seq": …, "hash": …}`: an earlier entry in the same chain. Requests take time, so the receipt usually arrives after more entries have been written. |
| `proof` | The receipt. |
| `via` | Optional. The service's address. |
| `replaces` | Optional, OpenTimestamps: the `seq` of an earlier pending anchor that this completed proof supersedes. |

What is sent to the service is the target's 32-byte entry hash and nothing else.

### 8.2 The two schemes compared

| | RFC 3161 timestamp authority | OpenTimestamps |
|---|---|---|
| What the receipt is | A statement signed by the authority: "this hash, at this time." | A path of hashes from the target to a transaction in a Bitcoin block. |
| When it is final | At once, in one request. | Pending at once; final after the calendar's next Bitcoin transaction confirms, typically one to a few hours. A second request is needed later to fetch the completed proof. |
| Precision | About a second. | The block's time, good to within about two hours. |
| Checked offline in a browser, years later | Yes, completely, given the authority's certificates (carried in the receipt, or shipped with the verifier). Needs a parser for the receipt's encoding (ASN.1 DER) and RSA or ECDSA verification, which browsers provide. | The hash path: yes. The last step, that Bitcoin block N has the expected Merkle root, needs that block's header, which is not in the receipt. The verifier states the block number and the value to compare; the reader checks it against any source of Bitcoin headers. |
| Depends on one operator | Yes, each authority. Its key, its clock, its honesty. | Not once final. Before that, on the calendar server staying up. |
| What can go wrong later | The certificate expires or is withdrawn; the algorithms age. A withdrawal cannot be checked offline. | Nothing short of Bitcoin's history being rewritten. |
| Library quality | Mature in general, but the audited implementations are not small JavaScript ones. The verification subset needed here is small enough to write and test in this package. | The original JavaScript library looks unmaintained (old CI, a maintenance score of zero from one tracker). The proof format is simple: a few hundred lines to verify. |
| What the writer must trust | The authority. | Bitcoin. |
| What the service learns | Address, time, hash. | The same, at the calendar servers. |

**Recommendation: both.** RFC 3161 gives an immediate, precise receipt that a verifier can check with no outside help; a writer who closes the laptop one minute later still has it. OpenTimestamps gives a receipt no operator can forge or withdraw, hours later. A record with both has a time bound that survives the failure of either. Two unrelated RFC 3161 authorities are better than one.

Which authorities to use, and their terms, is open (§15, item 5).

### 8.3 Verifying a receipt

**RFC 3161.** `proof` is the DER-encoded TimeStampToken. The verifier checks that: the token's message imprint is SHA-256 and equals the target's hash; the signature over the signed attributes is valid for the signer's certificate; the signed attributes' message digest equals the hash of the token's content; the signer's certificate is marked for timestamping and chains to a root on the verifier's list; and the token's time falls within the certificates' validity. The verifier's list of roots is a dated data file, part of the verifier's release. The result names the authority and says if its certificate has since expired.

**OpenTimestamps.** `proof` is the serialized timestamp (the operations and attestations, without the file header and without the initial digest, which is the target's hash). The verifier applies the operations to the target's hash. Version 0 accepts the operations `sha256`, `append` and `prepend`, and the Bitcoin and pending attestations; a proof using anything else is reported as not checked. (Proofs from today's calendars use only these. Some older proofs use RIPEMD-160, which WebCrypto does not have: the OpenTimestamps project's own first example is one, and is reported as not checked.) A proof ending in a Bitcoin attestation yields a block height and a Merkle root. If the caller supplies a source of block headers, the verifier completes the check and reads the block's time. If not, the result is "needs one outside check" with the height and root to compare. A proof ending only in a pending attestation establishes nothing.

### 8.4 What times a verifier may state

Let an anchor be **verified** with time *T*, with target entry *a* and stored in the chain at entry *r* (so *r* comes after *a*).

- **No later than.** Every entry up to and including *a* existed no later than *T*. For any entry, its upper bound is the earliest such *T* among verified anchors whose target is at or after it.
- **No earlier than.** Every entry after *r* was written after *T*, because it chains over a receipt that could not exist before *T*. For any entry, its lower bound is the latest such *T* among verified anchors stored before it. A Bitcoin block's time can be up to two hours from when it was mined, so for OpenTimestamps the upper bound is the block's time plus two hours and the lower bound is the block's time less two hours.
- **Between anchors.** Entries are in the order of the chain. Each is bounded only by the anchors around it. Nothing shows how they were spread within those bounds.
- **Before the first anchor:** no lower bound. **After the last anchor's target:** no upper bound; the verifier says "no outside evidence of when these were written".
- **An anchored checkpoint** therefore gives the statement that matters most: "A manuscript with file hash H existed no later than T."
- **Claimed times** (`t`) are always shown as "the computer's clock said". Where a claimed time lies outside its entry's bounds by more than five minutes, the verifier reports the disagreement and its size.
- The verifier reports the **longest stretch of claimed time with no verified anchor inside it**. In a record made honestly with a network connection this is hours or days. In a record regenerated after the fact it is the whole record.

A lower bound rests on the service not issuing receipts ahead of time. For RFC 3161 that is trust in the authority. For OpenTimestamps it is the unpredictability of Bitcoin blocks.

## 9. Gaps

**Decision: anything the record cannot vouch for is an entry. Silence is never used to mean "nothing happened".**

`gap` members: `why`, and where known `from` and `to` (claimed times, ms) and `n` (a count: saves, entries or bytes, as the reason implies).

| `why` | Meaning |
|---|---|
| `torn` | The previous write was cut short (a crash, a full disk). Carries `torn`: the SHA-256 of the incomplete line's bytes. |
| `failed` | The recorder could not write for a stretch. `n`: saves that happened meanwhile. |
| `interrupted` | The app stopped with activity not yet written. `from`: the last entry's time. |
| `off` | Recording was switched off by the writer for a stretch. |

Other values are listed by name. A new chain begun because the old one was lost says so in `chain.start` (`why`), and the verifier lists that among the gaps too, along with every `change` whose `op` is `outside` and every session that never ended.

**A torn line.** A writer never rewrites or shortens a chain file. If the file does not end in a line feed when opened for appending, the writer appends a line feed and then a `gap` with `why: "torn"`. That entry's `prev` is the hash of the last *complete* entry, and its `torn` is the hash of the incomplete line. A reader accepts a line that is not an entry only if the next line is such a gap naming it; otherwise it is a failure at that line. An incomplete **final** line with nothing after it is ignored and reported: "the last line is incomplete: the app was interrupted while writing".

## 10. Verification

### 10.1 Procedure

Given one or more record files, and optionally a manuscript, an expected head, a key fingerprint and a source of Bitcoin headers:

1. Read all lines. Refuse any file that is not UTF-8.
2. Parse each line. **If any entry has a `v` this verifier does not implement, stop** (§12).
3. Rebuild chains by `prev` (§4). Report forks, missing stretches, orphans, `seq` out of step, torn lines, non-canonical lines.
4. Check each chain's first entry and its `record`.
5. Check every seal against the key current at that point.
6. Verify every anchor's receipt and that its target is in the chain at the stated `seq`.
7. Compute time bounds (§8.4) and clock disagreements, including `t` decreasing and `t` against `m`.
8. Check consistency: each `session.start` opens on a file hash some earlier checkpoint produced, or is followed by a `change` accounting for it; `words` at each checkpoint equals the previous `words` plus what `activity` and `change` entries say was added and removed, within the tolerance the unit allows. Disagreements are reported as findings, not failures: counting is the app's claim.
9. Total the counts by source. If a chain failed at some entry, totals cover only the entries before it, and say so.
10. If a manuscript was given: hash it and compare with the last checkpoint, then with every checkpoint.
11. If an expected head was given: check it is in the record and is the last entry of its chain.

### 10.2 The result

A structured value with these parts. Every item has a status: **held**, **failed** (with chain and line), or **not checked** (with the reason).

| Part | Contents |
|---|---|
| `format` | Versions seen; verifier version. |
| `chains` | For each: identifier, entry count, first and last claimed time, why it began, whether its chain of hashes held, how many entries at the end follow the last seal. |
| `signatures` | Seals checked; keys seen and their fingerprints; key changes; what ties them (§7.4). |
| `anchors` | For each: scheme, service, time, status. |
| `time` | Earliest and latest anchored time; the bounds per stretch; clock disagreements; the longest unanchored stretch. |
| `totals` | Words added and removed by each source, and the count and sizes of outside pastes: **as claimed by the record**. |
| `gaps` | Every gap, outside change, lost chain and unended session, with claimed times. |
| `manuscript` | Whether a manuscript was given, and which checkpoint it matches. |
| `unknown` | Entry types and members not understood, with counts. |

Exit status of the command-line verifier: `0` nothing failed (there may be items not checked); `1` something failed; `2` the record could not be read or is in a version not understood.

### 10.3 Wording

The verifier's sentences, for a reader who is not technical. `{…}` are filled in.

**Held**

- "Chain intact: all {n} entries follow one another without alteration."
- "Signed: {n} signatures by one key, all valid. Nothing in the record shows whose key this is."
- "Timestamped from outside: {n} receipts from {services}, all valid. The earliest shows the record's first {k} entries existed no later than {T1}. The latest shows everything up to entry {j} existed no later than {T2}."
- "The manuscript you supplied is, byte for byte, the one saved at the record's last checkpoint ({claimed time} by the computer's clock; existed no later than {T})."
- "The record says: {a} words typed, {b} words pasted from outside in {c} pastes (the largest {d} words), {e} words imported, … These are the writing app's own counts. A verifier cannot check them."

**Failed**

- "Altered: line {n} of chain {x} does not follow the line before it. An entry was changed, removed, inserted or moved at or just before this point. Everything after it is unverified."
- "Signature invalid at entry {n}."
- "A receipt at entry {n} is for an entry that is not in this record. The record was changed after that receipt was issued."
- "This chain continues in two different ways after entry {n}. Two versions of this record exist."
- "The record you were told to expect ends at {head}. This copy does not contain that entry: it is shorter, or different."

**Not checked, and limits always stated**

- "The last {n} entries (since {claimed time}) are not covered by a signature or a timestamp. They could be changed without it showing."
- "No outside timestamps. Every time in this record is the computer's own claim. Nothing shows when any of it was written."
- "The computer's clock says this record covers {from} to {to}. Outside evidence covers {T1} to {T2}. The longest stretch with no outside timestamp is {d}, from {x} to {y}."
- "The computer's clock disagrees with an outside timestamp at entry {n} by {d}."
- "{n} receipts could not be checked: {reason: service not on this verifier's list / proof not yet final / needs Bitcoin block {h} to have Merkle root {r}}."
- "No manuscript was supplied, so nothing was compared with the record's checkpoints." Or: "The manuscript you supplied does not match the last checkpoint. It matches the checkpoint at entry {n}." Or: "… It matches no checkpoint: it was changed after the record ends, or it is a different text."
- "The record cannot vouch for {n} stretches: {list, each with reason and claimed times}."
- "A record that ends early looks the same as a complete one. Compare it with the manuscript, or with an entry hash you were given earlier."
- "This record was written on {n} devices."

**Never:** "authentic", "verified human", "proves", "original", a score, a percentage, a colour that means pass.

## 11. Size

Reference book: 150,000 words, two years, 500 sessions of 1.5 hours of activity: 750 hours, 45,000 active minutes. Sizes are of real canonical lines with 64-character hashes.

| Entries | Count | Bytes each | Total |
|---|---|---|---|
| `activity`: one per checkpoint, about 5 rows | 9,500 | 185 + 42 a row | 3.6 MB |
| `checkpoint`: every 5 active minutes, plus session ends and snapshots | 10,000 | 331 | 3.3 MB |
| `seal`: one per checkpoint | 10,000 | 233 | 2.3 MB |
| `session.start` + `session.end` | 500 pairs | 326 + 158 | 0.2 MB |
| `anchor`, RFC 3161: session start and end | 1,000 | 265 + about 1,300 | 1.6 MB |
| `anchor`, OpenTimestamps: one a session, pending then final | 1,000 | 265 + about 400 / 1,300 | 1.1 MB |
| **Total** | **32,500** | | **about 12 MB** |

**Budget: 12 MB for the reference book; about 16 KB for an hour of writing.** About half is hashes, signatures and receipts and will not compress; the rest compresses well.

Measured on genuine receipts (12 November 2026): an RFC 3161 token from FreeTSA **with** its certificates is 4,623 bytes (a 6.5 KB line); a pending OpenTimestamps receipt from one calendar is 172 bytes (a 0.5 KB line); a completed OpenTimestamps proof in the client's examples is 650 bytes. The table's 1,300 bytes for an RFC 3161 token assumes it is requested **without** certificates, which has not been measured: a writer should ask for certificates once per authority, not every time, or this row is four times larger.

For comparison: the existing Baretext recorder, at one 355-byte entry per save, would reach about 140 MB over the same book. Writing one `activity` entry per minute instead of one per checkpoint would add 6.6 MB (45,000 × 227 bytes). Sealing only at session ends and before anchors would save 2 MB.

A chain stored as one file per month keeps each file near 500 KB and leaves finished months untouched, which matters if the files are in a synced folder.

## 12. Versions

- Every entry carries `v`. A chain may contain entries of different versions; `v` never decreases along a chain. Each entry is read by the rules of its own version.
- **No new version is needed for:** a new entry type, a new optional member, a new `source`, `op`, `why`, `how`, anchor `scheme` or key `alg`. Verifiers pass over what they do not know and say so.
- **A new version is needed for:** any change to §2 (lines and hashing), §3 (the envelope), what a seal signs, how the tree is built, or the meaning of an existing member.
- **A verifier accepts every version ever released,** for as long as it is maintained. Removing support for an old version is never allowed.
- **An entry with a version the verifier does not know: refuse the whole record.** Message: "This record uses format version {n}. This verifier understands versions up to {m}. Nothing was checked. Use a newer verifier." A partial result would invite a reader to trust a check that did not cover the record.
- **Test records are frozen.** Each released version has a directory of records (`fixtures/v0/`) that are never regenerated or edited. A test fails if any byte of them changes. A new verifier must give the same results on them as the verifier of their day.
- Version 0 becomes 1 when the format is published for others to implement. Version 0 records remain valid.

## 13. What may never be in a record

In any entry of any type, core or extension:

- text of the manuscript, of notes, or of any other writing by the writer;
- a title of a book, chapter or scene;
- a file name, path or URL of the writer's (a service's address in `via` is allowed);
- a device name, host name, user name, account, email address or hardware identifier;
- a location or time zone;
- the timing of individual keys.

Allowed: counts, hashes, random identifiers, public keys, signatures, receipts, times, the app's name and version, the operating system's family, and words from the fixed vocabularies in this document.

## 14. Records from before this format

Baretext has kept an app-private record since 1 November 2026 (`app/main/ledger.ts`, `LEDGER_VERSION = 1`). It is hash-chained but unsigned, unanchored, tied to no device, and holds an imported file's name. At least one real book has one (2,589 entries). Those lines use `kind`, `n` and `hash`; version 0 lines use `type`, `seq` and `prev`; a reader tells them apart by that, not by the number in `v`.

`record.start` with `how: "continued"` exists for this. Its `prior` member holds the earlier file's SHA-256, entry count and first and last claimed times, with `kind: "baretext-ledger-1"`. The earlier file is kept unchanged. A verifier given both checks the hash and says: "This record continues an earlier one in a pre-release format, covering {from} to {to} by the computer's clock. That earlier record is not signed or timestamped; it existed no later than {the new record's first anchor}."

## 15. Open decisions for Christan

Each with my recommendation.

**Answered 11 November 2026 (Christan):** every item is accepted as recommended, except:
- **5 (timestamp services): settled 12 November 2026.** OpenTimestamps from the start, once a session; an RFC 3161 authority may be added later (each receipt names its scheme, so adding one needs no format change). No Baretext server.
- **7 (how many past states to keep): deferred.**
- **16 (the public name): open.** Christan is brainstorming names. It must be chosen before version 0 freezes.

Item 4 is settled as "reword the tests". Item 1 is settled as "continue the existing record by hash".

1. **The record already on your Mac.** The brief says version 0 has no real records. The app-private recorder does: `If_My_Skin_Was_Gold_Draft_2` has 2,589 entries from 1 to 10 November. *Recommend:* §14: phase 2 starts a version 0 record that continues it by hash, and keeps the old file. The alternative is to drop those ten days.
2. **Checkpoints at some saves, not every save** (§6.1). The brief says "written when the manuscript is saved"; the app saves 8.7 times a minute. *Recommend:* every 5 minutes of activity, at session end, with every History snapshot, and around every structural change.
3. **Seals as separate entries** (§7.2), where the brief says "checkpoints are signed". Every checkpoint is still covered by a signature, in the next line. *Recommend:* as written. It costs 2.3 MB over the reference book; sealing less often would cut that.
4. **Hashing bytes, with no hash of an entry inside itself** (§2). Simpler, checkable by hand, immune to serialization differences. The cost is that two of the brief's tests cannot pass as worded, and I would rather change the wording than the design:
   - *"Changing any single byte is reported"*: true for every line that has a successor. A change to the **final** line shows only if that line is a seal or is anchored. *Recommend:* fixtures end on a seal (a clean session does), and the test covers the unsealed-tail case by asserting the verifier reports those entries as uncovered.
   - *"Cutting it at any point is reported"*: a cut at a line boundary gives a valid shorter record. No format can detect that from the inside (threat model, attack 2). *Recommend:* the test asserts that every cut either leaves a reported broken line or unsealed tail, or yields a head that differs from the expected head or manuscript given to the verifier.
5. **Which timestamp services, and how often.** *Recommend:* both schemes; RFC 3161 at session start and end, OpenTimestamps once a session. I have not found terms that clearly allow this use for the free authorities usually named (DigiCert's and Sectigo's are run for code signing; FreeTSA is one volunteer). Before phase 2 someone must read their terms or choose a paid authority. Running our own would make Baretext the single operator a sceptic has to trust, which defeats the point. More frequent anchors (say every 30 minutes) tighten the real-time evidence and add about 1.3 KB each.
6. **Scene salts** (§6.3): one secret per device chain, the same salt for a scene at every checkpoint. *Recommend:* as written. If you would rather nothing could be learned from two proofs of the same scene, salts can vary per checkpoint, at the cost of rehashing every scene at every checkpoint.
7. **How many past states the writer keeps.** With 10 + 30 snapshots, almost every old checkpoint can show only unchanged scenes (§6.5). Keeping every checkpointed state (content-addressed, so unchanged scenes are stored once) would let a writer open any moment of the book's history. That is a product decision outside this package. *Recommend:* decide in phase 2; it changes how strong the evidence against attack 5 can be.
8. **No time zone in the record** (§3, §13). A report cannot then say "wrote mostly in the evenings" without the reader knowing the writer's zone. *Recommend:* leave it out; the writer can state it.
9. **Each outside paste's size is listed** (§5.4), up to 50 a minute. Needed for the "short pastes together, long pastes one by one" report you asked for on 1 November, without fixing the 25-word line in the format. *Recommend:* as written.
10. **Counts are words only.** Characters would catch revision inside a word and are less tied to one app's counting, but need new measurement in the editor. *Recommend:* words for version 0; characters can be added later as an optional member without a new version.
11. **Dictation is not told apart from system writing tools.** Both arrive as whole insertions; the record says `system` for both. *Recommend:* accept, and say so in the report. This is what the app can honestly know today.
12. **A writer's note explaining a paste** (decided 1 November) is the writer's prose, so it cannot go in the record. *Recommend:* a later `note` entry holding only the note's hash and the entry it is about; the text travels with the report.
13. **Activity rows are batched until the next checkpoint** (§5.4). A crash can lose up to five minutes of counts, recorded as a gap. Writing a line a minute loses nothing and costs 6.6 MB more. *Recommend:* batch.
14. **No hardware attestation.** Version 0 cannot show that a key is held where only the genuine app can use it; forum reports say Apple's App Attest is not supported on the Mac. *Recommend:* test this in phase 2 on a signed build before designing anything around it.
15. **RFC 3161 and OpenTimestamps parsing written in this package**, not taken from a library. I found no small, audited JavaScript library for either. Everything else uses WebCrypto (SHA-256, HMAC, ECDSA P-256, Ed25519, RSA), so the package would have **no runtime dependencies**. Ed25519 in WebCrypto needs Chrome 137, Firefox 129 or Safari 17. *Recommend:* write the two parsers (small, bounded, property-tested, checked against genuine receipts) and name them as the first thing for the outside security review.
16. **The format's public name.** *Answered 21 November 2026: Colophon; the signed strings are `colophon-seal-v0:` and `colophon-part-v0:`, and an exported record's file is `*.colophon`.* Yours to choose; the string `provenance-seal-v0:` and `provenance-part-v0:` are signed and hashed into every record, so if the name should appear there, it has to be chosen before version 0 freezes.

## 16. What building it changed (Part B, 12 November 2026)

Version 0 has no real records, so these were changed in the text above rather than worked around.

1. **A seal signs its own position and times, not only `prev`** (§7.2). With `prev` alone, the time of a record's final seal could be edited without anything showing.
2. **A signature has one spelling** (§7.2). Unpadded base64url leaves two unused bits in the last character of a 64-byte value; a verifier refuses the other spellings, or a record's last line could be changed with the signature still valid.
3. **An OpenTimestamps time has two hours of slack in both directions** (§8.4), not only for the lower bound.
4. **A change made outside does not add to the running word count** (§5.5): the session's opening `words` already includes it.
5. **The OpenTimestamps project's best-known example proof cannot be verified by version 0** (§8.3): it uses RIPEMD-160. A newer genuine proof that uses only SHA-256 is the test receipt; the older one is tested as "not checked".
6. **Swapping two lines is not tampering in this format** (§4): chains are rebuilt from hashes, so the record still verifies. The verifier reports the line out of place as a note.

Still not built, and said so in the code: producing a disclosure document (§6.4; the functions that make and check one exist), an RFC 3161 request without certificates, RSASSA-PSS signatures on receipts (reported as not checked).
