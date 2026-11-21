# Threat model

*Format version 0, draft for review, 10 November 2026. Colophon is the format's name (chosen 21 November 2026). Licensed CC BY 4.0.*

## The short version

A writing app keeps a **record** beside a book: a running log of when the book was worked on, how much text arrived and by what route (typed, pasted, imported and so on), and a fingerprint of the manuscript each time it was saved. The record never holds the writer's words.

What a record can show, and to whom:

- **One thing is hard evidence: time.** At intervals the app sends a fingerprint of the record to an outside timestamp service, which returns a receipt. A valid receipt shows that the record, up to that point, **existed no later than** the receipt's time. Nobody, including the writer and the app's maker, can produce such a receipt for a past date afterwards.
- **Everything else is a claim made by the software that wrote the record.** The word counts, the split between typed and pasted, the session times on the computer's clock: a verifier can check that these have not been altered since they were written and since they were timestamped. It cannot check that they were true when written.
- **The weight of the claims comes from cost.** A record that shows two years of gradual work, timestamped from outside every day along the way, can only be faked by someone who started faking it two years ago and kept at it, in real time, the whole way. That is expensive. It is not impossible.

What a record is **not**:

- It is not proof that a human wrote the book. Someone can type out text that a machine composed, and the record will say "typed", truthfully.
- It is not proof of who wrote the book. A record is tied to a signing key, not to a person.
- It is not a score. A verifier reports what it checked and what it found. The reader judges.

The rest of this document goes through twelve ways to cheat or to be let down, and says for each whether the design **prevents** it, **detects** it, **makes it costly**, or **does not address** it.

## Terms used below

- **Entry**: one line of the record. Each entry contains the fingerprint (SHA-256 hash) of the line before it, so the lines form a **chain**.
- **Chain**: the entries written by one device. A book written on two computers has two chains in one record.
- **Checkpoint**: an entry made at a save, holding a hash of the saved manuscript file and a single hash that summarises every scene.
- **Seal**: an entry holding a digital signature over the chain so far, made with the device's key.
- **Anchor**: an entry holding a receipt from an outside timestamp service for an earlier point in the chain.
- **Claimed time**: the time the computer's own clock gave. **Anchored time**: a time taken from a verified receipt.
- **The writer**, in the attacks below, is treated as a possible attacker. The record is meant to be worth something to a sceptic.

## Who can do what

The model assumes the attacker may be the writer, with full control of their own computer: they can read and edit every file, run any program, change the clock, and study the open format and the open verifier. They cannot forge a timestamp service's signature, cannot rewrite the Bitcoin block chain, and cannot find SHA-256 collisions.

That assumption is the reason so little is "prevented". On a computer the attacker controls, software cannot be made to tell the truth. What the design can do is make lies **show**, or make them **take as long as the truth would have**.

## The attacks

### 1. Editing, deleting or reordering entries

**Detects**, for everything except the last few entries.

Each entry contains the hash of the exact bytes of the line before it. Change one byte of a line, remove a line or swap two, and the next line no longer matches. The verifier names the first line where the chain breaks.

An attacker can repair the chain by recomputing every hash after the change. That defeats the chain alone, so two more things sit on top of it:

- **Seals.** The recomputed chain needs new signatures. Without the signing key that fails. With the key (the writer has it, see attack 9) it succeeds.
- **Anchors.** Receipts already issued were for the old hashes. After a rewrite, every old receipt from the change onward points at an entry that is no longer in the chain, and the verifier says so. The attacker can drop those receipts and get new ones, but new receipts carry today's date. The rewritten stretch is then shown as existing "no later than today", whatever its entries claim.

So: an edit made by someone without the key is detected outright. An edit made by the key's holder is detected as **lost time**: the altered part of the record loses its old anchored dates.

**Limit, stated plainly:** entries after the last seal and the last anchor are protected by nothing. The holder of the file can change them freely. The verifier always reports how many entries at the end are in that state.

### 2. Truncating a record

**Detects in some cases. Otherwise does not address.**

A record cut off at the end of a line is a valid, shorter record. Nothing inside it can say that more once followed. This is a property of every append-only log.

Truncation shows only when something outside the cut copy refers to what was removed:

- **The manuscript.** If the verifier is given the finished manuscript, its hash must equal the last checkpoint's. A record cut back to hide a late paste ends at a checkpoint of an earlier manuscript, and the verifier reports that the manuscript presented is not the one the record ends on. The attacker would need to present the earlier manuscript as the book, which defeats the purpose.
- **Another chain.** When a book is written on two devices, each chain notes how far the other had got ("sees" references). A chain cut shorter than another chain says it saw is reported.
- **A head someone already holds.** Anyone given the record's latest hash earlier (an agent, a contest, an export made at submission) can see that a later copy is shorter. The verifier accepts an expected head for this.
- **A cut in the middle of a line** leaves a broken last line, which is reported. On its own that is weak: a crash does the same.

A truncation none of these catch is **not detected**. The practical defence is the first: verify against the manuscript being submitted.

### 3. Regenerating a whole record with false dates (backdating)

**Detects.** This is the attack the design exists for.

A program can write a complete, internally consistent record in seconds: two years of sessions, plausible counts, valid hashes, valid signatures with a fresh key. All its claimed times can be in the past.

It cannot obtain anchors in the past. Every receipt it can get is dated now. The verifier's time report for such a record reads, in effect: "Claims to cover March 2025 to October 2026. Outside evidence: all of it existed no later than 10 November 2026. Nothing shows any of it existed earlier." A real record shows hundreds of receipts spread across the same two years.

This holds only where anchors exist. **A record that was never anchored (the writer was always offline, or switched anchoring off) has no defence against backdating at all**, and the verifier says that every time in it is the computer's own claim.

### 4. Keeping two versions and presenting the more flattering one

**Makes it costly. Does not prevent or reliably detect.**

Two cases:

- **A branch made in hindsight.** The writer copies the record at some past point and writes a different continuation now. This is attack 1 or 3 from that point on: the new branch has no anchors older than today, and it shows.
- **Two branches kept alive from the start.** The writer runs two records in parallel for months, each anchored as it goes, and later shows one. Anchors prove each branch existed. They do not prove it was the only one. If only one branch is ever shown, **the format does not detect this.** It is detected only if both branches surface (two entries naming the same previous entry: the verifier reports a fork), or if the hidden branch's hashes were given to someone.

What remains is cost: the flattering branch still has to be a full, real-time, months-long record. Keeping a second one does not make the first any cheaper to fake.

### 5. Retyping an AI-written draft by hand

**Does not address** at the level of keystrokes. A person typing is a person typing; the record says "typed" and that is true.

What remains is the shape of the work over time. A retyped draft arrives in order, at a steady rate, with few returns to earlier scenes. A book that was written shows scenes reopened weeks later, text cut and replaced, chapters moved, with checkpoints whose scene hashes change again and again. To imitate that, the retypist has to perform the revision too: months of going back, cutting and rewriting, in real time, because the anchors fix when each state existed.

That is a real cost and nothing more. The record is evidence of a **process**; it cannot see where the words came from before they reached the keyboard. Nothing in the format, the verifier or any text about them should suggest otherwise.

### 6. A program that feeds synthetic typing into the app

**Makes it costly. Does not detect.**

Keystrokes injected by a program reach the editor as typing. The format records counts per minute, not per-key timings, so there is nothing in it to analyse for robotic rhythm. This is a choice: per-key timings are a privacy cost (they can identify a person, and they describe their working mind in detail) and an arms race the format would lose, since a program can imitate human rhythm.

The cost that remains is time. The program must run for as long as the record claims, because the anchors arrive at real dates. A script that fakes a two-year record needs two years. It does not need a person, so this is cheaper than attack 5, and the model does not pretend otherwise.

### 7. A modified build, or another program, that writes false entries

**Does not prevent. What still holds is time.**

The format is open and the app runs on the attacker's computer. A modified build can write "typed" for pasted text, leave out a paste, or invent sessions. Its entries are well-formed, chained and signed. The verifier cannot tell them from honest ones.

What still holds:

- **Time.** False entries are anchored when they are written, like true ones. A false history still cannot be produced after the fact.
- **Content commitments.** Each checkpoint fixes what the manuscript was at that moment. False counts have to stay consistent with checkpoints that are fixed for good: a record claiming 300 words typed in a minute in which the manuscript grew by 5,000 contradicts itself, and anyone later shown those two states can see it.
- **The key.** A seal shows which key signed. Where a key is held in hardware that only the genuine app can use, a modified build has to use a different key, and the change of key is on the record. Version 0 defines **no way for a verifier to confirm that a key is of that kind**, so today this is not something a verifier can rely on. See "What a later version could add".

The honest summary for a reader: *a record shows what some software wrote down, and when. It does not show that the software was honest.*

### 8. Changing the computer's clock

**Detects, where anchors exist. Otherwise does not address.**

Every entry's time is the computer's claim and is labelled as that in every output. Two checks apply:

- **Against anchors.** An entry that comes after a receipt in the chain was written after that receipt's time. An entry that comes before an anchored point was written before that anchor's time. The verifier reports any claimed time that falls outside the anchored times around it, and by how much.
- **Against a second clock.** Within a session each entry also carries a reading from the computer's monotonic clock, which does not move when the wall clock is changed. A wall-clock jump in the middle of a session shows as a disagreement between the two.

A clock changed between sessions, on a record with no anchors nearby, is **not detected**. A wrong clock is also common and innocent (a dead battery, a time zone); the verifier reports the disagreement and does not call it tampering.

### 9. A stolen or copied signing key

**Does not prevent. Narrows what the thief can do.**

Someone with the key can sign anything: extend the record, or write a different one. Signatures stop being evidence of origin. What the thief cannot do is move in time: anything they sign is anchored when they make it, and they cannot alter stretches already anchored without losing those anchors (attack 1).

A key kept in the computer's secure hardware cannot be copied off it, which removes copying but not misuse on the same machine. A software key in a file can be copied by anything that can read the file.

The format has a **key change** entry, so a writer who learns a key was exposed can retire it; entries sealed by the old key after that point are reported. The format has **no revocation that reaches back**: nothing can mark earlier seals as made by a thief rather than the owner.

The verifier never says a key belongs to a person. For a key it cannot tie to anything it says: *"signed throughout by one key, first seen at this record's start; nothing here shows whose key it is."*

### 10. Editing the manuscript file outside the app

**Detects, in an honest build.**

Each session start records the hash of the manuscript as opened. If it differs from the last checkpoint on every chain, the app writes a "changed outside" entry with the size of the difference in words, and the verifier lists it among the stretches the record cannot vouch for. The verifier can also make part of this check itself: a session that opens on a manuscript no checkpoint ever produced, with no entry accounting for it, is reported.

A modified build can leave the entry out (attack 7), but it cannot hide the jump: the checkpoints before and after are fixed, and the word counts between them do not add up.

Edits made outside and never opened in the app again are caught by the final check: the manuscript presented does not match the last checkpoint.

### 11. A timestamp service that is unavailable, compromised or gone

**Unavailable:** nothing fails; the record gets no anchor until the service is reachable again. The stretch written meanwhile is bounded only by the anchors on either side, and the verifier shows that gap in outside evidence. Writing and saving are never affected.

**Compromised:** a service that will sign false times breaks every receipt that rests on it alone. The design uses two kinds of service that fail differently, so one compromise does not break a record:

- **RFC 3161 timestamp authorities** are single operators. Trusting a receipt means trusting that operator's key and clock. Using two unrelated authorities means both must be compromised.
- **OpenTimestamps** commits the hash into the Bitcoin block chain. No operator can backdate it, including the calendar servers that carry the request. Its weakness is different: receipts take hours to become final and the time they prove is coarse (to within a few hours).

**Gone, years later:** an RFC 3161 receipt stays checkable as long as the verifier has the authority's certificates, which are stored in the record or shipped with the verifier. Its strength fades as the signing algorithms age and certificates expire, and a certificate withdrawn after the fact cannot be checked offline. An OpenTimestamps receipt that reached the block chain needs no surviving operator, only Bitcoin's block headers. One that was still **pending** when its calendar server vanished is worthless. Any later anchor also covers every earlier receipt in the chain, so a record that is still being written keeps renewing its own evidence.

**Not addressed:** a writer whose only anchors were from one authority, later shown to have been compromised during that period, loses those time bounds.

### 12. Privacy

**What a record reveals to someone who is given it:**

- When the writer worked, to the minute: days, hours, session lengths, breaks. From that, a reader can infer their routine, their time zone, and periods of illness, travel or not writing.
- How fast text arrived, how much was cut, how often they pasted and how much.
- How many scenes the book had at each save and how its length changed.
- The name and version of the app and the kind of operating system. How many devices were used.
- A public key, the same one in every record that device signs for this book.

**What it does not contain:** any of the writer's words, any title, any file name or path, any device name, any account or user name, any location, any per-key timing. Scene identifiers are random strings.

**What cannot be undone:** a record cannot be shared in part. Checking the chain needs every entry, so whoever receives a record receives the whole working history above. A writer should understand this before sending one. (The manuscript's commitments are different: one scene's state can be shown without revealing the others.)

**Guessing content from hashes:** the hash of the whole manuscript file is unsalted, so someone who already has a candidate file can confirm it is the one. That is its purpose. Scene hashes are salted with a secret that stays with the writer, so a short or predictable scene cannot be guessed from the record or from a proof about a neighbouring scene.

**What a timestamp service learns:** the network address the request came from, the time, and a hash. From the hash it learns nothing about the book. From the pattern of requests it can learn when someone at that address is writing. An RFC 3161 authority sees every request directly. OpenTimestamps calendar servers see the same. The app must say this where anchoring is switched on, and must work with anchoring off.

## Summary

| # | Attack | Result |
|---|---|---|
| 1 | Edit, delete, reorder entries | Detected. By the key's holder: detected as loss of anchored dates. The unsealed tail is unprotected. |
| 2 | Truncate | Detected only against the manuscript, another chain, or a head already shared. Otherwise not addressed. |
| 3 | Regenerate with false dates | Detected where anchors exist. No defence in a record never anchored. |
| 4 | Two versions, show one | In hindsight: detected (as 3). Run in parallel from the start and one hidden: not detected. Costly. |
| 5 | Retype a machine draft | Not addressed at the keystroke. Costly: revision must be performed in real time. |
| 6 | Synthetic typing | Not detected. Costly in time only. |
| 7 | Modified build | Not prevented. Time and the content commitments still hold. |
| 8 | Change the clock | Detected against anchors and the monotonic clock. Otherwise not addressed. |
| 9 | Stolen key | Not prevented. Cannot alter anchored history. |
| 10 | Edit outside the app | Detected by an honest build; the jump stays visible in any build. |
| 11 | Timestamp service fails | Unavailable: wider time bounds. Compromised or gone: survivable with two kinds of service; not with one. |
| 12 | Privacy | No prose. The whole working timeline is revealed to any recipient. Services learn an address and a hash. |

## What a later version could add

These are outside version 0 and are listed so that nobody assumes they exist.

- **Showing that a key lives in hardware only the genuine app can use.** This would raise the cost of attack 7 from "modify the app" to "defeat the platform's protections". It needs attestation from the platform. On the Mac, Apple's App Attest was reported unsupported in developer forum posts as recently as June 2026; this has to be tested, not assumed.
- **A witness.** A third party that receives each new head would make truncation (2) and hidden forks (4) detectable. It also means the writer's activity leaves their computer continuously, which is a cost the strategy has so far refused.
- **Tying a key to a person**, for example by the writer publishing its fingerprint. Out of scope for a file format.

## Wording rules that follow from this model

For the spec, the verifier's output, the app and anything written about them:

- Say "existed no later than". Never "was written on".
- Say "the computer's clock said". Never state a claimed time as fact.
- Say "the record says N words were typed". Never "N words were typed".
- Say "tamper-evident". Never "tamper-proof".
- Never "proves", "certifies", "verified human", "authentic", a score or a percentage of confidence.
