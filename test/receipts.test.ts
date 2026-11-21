// Receipt verification is real, and tested against genuine receipts (the brief): an RFC 3161 token issued by
// FreeTSA for an entry of the clean fixture, and a complete proof from the OpenTimestamps client's own examples,
// which reached Bitcoin block 912095 in August 2025. No test here uses the network.
import { describe, expect, it } from 'vitest';
import { completeOpenTimestamps, concat, parseLine, pendingRequests, rootBytes, splitOtsFile, unbase64url, unhex, verifyOpenTimestamps, verifyRfc3161, hex, sha256, utf8 } from '../src/index.ts';
import { fixture, fixtureBytes } from './helpers.ts';

const anchors = fixture('clean.jsonl').split('\n').filter(Boolean).map((l) => parseLine(l)!).filter((e) => e.type === 'anchor') as { scheme: string; proof: string; target: { hash: string } }[];
const tsa = anchors.find((a) => a.scheme === 'rfc3161')!;
const token = unbase64url(tsa.proof)!;
const target = unhex(tsa.target.hash)!;

describe('an RFC 3161 receipt (SPEC §8.3)', () => {
  it('a genuine one holds: the hash, the authority’s signature, its certificate chained to a trusted root, the time', async () => {
    const r = await verifyRfc3161(token, target, rootBytes());
    expect(r).toMatchObject({ status: 'held', authority: 'www.freetsa.org' });
    if (r.status !== 'held') return;
    expect(new Date(r.time).toISOString().slice(0, 10)).toBe('2026-11-21');
    expect(r.expires).toBeGreaterThan(r.time);
  });

  it('for another hash, it fails', async () => {
    const other = Uint8Array.from(target); other[0]! ^= 1;
    expect(await verifyRfc3161(token, other, rootBytes())).toMatchObject({ status: 'failed', reason: 'the receipt is for a different hash' });
  });

  it('with no trusted root, it is not checked: never taken on its own word', async () => {
    expect(await verifyRfc3161(token, target, [])).toMatchObject({ status: 'unchecked' });
  });

  it('any byte of it changed, it no longer holds', async () => {
    // (every 7th byte: the whole token is 5 KB, and each check verifies two RSA signatures)
    for (let i = 0; i < token.length; i += 7) {
      const t = Uint8Array.from(token); t[i]! ^= 0x01;
      const r = await verifyRfc3161(t, target, rootBytes());
      // A change outside what is signed (an unsigned attribute, a spare certificate) can leave it holding: then
      // it must be the same statement, the same time.
      if (r.status === 'held') {
        const whole = await verifyRfc3161(token, target, rootBytes());
        expect(whole.status === 'held' && whole.time === r.time, `byte ${i}`).toBe(true);
      }
    }
    // The signed statement itself: the time changed by one second.
    const t = Uint8Array.from(token);
    const at = token.findIndex((_, i) => token[i] === 0x18 && token[i + 1] === 0x0f && token[i + 16] === 0x5a); // (a GeneralizedTime ending in Z)
    expect(at).toBeGreaterThan(0);
    t[at + 15]! ^= 0x01;
    expect((await verifyRfc3161(t, target, rootBytes())).status).toBe('failed');
  });

  it('nonsense is refused without throwing', async () => {
    for (const bytes of [new Uint8Array(0), Uint8Array.of(0x30), Uint8Array.of(0x30, 0x84, 0xff, 0xff, 0xff, 0xff), utf8('not a receipt at all'), token.subarray(0, 200)]) {
      expect((await verifyRfc3161(new Uint8Array(bytes), target, rootBytes())).status).toBe('failed');
    }
  });
});

describe('an OpenTimestamps receipt (SPEC §8.3)', () => {
  const file = fixtureBytes('receipts/gdp2q25-2nd.pdf.ots');
  const header = JSON.parse(new TextDecoder().decode(fixtureBytes('receipts/bitcoin-912095.json'))) as { height: number; merkleRoot: string; time: number };
  const split = splitOtsFile(file)!;

  it('an older proof whose path uses RIPEMD-160, which a browser cannot compute, is said to be not checked', async () => {
    const old = splitOtsFile(fixtureBytes('receipts/hello-world.txt.ots'))!;
    expect(hex(old.digest)).toBe(hex(await sha256(utf8('Hello World!\n'))));
    expect((await verifyOpenTimestamps(old.proof, old.digest)).status).toBe('unchecked');
  });

  it('without a block header, the path is checked and the one thing left is said exactly', async () => {
    expect(await verifyOpenTimestamps(split.proof, split.digest)).toEqual({ status: 'needs-header', height: 912095, merkleRoot: header.merkleRoot });
  });

  it('with the block’s header, it holds, at the block’s time', async () => {
    const r = await verifyOpenTimestamps(split.proof, split.digest, (h) => Promise.resolve(h === header.height ? header : null));
    expect(r).toEqual({ status: 'held', height: 912095, time: header.time * 1000 });
    expect(new Date(header.time * 1000).toISOString().slice(0, 10)).toBe('2025-08-28');
  });

  it('a header that says otherwise, another hash, or a changed proof: it does not hold', async () => {
    const wrong = { ...header, merkleRoot: header.merkleRoot.replace(/^./, '0') };
    expect((await verifyOpenTimestamps(split.proof, split.digest, () => Promise.resolve(wrong))).status).toBe('failed');
    const other = Uint8Array.from(split.digest); other[3]! ^= 1;
    expect((await verifyOpenTimestamps(split.proof, other, () => Promise.resolve(header))).status).toBe('failed');
    for (let i = 0; i < split.proof.length; i++) {
      const p = Uint8Array.from(split.proof); p[i]! ^= 0x01;
      const r = await verifyOpenTimestamps(p, split.digest, (h) => Promise.resolve(h === header.height ? header : null));
      expect(r.status, `byte ${i}`).not.toBe('held');
    }
  });

  it('a pending receipt from a calendar shows nothing yet, and says so', async () => {
    const pending = anchors.find((a) => a.scheme === 'opentimestamps')!;
    const r = await verifyOpenTimestamps(unbase64url(pending.proof)!, unhex(pending.target.hash)!);
    expect(r.status).toBe('pending');
    if (r.status === 'pending') expect(r.calendars[0]).toContain('calendar.opentimestamps.org');
  });

  it('a pending receipt says what to ask its calendar; the answer completes it, and nothing else does', async () => {
    // The genuine pending receipt: one request, to the calendar that issued it, for the commitment its path reaches.
    const pending = anchors.find((a) => a.scheme === 'opentimestamps')!;
    const [proof, target] = [unbase64url(pending.proof)!, unhex(pending.target.hash)!];
    const requests = await pendingRequests(proof, target);
    expect(requests).toHaveLength(1);
    expect(requests[0]!.calendar).toContain('calendar.opentimestamps.org');
    expect(requests[0]!.path.length).toBeGreaterThan(0);

    // A receipt pending at the genuine proof's own digest: the calendar's answer is the genuine proof, and completing
    // it gives exactly that proof, checked as far as Bitcoin block 912095.
    const url = utf8('https://alice.btc.calendar.opentimestamps.org');
    const att = concat(Uint8Array.of(0x00), unhex('83dfe30d2ef90c8e')!, Uint8Array.of(url.length + 1, url.length), url);
    const [request] = await pendingRequests(att, split.digest);
    expect(hex(request!.commitment)).toBe(hex(split.digest));
    const done = await completeOpenTimestamps(request!, split.proof, split.digest);
    expect(done && hex(done)).toBe(hex(split.proof));
    expect((await verifyOpenTimestamps(done!, split.digest)).status).toBe('needs-header');

    // An answer that is still pending, or nonsense, completes nothing. (One for another commitment reads as a path to
    // a block whose root won't match it: only the block's header can show that, and the verifier asks for it.)
    expect(await completeOpenTimestamps(request!, att, split.digest)).toBeNull();
    expect(await completeOpenTimestamps(request!, Uint8Array.of(0xff, 0x00), split.digest)).toBeNull();
    expect(await pendingRequests(Uint8Array.of(0xf0), target)).toEqual([]);
  });

  it('nonsense is refused without throwing', async () => {
    for (const bytes of [new Uint8Array(0), Uint8Array.of(0xff), Uint8Array.of(0xf0, 0xff, 0xff, 0xff, 0xff, 0x7f), new Uint8Array(5000).fill(0x08)]) {
      expect(['failed', 'unchecked']).toContain((await verifyOpenTimestamps(bytes, split.digest)).status);
    }
    expect(splitOtsFile(utf8('not a proof'))).toBeNull();
  });
});
