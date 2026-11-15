import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  auditPath, base64url, canonical, entryHash, fingerprint, hex, isCanonical, leafHash, merkleRoot, partLeaf, partSalt, rootFromPath, sealMessage, sha256,
  unbase64url, unhex, utf8, verifyDisclosure, verifySignature, type Json,
} from '../src/index.ts';
import { softwareSigner } from '../src/testing/index.ts';
import { parts, runs, SECRET } from './helpers.ts';

describe('the canonical form (SPEC §2)', () => {
  it('sorts members, writes no white space, and allows integers only', () => {
    expect(canonical({ b: 1, a: [true, null, 'x'], 'ä': { z: -3, y: 0 } })).toBe('{"a":[true,null,"x"],"b":1,"ä":{"y":0,"z":-3}}');
    expect(canonical({ t: 'a"b\\c\n\u0001é' })).toBe('{"t":"a\\"b\\\\c\\n\\u0001é"}');
    expect(() => canonical({ a: 1.5 })).toThrow();
    expect(() => canonical({ a: 2 ** 53 })).toThrow();
    expect(() => canonical({ a: undefined as unknown as Json })).toThrow();
    expect(canonical({ a: -0 })).toBe('{"a":0}');
  });

  it('a canonical line is its own canonical form; anything else is not', () => {
    expect(isCanonical('{"a":1,"b":2}')).toBe(true);
    for (const line of ['{"b":2,"a":1}', '{"a": 1}', '{"a":1.0}', '{"a":1,"a":2}', '[1]', 'nonsense', '{"a":1e3}']) expect(isCanonical(line), line).toBe(false);
  });

  it('any value of integers, strings, lists and objects round-trips, in one form however its members were ordered', async () => {
    const value = fc.letrec((tie) => ({
      v: fc.oneof({ depthSize: 'small' }, fc.constant(null), fc.boolean(), fc.maxSafeInteger(), fc.string({ unit: 'grapheme' }), fc.array(tie('v'), { maxLength: 4 }), fc.dictionary(fc.string(), tie('v'), { maxKeys: 4 })),
    })).v as fc.Arbitrary<Json>;
    await fc.assert(fc.property(fc.dictionary(fc.string(), value, { maxKeys: 6 }), (o) => {
      const line = canonical(o);
      expect(JSON.parse(line)).toEqual(JSON.parse(JSON.stringify(o)));
      expect(isCanonical(line)).toBe(true);
      expect(canonical(Object.fromEntries(Object.entries(o).reverse()))).toBe(line);
    }), runs(500));
  });
});

describe('bytes and hashes', () => {
  it('hex and base64url go there and back, and refuse what they are not', () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 80 }), (b) => {
      expect(unhex(hex(b))).toEqual(b);
      expect(unbase64url(base64url(b))).toEqual(b);
    }), runs(300));
    expect(unhex('ABCD')).toBeNull();
    expect(unhex('abc')).toBeNull();
    expect(unbase64url('a+b/')).toBeNull();
    expect(unbase64url('a')).toBeNull();
    expect(base64url(Uint8Array.of(251, 255))).toBe('-_8');
  });

  it('the entry hash is the SHA-256 of the line’s bytes, as any tool computes it', async () => {
    expect(await entryHash('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(await entryHash('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});

describe('the tree over a manuscript’s parts (SPEC §6.3)', () => {
  it('is RFC 6962’s: its published test roots', async () => {
    // (the leaves and roots of RFC 6962's reference test vectors, certificate-transparency-go's merkle tests)
    const data = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'].map((h) => unhex(h)!);
    const leaves = await Promise.all(data.map((d) => sha256(new Uint8Array([0, ...d]))));
    const roots = [
      '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
      'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
      'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
      'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
      '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
      '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
      'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
      '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
    ];
    for (let n = 1; n <= 8; n++) expect(hex((await merkleRoot(leaves.slice(0, n)))!), `${n} leaves`).toBe(roots[n - 1]);
    expect(await merkleRoot([])).toBeNull();
  });

  it('every leaf’s audit path gives the root, for every size; a wrong leaf, place or size does not', async () => {
    for (let n = 1; n <= 33; n++) {
      const leaves = await Promise.all(parts(n).map((p) => partLeaf(SECRET, p)));
      const root = (await merkleRoot(leaves))!;
      for (let i = 0; i < n; i++) {
        const path = await auditPath(leaves, i);
        expect(await rootFromPath(leaves[i]!, i, n, path)).toEqual(root);
        if (n > 1) {
          expect(await rootFromPath(leaves[(i + 1) % n]!, i, n, path)).not.toEqual(root);
          expect(await rootFromPath(leaves[i]!, i, n + 40, path)).not.toEqual(root);
        }
      }
    }
  });

  it('one part is shown with its salt and path; the same part has the same leaf at every checkpoint; a different secret gives a different leaf', async () => {
    const all = parts(7);
    const leaves = await Promise.all(all.map((p) => partLeaf(SECRET, p)));
    const root = (await merkleRoot(leaves))!;
    const d = { part: all[4]!, salt: await partSalt(SECRET, all[4]!.id), index: 4, parts: 7, path: await auditPath(leaves, 4) };
    expect(await verifyDisclosure(d, root)).toBe(true);
    expect(await verifyDisclosure({ ...d, part: { ...d.part, content: utf8('other words') } }, root)).toBe(false);
    expect(await verifyDisclosure({ ...d, part: { ...d.part, id: 'p5' } }, root)).toBe(false);
    expect(await partLeaf(SECRET, all[4]!)).toEqual(leaves[4]);
    expect(await partLeaf(new Uint8Array(32).fill(4), all[4]!)).not.toEqual(leaves[4]);
    expect(await leafHash(d.salt, all[4]!)).toEqual(leaves[4]);
    await expect(partSalt(new Uint8Array(8), 'x')).rejects.toThrow();
    await expect(partSalt(SECRET, 'has space')).rejects.toThrow();
  });
});

describe('signatures (SPEC §7.1)', () => {
  for (const alg of ['ed25519', 'ecdsa-p256-sha256'] as const) {
    it(`${alg}: a signature checks against its key and message, and nothing else`, async () => {
      const signer = await softwareSigner(alg);
      const key = { alg, pub: base64url(await signer.publicKey()) };
      const message = utf8(sealMessage({ prev: 'ab'.repeat(32), seq: 9, t: 1794000000000 }));
      const sig = new Uint8Array(await signer.sign(message));
      expect(await verifySignature(key, message, sig)).toBe(true);
      expect(await verifySignature(key, utf8(sealMessage({ prev: 'ab'.repeat(32), seq: 10, t: 1794000000000 })), sig)).toBe(false);
      const flipped = Uint8Array.from(sig); flipped[5]! ^= 1;
      expect(await verifySignature(key, message, flipped)).toBe(false);
      const other = await softwareSigner(alg);
      expect(await verifySignature({ alg, pub: base64url(await other.publicKey()) }, message, sig)).toBe(false);
      expect(await verifySignature({ alg, pub: 'not a key' }, message, sig)).toBe(false);
      expect(await verifySignature(key, message, sig.subarray(0, 63))).toBe(false);
      expect(await fingerprint(key)).toMatch(/^[0-9a-f]{64}$/);
    });
  }
});
