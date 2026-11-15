// Checking an RFC 3161 receipt (SPEC §8.3): a timestamp authority's signed statement that a hash existed at a time.
// Everything is checked here, offline: the hash, the signature, that the signing certificate is the one the token
// names and is for timestamping, and that it chains to a root the caller trusts. What can't be checked offline —
// whether a certificate was later withdrawn — is not, and the result says nothing about it.

import { concat, equal, hex } from '../bytes.ts';
import { bits, children, DerError, expect, oid, parseDer, TAG, time, unsigned, type Der } from './der.ts';

export type Rfc3161Result =
  | { status: 'held'; time: number; authority: string; root: string; expires: number }
  | { status: 'failed'; reason: string }
  | { status: 'unchecked'; reason: string; time?: number; authority?: string };

const OID = {
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  messageDigest: '1.2.840.113549.1.9.4',
  contentType: '1.2.840.113549.1.9.3',
  signingCert: '1.2.840.113549.1.9.16.2.12',
  signingCertV2: '1.2.840.113549.1.9.16.2.47',
  eku: '2.5.29.37',
  timeStamping: '1.3.6.1.5.5.7.3.8',
  rsa: '1.2.840.113549.1.1.1',
  ecPublicKey: '1.2.840.10045.2.1',
  cn: '2.5.4.3',
  org: '2.5.4.10',
} as const;

const DIGESTS: Record<string, string> = {
  '1.3.14.3.2.26': 'SHA-1',
  '2.16.840.1.101.3.4.2.1': 'SHA-256',
  '2.16.840.1.101.3.4.2.2': 'SHA-384',
  '2.16.840.1.101.3.4.2.3': 'SHA-512',
};
/** Signature algorithms that name their own digest. */
const SIGNATURES: Record<string, { kind: 'rsa' | 'ecdsa'; hash: string }> = {
  '1.2.840.113549.1.1.5': { kind: 'rsa', hash: 'SHA-1' },
  '1.2.840.113549.1.1.11': { kind: 'rsa', hash: 'SHA-256' },
  '1.2.840.113549.1.1.12': { kind: 'rsa', hash: 'SHA-384' },
  '1.2.840.113549.1.1.13': { kind: 'rsa', hash: 'SHA-512' },
  '1.2.840.10045.4.3.2': { kind: 'ecdsa', hash: 'SHA-256' },
  '1.2.840.10045.4.3.3': { kind: 'ecdsa', hash: 'SHA-384' },
  '1.2.840.10045.4.3.4': { kind: 'ecdsa', hash: 'SHA-512' },
};
const CURVES: Record<string, { name: string; size: number }> = {
  '1.2.840.10045.3.1.7': { name: 'P-256', size: 32 },
  '1.3.132.0.34': { name: 'P-384', size: 48 },
  '1.3.132.0.35': { name: 'P-521', size: 66 },
};

class Unsupported extends Error {}

const digest = async (alg: string, data: Uint8Array<ArrayBuffer>) => new Uint8Array(await crypto.subtle.digest(alg, data));

interface Cert {
  raw: Uint8Array<ArrayBuffer>;
  tbs: Uint8Array<ArrayBuffer>;
  issuer: Uint8Array<ArrayBuffer>;
  subject: Uint8Array<ArrayBuffer>;
  name: string;
  notBefore: number;
  notAfter: number;
  spki: Der;
  sigAlg: string;
  sig: Uint8Array<ArrayBuffer>;
  /** Extended key usages; null when the certificate has no such extension. */
  eku: string[] | null;
}

/** The name a person would know a certificate by: its common name, or its organisation. */
function nameOf(name: Der): string {
  let org = '';
  for (const rdn of children(name)) for (const attr of children(rdn)) {
    const [type, value] = children(attr);
    if (!type || !value) continue;
    const id = oid(type);
    // (text shown to a reader: printable characters only)
    const str = new TextDecoder().decode(value.body).replace(/[^\x20-\x7e -￿]/g, '').slice(0, 120);
    if (id === OID.cn) return str;
    if (id === OID.org) org = str;
  }
  return org || 'an unnamed authority';
}

export function parseCert(raw: Uint8Array<ArrayBuffer>): Cert {
  const [tbs, alg, sig] = children(expect(parseDer(raw), TAG.seq));
  const fields = children(expect(tbs, TAG.seq));
  // (a version, [0], comes first in everything but a version 1 certificate)
  const f = fields[0]?.tag === 0xa0 ? fields.slice(1) : fields;
  const [, , issuer, validity, subject, spki] = f;
  const [notBefore, notAfter] = children(expect(validity, TAG.seq));
  let eku: string[] | null = null;
  const ext = f.find((x) => x.tag === 0xa3);
  if (ext) for (const e of children(expect(children(ext)[0], TAG.seq))) {
    const parts = children(e);
    if (parts[0] && oid(parts[0]) === OID.eku) eku = children(expect(parseDer(expect(parts[parts.length - 1], TAG.octets).body), TAG.seq)).map(oid);
  }
  return {
    raw, tbs: expect(tbs, TAG.seq).raw, issuer: expect(issuer, TAG.seq).raw, subject: expect(subject, TAG.seq).raw, name: nameOf(subject!),
    notBefore: time(notBefore!), notAfter: time(notAfter!), spki: expect(spki, TAG.seq),
    sigAlg: oid(children(expect(alg, TAG.seq))[0]!), sig: bits(sig!), eku,
  };
}

/** An ECDSA signature as WebCrypto takes it: `r ‖ s`, each `size` bytes. */
function rawEcdsa(der: Uint8Array<ArrayBuffer>, size: number): Uint8Array<ArrayBuffer> {
  const [r, s] = children(expect(parseDer(der), TAG.seq)).map(unsigned);
  if (!r || !s || r.length > size || s.length > size) throw new DerError('a signature this reader does not accept');
  const out = new Uint8Array(size * 2);
  out.set(r, size - r.length);
  out.set(s, size * 2 - s.length);
  return out;
}

/** Whether `sig` is the signature of the key in `spki` over `data`. Throws Unsupported for algorithms not handled. */
async function verifyWith(spki: Der, kind: 'rsa' | 'ecdsa', hash: string, sig: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>): Promise<boolean> {
  const [alg] = children(spki);
  const [keyType, params] = children(expect(alg, TAG.seq));
  const type = oid(keyType!);
  if (kind === 'rsa') {
    if (type !== OID.rsa) return false;
    const key = await crypto.subtle.importKey('spki', spki.raw, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify']);
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, data);
  }
  if (type !== OID.ecPublicKey || !params) return false;
  const curve = CURVES[oid(params)];
  if (!curve) throw new Unsupported('an elliptic curve this verifier does not handle');
  const key = await crypto.subtle.importKey('spki', spki.raw, { name: 'ECDSA', namedCurve: curve.name }, false, ['verify']);
  return crypto.subtle.verify({ name: 'ECDSA', hash }, key, rawEcdsa(sig, curve.size), data);
}

/** How a signature algorithm identifier is checked, given the digest named beside it (for a bare key-type identifier). */
function signatureOf(algOid: string, digestName: string | undefined): { kind: 'rsa' | 'ecdsa'; hash: string } {
  const known = SIGNATURES[algOid];
  if (known) return known;
  if (algOid === OID.rsa && digestName) return { kind: 'rsa', hash: digestName };
  throw new Unsupported('a signature algorithm this verifier does not handle');
}

/**
 * Check a receipt (the DER of a TimeStampToken) for `hash`. `roots` are the certificates the caller trusts (DER);
 * `extra` are further certificates to build the chain with (a receipt asked for without its certificates).
 */
export async function verifyRfc3161(proof: Uint8Array<ArrayBuffer>, hash: Uint8Array, roots: Uint8Array<ArrayBuffer>[], extra: Uint8Array<ArrayBuffer>[] = []): Promise<Rfc3161Result> {
  let genTime: number | undefined;
  let authority: string | undefined;
  try {
    const [type, content] = children(expect(parseDer(proof), TAG.seq));
    if (!type || oid(type) !== OID.signedData || !content || content.tag !== 0xa0) return { status: 'failed', reason: 'not a timestamp receipt' };
    const signed = children(expect(children(content)[0], TAG.seq));
    const encap = children(expect(signed[2], TAG.seq));
    if (!encap[0] || oid(encap[0]) !== OID.tstInfo || !encap[1]) return { status: 'failed', reason: 'not a timestamp receipt' };
    const eContent = expect(children(encap[1])[0], TAG.octets).body;

    // What the authority stated: this hash, at this time.
    const tst = children(expect(parseDer(eContent), TAG.seq));
    const [imprintAlg, imprint] = children(expect(tst[2], TAG.seq));
    if (DIGESTS[oid(children(expect(imprintAlg, TAG.seq))[0]!)] !== 'SHA-256' || !equal(expect(imprint, TAG.octets).body, hash)) {
      return { status: 'failed', reason: 'the receipt is for a different hash' };
    }
    genTime = time(expect(tst[4], TAG.time));

    const signers = children(expect(signed[signed.length - 1], TAG.set));
    if (signers.length !== 1) return { status: 'failed', reason: 'a receipt has one signer' };
    const si = children(expect(signers[0], TAG.seq));
    const digestName = DIGESTS[oid(children(expect(si[2], TAG.seq))[0]!)];
    if (!digestName) throw new Unsupported('a digest this verifier does not handle');
    const attrsEl = si[3];
    if (!attrsEl || attrsEl.tag !== 0xa0) return { status: 'failed', reason: 'the receipt has no signed attributes' };
    const sigAlg = oid(children(expect(si[4], TAG.seq))[0]!);
    const signature = expect(si[5], TAG.octets).body;

    // The signed attributes: they must name the content's digest and the signing certificate.
    const attrs = new Map<string, Der>();
    for (const a of children(attrsEl)) {
      const [id, values] = children(expect(a, TAG.seq));
      const value = children(expect(values, TAG.set))[0];
      if (id && value) attrs.set(oid(id), value);
    }
    const ctype = attrs.get(OID.contentType);
    if (!ctype || oid(ctype) !== OID.tstInfo) return { status: 'failed', reason: 'the signed attributes are for something else' };
    const md = attrs.get(OID.messageDigest);
    if (!md || !equal(expect(md, TAG.octets).body, await digest(digestName, eContent))) return { status: 'failed', reason: 'the receipt’s contents were changed' };
    let certHash: { alg: string; value: Uint8Array } | null = null;
    const v2 = attrs.get(OID.signingCertV2);
    const v1 = attrs.get(OID.signingCert);
    if (v2) {
      const first = children(expect(children(expect(children(expect(v2, TAG.seq))[0], TAG.seq))[0], TAG.seq));
      const withAlg = first[0]?.tag === TAG.seq;
      const alg = withAlg ? DIGESTS[oid(children(first[0]!)[0]!)] : 'SHA-256';
      if (!alg) throw new Unsupported('a digest this verifier does not handle');
      certHash = { alg, value: expect(first[withAlg ? 1 : 0], TAG.octets).body };
    } else if (v1) {
      const first = children(expect(children(expect(children(expect(v1, TAG.seq))[0], TAG.seq))[0], TAG.seq));
      certHash = { alg: 'SHA-1', value: expect(first[0], TAG.octets).body };
    }
    if (!certHash) return { status: 'failed', reason: 'the receipt does not name its signing certificate' };

    // The certificates: those in the receipt, those supplied, and the roots.
    const pool: Cert[] = [];
    const embedded = signed.find((x) => x.tag === 0xa0);
    for (const c of embedded ? children(embedded) : []) if (c.tag === TAG.seq) { try { pool.push(parseCert(c.raw)); } catch { /* one unreadable certificate doesn't spoil the rest */ } }
    for (const raw of extra) { try { pool.push(parseCert(raw)); } catch { /* likewise */ } }
    const trusted: Cert[] = [];
    for (const raw of roots) { try { trusted.push(parseCert(raw)); } catch { /* likewise */ } }

    let signer: Cert | null = null;
    for (const c of [...pool, ...trusted]) if (equal(await digest(certHash.alg, c.raw), certHash.value)) { signer = c; break; }
    if (!signer) return { status: 'unchecked', reason: 'the authority’s certificate is not in the receipt or on this verifier’s list', time: genTime };
    authority = signer.name;

    // The signature, over the attributes as a SET (their tag on the wire is [0]).
    const signedBytes = concat(Uint8Array.of(TAG.set), attrsEl.raw.subarray(1));
    const how = signatureOf(sigAlg, digestName);
    if (!(await verifyWith(signer.spki, how.kind, how.hash, signature, signedBytes))) return { status: 'failed', reason: 'the authority’s signature is not valid' };

    if (!signer.eku || !signer.eku.includes(OID.timeStamping)) return { status: 'failed', reason: 'the signing certificate is not for timestamping' };

    // The chain, up to a trusted root; each certificate valid at the receipt's time.
    let at = signer;
    for (let depth = 0; depth < 8; depth++) {
      if (genTime < at.notBefore || genTime > at.notAfter) return { status: 'failed', reason: 'the receipt’s time is outside its certificate’s life' };
      const root = trusted.find((r) => equal(r.raw, at.raw));
      if (root) return { status: 'held', time: genTime, authority, root: hex(await digest('SHA-256', root.raw)), expires: signer.notAfter };
      const issuer = [...trusted, ...pool].find((c) => equal(c.subject, at.issuer) && !equal(c.raw, at.raw));
      if (!issuer) break;
      const alg = signatureOf(at.sigAlg, undefined);
      if (!(await verifyWith(issuer.spki, alg.kind, alg.hash, at.sig, at.tbs))) return { status: 'failed', reason: 'a certificate in the receipt’s chain is not validly signed' };
      at = issuer;
    }
    return { status: 'unchecked', reason: 'the authority is not on this verifier’s list', time: genTime, authority };
  } catch (e) {
    if (e instanceof Unsupported) return { status: 'unchecked', reason: e.message, time: genTime, authority };
    return { status: 'failed', reason: 'the receipt cannot be read' };
  }
}
