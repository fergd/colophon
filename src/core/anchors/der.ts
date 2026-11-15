// A reader for DER, the encoding of RFC 3161 receipts and X.509 certificates: just enough to walk them, strict
// about lengths, and never reading past the bytes it was given. It reads untrusted input.

export interface Der {
  /** The tag byte: class, constructed bit and number (numbers above 30 are refused). */
  tag: number;
  /** The whole element, header included. */
  raw: Uint8Array<ArrayBuffer>;
  /** Its contents. */
  body: Uint8Array<ArrayBuffer>;
}

export class DerError extends Error {}

/** The element starting at `at`, and where the next begins. */
export function readDer(bytes: Uint8Array<ArrayBuffer>, at = 0): { el: Der; next: number } {
  if (at + 2 > bytes.length) throw new DerError('cut short');
  const tag = bytes[at]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError('a tag this reader does not know');
  let len = bytes[at + 1]!;
  let head = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || at + 2 + n > bytes.length) throw new DerError('a length this reader does not accept');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + bytes[at + 2 + i]!;
    head = 2 + n;
  }
  const end = at + head + len;
  if (end > bytes.length) throw new DerError('cut short');
  return { el: { tag, raw: bytes.subarray(at, end), body: bytes.subarray(at + head, end) }, next: end };
}

/** One element that is the whole of `bytes`. */
export function parseDer(bytes: Uint8Array<ArrayBuffer>): Der {
  const { el, next } = readDer(bytes);
  if (next !== bytes.length) throw new DerError('bytes after the end');
  return el;
}

/** The elements inside a constructed one. */
export function children(el: Der): Der[] {
  if (!(el.tag & 0x20)) throw new DerError('not a constructed element');
  const out: Der[] = [];
  for (let at = 0; at < el.body.length;) {
    const r = readDer(el.body, at);
    out.push(r.el);
    at = r.next;
  }
  return out;
}

export const TAG = { int: 0x02, bits: 0x03, octets: 0x04, oid: 0x06, utf8: 0x0c, seq: 0x30, set: 0x31, printable: 0x13, ia5: 0x16, utc: 0x17, time: 0x18, bool: 0x01 } as const;

export function expect(el: Der | undefined, tag: number): Der {
  if (!el || el.tag !== tag) throw new DerError(`expected tag ${tag.toString(16)}`);
  return el;
}

/** An object identifier in dotted form. */
export function oid(el: Der): string {
  expect(el, TAG.oid);
  const b = el.body;
  if (!b.length) throw new DerError('an empty identifier');
  const parts: number[] = [];
  let v = 0;
  let first = true;
  for (let i = 0; i < b.length; i++) {
    v = v * 128 + (b[i]! & 0x7f);
    if (v > Number.MAX_SAFE_INTEGER) throw new DerError('an identifier too large');
    if (!(b[i]! & 0x80)) {
      if (first) { parts.push(Math.min(2, Math.floor(v / 40)), v - 40 * Math.min(2, Math.floor(v / 40))); first = false; } else parts.push(v);
      v = 0;
    } else if (i === b.length - 1) throw new DerError('an identifier cut short');
  }
  return parts.join('.');
}

/** A UTCTime or GeneralizedTime as milliseconds since 1970. */
export function time(el: Der): number {
  const s = String.fromCharCode(...el.body);
  const m = el.tag === TAG.utc ? /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s) : el.tag === TAG.time ? /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(?:\.(\d{1,9}))?Z$/.exec(s) : null;
  if (!m) throw new DerError('a time this reader does not accept');
  const year = el.tag === TAG.utc ? (+m[1]! < 50 ? 2000 : 1900) + +m[1]! : +m[1]!;
  const ms = el.tag === TAG.time && m[7] ? Math.floor(+`0.${m[7]}` * 1000) : 0;
  const t = Date.UTC(year, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!, ms);
  if (!Number.isFinite(t)) throw new DerError('a time this reader does not accept');
  return t;
}

/** A BIT STRING's bytes (whole bytes only). */
export function bits(el: Der): Uint8Array<ArrayBuffer> {
  expect(el, TAG.bits);
  if (!el.body.length || el.body[0] !== 0) throw new DerError('a bit string this reader does not accept');
  return el.body.subarray(1);
}

/** An INTEGER's bytes without a leading zero (a positive number, big-endian). */
export function unsigned(el: Der): Uint8Array<ArrayBuffer> {
  expect(el, TAG.int);
  let b = el.body;
  while (b.length > 1 && b[0] === 0) b = b.subarray(1);
  return b;
}
