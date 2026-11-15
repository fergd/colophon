// A checkpoint's commitment to the manuscript's parts (SPEC §6.3): the Merkle Tree Hash of RFC 6962 §2.1 over
// salted leaves, so one part can later be shown without revealing the others.

import { concat, equal, utf8 } from './bytes.ts';
import { hmacSha256, sha256 } from './hash.ts';

export interface Part {
  /** Stable identifier, 1 to 64 ASCII characters. */
  id: string;
  content: Uint8Array;
}

const SALT_LABEL = 'provenance-part-v0:';
const validId = (id: string) => /^[\x21-\x7e]{1,64}$/.test(id);

/** A part's salt: HMAC-SHA-256(secret, "provenance-part-v0:" ‖ id). The same for a part at every checkpoint. */
export async function partSalt(secret: Uint8Array<ArrayBuffer>, id: string): Promise<Uint8Array<ArrayBuffer>> {
  if (secret.length !== 32) throw new Error('the secret is 32 bytes');
  if (!validId(id)) throw new Error('a part id is 1 to 64 printable ASCII characters');
  return hmacSha256(secret, utf8(SALT_LABEL + id));
}

/** The leaf hash of a part given its salt: SHA-256(0x00 ‖ salt ‖ len(id) ‖ id ‖ content). */
export async function leafHash(salt: Uint8Array, part: Part): Promise<Uint8Array<ArrayBuffer>> {
  if (!validId(part.id)) throw new Error('a part id is 1 to 64 printable ASCII characters');
  const id = utf8(part.id);
  return sha256(concat(Uint8Array.of(0), salt, Uint8Array.of(id.length), id, part.content));
}

/** A part's leaf hash from the chain's secret. Unchanged parts give unchanged leaves: a host may cache them. */
export async function partLeaf(secret: Uint8Array<ArrayBuffer>, part: Part): Promise<Uint8Array<ArrayBuffer>> {
  return leafHash(await partSalt(secret, part.id), part);
}

const node = (left: Uint8Array, right: Uint8Array) => sha256(concat(Uint8Array.of(1), left, right));
/** The largest power of two smaller than n (n > 1). */
const split = (n: number) => { let k = 1; while (k * 2 < n) k *= 2; return k; };

/** The root over leaf hashes, in order; null for none. */
export async function merkleRoot(leaves: Uint8Array[]): Promise<Uint8Array | null> {
  if (!leaves.length) return null;
  if (leaves.length === 1) return leaves[0]!;
  const k = split(leaves.length);
  const [l, r] = await Promise.all([merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k))]);
  return node(l!, r!);
}

/** The audit path for the leaf at `index` (RFC 6962 §2.1.1): the hashes a reader needs, nearest first. */
export async function auditPath(leaves: Uint8Array[], index: number): Promise<Uint8Array[]> {
  if (index < 0 || index >= leaves.length) throw new Error('no such leaf');
  if (leaves.length === 1) return [];
  const k = split(leaves.length);
  return index < k
    ? [...await auditPath(leaves.slice(0, k), index), (await merkleRoot(leaves.slice(k)))!]
    : [...await auditPath(leaves.slice(k), index - k), (await merkleRoot(leaves.slice(0, k)))!];
}

/** The root a leaf and its audit path give, for a tree of `size` leaves; null when the path doesn't fit that tree. */
export async function rootFromPath(leaf: Uint8Array, index: number, size: number, path: Uint8Array[]): Promise<Uint8Array | null> {
  if (index < 0 || index >= size) return null;
  // (the tree's shape is walked from the root down to find which side each step is on, then the path is applied from the leaf up)
  const sides: ('left' | 'right')[] = [];
  let n = size;
  let i = index;
  while (n > 1) {
    const k = split(n);
    if (i < k) { sides.push('left'); n = k; } else { sides.push('right'); i -= k; n -= k; }
  }
  if (sides.length !== path.length) return null;
  let h = leaf;
  for (let step = 0; step < path.length; step++) {
    const side = sides[sides.length - 1 - step]!;
    h = side === 'left' ? await node(h, path[step]!) : await node(path[step]!, h);
  }
  return h;
}

/** What a writer shows to open one part of a checkpoint (SPEC §6.4). */
export interface Disclosure {
  part: Part;
  salt: Uint8Array;
  index: number;
  parts: number;
  path: Uint8Array[];
}

/** Whether a disclosed part is under `root`. */
export async function verifyDisclosure(d: Disclosure, root: Uint8Array): Promise<boolean> {
  const got = await rootFromPath(await leafHash(d.salt, d.part), d.index, d.parts, d.path);
  return !!got && equal(got, root);
}
