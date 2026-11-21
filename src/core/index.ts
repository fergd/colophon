// The core: pure functions that run anywhere WebCrypto does. Nothing here touches a file, a key store, a network
// or a clock; those come through `ports.ts`.

export { canonical, isCanonical, parseLine, type Json } from './canonical.ts';
export { base64url, unbase64url, hex, unhex, utf8, concat, equal } from './bytes.ts';
export { entryHash, sha256, HASH } from './hash.ts';
export * from './entries.ts';
export { partSalt, partLeaf, leafHash, merkleRoot, auditPath, rootFromPath, verifyDisclosure, type Part, type Disclosure } from './merkle.ts';
export { fingerprint, verifySignature } from './keys.ts';
export { Chain, newId, newSecret, type ChainPorts, type Written } from './chain.ts';
export { verify, exitStatus, VERIFIER, CLOCK_TOLERANCE_MS, BLOCK_SLACK_MS, type Result, type Finding, type Status, type VerifyInput, type ChainReport, type AnchorReport, type GapReport } from './verify.ts';
export { describe, span, type Sentence } from './describe.ts';
export { verifyRfc3161, type Rfc3161Result } from './anchors/rfc3161.ts';
export { verifyOpenTimestamps, splitOtsFile, pendingRequests, completeOpenTimestamps, type OtsResult, type Headers, type BlockHeader, type PendingRequest } from './anchors/opentimestamps.ts';
export { TRUSTED_ROOTS, ROOTS_DATED, rootBytes, type TrustedRoot } from './anchors/roots.ts';
