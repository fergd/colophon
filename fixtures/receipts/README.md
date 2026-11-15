# Genuine receipts

Receipts issued by real services, used to test that receipt verification is real. No test uses the network.

- `gdp2q25-2nd.pdf.ots`: a complete OpenTimestamps proof from the OpenTimestamps client's own examples
  (`opentimestamps-client/examples`). It commits the SHA-256 of a US Commerce Department PDF to a transaction in
  Bitcoin block 912095. It uses only the operations version 0 accepts (`sha256`, `append`, `prepend`).
- `bitcoin-912095.json`: that block's Merkle root and time, as any Bitcoin node or block explorer gives them
  (read from blockstream.info on 12 November 2026). It stands in for the header source a caller supplies.
- `hello-world.txt.ots`: the OpenTimestamps project's first example proof (block 358391, May 2015). Its path begins
  with RIPEMD-160, which browsers' WebCrypto does not have. Version 0's verifier reports it as **not checked**; the
  test holds it to that.

The genuine RFC 3161 receipt is inside `../v0/clean.jsonl` (its `anchor` entry with `scheme: "rfc3161"`), issued by
FreeTSA for that record's own entry. A genuine but **pending** OpenTimestamps receipt is beside it.
