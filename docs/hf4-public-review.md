# HF4 supply review: public evidence intake

## Status

This is an evidence request, not a consensus change or activation proposal. The exact historical DERO supply affected by the HF3 issue is not independently established here. Existing estimates and synthetic replay tests are not proof of the mainnet total. No mainnet HF4 activation is proposed by this document.

The technical proposal and archive format are in [HF4 proof-carrying supply checkpoint](hf4-supply-checkpoint.md). Its implementation gates remain open; in particular, there is no approved mainnet anchor, authenticated source-key registry, real archive pair, corrected full-history supply ledger, or production proof backend.

## What chain users can contribute

Please submit **one archive bundle per issue** using the `HF4 archive evidence` issue form. Two bundles are needed from independently operated sources, covering the same chain and a common anchor. Each must contain a contiguous, reproducible history from genesis through that anchor, including the exact serialized transaction bodies required by the specification. A non-genesis start is diagnostic only unless maintainers have already approved a fully verified prior anchor and its exact state; no such mainnet anchor is currently approved.

Include, or make available through a durable public URL:

- a canonical `manifest.json` and detached `manifest.sig`;
- the ordered `blocks.jsonl` and per-occurrence `bodies.jsonl` catalogs;
- the exact serialized transaction-body files referenced by the catalog;
- SHA-256 for the bundle and each manifest/catalog file;
- network/chain ID, genesis ID, source and operator IDs, node software commit, collection command, coverage range, and the shared anchor tuple (topological height, block ID, and state root).

A partial archive can help diagnose a specific transaction or block, but it cannot establish the complete aggregate supply. Label partial coverage clearly; do not describe it as a full-history verification.

## Verification bar

A submission is an **untrusted candidate**, not an approved source. Maintainers must independently:

1. verify canonical JSONL framing and all file hashes;
2. authenticate each Ed25519 public key out-of-band before trusting its manifest signature (a key posted in the issue is only a candidate key);
3. check distinct sources, operators, and signing keys, then assess whether collection was genuinely independent;
4. verify full contiguous coverage and agreement on chain identity and the anchor;
5. reproduce the exact block/body matches and corrected supply replay, including reorg/restart cases.

A valid signature alone does not prove source independence, completeness, or correct accounting. Do not claim an exact supply total until independent archives and corrected replay support it. Any later consensus proof, migration rule, or activation schedule requires separate review and approval.

## Data safety

Submit only public chain data. Never post seed phrases, private signing keys, passwords, RPC credentials, authenticated download URLs, private endpoints, internal IP addresses, or personal identifying information. Use pseudonymous source/operator IDs. For large bundles, provide a durable unauthenticated public URL and its SHA-256; never place access tokens in the URL or issue text.
