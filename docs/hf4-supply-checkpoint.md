# HF4 Proof-Carrying Supply Checkpoint

**Status:** Public evidence-intake/specification only in this branch; this documentation-only branch contains no consensus code changes. An experimental local scaffold exists for the canonical envelope, HF4 block carrier, mainnet fail-closed activation gate, local canonical-history replay, and source-anchor/body-provenance paths, but it is not published or part of this review. The intended file-based pair verifier requires canonical, Ed25519-signed manifests; signed block and body catalogs; distinct pinned keys/operators; and exact raw-body matches. Public-key pins remain caller-supplied out-of-band, and no approved mainnet anchor, trusted-source registry, collector, or real archive data is installed. Replay still does not establish exact supply. The proof system, corrected historical accounting, claim/nullifier state, and repair transition remain unimplemented. **Not production-ready; mainnet HF4 remains unscheduled.**

For archive submissions, see [public evidence intake](hf4-public-review.md).

## Objective

At the HF4 migration boundary, publish the exact aggregate amount of DERO credited to HF4 while keeping individual wallet balances private. The exact total outstanding is intentionally public on HF4 and remains a consensus-visible value after the checkpoint. Use that verified aggregate to select a deterministic, pre-authorized recovery rule. This is a base-layer state transition; a DVM contract must not mint, inspect, or reconcile native balances.

## Current code state — incomplete by design

- `supplycheckpoint` defines a versioned fixed-width envelope, canonical proof-length encoding, 4 MiB proof-size cap, metadata checks, domain-separated IDs/nullifier derivation, and a `ProofVerifier` interface that fails closed when no verifier is supplied. Its test verifier is only a unit-test double.
- HF4 blocks carry an optional length-prefixed checkpoint after `Block.Proof`; the block hash commits to the payload. `Block.Proof` remains reserved for the ordered transaction-body commitment. Every HF4 implementation must use this same wire format.
- `Blockchain.Add_Complete_Block` and the P2P bootstrap preflight both reject malformed, unexpected, and unverified checkpoint payloads. Bootstrap validates every returned block before applying peer-provided state. With mainnet's `RequireSupplyCheckpoint` enabled, a scheduled HF4 activation also rejects a missing checkpoint. No consensus proof backend or approved mainnet source anchor is configured, so a checkpoint-bearing activation cannot pass yet.
- Testnet leaves the activation gate disabled for existing HF4 simulation coverage; it still rejects non-empty, unverified checkpoint payloads. This is not a production-mode setting.
- `Blockchain.ReplayCanonicalHistoryInto` is an unanchored diagnostic path and cannot mark supply known. `ReplayCanonicalHistoryIntoWithAnchor` requires a non-nil `CanonicalReplayAnchorVerifier`, then checks that the local source matches the approved genesis, block ID, and state root and remains stable during replay. `ReplayCanonicalHistoryIntoWithAnchorAndBodyProvenance` requires anchor and body verifiers to expose the same authenticated archive trust set; `ReplayCanonicalHistoryIntoWithIndependentArchiveEvidence` uses one object for both. `ReplayCanonicalHistoryIntoWithAnchorAndDiagnosticBodyProvenance` can exercise mock sessions, but never marks their evidence verified. `IndependentArchiveBodyProvenanceVerifier` authenticates the anchor against two signed manifests and distinct caller-pinned sources before replay, without hashing the large catalogs twice. No production key enrollment or approved mainnet anchor is installed.
- `TransactionBodiesConsensusBound` is structural, not provenance: replay rechecks the v4 serialized-body commitment and marks legacy blocks with transactions as unbound. The ledger may instead accept a completed trust-bound provenance session that verifies every replayed body against at least two approved archive sources, hard-fails missing/conflicting records, and returns a domain-separated commitment root. `IndependentArchiveBodyProvenanceVerifier` consumes canonical `manifest.json`, lowercase-hex `manifest.sig`, `blocks.jsonl`, `bodies.jsonl`, and `tx/<lowercase-tx-hash>/<lowercase-body-sha256>.hex`. Each manifest signature is verified against a caller-pinned Ed25519 key; the signed manifest commits to both ordered block rows and a per-occurrence body catalog of `(topo_height, transaction_index, transaction_hash, body_sha256, body_size)`. The verifier requires distinct source IDs, operator IDs, and public keys; exact catalog/body/replay-source agreement; full prefix coverage; and end-of-stream/hash rechecks. The public-key pins still require authenticated out-of-band enrollment, and source collection/operator independence is not established by the file format. No production trust registry, collector, or real archive data exists, so pre-HF4 replay still cannot establish known supply. Corrected historical rules and adversarial reorg cases also remain to be validated.
- Exact per-wallet amounts are never serialized. The aggregate `S_hf4` is intentionally public and remains queryable after HF4; no DVM call is used for supply reconciliation. No migration balance is accepted from this envelope alone.

The 4 MiB cap and payload layout are provisional protocol choices, not a frozen mainnet specification. The wire change must be reviewed and finalized before any HF4 release.

The checkpoint counts **snapshot balances credited to HF4**, not gross historical transfer volume. Counting every transfer would count the same coins repeatedly.

### Archive bundle format

Each independently collected archive is a directory containing canonical `manifest.json`, lowercase-hex `manifest.sig`, `blocks.jsonl`, `bodies.jsonl`, and `tx/<lowercase-tx-hash>/<lowercase-body-sha256>.hex`. The content-addressed body path is required: a proof-less transaction ID can recur with distinct serialized proof bytes, so a single file keyed only by tx ID cannot represent the replay history. `blocks.jsonl` contains one canonical topological row per block, in height order, with `topo_height`, `block_hash`, and ordered `transaction_hashes`. `bodies.jsonl` contains one canonical row per transaction occurrence in that same replay order: `topo_height`, `transaction_index`, `transaction_hash`, `body_sha256`, and `body_size`. The manifest records the source/operator IDs, collection command, a public or non-identifying endpoint label (never a private/internal endpoint), full source commit, inclusive genesis-to-anchor range, anchor tuple, and SHA-256 of the exact `blocks.jsonl` and `bodies.jsonl` bytes. Its detached Ed25519 signature covers the exact canonical `manifest.json` bytes; each `.hex` file contains the exact serialized body, lowercase hex, with at most one trailing newline. The signed body catalog binds each occurrence to its content-addressed `.hex` body, size, and SHA-256. Optional raw collector responses may be retained alongside the bundle for audit, but are not consumed by the verifier.

Canonical JSON means the compact UTF-8 bytes returned by Go `encoding/json.Marshal` for the schema-v1 structs in their declared field order, with its default escaping; `manifest.json` has no trailing newline, and each JSONL record is followed by exactly one LF. The manifest signature file is exactly 128 lowercase hex characters with either no terminator, one LF, or one CRLF. The manifest hashes cover the exact JSONL files, including their LF separators.

The caller must provide two pre-approved, distinct source IDs, operator IDs, and lowercase-hex Ed25519 public keys in `ApprovedSources`; reading any identity or key from a bundle and echoing it into approvals is not approval. The signature authenticates the exact manifest and its signed block/body catalogs against the pinned key, but does not itself prove that the operators collected data independently or honestly. Enroll keys through a separate authenticated process and preserve the identity-to-key approval record. Private signing keys must remain with their archive operators and must never be included in bundles or this repository.

The returned body root is SHA-256 over domain `DERO-HF4-ARCHIVE-BODY-PROVENANCE-V2\0`. It first commits to each archive in sorted source-ID order: length-prefixed source ID, operator ID, and archive ID; raw 32-byte SHA-256 values of canonical manifest bytes, decoded Ed25519 signature, and pinned public key; then the approved anchor's big-endian through-topoheight, genesis block ID, anchor block ID, and state root. It then commits to each replayed height in order: big-endian topoheight, block hash, big-endian transaction count, and each ordered transaction's big-endian index, tx hash, SHA-256 of exact body bytes, and big-endian byte size. This is an evidence commitment, not a supply total or a consensus proof.

## Terms and accounting

All values are integer atomic units (`100,000` per DERO); no floating-point arithmetic is permitted.

- `H_s`: fixed source-chain snapshot height.
- `R_s`: source balance-tree root at `H_s`.
- `S_mig`: sum of source balances credited to HF4. The default policy is a complete snapshot: every eligible nonzero source leaf must be represented exactly once, whether or not its owner submits an individual claim.
- `S_hf4`: HF4 aggregate supply at checkpoint height, including HF4 issuance and excluding consensus burns.
- `T`: policy target derived from a validated corrected replay / approved supply rule. It is not the best estimate, a rounded cap, or the current reporting floor.
- `K`, `U`: respectively confirmed-correct and explicitly unresolved portions, only when the selected recovery policy has a proof-backed way to distinguish them.

`S_mig` and `S_hf4` are separate fields. A checkpoint must not describe claim volume as total supply. The default complete-snapshot policy requires proof that every eligible nonzero leaf under `R_s` is represented exactly once and that the resulting aggregate is correct; an unclaimed leaf must never be inferred to be zero.

If full-snapshot verification by replay or proof is infeasible, an opt-in fallback is possible only if HF4 still initializes its public total from an independently verified full-snapshot amount, derived from a separately validated supply ledger or corrected replay—not merely the current estimate. In that mode `S_mig` is the amount claimed so far; the unclaimed source amount remains in a consensus-locked, publicly counted reserve equal to the verified source total minus claims, with checkpoint-period issuance/burns accounted for separately. Later claims move value from reserve to spendable balances and must use unique nullifiers. The source snapshot must be frozen or replay-protected. If no independent total exists, opt-in can report only the claimed sum and does not satisfy the requirement to publish total outstanding supply.

On a direct aggregate-proof route, the balance representation makes complete-snapshot proving a participation/knowledge problem as well as a circuit-cost problem: `NonceBalance` stores an ElGamal balance (`cryptography/crypto/balance_serdes.go:29-32`), `CommitElGamal` encrypts under a supplied account key (`cryptography/crypto/algebra_elgamal.go:44-49`), and the wallet decrypts using that account's secret (`walletapi/daemon_communication.go:379-382`). A distributed zero-knowledge prover can keep those witnesses private, but a missing account witness cannot be recovered from these ciphertexts without an independent verified supply/replay source or a decryption-key model, which this design forbids. Deterministic replay is the candidate that could avoid that holder-participation requirement while preserving the full snapshot.

If HF3 remains live, HF4 is a separate chain snapshot/copy. HF4 migration does not erase or burn the corresponding HF3 balances. Chain identity and transaction-domain separation must make that distinction explicit.

## Why a plain counter is insufficient

`cryptography/crypto/balance_serdes.go` stores each `NonceBalance` as an ElGamal ciphertext. `cryptography/crypto/algebra_elgamal.go` constructs the ciphertext using a supplied account key; adding ciphertext points under different account keys does not reveal the total. The existing transaction `crypto.Proof` is not a direct proof of an arbitrary snapshot sum.

A deterministic corrected replay is a separate possible verification route: if every historical block is revalidated and each confidential transaction proof enforces amount conservation, validators can derive the aggregate inductively from public issuance and burn events while replaying the encrypted state transitions. That would verify a full snapshot without decrypting individual balances. The unanchored `ReplayCanonicalHistoryInto` path is diagnostic-only; `ReplayCanonicalHistoryIntoWithAnchor` adds a required verifier callback and matches the source genesis/block/state root to the approved tuple. `IndependentArchiveBodyProvenanceVerifier` now provides an archive-backed callback that checks the anchor against two signed manifests, using distinct caller-supplied source/operator IDs and pinned public keys. No production source pins, trusted registry, approved mainnet anchor, or real archives are installed. Replay still applies active rules, does not derive the exact issuance-minus-burn ledger, and does not produce a consensus checkpoint proof. It must cover historical corrections and the known exploit before it can establish the full snapshot.

Therefore, a field such as `supply_total: 3564000000` without a proof or a fully validated deterministic replay is not a consensus check: a block producer could assert an arbitrary value. The existing `GetInfo.total_supply` is the scheduled `CalcSupply(height)` value in whole DERO; `spendable_supply` adds a fixed exploit estimate. Neither is an independently verified exact aggregate of encrypted balances, and neither accounts for historical burn events. HF4's exact `S_hf4` will be public in atomic units and must be consensus-verified. Do not substitute plaintext balances, a public per-claim amount, or an undisclosed auditor key.

### Replay-first feasibility checks

- `CalcSupply` is calculated from premine, a fixed historical registration grant, and the block-reward schedule (`blockchain/supply.go:5-25`). `SpendableSupply` only adds a hard-coded exploit estimate (`blockchain/supply.go:28-32`); `GetInfo` rounds both values down to whole DERO (`cmd/derod/rpc/rpc_dero_getinfo.go:84-85`). These are not yet an exact checkpoint anchor.
- A native `BURN_TX` carries public `BurnValue` in its asset payload and the transaction proof binds fees plus that public value (`transaction/transaction.go:97-100`, `cryptography/crypto/proof_verify.go:108-110`). A supply replay must distinguish true native burns from `SC_TX` value that moves into contract state.
- Block execution updates encrypted balances homomorphically (`cryptography/crypto/algebra_elgamal.go:69-74`, `blockchain/transaction_execute.go:203-256`). The new replay runner applies canonical blocks to a fresh chain and compares state roots at each topological height; a small simulator case passes. If corrected replay from genesis or a verified prior anchor also derives the exact public issuance-minus-burn accumulator, it can preserve all wallet allocations without requiring every holder to submit a claim. A succinct proof may still be needed for nodes that cannot replay the history.
- Still open: corrected exploit treatment, exact public total, full-history/reorg determinism, and light-client/bootstrap proof. The current simulator test does not establish those properties.

## Checkpoint placement and payload

Use an ordinary HF4 block at a deterministic migration-close height, with one canonical consensus checkpoint payload. Do not create a special PoW/block-validation path and do not overload `Block.Proof`, which is already used by HF4 to commit to ordered serialized transaction bodies. The checkpoint payload and proof bytes must be available to every validating node and committed by the HF4 block ID.

The versioned, canonical payload contains:

```text
protocol_version
source_chain_id
source_height
source_block_hash
source_balance_root
migration_claim_root
hf4_state_root
migrated_total_atomic_units (S_mig)
hf4_total_supply_atomic_units (S_hf4)
repair_policy_hash
proof_system_id
proof_bytes
```

Use fixed-width/canonical encodings, explicit byte order, checked integer arithmetic, and domain-separated hashes. Bind the checkpoint to the source chain ID, snapshot identity, destination chain ID, both state roots, both public totals, and policy hash. Any proof or replay certificate must be consensus data, not an off-chain attachment that nodes are expected to trust or fetch later.

## Required verification statement

An independently checkable verification method is a blocking prerequisite, but it need not be a new SNARK. First test whether deterministic corrected replay can establish the complete source root and public total. If it cannot, specify and review a succinct zero-knowledge proof of the complete state transition. Either route must let independent nodes verify, without seeing per-wallet amounts, that:

1. The source chain ID, snapshot height, block hash, and `R_s` match the fixed consensus anchor; in opt-in mode, every claim also proves source-leaf membership and account control.
2. A source leaf/nullifier is used at most once on HF4; claims cannot be replayed across chain domains.
3. Each destination encrypted balance equals the source amount or the exact deterministic repair result for that leaf.
4. Amounts are in range; every addition, sum, and repair operation is overflow-checked.
5. The aggregate of accepted destination balances is exactly `S_mig`.
6. In complete-snapshot mode, no eligible nonzero source leaf is omitted or duplicated.
7. In opt-in mode, the locked unclaimed reserve equals the independently verified source total minus claims, adjusted for checkpoint-period issuance/burns; every later claim consumes it under a unique nullifier.
8. The resulting HF4 state root is exactly `hf4_state_root`.

The verification path must not require one operator to collect plaintext balances or private keys. The existing transaction Bulletproof is not a standalone aggregate-state proof, though it can be checked per transaction during deterministic replay. If replay cannot be validated by all required nodes, use an independently reviewed zero-knowledge/distributed proof of the complete state transition; if neither route verifies, fail closed. No threshold auditor/decryption key is part of this proposal.

## Deterministic repair state machine

Every node evaluates the same replay or proof and the same committed policy hash. There is no discretionary or heuristic repair at runtime.

1. **Failed replay/proof, wrong source root, duplicate claim, or incomplete required evidence:** reject the checkpoint; do not infer a total.
2. **Verified `S_mig` matches the approved corrected target:** initialize the proven destination state unchanged.
3. **Confirmed invalid deltas are attributable by corrected replay:** use the corrected state/root and independently recompute the checkpoint total.
4. **Excess remains unresolved:** apply a proportional reduction only if the precommitted policy explicitly authorizes it and provides proof-backed `K` and `U`. For `U > 0`, the fixed rule is `R = max(T-K, 0)`, `alpha = min(1, R/U)`, and `new_i = floor(alpha * unresolved_i)`; all rounding remainder is burned. If `K >= T`, halt for governance rather than silently haircut confirmed balances.
5. **Verified total is below `T`:** import the proven total; do not mint the difference merely to reach a target.

The exact `T`, evidence roots, treatment classes, policy hash, and migration-close height must be committed before activation. The present `35.64M` figure is a best estimate, not a proven checkpoint value or a hard-coded target.

## Post-checkpoint invariant

After finalization, HF4's public aggregate supply is initialized from the verified `S_hf4`. Every later confidential transaction must satisfy the existing amount-conservation proof; rewards and burns update the public aggregate deterministically. A supply mismatch is a block-validity failure, not a reporting warning. The exact current outstanding total in atomic units must remain consensus-visible and be exposed by RPC with checkpoint height, policy version, and proof status. The legacy whole-DERO `total_supply` field may remain for compatibility, but must not substitute for the exact total; individual balances remain private.

A published precedent is [XLS-0096](https://xls.xrpl.org/xls/XLS-0096-confidential-mpt.html): it keeps the aggregate outstanding amount public and treats private transfers as supply-neutral. Its design also stores issuer- and optionally auditor-encrypted balance copies; HF4 must not adopt that key model. Reuse only the public-counter invariant. This pattern addresses post-checkpoint accounting, not the one-time proof that the complete source snapshot sums to `S_hf4`.

## Validation snapshot (local implementation tree; not this documentation-only branch)

These results are from a separate local implementation worktree. They verify code paths and synthetic fixtures, not mainnet archive truth.

- `gofmt -l` over 29 changed Go files: no output (clean).
- Go 1.25.14, vendored/offline whole-repository suite (`GOPROXY=off GOSUMDB=off GOMAXPROCS=1 go test -count=1 -mod=vendor -p 1 ./...`): PASS (exit 0).
- Repeated package set, `go test -count=50 -mod=vendor -p 1 ./block ./config ./supplycheckpoint ./p2p`: PASS.
- Targeted HF4/supply-ledger tests in `./blockchain`, `-count=50`: PASS.
- `TestSeamlessMigrationAtHF4AndLaterBlock`, `-count=10`: PASS (43.504 s).
- Package-wide repeatability attempt, `go test -count=50 -mod=vendor -p 1 ./blockchain ./cmd/simulator`: NOT PASS. The `cmd/simulator` package reached Go's default 10-minute test timeout at 600.103 s and emitted a goroutine dump. We do not claim package-wide 50x stability.
- Whole-repository `go vet -mod=vendor -p 1 ./...`: exit 1. Diagnostics were unreachable-code warnings in `blockchain`, `cmd/derod`, `cryptography/crypto`, and `dvm`, plus unkeyed `rpc.Argument` literals in DVM tests. No diagnostic pointed to the new supply checkpoint/archive files; the failing vet gate remains open.

These checks do not validate real mainnet archives or authenticated source identities/anchor, any aggregate proof, corrected full-history supply accounting, claim/nullifier state, full-chain reorg stability, or the repair transition. The checkpoint is still not production-ready.

## Required adversarial tests

- Valid proof; wrong total; wrong source/destination roots; wrong chain ID; wrong policy hash; altered proof bytes.
- Missing, duplicate, reordered, or omitted claims; duplicate nullifiers; replay across HF3/HF4 and across two HF4 domains.
- Zero balances, maximum supported balances, integer overflow, sum overflow, haircut rounding, `K >= T`, and empty migration set.
- Incomplete snapshot versus complete-snapshot policy; unclaimed leaves must never be silently treated as zero.
- Checkpoint at the wrong height, before migration close, after close, after reorg, and after restart/state restore.
- Old-node rejection, block-ID/body commitment binding, canonical serialization, and deterministic verifier behavior across architectures.
- Differential comparison against an independently reproduced corrected replay and its committed state roots.

## Implementation gates

1. Freeze the source snapshot, corrected replay evidence, migration semantics, and policy before setting `T`.
2. First test deterministic corrected replay from the fixed source anchor: it must reproduce the full balance root and exact public total from validated issuance, registration grants, burns, and corrected exploit treatment. If full validators cannot independently run it, specify and review a succinct zero-knowledge/distributed proof of the complete transition. Do not hand-roll a SNARK or substitute a trusted estimate.
3. Freeze the wire format for the chosen route; the archive-backed source-anchor verifier now exists and checks two signed manifests against distinct caller-pinned sources. Still required: authenticate/enroll the production keys and anchor, complete the exact public supply ledger, and implement claim/nullifier plus locked-reserve state if opt-in migration is selected. No production source registry/anchor is installed, the replay does not derive exact supply, and it does not feed a consensus proof verifier.
4. Extend simulator and adversarial tests for the full state transition, replay/reorg behavior, body ambiguity, and every repair branch. Current replay coverage is a small simulator chain with one legacy registration transaction; it does not establish full-history corrected replay or the repair branches.
5. Only after those gates pass should an HF4 activation schedule or release documentation include the checkpoint. Mainnet activation remains unscheduled.
