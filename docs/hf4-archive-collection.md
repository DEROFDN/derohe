# HF4 archive collection

`cmd/hf4-archive-collect` is the reference collector for signed HF4 supply
archives. It reads a DERO node over JSON-RPC and writes one canonical, signed
bundle. It is not an audited tool; verification is separate and mandatory.

## Requirements

- A DERO node exposing JSON-RPC (`getblock`, `gettransactions`).
- **Genesis prefixes need a full-history node.** Public RPC nodes are pruned and
  return `empty block` for old heights. Sections only need the covered range.
- An approved anchor tuple: topo height, block hash, and state root. A section
  also needs an approved start checkpoint: first topo height, block hash, and
  state root.
- A dedicated Ed25519 signing key. Keep the 32-byte seed in a `0600` file
  outside the bundle; never reuse another operator's key.

## Build

```sh
go build -o bin/hf4-archive-collect ./cmd/hf4-archive-collect
```

## Section example

```sh
./bin/hf4-archive-collect \
  -rpc https://node.example.org/json_rpc \
  -network mainnet \
  -from 7813860 -to 7813870 \
  -start-block 47a0e9097f3194a5534f607814106877f7f980e06aef73b3a6fee87f5a791f88 \
  -start-state-root 19efc2129a96f07cfbaa429e010b0eda0b6078667292b6b5b7de6514a01acf22 \
  -out ./archive-a \
  -archive-id archive-a \
  -source-id community-node-a \
  -operator-id operator-a \
  -endpoint https://archive.example.org/archive-a \
  -collection-command "hf4-archive-collect -from 7813860 -to 7813870" \
  -source-commit <40-or-64-lowercase-hex> \
  -key-file ./archive-a.hex
```

## Genesis prefix example

```sh
./bin/hf4-archive-collect \
  -rpc http://127.0.0.1:10102/json_rpc \
  -network mainnet \
  -from 0 -to <approved-anchor-topo> \
  -genesis-block <approved-genesis-block-id> \
  -out ./archive-a \
  ... \
  -key-file ./archive-a.hex
```

`127.0.0.1` is the node connection, not the manifest endpoint. The
`-endpoint` value must be public or a non-identifying label; private hosts are
rejected by the verifier.

## Output

```text
archive-a/
  manifest.json
  manifest.sig
  blocks.jsonl
  bodies.jsonl
  tx/<transaction-hash>/<body-sha256>.hex
```

The collector prints the signing public key, first block, anchor block, and
anchor state root. Record the public key out-of-band with the submission.

## Verify

```sh
./bin/hf4-archive-verify verify-one \
  -dir ./archive-a \
  -source-id community-node-a -operator-id operator-a \
  -pubkey <printed-public-key> \
  -first-topo 7813860 \
  -start-block <64 hex> -start-state-root <64 hex> \
  -anchor-block <64 hex> -anchor-state-root <64 hex> \
  -anchor-topo 7813870 -network mainnet
```

A second operator must collect the same range independently and pass
`verify-pair`; the two catalogs must be byte-identical.

## Limits

- Single-threaded, no resume. For a full 230 GB+ history, run it on a
  full-history node with enough disk and expect a long run.
- Reorgs are not handled. Collect to a stable height below the node's
  `stableheight`, and publish the anchor before collection.
- The node supplies the data. The collector checks block hashes, transaction
  hashes, ordering, and the approved start/anchor identities; it does not prove
  the node is honest. The two-operator pair and independent review cover that.
- One archive per run. Two operators run separate commands, keys, and hosts.
