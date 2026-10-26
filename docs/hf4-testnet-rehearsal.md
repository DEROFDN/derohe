# HF4 loopback testnet rehearsal

_Status: partial rehearsal. This is a two-node loopback testnet, not the multi-operator WAN rehearsal required before a mainnet activation height is set._

## Purpose

Exercise the HF4 v4 block path, the transaction-body commitment, the hardcoded migration install, and the reporting-only supply gate on a live testnet chain.

## Build and topology

Built from the release branch commit `ffebe92`.

| Node | P2P | JSON-RPC | getwork |
|---|---|---|---|
| N1 | `127.0.0.1:28101` | `127.0.0.1:28201` | `127.0.0.1:28301` |
| N2 | `127.0.0.2:28102` | `127.0.0.2:28202` | `127.0.0.2:28302` |

N2 dials N1 with `--add-exclusive-node=127.0.0.1:28101`. Both use `--testnet`, where `MAJOR_HF4_HEIGHT = 0` and `K0_MIN_RING4_HEIGHT = 0`, so HF4 is active at genesis.

```sh
go build -o derod.exe ./cmd/derod
go build -o dero-miner.exe ./cmd/dero-miner

./derod.exe --testnet --data-dir=<scratch>/n1 \
  --p2p-bind=127.0.0.1:28101 --rpc-bind=127.0.0.1:28201 --getwork-bind=127.0.0.1:28301 \
  --min-peers=1 --max-peers=8 --node-tag=n1

./derod.exe --testnet --data-dir=<scratch>/n2 \
  --p2p-bind=127.0.0.2:28102 --rpc-bind=127.0.0.2:28202 --getwork-bind=127.0.0.2:28302 \
  --add-exclusive-node=127.0.0.1:28101 --min-peers=1 --max-peers=8 --node-tag=n2

./dero-miner.exe \
  --wallet-address deto1qy0ehnqjpr0wxqnknyc66du2fsxyktppkr8m8e6jvplp954klfjz2qqdzcd8p \
  --daemon-rpc-address=127.0.0.1:28301 --mining-threads=2 --testnet
```

The miner address is the public testnet development address from `config.Testnet`; no funded wallet was used.

## Results

| Check | Result |
|---|---|
| Blocks produced | heights 1, 2, 3 |
| Block version | `major_version=4`, `minor_version=4` on all three |
| Cross-node agreement | identical block hashes at topoheight 1, 2, 3 on N1 and N2 |
| Body commitment | block 1 deserialized: `txhashes=0`, `proof=82d2c12431b98d47f03b2663cccc764b1e05fad384a0c713e222db15a618cf7b`, equal to `SerializedTransactionsCommitment(nil)` |
| Migration SC | installed and queryable on both nodes; code begins `// Stateless migration marker...`, balance `0` |
| Supply reporting | at height 3: `total_supply=12283973`, `spendable_supply=12283973`, `forensic_supply` absent (testnet gate) |
| Follower sync | N2 reached the same height and hashes as N1 |

The migration SCID is the reserved hash with the final byte `0x02`. The installed contract carries no value, matching the stateless marker design.

## Operational findings

- Peer identity is keyed by IP address. Multiple loopback nodes sharing `127.0.0.1` collapse to a single peer, so each loopback node needs a distinct `127.0.0.x` address.
- Starting peers simultaneously produced mutual dial backoff. Sequential start, or one-way exclusive dials, connected cleanly.
- `--min-peers=0` is rejected by the P2P engine (`--min-peers should be positive and more than 1`). Use at least `1`.
- The miner must target the daemon getwork port (for example `28301`). Dialing the JSON-RPC port returns empty blockwork and the miner loops on `Blockwork could not be decoded successfully`.

## Not covered

- Multi-operator WAN rehearsal. This remains an activation gate in the runbook.
- A live migration transaction from a funded wallet. The validation matrix is covered deterministically by `blockchain/migration_validation_test.go`, `dvm/seamless_migration_test.go`, `cmd/simulator/seamless_migration_fork_test.go`, and `walletapi/rpcserver/rpc_scinvoke_migration_test.go`.
- A reorg across the activation boundary. This is covered by the simulator migration/fork tests.
