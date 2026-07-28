# Go 1.26 Differential Testing Specification

**Purpose:** Validate that a Go 1.26 node produces byte-identical state
transitions to a Go 1.17 node running the same chain, before any mainnet
consensus deployment.

**Status:** Reference spec — must be implemented before Phase 1 rollout.

**Workaround C note:** Under the chosen operator-discipline path, the
differential test must also verify that `GODEBUG=randmapiter=0` is set
on all v1.26 nodes. See §13 for Workaround C-specific test requirements.

---

## 1. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                 TESTNET ORCHESTRATOR                              │
├───────────────────────────┬─────────────────────────────────────┤
│   CLUSTER A (Go 1.17)     │     CLUSTER B (Go 1.26)             │
│  ┌─────┐ ┌─────┐ ┌─────┐  │  ┌─────┐ ┌─────┐ ┌─────┐           │
│  │Node1│ │Node2│ │Node3│  │  │Node1│ │Node2│ │Node3│           │
│  └──┬──┘ └──┬──┘ └──┬──┘  │  └──┬──┘ └──┬──┘ └──┬──┘           │
│     └───────┼────────┘     │     └───────┼────────┘              │
│             │               │             │                       │
│             └───────┬───────┘             │                       │
│                     │                     │                       │
│                     ▼                     ▼                       │
│         ┌─────────────────────────────────────────┐              │
│         │     STATE COMPARATOR (Go binary)        │              │
│         │  - BlockHash @ height                   │              │
│         │  - AppStateHash (Merkle root)           │              │
│         │  - SC State Trie Root                   │              │
│         │  - Gas used (per block)                 │              │
│         │  - MiniBlock hashes                     │              │
│         │  - PoW solution                         │              │
│         └─────────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

**Constraints:**
- Each cluster must have ≥3 nodes for chain-finality
- Both clusters must connect to the same seed nodes
- All blocks produced in either cluster must be visible to both
- The state comparator polls both clusters via RPC

---

## 2. Build Both Versions

```bash
# Set up Go 1.17 toolchain (use go.mod toolchain directive or manual)
# Option A: Use a separate $GOPATH and a downloaded 1.17 tarball
GOROOT_117=/opt/go-1.17
GOROOT_126=/opt/go-1.26

# Build derod under each Go version
$GOROOT_117/bin/go build -mod=vendor -o derod_v1.17 ./cmd/derod
$GOROOT_126/bin/go build -mod=vendor -o derod_v1.26 ./cmd/derod

# Verify versions
./derod_v1.17 --version
./derod_v1.26 --version
```

If only one Go version is available (e.g. only 1.26 installed), use the
`go` toolchain directive in `go.mod` to pin a specific version, or use
a Docker image with the older Go version.

---

## 3. Generate Test Vectors

```bash
# Export historical blocks from mainnet (genesis to current tip)
./tools/export_blocks \
    --from 1 \
    --to <CURRENT_TIP> \
    --out mainnet_blocks.bin

# Verify checksum
sha256sum mainnet_blocks.bin
```

The block export must include:
- Full block headers
- Full transactions (with payloads)
- MiniBlock data
- SC state snapshots (for SC-active blocks)

---

## 4. Spin Up Shadow Testnet

```bash
# Create two datadirs
mkdir -p /tmp/testnet_v17 /tmp/testnet_v26

# Start cluster A (Go 1.17)
for i in 1 2 3; do
    ./derod_v1.17 \
        --testnet \
        --datadir /tmp/testnet_v17/node$i \
        --rpc-bind 127.0.0.1:2017$i \
        --p2p-bind 127.0.0.1:3017$i \
        --state-comparison-socket :90017 &
done

# Start cluster B (Go 1.26)
for i in 1 2 3; do
    ./derod_v1.26 \
        --testnet \
        --datadir /tmp/testnet_v26/node$i \
        --rpc-bind 127.0.0.1:2026$i \
        --p2p-bind 127.0.0.1:3026$i \
        --state-comparison-socket :90026 &
done
```

**Note:** The `--state-comparison-socket` flag is hypothetical — it would
need to be added to derohe to expose internal state hashes for comparison.
Alternative: use the existing RPC `get_info` to retrieve `topoheight` and
`get_block_header_by_topo_height` to get the block hash.

---

## 5. State Comparison Points (Every Block)

The state comparator MUST check ALL of the following at every block height:

| Metric | Source | Tolerance |
|--------|--------|-----------|
| `BlockHash` | `get_block_header_by_topo_height` | 0 bytes (exact) |
| `MiniBlockHashes` (count + each) | Block payload | 0 |
| `Tx_hashes` (count + each) | Block payload | 0 |
| `Timestamp` | Block header | 0 (modulo network clock skew) |
| `PoW Difficulty` | Block header | 0 |
| `AppStateHash` (state root) | `get_info` or new RPC | **0 (CRITICAL)** |
| `SC State Trie Root` | new RPC | **0 (CRITICAL)** |
| `UTXO Root` (balance tree) | new RPC | **0 (CRITICAL)** |
| `GasComputeUsed` (per tx) | Receipt | 0 |
| `GasStoreUsed` (per tx) | Receipt | 0 |
| `PoW Nonce` | Block header | 0 |
| `MinerAddress` | Block header | 0 |

**All metrics must be 0-tolerance (byte-exact).** Any mismatch is a hard-fork candidate.

---

## 6. State Comparator Implementation (Pseudocode)

```go
// state_comparator/main.go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "time"
)

type Snapshot struct {
    Height      uint64 `json:"height"`
    BlockHash   string `json:"block_hash"`
    AppState    string `json:"app_state"`
    UTXORoot    string `json:"utxo_root"`
    SCRoot      string `json:"sc_root"`
    GasCompute  uint64 `json:"gas_compute"`
    GasStore    uint64 `json:"gas_store"`
    MiniBlockCount int  `json:"mini_block_count"`
}

func fetchSnapshot(rpcURL string, height uint64) (*Snapshot, error) {
    // Implementation: HTTP call to derohe RPC
    // Returns 0 on mismatch
}

func main() {
    rpcA := os.Getenv("RPC_A")  // e.g. http://127.0.0.1:20171
    rpcB := os.Getenv("RPC_B")  // e.g. http://127.0.0.1:20261

    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()

    var height uint64 = 1
    for range ticker.C {
        snapA, _ := fetchSnapshot(rpcA, height)
        snapB, _ := fetchSnapshot(rpcB, height)

        if !reflect.DeepEqual(snapA, snapB) {
            fmt.Printf("MISMATCH at height %d\n", height)
            fmt.Printf("  A: %+v\n", snapA)
            fmt.Printf("  B: %+v\n", snapB)
            os.Exit(1)  // hard fail
        }

        // Advance height when both nodes have reached it
        if snapA != nil && snapB != nil {
            height++
        }
    }
}
```

---

## 7. Failure Modes & Alert Thresholds

| Failure | Severity | Action |
|---------|----------|--------|
| `BlockHash` mismatch | **CRITICAL** | Halt, snapshot both datadirs, alert |
| `AppStateHash` mismatch | **CRITICAL** | Halt, snapshot, alert |
| `SC State Trie Root` mismatch | **CRITICAL** | Halt, snapshot, alert |
| `UTXO Root` mismatch | **CRITICAL** | Halt, snapshot, alert |
| `GasComputeUsed` mismatch | **CRITICAL** | Halt, snapshot, alert |
| `MiniBlockCount` mismatch | **CRITICAL** | Halt, snapshot, alert |
| `Timestamp` drift > 1s | HIGH | Alert (network clock skew) |
| `PoW Nonce` mismatch | **CRITICAL** | Halt (impossible if BlockHash matches) |
| Sync lag (1.26 behind 1.17 by >10 blocks) | MEDIUM | Investigate, possible perf regression |

**No `WARNING` tier** for consensus metrics. Every metric is CRITICAL.

---

## 8. Test Phases & Exit Criteria

### Phase 0: Devnet (7 days)

- **Setup:** 1 v1.17 node + 1 v1.26 node, fresh genesis
- **Traffic:** Synthetic block production (no real transactions)
- **Pass criteria:**
  - 100% block hash match for 7 days
  - 0 panics
  - 0 mempool divergence

### Phase 1: Testnet Mixed (14 days)

- **Setup:** 3 v1.17 nodes + 3 v1.26 nodes, real testnet traffic
- **Traffic:** Real testnet transactions, SC calls
- **Pass criteria:**
  - 100% state hash match for 14 days
  - Sync stability >99.9%
  - 0 unscheduled restarts
  - SC calls (including complex multi-asset ones) match

### Phase 2: Mainnet Non-Consensus (30 days)

- **Setup:** v1.26 nodes running as RPC/explorer, NOT validating
- **Traffic:** Read-only, no block production
- **Pass criteria:**
  - 0 crashes
  - 100% RPC compatibility (every existing RPC method works)
  - Block sync from v1.17 validators completes without error
  - Memory profile stable (no leaks vs 1.17 baseline)

### Phase 3: Mainnet Validators Opt-In (14 days)

- **Setup:** <10% of validators upgrade; majority remain on 1.17
- **Traffic:** Mixed-version chain
- **Pass criteria:**
  - 0 forks
  - 0 peer-compat failures
  - v1.26 validators produce blocks that v1.17 validators accept
  - v1.17 validators produce blocks that v1.26 validators accept

### Phase 4: Mainnet Full Consensus (Coordinated)

- **Setup:** Coordinated upgrade window
- **Trigger:** All v1.17 validators must upgrade within the window
- **Pass criteria:** Network continues producing blocks without re-org

---

## 9. Bash Orchestration Script (Reference)

```bash
#!/usr/bin/env bash
# orchestrate_differential_test.sh
set -euo pipefail

# Config
TESTNET_DIR=/tmp/diff_testnet
DURATION_DAYS=7
LOG_DIR=/tmp/diff_logs

mkdir -p "$LOG_DIR"

# Step 1: Build
echo "[1/5] Building binaries..."
go build -mod=vendor -o derod_v1.17 ./cmd/derod
go1.26 build -mod=vendor -o derod_v1.26 ./cmd/derod

# Step 2: Generate blocks
echo "[2/5] Generating test blocks..."
./tools/export_blocks --from 1 --to 100000 --out "$TESTNET_DIR/blocks.bin"

# Step 3: Start clusters
echo "[3/5] Starting clusters..."
$TESTNET_DIR/derod_v1.17 --testnet --datadir $TESTNET_DIR/v17 &
PID_V17=$!
$TESTNET_DIR/derod_v1.26 --testnet --datadir $TESTNET_DIR/v26 &
PID_V26=$!

# Step 4: Start comparator
echo "[4/5] Starting state comparator..."
RPC_A=http://127.0.0.1:20171 \
RPC_B=http://127.0.0.1:20261 \
./state_comparator 2>&1 | tee "$LOG_DIR/comparator.log" &
PID_COMP=$!

# Step 5: Run for duration
echo "[5/5] Running for $DURATION_DAYS days..."
sleep $((DURATION_DAYS * 86400))

# Cleanup
kill $PID_V17 $PID_V26 $PID_COMP || true
echo "Test complete. Check $LOG_DIR/comparator.log for results."
```

---

## 10. Pre-Upgrade Reference State Capture

Before any validator upgrades, capture a known-good state root:

```bash
# Run on a v1.17 validator, AFTER consensus finalizes block N
derod_v1.17 --rpc-get-state-root --at-topoheight $N > state_root_v17_at_N.txt
sha256sum state_root_v17_at_N.txt
```

After upgrade, the v1.26 node should produce an identical state root
at the same topoheight. If not, the upgrade has introduced a divergence.

---

## 11. Differential Test Limitations

**What this test CAN detect:**
- Map iteration order differences
- Struct layout changes (size, alignment, padding)
- Standard library behavior changes
- Wire-format breakages (gob, custom encoders)
- GC timing affecting gas (if any)

**What this test CANNOT detect:**
- Cryptographic weakness (requires security audit)
- P2P protocol-level incompatibility (requires separate test)
- Performance regressions (requires benchmark)
- Memory leaks (requires soak test)

---

## 12. Related Documents

- `docs/go-1.26-upgrade-audit.md` — full audit, 19 sections
- `docs/go-1.26-fix-patches/` — 7 consensus-critical fix patches
- `docs/go-1.26-operator-guide.md` — operator quick-start
- `consensus/go126_compat_test.go` — Go 1.26 runtime compat tests

---

## 13. Workaround C Differential Testing

Under Workaround C (`GODEBUG=randmapiter=0` on all daemons), the
differential test must verify additional constraints:

### 13.1 GODEBUG Flag Verification

Before each phase exit criteria check, verify:

```bash
# Every v1.26 node must have the flag
for pid in $(pgrep -f derod_v1.26); do
    echo "Node $pid:"
    cat /proc/$pid/environ | tr '\0' '\n' | grep GODEBUG
done
```

All nodes must show `GODEBUG=randmapiter=0`. If any node is missing
the flag, the test is invalid — treat as a test infrastructure failure.

### 13.2 Negative Test: Remove Flag and Observe Divergence

To validate that the flag is actually needed, run a controlled negative test:

1. Start a v1.26 node **without** `GODEBUG=randmapiter=0`
2. Start a v1.17 node on the same testnet
3. Wait for 10 blocks
4. **Expected:** state root diverges within 10 blocks (confirms the risk is real)
5. Stop the v1.26 node, restart with the flag, re-sync from v1.17
6. **Expected:** re-synced node produces matching state roots

This test confirms the flag is not optional and validates the rollback procedure.

### 13.3 Phase Exit Criteria Addition

For each phase, add to the pass criteria:

```
[ ] GODEBUG=randmapiter=0 verified on all v1.26 nodes
[ ] Negative test (flag removed) produced divergence within 10 blocks
```

### 13.4 Patch 07 (gob) Still Required

The differential test must also verify patch 07 independently of
the GODEBUG flag. Chunk sync between a v1.17 node and a v1.26 node
(both with `GODEBUG=randmapiter=0`) must succeed without the flag
fixing the gob issue — the flag does not affect gob wire format.
