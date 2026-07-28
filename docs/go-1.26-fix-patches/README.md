# Go 1.26 Consensus-Critical Fix Patches

This directory contains **7 reference patches** documenting the fixes
required for Go 1.26 consensus safety. Under **Workaround C**, only
**patch 07** is mandatory — the remaining 6 are deferred.

## Workaround C (Chosen Path)

Instead of applying code patches to all 8 map iteration sites, every
`derod` operator sets `GODEBUG=randmapiter=0` in the environment.
This forces deterministic map iteration across all Go versions,
eliminating the need for patches 01–06.

Patch 07 (gob replacement) is **unaffected** by the GODEBUG flag
and remains mandatory.

See `docs/go-1.26-upgrade-audit.md §18` and `docs/go-1.26-operator-guide.md`
for details.

## Patch Index

| # | File | Purpose | Audit Site | Status |
|---|------|---------|-----------|--------|
| 01 | `01-blockchain-blockchain-sc_change_cache-sort.diff` | Sort SC change cache by SCID | §5 site #1 | **DEFERRED** — mitigated by GODEBUG |
| 02 | `02-dvm-sc-RawKeys-sort.diff` | Sort SC store keys | §5 site #2 | **DEFERRED** — mitigated by GODEBUG |
| 03 | `03-dvm-simulator-Entries-sort.diff` | Sort all `Entries` iterations (3 sites) | §5 sites #3, #4, #5 | **DEFERRED** — mitigated by GODEBUG |
| 04 | `04-dvm-simulator-total_per_asset-sort.diff` | Sort asset totals | §5 site #6 | **DEFERRED** — mitigated by GODEBUG |
| 05 | `05-dvm-simulator-incoming_values-sort.diff` | Sort incoming values (2 sites) | §5 site #7 | **DEFERRED** — mitigated by GODEBUG |
| 06 | `06-hardcoded_contracts-Entries-sort.diff` | Sort genesis/HF Entries | §5 site #8 | **DEFERRED** — mitigated by GODEBUG |
| 07 | `07-p2p-chunk_server-replace-gob.diff` | Replace gob with custom encoding | §7 wire risk | **MANDATORY** — unaffected by GODEBUG |

## Why Patches 01–06 Are Deferred

`GODEBUG=randmapiter=0` has been supported since Go 1.17 and is
guaranteed through at least Go 1.30. Setting this flag on all daemons
produces the same deterministic iteration as explicit key sorting,
without requiring code changes.

If the flag is removed in a future Go release, apply patches 01–06
as documented. The patch content remains valid.

## Patch 07 Is Still Mandatory

The `gob` encoder in `p2p/chunk_server.go:354` is Go-version-sensitive.
Different Go versions may produce incompatible byte streams regardless
of the `randmapiter` flag. Replace with the custom length-prefixed
encoding documented in patch 07.

## How to Apply (When Needed)

```bash
# From the derohe repo root
cd /path/to/derohe

# Apply one patch
git apply docs/go-1.26-fix-patches/07-p2p-chunk_server-replace-gob.diff

# Apply all deferred patches (only if randmapiter flag is removed)
for p in docs/go-1.26-fix-patches/0[1-6]-*.diff; do
    echo "Applying $p"
    git apply "$p" || { echo "FAILED: $p"; exit 1; }
done

# Verify
go mod tidy
go mod vendor
go build -mod=vendor ./...
go test -mod=vendor ./walletapi/xswd/...
```

## Risk If Skipped

| Site | Risk if not patched AND GODEBUG not set |
|------|-----------------------------------------|
| 1 (sc_change_cache) | Hard fork at first block with SC activity |
| 2 (RawKeys) | Hard fork at first SC write |
| 3-4 (Entries) | Hard fork at first SC finalization |
| 5 (ErrorDeposit Entries) | Hard fork on first SC error path |
| 6 (total_per_asset) | Hard fork at first multi-asset SC transfer |
| 7 (incoming_values) | Hard fork on first error-rollback |
| 8 (hardcoded_contracts) | Hard fork at block 1 (genesis SC) |
| gob (chunk_server) | Network segmentation, chunk sync failure |

**Sites 1–8: mitigated by `GODEBUG=randmapiter=0`.**
**Site gob: requires patch 07 regardless.**

## Related Documents

- `docs/go-1.26-upgrade-audit.md` — full audit, 19 sections
- `docs/go-1.26-differential-test-spec.md` — shadow testnet spec
- `docs/go-1.26-operator-guide.md` — operator quick-start
- PR #19 — currently a draft, blocked on patch 07 + startup self-check
