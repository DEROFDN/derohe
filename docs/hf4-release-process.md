# HF4 release process

_Status: draft for public review. **No activation height is set by this document.**_

This process produces reviewable, reproducible binaries. It does not schedule mainnet activation. Use it only after the gates in [the activation runbook](hf4-activation-runbook.md) are closed.

## 1. Freeze the commit

- Confirm the code review and CI gates are closed.
- Tag the exact commit using the project's release convention, for example `vX.Y.Z-hf4-rcN`.
- Confirm the working tree is clean. The build script refuses a dirty tree.

## 2. Build reproducible artifacts

```sh
./scripts/hf4-release-build.sh dist
```

The script builds:

| Target | File |
|---|---|
| Linux amd64 | `derod-linux-amd64-<commit>` |
| Linux arm64 | `derod-linux-arm64-<commit>` |
| Windows amd64 | `derod-windows-amd64-<commit>.exe` |
| macOS amd64 | `derod-darwin-amd64-<commit>` |
| macOS arm64 | `derod-darwin-arm64-<commit>` |

It also writes `SHA256SUMS-<commit>` and `BUILD-INFO-<commit>`. The build uses `CGO_ENABLED=0`, `-trimpath`, and `-buildvcs=false`.

## 3. Verify reproducibility

Build twice from two clean checkouts of the same commit and compare the checksums:

```sh
sha256sum -c SHA256SUMS-<commit>
```

Publish the checksums and the Go toolchain version from `BUILD-INFO-<commit>`. If the two builds differ, do not release; record the difference and investigate.

## 4. Sign and publish

- Detached-sign `SHA256SUMS-<commit>` with the release key.
- Publish the binaries, checksums, signature, `BUILD-INFO`, and release notes together.
- Release notes must state:
  - HF4 changes v4 block IDs through the transaction-body commitment.
  - HF4 adds the seamless migration path and the HF3-gated reporting-only supply record.
  - The proof-carrying supply checkpoint and corrected accounting are not part of this release.
  - No mainnet activation height is set unless one has been agreed and published separately.

## 5. Coordinate the upgrade

Use [the activation runbook](hf4-activation-runbook.md) for the notification order, minimum versions, monitoring, and abort criteria. Do not announce a mainnet activation height in the release notes before the runbook gates are closed.

## 6. Preserve the evidence

Archive the release commit, tag, checksums, signatures, build logs, CI run URLs, and testnet rehearsal records with the release. These are the artifacts independent reviewers and operators will check.
