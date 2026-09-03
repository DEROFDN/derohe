#!/usr/bin/env bash
# Vendor patch guard.
#
# WHY THIS EXISTS
# vendor/ carries local edits that `go mod vendor` reverts silently. There is no
# warning: the tree is simply regenerated from the module cache and the edits are
# gone. Some of those edits are load bearing.
#
# The readline patch is the live case. It has two halves and only one of them is
# caught by the compiler:
#
#   operation.go  KickReader()          -- cmd/dero-wallet-cli/prompt.go calls it,
#                                          so losing it breaks the build. Safe.
#   std.go        FillableStdin.Close() -- closes the underlying stdin. Nothing
#                                          calls it through a changed signature,
#                                          so losing it builds clean and leaks
#                                          the descriptor. NOT safe.
#
# That second one is why a build is not a sufficient check after re-vendoring.
#
# Deliberately dropped during the 2026-08 dependency upgrade, and expected to be
# absent: the x/net proxy dial timeout (unreachable -- globals.Dialer's only call
# sites are in functions with no callers) and the graviton KeyCountEstimate edit
# (inert at the tree sizes it affects).
#
# Run after any `go mod vendor`:  ./check_vendor_patches.sh

set -euo pipefail

cd "$(dirname "$0")"

fail=0

check() {
  local file="$1" pattern="$2" desc="$3"
  if [ ! -f "$file" ]; then
    echo "MISSING FILE  $file" >&2
    fail=1
  elif ! grep -qF -- "$pattern" "$file"; then
    echo "PATCH LOST    $desc" >&2
    echo "              $file" >&2
    echo "              expected to contain: $pattern" >&2
    fail=1
  fi
}

RL=vendor/github.com/chzyer/readline

check "$RL/operation.go" 'func (o *Operation) KickReader()' \
  'readline KickReader -- lets another thread take over reading'
check "$RL/operation.go" 'kickerchan chan struct{}' \
  'readline kickerchan field'
check "$RL/operation.go" 'case <-o.kickerchan:' \
  'readline kickerchan receive in the read loop'
check "$RL/std.go" 'func NewFillableStdin(stdin io.ReadCloser)' \
  'readline FillableStdin takes a ReadCloser'
check "$RL/std.go" 's.stdin.Close()' \
  'readline FillableStdin.Close closes the underlying stdin'

if [ "$fail" -ne 0 ]; then
  echo "" >&2
  echo "vendor patches are missing. Re-apply them before committing:" >&2
  echo "  git checkout HEAD -- $RL" >&2
  exit 1
fi

echo "vendor patches present"
