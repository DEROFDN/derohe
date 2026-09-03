#!/usr/bin/env bash
# Regenerate vendor/ correctly, and preserve the local patches inside it.
#
# THE RULE THIS EXISTS TO ENCODE
#
#   Never rebase or merge vendor/. Recompute it.
#
# vendor/ is a deterministic function of go.mod plus the module cache — running
# `go mod vendor` twice on the same inputs produces a byte-identical tree. So a
# vendor/ change is not something to carry across a rebase; it is something to
# recompute once you have landed on your final base.
#
# Trying to rebase it instead is what produces thousands of modify/delete
# conflicts. Those conflicts are not real disagreements, they are two different
# machine-generated trees being diffed against each other, and resolving them by
# hand produces a vendor/ that matches neither.
#
# SO, WHEN DOING DEPENDENCY WORK:
#
#   1. Put your SOURCE changes in their own commits. Those rebase cleanly onto
#      anything, because they are small and hand-written.
#   2. Rebase/merge onto whatever base you are actually targeting.
#   3. THEN run this script, and commit vendor/ as ONE separate, final commit.
#
# A reviewer can re-run step 3 and diff the result, which is the only practical
# way to review a vendor/ change of this size.
#
# WHY THE PATCH RESTORE BELOW IS NOT OPTIONAL
#
# vendor/ carries local edits that `go mod vendor` silently reverts. Some of them
# do not break the build when lost, so a green build after re-vendoring proves
# nothing. check_vendor_patches.sh is the check that does.
#
# Usage:
#   ./vendor_update.sh                                  # tidy + vendor + verify
#   ./vendor_update.sh github.com/foo/bar@v1.2.3 ...    # bump first, then the above

set -euo pipefail

cd "$(dirname "$0")"

# vendor/ paths carrying local edits, restored from HEAD after regeneration
PATCHED_PATHS=(
  vendor/github.com/chzyer/readline
)

if [ $# -gt 0 ]; then
  echo "==> go get $*"
  GOFLAGS=-mod=mod go get "$@"
fi

echo "==> go mod tidy"
GOFLAGS=-mod=mod go mod tidy

echo "==> go mod vendor"
GOFLAGS=-mod=mod go mod vendor

echo "==> restoring local vendor patches from HEAD"
for p in "${PATCHED_PATHS[@]}"; do
  if git cat-file -e "HEAD:$p" 2>/dev/null; then
    git checkout HEAD -- "$p"
    echo "    restored $p"
  else
    echo "    WARNING: $p not present at HEAD -- nothing to restore" >&2
  fi
done

echo "==> verifying patches survived"
./check_vendor_patches.sh

echo "==> go build ./..."
go build ./...

cat <<'DONE'

vendor/ regenerated and verified.

Commit it on its own, e.g.

    git add vendor go.mod go.sum
    git commit -m "vendor: regenerate"

Keep it as the LAST commit on the branch. If you later need to move the branch
to a different base, drop this commit, rebase the source commits, and run this
script again rather than trying to rebase vendor/.
DONE
