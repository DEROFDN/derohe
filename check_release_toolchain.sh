#!/usr/bin/env bash
# Release guard: derod release binaries must be built with a validated toolchain.
#
# WHY THIS EXISTS
# derod is the node our users run. Some of its behaviour is decided by the Go
# standard library rather than by this repo's source, and those library details
# change between Go releases. A release built on an unvalidated toolchain can
# therefore behave differently from the rest of the network while looking
# completely normal and passing every test.
#
# So release builds are pinned to toolchains that have been checked against the
# network, and this script refuses anything else.
#
# ⚠️ DO NOT widen DERO_RELEASE_TOOLCHAINS or delete this check without asking
# DHEBP first. It is not lint and it is not stale. The specific rationale is
# recorded outside this repository, deliberately.
#
# Usage:  ./check_release_toolchain.sh path/to/derod [more binaries...]
#         DERO_RELEASE_TOOLCHAINS="go1.26" ./check_release_toolchain.sh derod
# Deliberate override:  SKIP_TOOLCHAIN_GUARD=1

set -uo pipefail

# space-separated prefixes; a binary matches if its toolchain starts with one
ALLOWED="${DERO_RELEASE_TOOLCHAINS:-go1.25 go1.26}"

if [ "${SKIP_TOOLCHAIN_GUARD:-0}" = "1" ]; then
  echo "release guard: toolchain check SKIPPED by request" >&2
  exit 0
fi

if [ $# -eq 0 ]; then
  echo "usage: $0 <binary> [binary...]" >&2
  exit 2
fi

fail=0

for bin in "$@"; do
  if [ ! -f "$bin" ]; then
    echo "MISSING     $bin" >&2
    fail=1
    continue
  fi

  # first line of 'go version -m' is: <path>: <toolchain>
  raw="$(go version -m "$bin" 2>/dev/null | head -1 | awk '{print $2}')"
  if [ -z "$raw" ]; then
    echo "UNREADABLE  $bin -- not a Go binary, or no build info." >&2
    echo "            Refusing rather than assuming." >&2
    fail=1
    continue
  fi

  ok=0
  for pfx in $ALLOWED; do
    case "$raw" in "$pfx"*) ok=1 ;; esac
  done

  if [ "$ok" -ne 1 ]; then
    echo "" >&2
    echo "RELEASE BLOCKED -- $bin" >&2
    echo "  built with : $raw" >&2
    echo "  validated  : $ALLOWED" >&2
    echo "" >&2
    echo "  Rebuild with a validated toolchain, e.g." >&2
    echo "    GOTOOLCHAIN=go1.26.5 go build -o $bin ./cmd/derod" >&2
    fail=1
  else
    echo "ok  $bin -- $raw"
  fi
done

exit $fail
