#!/usr/bin/env sh
# Build reproducible HF4 release binaries and checksums.
#
# Usage: ./scripts/hf4-release-build.sh [output-dir]
#
# The script refuses to build from a dirty tree. It uses -trimpath and
# -buildvcs=false so the binary does not embed local paths or VCS metadata,
# and it records the source commit and Go toolchain in BUILD-INFO.

set -eu

out="${1:-dist}"
commit="$(git rev-parse --short=12 HEAD)"

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "error: working tree is dirty; commit or stash before building a release" >&2
  exit 1
fi

mkdir -p "$out"
export CGO_ENABLED=0

build() {
  goos="$1"
  goarch="$2"
  suffix="$3"
  name="derod-${goos}-${goarch}-${commit}${suffix}"
  echo "building ${name}"
  GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -buildvcs=false -o "${out}/${name}" ./cmd/derod
}

build linux amd64 ""
build linux arm64 ""
build windows amd64 ".exe"
build darwin amd64 ""
build darwin arm64 ""

(
  cd "$out"
  sha256sum derod-* > "SHA256SUMS-${commit}"
)

{
  echo "commit=${commit}"
  go version
} > "${out}/BUILD-INFO-${commit}"

echo "wrote ${out}/SHA256SUMS-${commit}"
echo "wrote ${out}/BUILD-INFO-${commit}"
