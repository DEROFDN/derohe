//go:build !amd64

package astrobwtv3

import "github.com/minio/sha256-simd"

// No multi-buffer SHA-NI kernel on this arch: pair hashing degrades to two
// ordinary hashes. See sha256mb_amd64.go for the real (amd64) path.

func sha256Fallback(p []byte) [32]byte { return sha256.Sum256(p) }

func pairHashAvailable() bool { return false }

func sha256Sum256Pair(a, b []byte) ([32]byte, [32]byte) {
	return sha256Fallback(a), sha256Fallback(b)
}
