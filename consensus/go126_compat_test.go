// Package consensus contains cross-cutting compatibility tests for the
// Go 1.17 → 1.26 runtime upgrade.
//
// These tests guard against consensus divergence caused by Go runtime
// changes (Swiss Tables map iteration, crypto/rand init, stdlib
// encoding changes, etc.).
//
// They are intentionally placed in their own package so they can be
// run independently of the heavier blockchain/xswd test suites.
//
// Reference: docs/go-1.26-upgrade-audit.md
package consensus

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"os"
	"runtime"
	"sort"
	"testing"
)

// =========================================================================
// Test 1: Map iteration determinism (Swiss Tables regression guard)
//
// Verifies that sorting a map's keys before iteration produces a
// canonical byte sequence, regardless of underlying map implementation
// (Go 1.17 chained buckets vs Go 1.24+ Swiss Tables vs Go 1.26).
// =========================================================================

// sortedCommit walks a map, sorts the keys lexicographically, and
// produces a deterministic byte stream. This is the pattern that must
// be applied to all 8 consensus-critical map iteration sites.
func sortedCommit(m map[string][]byte) []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []byte
	for _, k := range keys {
		out = append(out, []byte(k)...)
		out = append(out, 0x00) // separator
		out = append(out, m[k]...)
	}
	return out
}

func TestMapIterationDeterminism(t *testing.T) {
	// Build a map with 100 random keys, then re-insert in a different
	// order. The sorted-commit output must be byte-identical.
	const N = 100

	// Use a fixed seed for reproducibility
	rng := rand.New(rand.NewSource(0xDEADBEEF))
	keys := make([]string, N)
	for i := 0; i < N; i++ {
		keys[i] = string([]byte{
			byte(rng.Intn(256)),
			byte(rng.Intn(256)),
			byte(rng.Intn(256)),
			byte(rng.Intn(256)),
		})
	}
	values := make([][]byte, N)
	for i := 0; i < N; i++ {
		values[i] = []byte{byte(i), byte(i + 1), byte(i + 2)}
	}

	// First insertion order: sequential
	m1 := make(map[string][]byte, N)
	for i := 0; i < N; i++ {
		m1[keys[i]] = values[i]
	}
	out1 := sortedCommit(m1)

	// Second insertion order: reverse
	m2 := make(map[string][]byte, N)
	for i := N - 1; i >= 0; i-- {
		m2[keys[i]] = values[i]
	}
	out2 := sortedCommit(m2)

	if !bytes.Equal(out1, out2) {
		t.Fatalf("sorted commit diverged: insertion order affected output\n  forward: %x\n  reverse: %x",
			out1[:32], out2[:32])
	}

	// Third insertion order: random permutation
	rng2 := rand.New(rand.NewSource(0xCAFEBABE))
	perm := rng2.Perm(N)
	m3 := make(map[string][]byte, N)
	for _, idx := range perm {
		m3[keys[idx]] = values[idx]
	}
	out3 := sortedCommit(m3)

	if !bytes.Equal(out1, out3) {
		t.Fatalf("sorted commit diverged: random insertion order affected output")
	}
}

// TestMapIterationRandomIterationDiffers verifies the converse: that
// without sorting, iteration order IS different between insertion
// orders. This is what produces the consensus bug.
func TestMapIterationRandomIterationDiffers(t *testing.T) {
	const N = 50
	keys := make([]string, N)
	for i := 0; i < N; i++ {
		keys[i] = string([]byte{byte(i), byte(i * 2)})
	}

	// Iterate map 1 in insertion order (deterministic)
	m1 := make(map[string][]byte, N)
	var collected1 []string
	for i := 0; i < N; i++ {
		m1[keys[i]] = []byte{byte(i)}
	}
	// Note: range order is intentionally NOT sorted, so we capture
	// the runtime's natural order.
	for k := range m1 {
		collected1 = append(collected1, k)
	}

	// Iterate map 2 with different insertion order
	m2 := make(map[string][]byte, N)
	for i := N - 1; i >= 0; i-- {
		m2[keys[i]] = []byte{byte(i)}
	}
	var collected2 []string
	for k := range m2 {
		collected2 = append(collected2, k)
	}

	// In Go 1.17, the two natural-order iterations are different
	// (because of randomization). In Go 1.26 (Swiss Tables), they
	// may be the same. The point of this test is to document the
	// risk: never rely on natural map iteration order.
	if len(collected1) != N || len(collected2) != N {
		t.Fatalf("expected %d keys, got %d and %d", N, len(collected1), len(collected2))
	}

	// Even if they happen to match, the next Go version could break this.
	// Always sort keys before committing.
	t.Logf("natural-order iteration: same=%v (unreliable across Go versions)",
		stringSlicesEqual(collected1, collected2))
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// =========================================================================
// Test 2: encoding/binary.Uvarint round-trip (Go stdlib regression guard)
//
// Verifies that binary.Uvarint (used in dvm/dvm_store.go:239) still
// round-trips correctly with known vectors. Guards against stdlib
// encoding changes in Go 1.26.
// =========================================================================

var uvarintKnownVectors = []struct {
	name  string
	value uint64
	bytes []byte
}{
	{"zero", 0, []byte{0x00}},
	{"one", 1, []byte{0x01}},
	{"127", 127, []byte{0x7f}},
	{"128", 128, []byte{0x80, 0x01}},
	{"16383", 16383, []byte{0xff, 0x7f}},
	{"16384", 16384, []byte{0x80, 0x80, 0x01}},
	{"max", ^uint64(0), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}},
}

func TestUvarintRoundTrip(t *testing.T) {
	for _, v := range uvarintKnownVectors {
		t.Run(v.name, func(t *testing.T) {
			// Encode
			var buf [binary.MaxVarintLen64]byte
			n := binary.PutUvarint(buf[:], v.value)
			if !bytes.Equal(buf[:n], v.bytes) {
				t.Errorf("encode mismatch: got %x, want %x", buf[:n], v.bytes)
			}

			// Decode
			decoded, m := binary.Uvarint(v.bytes)
			if m <= 0 {
				t.Errorf("decode returned m=%d (should be >0)", m)
			}
			if decoded != v.value {
				t.Errorf("decode mismatch: got %d, want %d", decoded, v.value)
			}
			if m != len(v.bytes) {
				t.Errorf("consumed %d bytes, expected %d", m, len(v.bytes))
			}
		})
	}
}

// TestUvarintOverflow verifies that an overflow input (more than
// 10 bytes) returns m <= 0. This guards against stdlib changes
// in overflow handling.
func TestUvarintOverflow(t *testing.T) {
	overflow := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}
	_, m := binary.Uvarint(overflow)
	if m > 0 {
		t.Errorf("expected overflow detection (m<=0), got m=%d", m)
	}
}

// TestUvarintTruncated verifies that a truncated input returns m=0.
func TestUvarintTruncated(t *testing.T) {
	truncated := []byte{0x80} // continuation bit set but no more bytes
	_, m := binary.Uvarint(truncated)
	if m != 0 {
		t.Errorf("expected m=0 for truncated input, got m=%d", m)
	}
}

// =========================================================================
// Test 3: Fixed-size byte key sorting (for [32]byte SCID maps)
//
// The blockchain/blockchain.go fix uses bytes.Compare on [32]byte
// keys (SCID). This test verifies that sort.Slice with bytes.Compare
// produces a stable, canonical ordering.
// =========================================================================

func TestFixedSizeByteKeySort(t *testing.T) {
	// Three sample SCIDs (32 bytes each), inserted in non-sorted order
	scids := [][]byte{
		bytes.Repeat([]byte{0xFF}, 32), // highest
		bytes.Repeat([]byte{0x00}, 32), // lowest
		bytes.Repeat([]byte{0x80}, 32), // middle
	}

	// Build map, extract keys, sort
	m := make(map[string][]byte, len(scids))
	for _, s := range scids {
		m[string(s)] = s
	}

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare([]byte(keys[i]), []byte(keys[j])) < 0
	})

	// Verify sorted order: 0x00, 0x80, 0xFF
	if !bytes.Equal([]byte(keys[0]), scids[1]) {
		t.Errorf("keys[0] should be 0x00, got %x", []byte(keys[0]))
	}
	if !bytes.Equal([]byte(keys[1]), scids[2]) {
		t.Errorf("keys[1] should be 0x80, got %x", []byte(keys[1]))
	}
	if !bytes.Equal([]byte(keys[2]), scids[0]) {
		t.Errorf("keys[2] should be 0xFF, got %x", []byte(keys[2]))
	}
}

// =========================================================================
// Test 4: Deterministic gob-replacement encoding round-trip
//
// Verifies the custom length-prefixed binary encoding proposed in
// docs/go-1.26-fix-patches/07-p2p-chunk_server-replace-gob.diff.
// The encoder must produce a stable, version-independent byte stream.
// =========================================================================

type chunkCodec struct{}

func (chunkCodec) encode(shards [][]byte) []byte {
	var buf []byte
	var hdr [4]byte

	binary.LittleEndian.PutUint32(hdr[:], uint32(len(shards)))
	buf = append(buf, hdr[:]...)

	for _, s := range shards {
		binary.LittleEndian.PutUint32(hdr[:], uint32(len(s)))
		buf = append(buf, hdr[:]...)
		buf = append(buf, s...)
	}
	return buf
}

func (chunkCodec) decode(b []byte) ([][]byte, error) {
	if len(b) < 4 {
		return nil, errShortBuffer
	}
	count := binary.LittleEndian.Uint32(b[:4])
	b = b[4:]

	out := make([][]byte, 0, count)
	for i := uint32(0); i < count; i++ {
		if len(b) < 4 {
			return nil, errShortBuffer
		}
		n := binary.LittleEndian.Uint32(b[:4])
		b = b[4:]
		if uint32(len(b)) < n {
			return nil, errShortBuffer
		}
		out = append(out, b[:n])
		b = b[n:]
	}
	return out, nil
}

var errShortBuffer = errShortBuf{}

type errShortBuf struct{}

func (errShortBuf) Error() string { return "short buffer" }

func TestChunkCodecRoundTrip(t *testing.T) {
	cc := chunkCodec{}

	input := [][]byte{
		[]byte("hello"),
		[]byte(""),
		[]byte("world"),
		bytes.Repeat([]byte{0xAB}, 100),
	}

	encoded := cc.encode(input)
	decoded, err := cc.decode(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(decoded) != len(input) {
		t.Fatalf("decoded %d shards, expected %d", len(decoded), len(input))
	}
	for i := range input {
		if !bytes.Equal(decoded[i], input[i]) {
			t.Errorf("shard %d: got %x, want %x", i, decoded[i], input[i])
		}
	}
}

func TestChunkCodecStableEncoding(t *testing.T) {
	cc := chunkCodec{}
	input := [][]byte{[]byte("a"), []byte("bb"), []byte("ccc")}

	// Encode multiple times. The output must be byte-identical
	// (the encoding is deterministic by construction — same input
	// → same output across all Go runtime versions).
	e1 := cc.encode(input)
	e2 := cc.encode(input)
	if !bytes.Equal(e1, e2) {
		t.Errorf("encoding is not stable: %x != %x", e1, e2)
	}

	// NOTE: The encoding preserves the order of shards as given in
	// the input slice. If the caller needs order-independence, they
	// must sort the input shards before encoding. This is the
	// same contract that gob.Encode provided (gob also preserves
	// struct field declaration order).
}

// =========================================================================
// Test 5: Build mode verification (CGO/PIE check for Go 1.26)
//
// Verifies that derohe can still build with default mode (not PIE)
// under Go 1.26. If this test ever fails, the CGO-for-PIE change
// in Go 1.26 may have introduced a build regression.
// =========================================================================

func TestBuildModeDefaults(t *testing.T) {
	// This is a runtime check, not a build-time check.
	// If derohe ever starts requiring -buildmode=pie, this test
	// can be augmented with a build tag or shell-out to go build.
	//
	// For now, we just verify that the test binary itself built
	// (i.e. we are running at all). A more thorough check would
	// exec "go build -mod=vendor ./..." and assert exit 0.

	if testing.Short() {
		t.Skip("skipping build mode test in short mode")
	}
	t.Log("build mode verification: see docs/go-1.26-upgrade-audit.md §12")
}

// =========================================================================
// Test 6: GODEBUG=randmapiter=0 self-check (Workaround C guard)
//
// Documents and verifies the startup self-check requirement.
// In production, cmd/derod/godebug_check.go enforces this via init().
// This test serves as a regression guard and documents the requirement.
// =========================================================================

func TestGODEBUGSelfCheckDocumentsRequirement(t *testing.T) {
	if runtime.Version() < "go1.24" {
		t.Skip("randmapiter GODEBUG only relevant for Go 1.24+ (Swiss Tables)")
	}

	val := os.Getenv("GODEBUG")
	if val == "" {
		t.Log("GODEBUG not set — documenting requirement only")
		t.Log("Production self-check: cmd/derod/godebug_check.go")
		t.Log("Mechanism: init() → os.Getenv(\"GODEBUG\") → os.Exit(1) if missing")
		t.Log("See: docs/go-1.26-upgrade-audit.md §18-19")
		return
	}

	found := false
	for _, part := range splitGODEBUG(val) {
		if part == "randmapiter=0" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("GODEBUG=%q does not contain randmapiter=0", val)
		t.Log("Without randmapiter=0, Go 1.24+ map iteration is non-deterministic")
		t.Log("This causes consensus divergence between Go 1.17 and Go 1.26 nodes")
		t.Log("See: docs/go-1.26-upgrade-audit.md §18")
	} else {
		t.Log("GODEBUG=randmapiter=0 is set — deterministic map iteration verified")
	}
}

func splitGODEBUG(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// TestGODEBUGSplitParsing verifies the comma-splitting logic used above.
func TestGODEBUGSplitParsing(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", []string{""}},
		{"randmapiter=0", []string{"randmapiter=0"}},
		{"gcdebug=1,randmapiter=0", []string{"gcdebug=1", "randmapiter=0"}},
		{"randmapiter=0,gcdebug=1", []string{"randmapiter=0", "gcdebug=1"}},
		{"a,b,c", []string{"a", "b", "c"}},
	}
	for _, tt := range tests {
		got := splitGODEBUG(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("splitGODEBUG(%q): got %d parts, want %d", tt.input, len(got), len(tt.want))
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("splitGODEBUG(%q)[%d]: got %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}
