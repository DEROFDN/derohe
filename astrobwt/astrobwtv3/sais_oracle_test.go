package astrobwtv3

// Correctness oracle for the suffix-array construction used by AstroBWTv3.
//
// AstroBWTv3 -> text_32_0alloc sits on DERO's blockchain VALIDATION path
// (block.MiniBlock.GetPoWHash, called from blockchain difficulty checks and
// p2p chain sync), not just the miner. A divergence here on any input would
// be a consensus bug, not a performance regression. text_32_0alloc was
// originally backed by sais_8_32 (SA-IS); since the Stage 4b cutover it's
// backed by the divsufsort port (computeSuffixArrayDivSufSort0Alloc,
// divsufsort_go.go) instead, with sais_8_32 kept as text_32_0alloc_sais, a
// permanent comparison oracle (see divsufsort_go_test.go). This file's
// tests run against whichever implementation text_32_0alloc actually calls,
// unchanged in intent since the whole point is validating the real
// production path. Before this file, no independent check of the
// suffix-array construction existed: the only prior test compares it
// against one hardcoded 10-byte case, and every test that would cross-check
// the alternate sort_indices path was commented out.
//
// Three independent-as-possible tiers, from strongest to weakest:
//
//  1. assertValidSuffixArray: the defining property of a suffix array,
//     checked directly with no reference implementation at all. Necessary
//     AND sufficient, so this is the strongest check available -- bounded
//     to sizes where its O(n^2) worst case is affordable.
//  2. naiveSuffixArray: a direct comparison sort, algorithmically unrelated
//     to SA-IS. Genuinely independent, but only affordable at small n.
//  3. stdlibSuffixArray: Go's real standard library index/suffixarray
//     package. NOTE this is NOT algorithmically independent -- stdlib's
//     New() also computes its suffix array via an SA-IS implementation
//     (this package's sais.go/sais2.go are a renamed, otherwise verbatim
//     copy of stdlib's own sources). Agreement here proves the local copy
//     hasn't drifted from upstream via transcription error; it does NOT
//     prove SA-IS itself is bug-free, since a bug in the algorithm's
//     lineage would reproduce identically in both copies. Tiers 1 and 2
//     are what actually guard against that class of bug.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"index/suffixarray"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// ---------- Tier 1: oracle-free invariant ----------

// invariantCheckMaxN bounds assertValidSuffixArray's use to sizes where its
// O(n^2) worst-case pairwise-compare cost (adjacent suffixes can share long
// common prefixes, e.g. on repetitive input) stays cheap enough for a test run.
const invariantCheckMaxN = 8192

// assertValidSuffixArray verifies sa is THE correct suffix array of text via
// the defining property: sa must be a permutation of {0,...,n-1}, and
// suffixes text[sa[i]:] must be in strictly increasing lexicographic order.
// Every byte position starts a suffix of a different length, so all suffixes
// here are distinct strings -- there is no tie-breaking ambiguity, and this
// property is both necessary and sufficient for correctness.
func assertValidSuffixArray(t *testing.T, label string, text []byte, sa []int32) {
	t.Helper()
	n := len(text)
	if len(sa) != n {
		t.Fatalf("%s: len(sa)=%d != len(text)=%d", label, len(sa), n)
	}
	if n == 0 {
		return
	}
	seen := make([]bool, n)
	for _, v := range sa {
		if v < 0 || int(v) >= n {
			t.Fatalf("%s: sa contains out-of-range index %d (n=%d)", label, v, n)
		}
		if seen[v] {
			t.Fatalf("%s: sa contains duplicate index %d -- not a permutation", label, v)
		}
		seen[v] = true
	}
	for i := 0; i < n-1; i++ {
		if bytes.Compare(text[sa[i]:], text[sa[i+1]:]) >= 0 {
			t.Fatalf("%s: suffixes out of order at rank %d: sa[%d]=%d, sa[%d]=%d",
				label, i, i, sa[i], i+1, sa[i+1])
		}
	}
}

// ---------- Tier 2: naive, algorithmically-unrelated oracle ----------

// naiveOracleMaxN bounds naiveSuffixArray's use -- sort.Slice with a
// bytes.Compare-based Less is O(n^2 log n) worst case on repetitive input.
const naiveOracleMaxN = 4096

func naiveSuffixArray(text []byte) []int32 {
	n := len(text)
	idx := make([]int32, n)
	for i := range idx {
		idx[i] = int32(i)
	}
	sort.Slice(idx, func(i, j int) bool {
		return bytes.Compare(text[idx[i]:], text[idx[j]:]) < 0
	})
	return idx
}

// ---------- Tier 3: stdlib index/suffixarray (transcription-fidelity oracle) ----------

// stdlibSuffixArray extracts the raw suffix array stdlib's index/suffixarray
// computed for text. There's no exported accessor for it, so this goes
// through the public Write() serialization and decodes the documented wire
// format. Self-checking: the decoded result is validated as a real
// permutation via assertValidSuffixArray before being trusted, so a decode
// bug would almost certainly surface immediately rather than silently.
func stdlibSuffixArray(t *testing.T, text []byte) []int32 {
	t.Helper()
	idx := suffixarray.New(text)
	var buf bytes.Buffer
	if err := idx.Write(&buf); err != nil {
		t.Fatalf("stdlib suffixarray Write failed: %v", err)
	}
	sa, err := decodeSuffixArrayWireFormat(&buf, len(text))
	if err != nil {
		t.Fatalf("failed decoding stdlib suffixarray wire format: %v", err)
	}
	assertValidSuffixArray(t, "stdlib-decoded", text, sa)
	return sa
}

// decodeSuffixArrayWireFormat parses the wire format written by
// (*suffixarray.Index).Write: a fixed-width (binary.MaxVarintLen64-byte)
// varint data length, the raw data bytes, then repeated
// [fixed-width varint chunk-byte-size][uvarint element]... chunks encoding
// the suffix array. Mirrors the unexported writeInt/writeSlice/readSlice in
// $GOROOT/src/index/suffixarray/suffixarray.go -- this is stdlib's
// persistence format, which has strong backward-compat pressure not to
// change, but pin against whatever Go toolchain actually builds this
// project rather than assuming it forever.
func decodeSuffixArrayWireFormat(r io.Reader, wantN int) ([]int32, error) {
	buf := make([]byte, 16<<10)

	readFixedVarint := func() (int64, error) {
		if _, err := io.ReadFull(r, buf[0:binary.MaxVarintLen64]); err != nil {
			return 0, err
		}
		x, _ := binary.Varint(buf)
		return x, nil
	}

	n64, err := readFixedVarint()
	if err != nil {
		return nil, fmt.Errorf("reading data length: %w", err)
	}
	n := int(n64)
	if n != wantN {
		return nil, fmt.Errorf("wire data length %d != expected %d", n, wantN)
	}

	if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
		return nil, fmt.Errorf("skipping data bytes: %w", err)
	}

	sa := make([]int32, 0, n)
	for len(sa) < n {
		size64, err := readFixedVarint()
		if err != nil {
			return nil, fmt.Errorf("reading chunk size: %w", err)
		}
		size := int(size64)
		if size < binary.MaxVarintLen64 || size > len(buf) {
			return nil, fmt.Errorf("implausible chunk size %d", size)
		}
		if _, err := io.ReadFull(r, buf[binary.MaxVarintLen64:size]); err != nil {
			return nil, fmt.Errorf("reading chunk payload: %w", err)
		}
		for p := binary.MaxVarintLen64; p < size; {
			x, w := binary.Uvarint(buf[p:])
			if w <= 0 {
				return nil, fmt.Errorf("malformed uvarint in chunk at offset %d", p)
			}
			sa = append(sa, int32(x))
			p += w
		}
	}
	if len(sa) != n {
		return nil, fmt.Errorf("decoded %d elements, want %d", len(sa), n)
	}
	return sa, nil
}

// ---------- corpus generators ----------

func genUniformRandom(rng *rand.Rand, n int) []byte {
	buf := make([]byte, n)
	rng.Read(buf)
	return buf
}

func genAllSameByte(n int, b byte) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return buf
}

func genPeriodic(n, period int) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = byte(i % period)
	}
	return buf
}

func genAscendingRun(n int) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = byte(i)
	}
	return buf
}

func genDescendingRun(n int) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = byte(n - i)
	}
	return buf
}

// genFibonacciWord builds a classic SA-IS stress pattern: the Fibonacci word
// over {0,1}, defined by S(0)="0", S(1)="01", S(k)=S(k-1)+S(k-2). It's
// maximally repetitive without being periodic, which forces SA-IS's
// recursive LMS-substring reduction to actually execute meaningfully --
// uniform random text rarely needs recursion since ordering is usually
// resolved at the first induced-sort pass.
func genFibonacciWord(minLen int) []byte {
	a := []byte{0}
	b := []byte{0, 1}
	for len(b) < minLen {
		a, b = b, append(append([]byte{}, b...), a...)
	}
	return b
}

func mutateOneByte(src []byte, pos int, newVal byte) []byte {
	out := append([]byte{}, src...)
	out[pos%len(out)] = newVal
	return out
}

// ---------- the function under test ----------

// runOracle computes the suffix array via the actual production entry point
// (text_32_0alloc, exactly what pow.go calls) and checks it against however
// many tiers are affordable at this size.
func runOracle(t *testing.T, label string, text []byte) {
	t.Helper()
	n := len(text)
	sa := make([]int32, n)
	text_32_0alloc(text, sa)

	if n <= invariantCheckMaxN {
		assertValidSuffixArray(t, label+"/self", text, sa)
	}
	if n <= naiveOracleMaxN {
		want := naiveSuffixArray(text)
		if !equalInt32(sa, want) {
			t.Fatalf("%s: text_32_0alloc output disagrees with naive oracle at n=%d", label, n)
		}
	}
	want := stdlibSuffixArray(t, text)
	if !equalInt32(sa, want) {
		t.Fatalf("%s: text_32_0alloc output disagrees with stdlib oracle at n=%d", label, n)
	}
}

func equalInt32(a, b []int32) bool {
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

// ---------- Stage 0 deliverable ----------

func TestSuffixArrayOracleSmall(t *testing.T) {
	cases := map[string][]byte{
		"n=0":                {},
		"n=1":                {0x42},
		"all-zero/16":        genAllSameByte(16, 0x00),
		"all-zero/1000":      genAllSameByte(1000, 0x00),
		"all-0xff/1000":      genAllSameByte(1000, 0xff),
		"all-0x7f/4096":      genAllSameByte(4096, 0x7f),
		"periodic-2/1000":    genPeriodic(1000, 2),
		"periodic-3/999":     genPeriodic(999, 3),
		"periodic-5/1000":    genPeriodic(1000, 5),
		"periodic-7/1001":    genPeriodic(1001, 7),
		"ascending/300":      genAscendingRun(300),
		"ascending/4096":     genAscendingRun(4096),
		"descending/300":     genDescendingRun(300),
		"fibonacci/500":      genFibonacciWord(500),
		"fibonacci/4096":     genFibonacciWord(4096),
	}

	rng := rand.New(rand.NewSource(1))
	base := genUniformRandom(rng, 256)
	cases["random-base/256"] = base
	for i := 0; i < 256; i++ {
		cases[fmt.Sprintf("random-base-mutated/%d", i)] = mutateOneByte(base, i, byte(rng.Intn(256)))
	}

	for i, n := range []int{1, 2, 3, 5, 8, 13, 21, 64, 100, 1000, 4096} {
		cases[fmt.Sprintf("random/seed%d/n=%d", i, n)] = genUniformRandom(rand.New(rand.NewSource(int64(1000+i))), n)
	}

	for label, text := range cases {
		text, label := text, label
		t.Run(label, func(t *testing.T) {
			runOracle(t, label, text)
		})
	}
}

// TestSuffixArrayOracleLarge property-tests at the realistic sizes AstroBWTv3
// actually produces: data_len in pow.go tops out around (276-4)*256+1023 =
// ~70,655 bytes, and the package's own declared MAX_LENGTH (98,303) bounds
// it as a general-purpose library. Uniform random is the easy case for
// SA-IS -- structured/repetitive generators exercise the recursive
// reduction path uniform random rarely touches.
func TestSuffixArrayOracleLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large-n suffix array property test in -short mode")
	}

	sizes := []int{8193, 16384, 32768, 65536, 69632, 70655, 98303}
	trials := 0

	for si, n := range sizes {
		n := n
		rng := rand.New(rand.NewSource(int64(42 + si)))

		t.Run(fmt.Sprintf("uniform-random/n=%d", n), func(t *testing.T) {
			runOracle(t, t.Name(), genUniformRandom(rng, n))
		})
		trials++

		t.Run(fmt.Sprintf("periodic-64/n=%d", n), func(t *testing.T) {
			runOracle(t, t.Name(), genPeriodic(n, 64))
		})
		trials++

		t.Run(fmt.Sprintf("periodic-1/n=%d", n), func(t *testing.T) {
			runOracle(t, t.Name(), genAllSameByte(n, 0x55))
		})
		trials++

		t.Run(fmt.Sprintf("fibonacci/n=%d", n), func(t *testing.T) {
			word := genFibonacciWord(n)
			runOracle(t, t.Name(), word[:n])
		})
		trials++

		// several independent random seeds per size, since uniform random
		// input rarely exercises the recursive reduction path -- breadth
		// across seeds matters less here than across generator shapes, but
		// a few extra seeds are cheap insurance.
		for extra := 0; extra < 3; extra++ {
			extra := extra
			t.Run(fmt.Sprintf("uniform-random-extra%d/n=%d", extra, n), func(t *testing.T) {
				runOracle(t, t.Name(), genUniformRandom(rng, n))
			})
			trials++
		}
	}

	t.Logf("ran %d large-n property trials across %d sizes", trials, len(sizes))
}

// TestSuffixArrayOracleRealFixtures runs the oracle against real captured
// scratch.data output from actual AstroBWTv3() runs (see
// sa_fixture_gen_test.go), not just the synthetic stress patterns above --
// closing the gap between "adversarially-shaped" and "what the chain
// actually produces". Fixtures aren't committed (see
// testdata/safixtures/.gitignore), so this skips cleanly if they haven't
// been generated:
//
//	go test -tags astrobwt_capture -run TestGenerateSAFixtures -v .
func TestSuffixArrayOracleRealFixtures(t *testing.T) {
	entries, err := os.ReadDir(saFixtureDirForBench)
	if err != nil || len(entries) == 0 {
		t.Skipf("no fixtures in %s -- generate with: go test -tags astrobwt_capture -run TestGenerateSAFixtures -v .", saFixtureDirForBench)
	}

	ran := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".bin" {
			continue
		}
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(saFixtureDirForBench, name))
			if err != nil {
				t.Fatalf("reading fixture %s: %v", name, err)
			}
			runOracle(t, name, data)
		})
		ran++
	}
	if ran == 0 {
		t.Skipf("no .bin fixtures found in %s", saFixtureDirForBench)
	}
	t.Logf("ran oracle against %d real captured fixtures", ran)
}

// FuzzSuffixArray is intentionally NOT run via `go test -fuzz` in this
// session: go.mod currently declares `go 1.17`, and reliable native fuzzing
// needs 1.18+; -fuzz mode also writes newly discovered corpus entries into
// testdata/fuzz/FuzzSuffixArray/ in the repo, a repo-mutating side effect
// that needs explicit go-ahead. This wraps the same helpers used above so
// the infrastructure is ready the moment both are approved -- it still runs
// fine as a normal seed-corpus test under plain `go test`.
func FuzzSuffixArray(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x42})
	f.Add(genAllSameByte(64, 0x00))
	f.Add(genPeriodic(64, 3))
	f.Add(genFibonacciWord(64))
	seedRng := rand.New(rand.NewSource(7))
	f.Add(genUniformRandom(seedRng, 64))

	f.Fuzz(func(t *testing.T, text []byte) {
		if len(text) > naiveOracleMaxN {
			t.Skip("keep fuzz cases within the naive-oracle-affordable range")
		}
		runOracle(t, "fuzz", text)
	})
}
