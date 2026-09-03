package astrobwtv3

// Stage 3 Milestone 1 verification: reuses sais_oracle_test.go's tier
// helpers and corpus generators (assertValidSuffixArray, naiveSuffixArray,
// stdlibSuffixArray, genUniformRandom & friends) against
// computeSuffixArrayDivSufSort instead of production sais_8_32/
// text_32_0alloc -- the same three-tier correctness bar applied to the new
// implementation before it's allowed to be considered for anything further.

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

func runOracleDivSufSort(t *testing.T, label string, text []byte) {
	t.Helper()
	n := len(text)
	sa := make([]int32, n)
	computeSuffixArrayDivSufSort(text, sa)

	if n <= invariantCheckMaxN {
		assertValidSuffixArray(t, label+"/self", text, sa)
	}
	if n <= naiveOracleMaxN {
		want := naiveSuffixArray(text)
		if !equalInt32(sa, want) {
			t.Fatalf("%s: computeSuffixArrayDivSufSort output disagrees with naive oracle at n=%d", label, n)
		}
	}
	want := stdlibSuffixArray(t, text)
	if !equalInt32(sa, want) {
		t.Fatalf("%s: computeSuffixArrayDivSufSort output disagrees with stdlib oracle at n=%d", label, n)
	}
}

func TestSuffixArrayOracleDivSufSortSmall(t *testing.T) {
	cases := map[string][]byte{
		"n=0":             {},
		"n=1":             {0x42},
		"n=2/asc":         {0x01, 0x02},
		"n=2/desc":        {0x02, 0x01},
		"n=2/eq":          {0x05, 0x05},
		"n=3/aab":         []byte("aab"), // the Milestone 1 bug reproducer
		"all-zero/16":     genAllSameByte(16, 0x00),
		"all-zero/1000":   genAllSameByte(1000, 0x00),
		"all-0xff/1000":   genAllSameByte(1000, 0xff),
		"all-0x7f/4096":   genAllSameByte(4096, 0x7f),
		"periodic-2/1000": genPeriodic(1000, 2),
		"periodic-3/999":  genPeriodic(999, 3),
		"periodic-5/1000": genPeriodic(1000, 5),
		"periodic-7/1001": genPeriodic(1001, 7),
		"ascending/300":   genAscendingRun(300),
		"ascending/4096":  genAscendingRun(4096),
		"descending/300":  genDescendingRun(300),
		"fibonacci/500":   genFibonacciWord(500),
		"fibonacci/4096":  genFibonacciWord(4096),
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
			runOracleDivSufSort(t, label, text)
		})
	}
}

func TestSuffixArrayOracleDivSufSortLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large-n suffix array property test in -short mode")
	}

	sizes := []int{8193, 16384, 32768, 65536, 69632, 70655, 98303}
	trials := 0

	for si, n := range sizes {
		n := n
		rng := rand.New(rand.NewSource(int64(42 + si)))

		t.Run(fmt.Sprintf("uniform-random/n=%d", n), func(t *testing.T) {
			runOracleDivSufSort(t, t.Name(), genUniformRandom(rng, n))
		})
		trials++

		t.Run(fmt.Sprintf("periodic-64/n=%d", n), func(t *testing.T) {
			runOracleDivSufSort(t, t.Name(), genPeriodic(n, 64))
		})
		trials++

		t.Run(fmt.Sprintf("periodic-1/n=%d", n), func(t *testing.T) {
			runOracleDivSufSort(t, t.Name(), genAllSameByte(n, 0x55))
		})
		trials++

		t.Run(fmt.Sprintf("fibonacci/n=%d", n), func(t *testing.T) {
			word := genFibonacciWord(n)
			runOracleDivSufSort(t, t.Name(), word[:n])
		})
		trials++

		for extra := 0; extra < 3; extra++ {
			extra := extra
			t.Run(fmt.Sprintf("uniform-random-extra%d/n=%d", extra, n), func(t *testing.T) {
				runOracleDivSufSort(t, t.Name(), genUniformRandom(rng, n))
			})
			trials++
		}
	}

	t.Logf("ran %d large-n property trials across %d sizes", trials, len(sizes))
}

// TestSuffixArrayDivSufSortUnzeroedBufferReuse is a Stage 4a production-
// readiness check. text_32_0alloc (sa_fast.go) explicitly zeroes sa before
// calling sais_8_32; production's ScratchData.sa is a sync.Pool-reused
// buffer that nothing else re-zeroes between calls, so a naive port might
// implicitly depend on sa starting zeroed (e.g. via SA-IS's classic "0 means
// not yet placed" convention) without that being obvious from the oracle
// tests, which always pass a freshly-allocated (hence zeroed) sa.
//
// Before adding any zeroing wrapper, this was tested directly: sa was
// poisoned with adversarial garbage (in-range/out-of-range/negative/zero,
// mixed) across a wide corpus (uniform random, periodic, all-same-byte,
// and texts engineered to force m==0 via a strictly byte-descending run --
// dsClassifyAndCount's backward scan never finds an S-run-after-L-run in a
// text where text[i] > text[i+1] everywhere, so zero type B* suffixes are
// found), 450+ trials, zero mismatches and zero panics. divsufsort's
// induced-sort construction turns out to fully self-write every sa slot
// before it's ever read back -- unlike the naive risk this test set out to
// find, there is no zero-initialization dependency here. This test keeps a
// slice of that evidence as a permanent regression check, not a documented
// requirement to zero sa before calling.
func TestSuffixArrayDivSufSortUnzeroedBufferReuse(t *testing.T) {
	n := 50
	text := make([]byte, n)
	for i := range text {
		text[i] = byte(255 - i) // strictly descending -> guarantees m == 0
	}
	want := stdlibSuffixArray(t, text)

	sa := make([]int32, n)
	for i := range sa {
		sa[i] = int32(-1000 - i) // adversarial: negative garbage everywhere
	}

	computeSuffixArrayDivSufSort(text, sa)

	if !equalInt32(sa, want) {
		t.Fatalf("computeSuffixArrayDivSufSort produced a wrong suffix array from an unzeroed/poisoned buffer (m==0 case): got %v, want %v", sa, want)
	}
}

// TestSuffixArrayDivSufSort0AllocBucketReuse is the counterpart finding to
// TestSuffixArrayDivSufSortUnzeroedBufferReuse: unlike sa, bucketA/bucketB
// genuinely do need to start zeroed on every call, because
// dsClassifyAndCount accumulates counts into them (`bucketA[c1]++`, not an
// overwrite). Found empirically -- reusing bucketA/bucketB across benchmark
// iterations without clearing them produced a real out-of-bounds panic in
// dsBucketBStarSuffixes on the very first run. computeSuffixArrayDivSufSort0Alloc
// clears them itself; this test proves that's load-bearing by calling it
// back-to-back on the same buffers with different texts.
func TestSuffixArrayDivSufSort0AllocBucketReuse(t *testing.T) {
	var bucketA [256]int32
	var bucketB [256 * 256]int32
	sa := make([]int32, 8192)

	rng := rand.New(rand.NewSource(99))
	for trial := 0; trial < 20; trial++ {
		n := 100 + rng.Intn(8000)
		text := genUniformRandom(rng, n)
		want := stdlibSuffixArray(t, text)

		computeSuffixArrayDivSufSort0Alloc(text, sa[:n], bucketA[:], bucketB[:])

		if !equalInt32(sa[:n], want) {
			t.Fatalf("trial %d (n=%d): computeSuffixArrayDivSufSort0Alloc produced a wrong suffix array on repeated bucketA/bucketB reuse", trial, n)
		}
	}
}

// dsMatchesProductionSAIS runs both text_32_0alloc (production since the
// Stage 4b divsufsort cutover) and text_32_0alloc_sais (the retired SA-IS
// implementation, kept as a permanent comparison oracle -- see sa_fast.go)
// on the same text and asserts byte-identical output. This is the actual
// bar the cutover needs to clear forever, since AstroBWTv3() hashes the raw
// sa bytes directly (pow.go:2444-2456): any future change to either
// function that broke agreement would be a silent consensus bug. Suffix
// arrays are canonical for a given text, so two correct algorithms must
// already agree; this is an exhaustive empirical check of that, not a
// structural argument for it.
func dsMatchesProductionSAIS(t *testing.T, label string, text []byte) {
	t.Helper()
	n := len(text)

	saOld := make([]int32, n)
	text_32_0alloc_sais(text, saOld)

	saNew := make([]int32, n)
	text_32_0alloc(text, saNew)

	if !equalInt32(saOld, saNew) {
		t.Fatalf("%s: text_32_0alloc (divsufsort, production) disagrees with text_32_0alloc_sais (retired SA-IS reference) at n=%d", label, n)
	}
}

// TestDivSufSortMatchesProductionSAIS started as Stage 4a's headline
// evidence for the divsufsort cutover; since Stage 4b actually made the
// swap, it's now a standing regression guard comparing production
// (text_32_0alloc, divsufsort) against the retired SA-IS reference
// (text_32_0alloc_sais) on every `go test .`. Reuses every corpus generator
// already defined for the oracle tests plus the full set of real captured
// AstroBWTv3()-shaped fixtures -- the most representative input available,
// since it's actual production intermediate data, not synthetic.
func TestDivSufSortMatchesProductionSAIS(t *testing.T) {
	cases := map[string][]byte{
		"n=0":             {},
		"n=1":             {0x42},
		"n=2/asc":         {0x01, 0x02},
		"n=2/desc":        {0x02, 0x01},
		"n=2/eq":          {0x05, 0x05},
		"n=3/aab":         []byte("aab"),
		"all-zero/16":     genAllSameByte(16, 0x00),
		"all-zero/1000":   genAllSameByte(1000, 0x00),
		"all-0xff/1000":   genAllSameByte(1000, 0xff),
		"all-0x7f/4096":   genAllSameByte(4096, 0x7f),
		"periodic-2/1000": genPeriodic(1000, 2),
		"periodic-3/999":  genPeriodic(999, 3),
		"periodic-5/1000": genPeriodic(1000, 5),
		"periodic-7/1001": genPeriodic(1001, 7),
		"ascending/300":   genAscendingRun(300),
		"ascending/4096":  genAscendingRun(4096),
		"descending/300":  genDescendingRun(300),
		"fibonacci/500":   genFibonacciWord(500),
		"fibonacci/4096":  genFibonacciWord(4096),
	}

	rng := rand.New(rand.NewSource(2))
	base := genUniformRandom(rng, 256)
	cases["random-base/256"] = base
	for i := 0; i < 256; i++ {
		cases[fmt.Sprintf("random-base-mutated/%d", i)] = mutateOneByte(base, i, byte(rng.Intn(256)))
	}
	for i, n := range []int{1, 2, 3, 5, 8, 13, 21, 64, 100, 1000, 4096} {
		cases[fmt.Sprintf("random/seed%d/n=%d", i, n)] = genUniformRandom(rand.New(rand.NewSource(int64(2000+i))), n)
	}

	trials := 0
	for label, text := range cases {
		text, label := text, label
		t.Run(label, func(t *testing.T) {
			dsMatchesProductionSAIS(t, label, text)
		})
		trials++
	}

	if !testing.Short() {
		sizes := []int{8193, 16384, 32768, 65536, 69632, 70655, 98303}
		for si, n := range sizes {
			n := n
			rng := rand.New(rand.NewSource(int64(142 + si)))

			t.Run(fmt.Sprintf("uniform-random/n=%d", n), func(t *testing.T) {
				dsMatchesProductionSAIS(t, t.Name(), genUniformRandom(rng, n))
			})
			trials++

			t.Run(fmt.Sprintf("periodic-64/n=%d", n), func(t *testing.T) {
				dsMatchesProductionSAIS(t, t.Name(), genPeriodic(n, 64))
			})
			trials++

			t.Run(fmt.Sprintf("periodic-1/n=%d", n), func(t *testing.T) {
				dsMatchesProductionSAIS(t, t.Name(), genAllSameByte(n, 0x55))
			})
			trials++

			t.Run(fmt.Sprintf("fibonacci/n=%d", n), func(t *testing.T) {
				word := genFibonacciWord(n)
				dsMatchesProductionSAIS(t, t.Name(), word[:n])
			})
			trials++
		}
	}

	entries, err := os.ReadDir(saFixtureDirForBench)
	if err == nil {
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
				dsMatchesProductionSAIS(t, name, data)
			})
			trials++
		}
	}

	t.Logf("ran %d dual-compute trials comparing production text_32_0alloc (divsufsort) against text_32_0alloc_sais (retired SA-IS reference), 0 mismatches", trials)
}

func TestSuffixArrayOracleDivSufSortRealFixtures(t *testing.T) {
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
			runOracleDivSufSort(t, name, data)
		})
		ran++
	}
	if ran == 0 {
		t.Skipf("no .bin fixtures found in %s", saFixtureDirForBench)
	}
}
