package astrobwtv3

import (
	"math/rand"
	"testing"
)

// TestAstroBWTv3PairMatchesSequential checks AstroBWTv3Pair(a, b) against
// (AstroBWTv3(a), AstroBWTv3(b)) across varied lengths and this package's
// own KAT inputs (pow_test.go's random_pow_tests). Correctness holds
// regardless of pairHashAvailable(): the fallback branch calls AstroBWTv3
// directly (see AstroBWTv3Pair's doc comment in pow.go), so this test is
// meaningful on any host, not just SHA-NI-capable ones.
func TestAstroBWTv3PairMatchesSequential(t *testing.T) {
	for i := range random_pow_tests {
		in := []byte(random_pow_tests[i].in)
		wa := AstroBWTv3(in)
		ga, gb := AstroBWTv3Pair(in, in)
		if ga != wa || gb != wa {
			t.Fatalf("KAT input %q: pair = (%x, %x), want (%x, %x)", in, ga, gb, wa, wa)
		}
	}

	rnd := rand.New(rand.NewSource(20260804))
	lengths := []int{1, 2, 3, 7, 16, 31, 47, 48, 49, 64, 255, 1024}
	iters := 200
	if testing.Short() {
		iters = 30
	}
	for i := 0; i < iters; i++ {
		na := lengths[i%len(lengths)]
		nb := lengths[(i+3)%len(lengths)]
		a := make([]byte, na)
		b := make([]byte, nb)
		rnd.Read(a)
		rnd.Read(b)

		wa := AstroBWTv3(a)
		wb := AstroBWTv3(b)
		ga, gb := AstroBWTv3Pair(a, b)
		if ga != wa || gb != wb {
			t.Fatalf("iter %d (len a=%d b=%d): pair = (%x, %x), want (%x, %x)", i, na, nb, ga, gb, wa, wb)
		}
	}
}

// TestAstroBWTv3PairZeroAllocsAfterWarmup scopes to the SHA-NI-specific new
// code (astroBWTv3Stream x2 + sha256Sum256Pair), not the whole
// AstroBWTv3Pair call: on a host without SHA-NI, AstroBWTv3Pair's fallback
// branch calls AstroBWTv3 directly, which already carries ~1 alloc/op of
// its own (confirmed pre-existing, unrelated to this port -- Pool.Get()
// interface-boxing overhead present before any of this work, same finding
// already made scoping TestTemplateSAZeroAllocsAfterWarmup). Testing the
// whole AstroBWTv3Pair call here would just be re-measuring that unrelated,
// already-known overhead twice, not this milestone's own code.
func TestAstroBWTv3PairZeroAllocsAfterWarmup(t *testing.T) {
	var a, b [48]byte
	rand.Read(a[:])
	rand.Read(b[:])

	scratchA := Pool.Get().(*ScratchData)
	defer Pool.Put(scratchA)
	scratchB := Pool.Get().(*ScratchData)
	defer Pool.Put(scratchB)

	// Warmup: grows both scratches' pooled internals (template-SA included).
	la := astroBWTv3Stream(a[:], scratchA)
	lb := astroBWTv3Stream(b[:], scratchB)
	if la == 0 || lb == 0 {
		t.Fatalf("astroBWTv3Stream panicked during warmup")
	}
	sha256Sum256Pair(scratchA.sa_bytes[:la*4], scratchB.sa_bytes[:lb*4])

	allocs := testing.AllocsPerRun(100, func() {
		a[0]++
		b[0]++
		la := astroBWTv3Stream(a[:], scratchA)
		lb := astroBWTv3Stream(b[:], scratchB)
		if la == 0 || lb == 0 {
			t.Fatalf("astroBWTv3Stream panicked during the measured run")
		}
		sha256Sum256Pair(scratchA.sa_bytes[:la*4], scratchB.sa_bytes[:lb*4])
	})
	if allocs != 0 {
		t.Fatalf("astroBWTv3Stream+sha256Sum256Pair allocate %.1f times per run, want 0", allocs)
	}
}

// BenchmarkAstroBWTv3Pair mirrors pow_test.go's benchmark_AstroBWTv3
// (1024-input cycling) shape, one iteration = TWO hashes, directly
// comparable to Benchmark_AstroBWTv3_128 for a same-shape single-vs-pair
// throughput comparison. On a host without SHA-NI this measures the
// fallback path (expect roughly 2x Benchmark_AstroBWTv3_128's per-hash
// cost, not a win) -- the real comparison only means something on
// SHA-NI-capable hardware.
func BenchmarkAstroBWTv3Pair(b *testing.B) {
	b.ReportAllocs()

	var inputsA, inputsB [1024][]byte
	for i := 0; i < 1024; i++ {
		inputsA[i] = make([]byte, 128)
		inputsB[i] = make([]byte, 128)
		rand.Read(inputsA[i])
		rand.Read(inputsB[i])
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AstroBWTv3Pair(inputsA[i%1024], inputsB[i%1024])
	}
}

// TestSha256Sum256PairDifferential pins the multi-buffer SHA kernel itself
// against this package's own sha256-simd-backed hashing, over varied
// lengths including block boundaries (56/64-byte padding/block edges) and
// unequal pairs. This is deliberately a kernel-level test, not just an
// end-to-end one: an end-to-end gate that only ever feeds the kernel the
// miner's own fixed input sizes could let a wrong two-stream kernel slip
// through undetected.
//
// pairHashAvailable() reports whether the real SHA-NI branch inside
// sha256Sum256Pair actually ran on this host, or whether every call took
// the plain sha256Fallback path instead (no SHA-NI hardware, or
// big-endian). A green run here with pairHashAvailable()==false proves the
// fallback is correct; it does NOT exercise sha256mb_amd64.s at all. Only a
// run with pairHashAvailable()==true is evidence the assembly itself is
// correct -- check the log line before trusting this test as proof the
// kernel works.
func TestSha256Sum256PairDifferential(t *testing.T) {
	t.Logf("useSHANI=%v LittleEndian=%v pairHashAvailable=%v", useSHANI, LittleEndian, pairHashAvailable())
	rnd := rand.New(rand.NewSource(42))
	lengths := []int{
		1, 2, 31, 32, 47, 48, 55, 56, 57, 63, 64, 65,
		119, 120, 127, 128, 129, 191, 192, 255, 1024, 4096, 283 * 1024,
	}
	buf := make([]byte, 283*1024)
	rnd.Read(buf)
	for _, la := range lengths {
		for _, lb := range lengths {
			a := buf[:la]
			b := buf[len(buf)-lb:]
			ga, gb := sha256Sum256Pair(a, b)
			if wa := sha256Fallback(a); ga != wa {
				t.Fatalf("len(a)=%d len(b)=%d: lane A digest mismatch\ngot  %x\nwant %x", la, lb, ga, wa)
			}
			if wb := sha256Fallback(b); gb != wb {
				t.Fatalf("len(a)=%d len(b)=%d: lane B digest mismatch\ngot  %x\nwant %x", la, lb, gb, wb)
			}
		}
	}
}
