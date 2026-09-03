package astrobwtv3

// Benchmarks the actual production suffix-array entry point (text_32_0alloc,
// backed by the divsufsort port since the Stage 4b cutover) in isolation, on
// realistic ~64-70KB fixtures captured from real AstroBWTv3() runs (see
// sa_fixture_gen_test.go / sa_capture_hook.go). This isolates exactly the
// ~82%-of-per-hash-cost component identified by profiling AstroBWTv3 as a
// whole (go test -bench=Benchmark_AstroBWTv3_16 -cpuprofile).
//
// The BenchmarkSAIS_* names below now measure text_32_0alloc_sais, the
// retired SA-IS implementation, kept only as the historical baseline these
// benchmarks have always compared against -- not renamed, so numbers stay
// comparable across every prior stage's recorded results.
//
// Fixtures aren't committed to the repo (see testdata/safixtures/.gitignore)
// -- regenerate with:
//
//	go test -tags astrobwt_capture -run TestGenerateSAFixtures -v .
//
// For statistically sound comparisons (this session already got burned once
// by single-sample/thermal-drift noise on the miner's live hashrate), run
// with -count=10 or more and feed through benchstat rather than trusting a
// single ns/op figure:
//
//	go test -bench=BenchmarkSAIS_Realistic -benchtime=20x -count=10 . | tee /tmp/new.txt
//	benchstat /tmp/new.txt

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

func loadSAFixtures(tb testing.TB) [][]byte {
	tb.Helper()
	entries, err := os.ReadDir(saFixtureDirForBench)
	if err != nil || len(entries) == 0 {
		tb.Skipf("no fixtures in %s -- generate with: go test -tags astrobwt_capture -run TestGenerateSAFixtures -v .", saFixtureDirForBench)
	}
	var fixtures [][]byte
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".bin" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(saFixtureDirForBench, e.Name()))
		if err != nil {
			tb.Fatalf("reading fixture %s: %v", e.Name(), err)
		}
		fixtures = append(fixtures, data)
	}
	if len(fixtures) == 0 {
		tb.Skipf("no .bin fixtures found in %s", saFixtureDirForBench)
	}
	return fixtures
}

// saFixtureDirForBench duplicates the path used by the (build-tag-gated)
// generator rather than referencing its constant, so this file compiles and
// runs in a normal (non astrobwt_capture) build.
const saFixtureDirForBench = "testdata/safixtures"

// BenchmarkSAIS_Realistic times text_32_0alloc_sais (the retired SA-IS
// implementation; production itself is text_32_0alloc since Stage 4b)
// directly on captured real-world-shaped input, cycling through all
// available fixtures to average out any single-input quirk.
func BenchmarkSAIS_Realistic(b *testing.B) {
	fixtures := loadSAFixtures(b)
	sa := make([]int32, MAX_LENGTH)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		text := fixtures[i%len(fixtures)]
		text_32_0alloc_sais(text, sa[:len(text)])
	}
}

// BenchmarkSAIS_RealisticParallel is the same workload run across GOMAXPROCS
// goroutines, closer to how the miner actually drives this function (one
// call per mining thread, continuously).
func BenchmarkSAIS_RealisticParallel(b *testing.B) {
	fixtures := loadSAFixtures(b)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		sa := make([]int32, MAX_LENGTH)
		i := 0
		for pb.Next() {
			text := fixtures[i%len(fixtures)]
			text_32_0alloc_sais(text, sa[:len(text)])
			i++
		}
	})
}

// BenchmarkSortIndicesFastPath_Realistic times the alternate sort_indices/
// ScratchData ("fast") code path that already exists in sa_fast.go but is
// NOT used by production AstroBWTv3 today -- informational only, per the
// plan, since it's already sitting in the codebase unused and worth having
// current numbers for.
func BenchmarkSortIndicesFastPath_Realistic(b *testing.B) {
	fixtures := loadSAFixtures(b)
	scratch := Pool.Get().(*ScratchData)
	defer Pool.Put(scratch)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		text := fixtures[i%len(fixtures)]
		n := uint32(len(text))
		copy(scratch.data[:], text)
		for j := n; j < n+64 && int(j) < len(scratch.data); j++ {
			scratch.data[j] = 0
		}
		sort_indices(n, scratch.data[:n+64], scratch.stage1_result[:], scratch)
	}
}

// BenchmarkSAIS_BySize benchmarks across the small input sizes the existing
// Benchmark_AstroBWTv3_* suite in pow_test.go already uses, so per-call
// overhead at small n (which may not scale like large-n throughput) is
// visible too.
func BenchmarkSAIS_BySize(b *testing.B) {
	for _, n := range []int{2, 4, 8, 16, 32, 48, 64, 128} {
		n := n
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			rng := rand.New(rand.NewSource(int64(n)))
			text := genUniformRandom(rng, n)
			sa := make([]int32, n)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				text_32_0alloc_sais(text, sa)
			}
		})
	}
}

// BenchmarkDivSufSortGo_Realistic mirrors BenchmarkSAIS_Realistic exactly
// (same fixtures, same methodology) but drives computeSuffixArrayDivSufSort
// directly (allocating bucketA/bucketB fresh each call) rather than through
// text_32_0alloc. Kept from Stage 3 for historical comparability; see
// BenchmarkDivSufSortGo0Alloc_Realistic for the 0-alloc variant that now
// mirrors production exactly.
func BenchmarkDivSufSortGo_Realistic(b *testing.B) {
	fixtures := loadSAFixtures(b)
	sa := make([]int32, MAX_LENGTH)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		text := fixtures[i%len(fixtures)]
		computeSuffixArrayDivSufSort(text, sa[:len(text)])
	}
}

// BenchmarkDivSufSortGo0Alloc_Realistic is BenchmarkDivSufSortGo_Realistic
// through computeSuffixArrayDivSufSort0Alloc with local 0-alloc bucketA/
// bucketB scratch (Stage 4a). Since the Stage 4b cutover this is exactly
// what text_32_0alloc (production) does internally -- this benchmark now
// *is* production timing, not just a comparison against it.
func BenchmarkDivSufSortGo0Alloc_Realistic(b *testing.B) {
	fixtures := loadSAFixtures(b)
	sa := make([]int32, MAX_LENGTH)
	var bucketA [256]int32
	var bucketB [256 * 256]int32

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		text := fixtures[i%len(fixtures)]
		computeSuffixArrayDivSufSort0Alloc(text, sa[:len(text)], bucketA[:], bucketB[:])
	}
}
