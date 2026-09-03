package astrobwtv3

// Benchmarks the template-descriptor SA path (buildTemplateSA,
// sa_template.go) in isolation, on the same kind of realistic fixture data
// as sais_bench_test.go's BenchmarkSAIS_Realistic /
// BenchmarkDivSufSortGo0Alloc_Realistic -- except this path also needs real
// template markers, which the existing testdata/safixtures corpus doesn't
// have (see sa_capture_hook.go's ScratchCaptureTemplateHook doc comment),
// so this loads testdata/safixtures_template instead (regenerate with:
// go test -tags astrobwt_capture -run TestGenerateSATemplateFixtures -v .).
//
// BenchmarkTemplateSAStageOnly_Realistic is the number directly comparable
// to the existing baselines:
//
//	go test -bench='BenchmarkTemplateSAStageOnly_Realistic|BenchmarkDivSufSortGo0Alloc_Realistic|BenchmarkSAIS_Realistic' \
//	  -benchtime=20x -count=10 . | tee /tmp/templatesa.txt
//	benchstat /tmp/templatesa.txt
//
// BenchmarkHashTemplateSA is a secondary, informational number covering the
// *whole* hash (wolf loop + SA + SHA), not just the isolated SA stage --
// never compare it directly against the SA-stage-only benchmarks above.

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type templateFixture struct {
	scratch *ScratchData
	dataLen uint32
	input   []byte
}

func loadSATemplateFixtures(tb testing.TB) []templateFixture {
	tb.Helper()
	entries, err := os.ReadDir(saTemplateFixtureDirForTest)
	if err != nil || len(entries) == 0 {
		tb.Skipf("no fixtures in %s -- generate with: go test -tags astrobwt_capture -run TestGenerateSATemplateFixtures -v .", saTemplateFixtureDirForTest)
	}

	var fixtures []templateFixture
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "data_") || filepath.Ext(name) != ".bin" {
			continue
		}
		rest := strings.TrimSuffix(strings.TrimPrefix(name, "data_"), ".bin")
		parts := strings.SplitN(rest, "_", 2)
		if len(parts) != 2 {
			tb.Fatalf("unexpected fixture filename %s", name)
		}
		dataLenStr, idx := parts[0], parts[1]
		dataLen, err := strconv.Atoi(dataLenStr)
		if err != nil {
			tb.Fatalf("fixture %s: bad dataLen: %v", name, err)
		}

		data, err := os.ReadFile(filepath.Join(saTemplateFixtureDirForTest, name))
		if err != nil {
			tb.Fatalf("fixture %s: read data: %v", name, err)
		}
		markersRaw, err := os.ReadFile(filepath.Join(saTemplateFixtureDirForTest, fmt.Sprintf("markers_%s_%s.bin", dataLenStr, idx)))
		if err != nil {
			tb.Fatalf("fixture %s: read markers: %v", name, err)
		}
		inputRaw, err := os.ReadFile(filepath.Join(saTemplateFixtureDirForTest, fmt.Sprintf("input_%s_%s.bin", dataLenStr, idx)))
		if err != nil {
			tb.Fatalf("fixture %s: read input: %v", name, err)
		}

		scratch := Pool.Get().(*ScratchData) // properly initialized (hasher, sa_bytes) via Pool.New
		copy(scratch.data[:dataLen], data)
		for i := 0; i*2 < len(markersRaw); i++ {
			scratch.markers[i] = binary.LittleEndian.Uint16(markersRaw[i*2:])
		}
		scratch.nTemplates = uint32(len(markersRaw) / 2)

		fixtures = append(fixtures, templateFixture{scratch: scratch, dataLen: uint32(dataLen), input: inputRaw})
	}
	if len(fixtures) == 0 {
		tb.Skipf("no .bin fixtures found in %s", saTemplateFixtureDirForTest)
	}
	return fixtures
}

// BenchmarkTemplateSAStageOnly_Realistic times buildTemplateSA directly on real
// captured (data, markers) fixtures -- the number directly comparable to
// BenchmarkDivSufSortGo0Alloc_Realistic / BenchmarkSAIS_Realistic.
func BenchmarkTemplateSAStageOnly_Realistic(b *testing.B) {
	fixtures := loadSATemplateFixtures(b)

	// Warm up every fixture's scratch.templateSA (lazily allocated on first use,
	// sa_template.go) before timing: each fixture owns its own persistent
	// scratch (unlike a real pooled ScratchData reused across many hashes),
	// so without this, cycling through fixtures[i%len(fixtures)] for a
	// small b.N would still be hitting first-ever calls on most/all of
	// them, allocating every time and misrepresenting steady-state cost --
	// see TestTemplateSAZeroAllocsAfterWarmup's identical "one warmup call first"
	// convention.
	for _, f := range fixtures {
		if !buildTemplateSA(f.scratch, f.dataLen) {
			b.Fatalf("buildTemplateSA declined during warmup (dataLen=%d)", f.dataLen)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	fallbacksBefore := templateSAFallbacks.Load()
	for i := 0; i < b.N; i++ {
		f := fixtures[i%len(fixtures)]
		if !buildTemplateSA(f.scratch, f.dataLen) {
			b.Fatalf("buildTemplateSA declined on fixture %d (dataLen=%d)", i%len(fixtures), f.dataLen)
		}
	}
	b.StopTimer()
	if fell := templateSAFallbacks.Load() - fallbacksBefore; fell != 0 {
		b.Fatalf("templateSAFallbacks moved by %d during a measured run that should never decline", fell)
	}
}

// BenchmarkHashTemplateSA times the whole hash (wolf loop + SA + SHA)
// through the template-descriptor path, informational only -- not
// comparable to the SA-stage-only benchmarks above.
func BenchmarkHashTemplateSA(b *testing.B) {
	fixtures := loadSATemplateFixtures(b)
	inputs := make([][]byte, 0, len(fixtures))
	for _, f := range fixtures {
		if len(f.input) > 0 {
			inputs = append(inputs, f.input)
		}
	}
	if len(inputs) == 0 {
		b.Skip("no fixture inputs available")
	}

	scratch := Pool.Get().(*ScratchData)
	scratch.useTemplateSA = true
	defer Pool.Put(scratch)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		astroBWTv3(inputs[i%len(inputs)], scratch)
	}
}

// BenchmarkHashDivSufSortOnly is BenchmarkHashTemplateSA's mirror, forcing
// scratch.useTemplateSA = false explicitly -- the whole-hash divsufsort
// reference, for a permanent, fair end-to-end comparison against the
// production default (sa_fast.go's Pool.New). Same fixture inputs as
// BenchmarkHashTemplateSA, so the two are directly comparable to each
// other (unlike either against the SA-stage-only benchmarks).
func BenchmarkHashDivSufSortOnly(b *testing.B) {
	fixtures := loadSATemplateFixtures(b)
	inputs := make([][]byte, 0, len(fixtures))
	for _, f := range fixtures {
		if len(f.input) > 0 {
			inputs = append(inputs, f.input)
		}
	}
	if len(inputs) == 0 {
		b.Skip("no fixture inputs available")
	}

	scratch := Pool.Get().(*ScratchData)
	scratch.useTemplateSA = false
	defer Pool.Put(scratch)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		astroBWTv3(inputs[i%len(inputs)], scratch)
	}
}
