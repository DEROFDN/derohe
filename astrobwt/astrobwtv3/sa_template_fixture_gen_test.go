//go:build astrobwt_capture

package astrobwtv3

// Fixture generator for the template-descriptor SA path's own, marker-aware
// corpus. See sa_capture_hook.go's ScratchCaptureTemplateHook doc comment
// for why this is a separate corpus from testdata/safixtures (which
// predates scratch.markers/nTemplates and can't drive buildTemplateSA on
// its own).
//
// Writes paired files per fixture, data_<len>_<idx>.bin and
// markers_<len>_<idx>.bin, into testdata/safixtures_template/ — a directory of
// its own, not testdata/safixtures, so the existing .bin-glob loaders
// (loadSAFixtures, sais_bench_test.go) never see these files. markers is
// serialized as little-endian uint16s, nTemplates entries, no header (the
// filename already encodes dataLen and index; nTemplates is recoverable as
// len(markers file)/2 on load).
//
// Run explicitly (not part of normal `go test`):
//
//	go test -tags astrobwt_capture -run TestGenerateSATemplateFixtures -v .

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

const (
	saTemplateFixtureDir = "testdata/safixtures_template"
)

func TestGenerateSATemplateFixtures(t *testing.T) {
	if err := os.MkdirAll(saTemplateFixtureDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", saTemplateFixtureDir, err)
	}

	// Same seed/count/input-size convention as the existing generator
	// (sa_fixture_gen_test.go) — a different, independent corpus, not a
	// duplicate of it (this path needs markers, which that one never
	// captured).
	rng := rand.New(rand.NewSource(saFixtureSeed))
	input := make([]byte, saFixtureInputSize)

	for i := 0; i < saFixtureCount; i++ {
		rng.Read(input)

		var capturedData []byte
		var capturedLen uint32
		var capturedMarkers []uint16
		var capturedNTemplates uint32
		ScratchCaptureTemplateHook = func(data []byte, dataLen uint32, markers []uint16, nTemplates uint32) {
			capturedData = data
			capturedLen = dataLen
			capturedMarkers = markers
			capturedNTemplates = nTemplates
		}

		_ = AstroBWTv3(input)

		ScratchCaptureTemplateHook = nil

		if capturedData == nil {
			t.Fatalf("fixture %d: capture hook never fired", i)
		}
		if capturedNTemplates == 0 || uint32(len(capturedMarkers)) != capturedNTemplates {
			t.Fatalf("fixture %d: bad marker capture: nTemplates=%d len(markers)=%d", i, capturedNTemplates, len(capturedMarkers))
		}

		dataPath := filepath.Join(saTemplateFixtureDir, fmt.Sprintf("data_%d_%02d.bin", capturedLen, i))
		if err := os.WriteFile(dataPath, capturedData, 0o644); err != nil {
			t.Fatalf("fixture %d: write %s: %v", i, dataPath, err)
		}

		// The original 48-byte seed, so a round-trip test can re-derive this
		// exact fixture via a fresh AstroBWTv3(input) call, not just replay
		// the captured bytes.
		inputPath := filepath.Join(saTemplateFixtureDir, fmt.Sprintf("input_%d_%02d.bin", capturedLen, i))
		if err := os.WriteFile(inputPath, append([]byte(nil), input...), 0o644); err != nil {
			t.Fatalf("fixture %d: write %s: %v", i, inputPath, err)
		}

		markersBytes := make([]byte, len(capturedMarkers)*2)
		for j, m := range capturedMarkers {
			binary.LittleEndian.PutUint16(markersBytes[j*2:], m)
		}
		markersPath := filepath.Join(saTemplateFixtureDir, fmt.Sprintf("markers_%d_%02d.bin", capturedLen, i))
		if err := os.WriteFile(markersPath, markersBytes, 0o644); err != nil {
			t.Fatalf("fixture %d: write %s: %v", i, markersPath, err)
		}

		t.Logf("wrote %s + %s (dataLen=%d nTemplates=%d, from 48-byte input %x)",
			dataPath, markersPath, capturedLen, capturedNTemplates, input)
	}
}
