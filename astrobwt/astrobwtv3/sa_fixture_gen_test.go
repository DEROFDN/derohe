//go:build astrobwt_capture

package astrobwtv3

// Fixture generator for realistic suffix-array benchmark/oracle input.
//
// AstroBWTv3's real production input is always exactly 48 bytes (a
// serialized MiniBlock -- block.MINIBLOCK_SIZE, which can't be imported
// here since block already imports this package). What varies in size is
// the internally-expanded scratch.data buffer the branchy mixing loop
// builds up before the suffix sort (up to ~70KB, see pow.go's data_len
// computation) -- that's what actually gets fed to sais_8_32, and what a
// realistic benchmark/oracle fixture needs to look like. Rather than guess
// at its statistical shape, this drives the real, unmodified AstroBWTv3()
// with random 48-byte inputs and captures the authentic scratch.data via
// the astrobwt_capture hook (sa_capture_hook.go).
//
// Run explicitly (not part of normal `go test`):
//
//	go test -tags astrobwt_capture -run TestGenerateSAFixtures -v .

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

const (
	saFixtureInputSize = 48 // matches block.MINIBLOCK_SIZE
	saFixtureCount     = 64
	saFixtureDir       = "testdata/safixtures"
	saFixtureSeed      = 20260803
)

func TestGenerateSAFixtures(t *testing.T) {
	if err := os.MkdirAll(saFixtureDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", saFixtureDir, err)
	}

	rng := rand.New(rand.NewSource(saFixtureSeed))
	input := make([]byte, saFixtureInputSize)

	for i := 0; i < saFixtureCount; i++ {
		rng.Read(input)

		var captured []byte
		var capturedLen uint32
		ScratchCaptureHook = func(data []byte, dataLen uint32) {
			captured = data
			capturedLen = dataLen
		}

		_ = AstroBWTv3(input)

		ScratchCaptureHook = nil

		if captured == nil {
			t.Fatalf("fixture %d: capture hook never fired", i)
		}
		if uint32(len(captured)) != capturedLen {
			t.Fatalf("fixture %d: captured len mismatch: len(data)=%d dataLen=%d", i, len(captured), capturedLen)
		}

		path := filepath.Join(saFixtureDir, fmt.Sprintf("sa_fixture_%d_%02d.bin", capturedLen, i))
		if err := os.WriteFile(path, captured, 0o644); err != nil {
			t.Fatalf("fixture %d: write %s: %v", i, path, err)
		}
		t.Logf("wrote %s (%d bytes, from 48-byte input %x)", path, capturedLen, input)
	}
}
