package astrobwtv3

// Stage 2b: cross-checks a suffix array computed by the standalone C
// divsufsort harness (divsufsort_bench/) against Go's stdlib oracle for the
// exact same input bytes. A suffix array is unique for a given input
// regardless of algorithm, so a correct divsufsort output and a correct
// SA-IS output must be byte-for-byte identical -- this is a third,
// independent cross-check of the whole oracle chain using a mature,
// long-deployed C implementation, and (going the other direction) validates
// that divsufsort_bench/sabench is actually computing what it claims to.
//
// Requires a manual build+run step first (not part of normal `go test`):
//
//	cd divsufsort_bench
//	gcc -O2 -DHAVE_CONFIG_H -I../../../../tnn-miner/src/crypto/astrobwtv3 \
//	  main.c ../../../../tnn-miner/src/crypto/astrobwtv3/{divsufsort,sssort,trsort,utils}.c \
//	  -lm -o sabench
//	FIXTURE=$(ls ../testdata/safixtures/*.bin | head -1)
//	./sabench --dump-sa "$FIXTURE" /tmp/c_sa_dump.bin
//
// then set CROSSCHECK_FIXTURE and CROSSCHECK_C_DUMP below (or via env vars)
// and run: go test -run TestSuffixArrayCrossCheckC -v .

import (
	"encoding/binary"
	"os"
	"testing"
)

func TestSuffixArrayCrossCheckC(t *testing.T) {
	fixturePath := os.Getenv("CROSSCHECK_FIXTURE")
	dumpPath := os.Getenv("CROSSCHECK_C_DUMP")
	if fixturePath == "" || dumpPath == "" {
		t.Skip("set CROSSCHECK_FIXTURE and CROSSCHECK_C_DUMP env vars to run (see file header for how to produce them)")
	}

	text, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", fixturePath, err)
	}
	dump, err := os.ReadFile(dumpPath)
	if err != nil {
		t.Fatalf("reading C dump %s: %v", dumpPath, err)
	}
	if len(dump) != len(text)*4 {
		t.Fatalf("C dump size %d != expected %d (len(text)*4 for int32 LE)", len(dump), len(text)*4)
	}

	cSA := make([]int32, len(text))
	for i := range cSA {
		cSA[i] = int32(binary.LittleEndian.Uint32(dump[i*4:]))
	}
	assertValidSuffixArray(t, "C-divsufsort", text, cSA)

	goSA := stdlibSuffixArray(t, text)
	if !equalInt32(cSA, goSA) {
		t.Fatalf("C divsufsort output disagrees with Go stdlib oracle for %s (n=%d)", fixturePath, len(text))
	}

	// also cross-check against production text_32_0alloc directly (the
	// divsufsort port since the Stage 4b cutover -- this now cross-checks
	// the Go divsufsort port against the real C divsufsort implementation)
	prodSA := make([]int32, len(text))
	text_32_0alloc(text, prodSA)
	if !equalInt32(cSA, prodSA) {
		t.Fatalf("C divsufsort output disagrees with production text_32_0alloc for %s (n=%d)", fixturePath, len(text))
	}

	t.Logf("C divsufsort output matches both Go stdlib oracle and production text_32_0alloc for %s (n=%d)", fixturePath, len(text))
}
