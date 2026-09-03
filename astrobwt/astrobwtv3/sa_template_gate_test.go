package astrobwtv3

// TestTemplateSAMillionHashGate is a large-N smoke gate for CI/manual runs,
// mirroring the reference port's own gate test. Off by default (this
// package's normal `go test .` never runs it) since it's meant for a
// deliberate, larger-than-unit-test confirmation pass, not routine CI:
//
//	TEMPLATE_SA_GATE_HASHES=1000000 go test -run TestTemplateSAMillionHashGate -v .

import (
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

func TestTemplateSAMillionHashGate(t *testing.T) {
	raw := os.Getenv("TEMPLATE_SA_GATE_HASHES")
	if raw == "" {
		t.Skip("TEMPLATE_SA_GATE_HASHES not set; skipping (see this test's doc comment)")
	}
	total, err := strconv.Atoi(raw)
	if err != nil || total <= 0 {
		t.Fatalf("TEMPLATE_SA_GATE_HASHES=%q: invalid positive integer", raw)
	}

	workers := runtime.NumCPU()
	perWorker := total / workers
	if perWorker == 0 {
		perWorker = 1
		workers = total
	}

	var failed atomic.Bool
	var once sync.Once
	var wg sync.WaitGroup
	var checked atomic.Int64

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			refScratch := Pool.Get().(*ScratchData)
			refScratch.useTemplateSA = false
			defer Pool.Put(refScratch)

			for i := 0; i < perWorker; i++ {
				if failed.Load() {
					return
				}
				input := genUniformRandom(rng, 48)
				want := astroBWTv3(input, refScratch)
				got := AstroBWTv3(input) // production = template path by default
				checked.Add(1)
				if got != want {
					once.Do(func() {
						t.Errorf("mismatch on worker seed=%d after %d hashes: input=%x production(template)=%x divsufsort_ref=%x", seed, i, input, got, want)
					})
					failed.Store(true)
					return
				}
			}
		}(20260803 + int64(w))
	}
	wg.Wait()

	t.Logf("template SA million-hash gate: checked %d hashes across %d workers, 0 mismatches", checked.Load(), workers)
}
