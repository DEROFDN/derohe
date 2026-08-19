package blockchain

import "math/rand"
import "os"
import "path/filepath"
import "sync"
import "testing"

// linearCount is Count()'s backward walk, run against the file with no memory
// of any earlier answer. Count() must keep returning exactly this, always.
func linearCount(s *storetopofs) int64 {
	fstat, err := s.topomapping.Stat()
	if err != nil {
		panic(err)
	}
	count := int64(fstat.Size() / TOPORECORD_SIZE)
	for ; count >= 1; count-- {
		if record, err := s.Read(count - 1); err == nil && !record.IsClean() {
			break
		} else if err != nil {
			panic(err)
		}
	}
	return count
}

// one state version for every record keeps Write() off its fsync path, so the
// test does not spend minutes on a disk backed TMPDIR.
const test_state_version = 7

func newStore(t testing.TB) *storetopofs {
	t.Helper()
	var s storetopofs
	if err := s.Open(t.TempDir()); err != nil {
		t.Fatalf("cannot open topo store: %s", err)
	}
	t.Cleanup(func() { s.topomapping.Close() })
	return &s
}

func writeLive(t testing.TB, s *storetopofs, index int64) {
	t.Helper()
	var blid [32]byte
	blid[0], blid[1], blid[2] = byte(index), byte(index>>8), byte(index>>16)
	blid[3] = 1 // never all zero, even at index 0
	if err := s.Write(index, blid, test_state_version, index); err != nil {
		t.Fatalf("cannot write record %d: %s", index, err)
	}
}

// writeShape writes one of the three shapes derod actually produces: a clean
// record, a live record, and chain_bootstrap's zero blid carrying a live state
// version, which is the highest volume write in the daemon and is live to the
// walk, so Write() must treat it as live too.
func writeShape(t testing.TB, s *storetopofs, r *rand.Rand, index int64) {
	t.Helper()
	switch r.Intn(3) {
	case 0:
		if err := s.Clean(index); err != nil {
			t.Errorf("cannot clean %d: %s", index, err)
		}
	case 1:
		writeLive(t, s, index)
	default:
		var blid [32]byte
		if err := s.Write(index, blid, test_state_version, index); err != nil {
			t.Errorf("cannot write %d: %s", index, err)
		}
	}
}

// fill writes total live records then cleans the top popped ones, the same
// descending order Rewind_Chain cleans in.
func fill(t testing.TB, total, popped int64) *storetopofs {
	t.Helper()
	s := newStore(t)
	for i := int64(0); i < total; i++ {
		writeLive(t, s, i)
	}
	for i := int64(0); i < popped; i++ {
		if err := s.Clean(total - 1 - i); err != nil {
			t.Fatalf("cannot clean record %d: %s", total-1-i, err)
		}
	}
	return s
}

// the remembered count must equal the walk at every boundary.
func TestTopoCountMatchesWalk(t *testing.T) {
	shapes := [][2]int64{
		{0, 0}, {1, 0}, {1, 1}, {2, 1}, {10, 9}, {10, 10}, {100, 1},
		{1000, 999}, {1000, 0}, {20000, 19999}, {20000, 8000},
	}
	for i := int64(0); i < 100; i++ {
		total := rand.New(rand.NewSource(i)).Int63n(300) + 1
		shapes = append(shapes, [2]int64{total, rand.New(rand.NewSource(i + 1000)).Int63n(total + 1)})
	}

	for _, shape := range shapes {
		s := fill(t, shape[0], shape[1])
		if want, got := linearCount(s), s.Count(); want != got {
			t.Fatalf("total %d popped %d: Count() = %d, walk = %d", shape[0], shape[1], got, want)
		}
		if want, got := shape[0]-shape[1], s.Count(); want != got {
			t.Fatalf("total %d popped %d: Count() = %d, want %d", shape[0], shape[1], got, want)
		}
	}
}

// arbitrary write orders, including interior clean records and writes below the
// top, which the walk tolerates. Count() must agree after every single write.
// kept small on purpose: a live write following a clean one takes Write()'s
// fsync path, so a larger sequence costs minutes on a disk backed TMPDIR.
func TestTopoCountMatchesWalkUnderRandomWrites(t *testing.T) {
	for seed := int64(0); seed < 12; seed++ {
		r := rand.New(rand.NewSource(seed))
		s := newStore(t)
		for op := 0; op < 60; op++ {
			index := r.Int63n(60)
			writeShape(t, s, r, index)
			if want, got := linearCount(s), s.Count(); want != got {
				t.Fatalf("seed %d op %d index %d: Count() = %d, walk = %d", seed, op, index, got, want)
			}
		}
	}
}

// a chain that pops and then catches up again, plus the derod "fix" console
// command rewriting a live record well below the top.
func TestTopoCountAfterRegrow(t *testing.T) {
	s := fill(t, 20000, 8000)

	if got := s.Count(); got != 12000 {
		t.Fatalf("count = %d, want 12000", got)
	}
	writeLive(t, s, 20000)
	if got := s.Count(); got != 20001 {
		t.Fatalf("count after regrow = %d, want 20001", got)
	}
	writeLive(t, s, 5)
	if got := s.Count(); got != 20001 {
		t.Fatalf("count after write below the top = %d, want 20001", got)
	}
	if err := s.Clean(20000); err != nil {
		t.Fatalf("cannot clean: %s", err)
	}
	if want, got := linearCount(s), s.Count(); want != got {
		t.Fatalf("count after cleaning the top = %d, walk = %d", got, want)
	}
}

// the answer must be served without touching the file at all, which is the
// whole point: closing it would fail every read the walk makes.
func TestTopoCountServedWithoutReading(t *testing.T) {
	s := fill(t, 500, 200)
	if got := s.Count(); got != 300 {
		t.Fatalf("count = %d, want 300", got)
	}
	s.topomapping.Close()
	if got := s.Count(); got != 300 {
		t.Fatalf("count after close = %d, want 300", got)
	}
}

// reopening the same store on a different file must not serve the old answer,
// neither from the remembered value nor from a walk that was already running
// against the old file, so Open() moves the generation like every other
// invalidation does.
func TestTopoCountReopen(t *testing.T) {
	s := fill(t, 500, 200)
	if got := s.Count(); got != 300 {
		t.Fatalf("count = %d, want 300", got)
	}

	s.count_mu.Lock() // a walk starts against the old file
	gen := s.count_gen
	s.count_mu.Unlock()

	s.topomapping.Close()
	if err := s.Open(t.TempDir()); err != nil {
		t.Fatalf("cannot reopen topo store: %s", err)
	}
	s.publish_count(gen, 300) // that walk finishes and offers the old file's answer

	if got := s.Count(); got != 0 {
		t.Fatalf("count after reopen = %d, want 0", got)
	}
}

// a walk which raced a write must not publish its stale answer. driven directly
// rather than by racing goroutines, so the guard is actually pinned.
func TestTopoCountDoesNotPublishAcrossWrites(t *testing.T) {
	s := fill(t, 100, 0)
	if got := s.Count(); got != 100 {
		t.Fatalf("count = %d, want 100", got)
	}

	s.count_mu.Lock() // a walk starts and reads the file as it is now
	gen := s.count_gen
	s.count_mu.Unlock()

	if err := s.Clean(99); err != nil { // a write lands while that walk runs
		t.Fatalf("cannot clean: %s", err)
	}

	s.publish_count(gen, 100) // the walk finishes and offers its stale answer

	if got := s.Count(); got != 99 {
		t.Fatalf("stale walk was remembered: count = %d, want 99", got)
	}
	if want, got := linearCount(s), s.Count(); want != got {
		t.Fatalf("count = %d, walk = %d", got, want)
	}
}

// a write which fails must not be remembered, or Count() would answer above the
// records the file actually holds and Get_Top_ID would panic on the read.
func TestTopoCountIgnoresFailedWrite(t *testing.T) {
	dir := t.TempDir()
	var s storetopofs
	if err := s.Open(dir); err != nil {
		t.Fatalf("cannot open topo store: %s", err)
	}
	for i := int64(0); i < 100; i++ {
		writeLive(t, &s, i)
	}
	if got := s.Count(); got != 100 {
		t.Fatalf("count = %d, want 100", got)
	}

	s.topomapping.Close() // reopen read only, so the next write fails
	readonly, err := os.OpenFile(filepath.Join(dir, "topo.map"), os.O_RDONLY, 0700)
	if err != nil {
		t.Fatalf("cannot reopen read only: %s", err)
	}
	defer readonly.Close()
	s.topomapping = readonly

	var blid [32]byte
	blid[3] = 1
	if err := s.Write(200, blid, test_state_version, 200); err == nil {
		t.Fatal("write to a read only file unexpectedly succeeded")
	}
	if got := s.Count(); got != 100 {
		t.Fatalf("failed write was remembered: count = %d, want 100", got)
	}
}

// readers are lock free, so a walk has to be able to race an invalidating write.
// writeShape mixes Clean() in deliberately: a live write can only raise the
// count, so a live only writer never takes the invalidate branch the generation
// guard exists for. run under -race. the assertion is the quiesced differential,
// the race detector carries the rest.
func TestTopoCountConcurrentWithCleans(t *testing.T) {
	s := fill(t, 2000, 500)
	var readers sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s.Count()
				}
			}
		}()
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 800; i++ { // write from this goroutine, readers race it
		writeShape(t, s, rng, int64(rng.Intn(2500)))
	}
	close(stop)
	readers.Wait()
	if want, got := linearCount(s), s.Count(); want != got {
		t.Fatalf("count = %d, walk = %d", got, want)
	}
}
