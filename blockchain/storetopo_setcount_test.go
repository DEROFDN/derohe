package blockchain

// Does the remembered count survive Rewind_Chain's run of Clean() calls?
//
// Deterministic rather than timed: after the rewind the file is CLOSED, so a
// Count() that still needs to walk fails loudly instead of quietly succeeding.
// Each test carries its own negative control.

import (
	"os"
	"testing"
)

func newTopo(t *testing.T, live int64) (*storetopofs, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "setcount")
	if err != nil {
		t.Fatal(err)
	}
	s := &storetopofs{}
	if err := s.Open(dir); err != nil {
		t.Fatal(err)
	}
	var blid [32]byte
	blid[0] = 1
	for i := int64(0); i < live; i++ {
		if err := s.Write(i, blid, uint64(i+1), i); err != nil {
			t.Fatal(err)
		}
	}
	return s, dir
}

// walks reports whether Count() had to walk, by closing the file first: the
// walk's Stat/Read then fail and Count() panics, which we recover.
func walks(s *storetopofs) (walked bool, got int64) {
	defer func() {
		if r := recover(); r != nil {
			walked = true
		}
	}()
	got = s.Count()
	return false, got
}

// rewind mimics blockchain.go's Rewind_Chain: settle the count, then clean.
func rewind(s *storetopofs, top, n int64, settle bool) int64 {
	settled := top - n + 1
	if settle && n > 0 && settled >= 1 {
		if r, err := s.Read(settled - 1); err == nil && !r.IsClean() {
			s.SetCount(settled)
		}
	}
	for i := int64(0); i < n; i++ {
		s.Clean(top - i)
	}
	if settle {
		s.SetCount(settled)
	}
	return settled
}

// THE FIX: with the count settled up front, the run of Clean() calls does not
// invalidate the memo, so Count() answers without touching the file.
func TestSetCount_MemoSurvivesRewind(t *testing.T) {
	const live, pop = 20000, 15000
	s, dir := newTopo(t, live)
	defer os.RemoveAll(dir)

	want := rewind(s, live-1, pop, true)
	s.topomapping.Close() // any walk from here on must fail

	walked, got := walks(s)
	if walked {
		t.Fatal("Count() walked after the rewind - the memo did not survive Clean()")
	}
	if got != want {
		t.Fatalf("Count() = %d, want %d", got, want)
	}
	t.Logf("rewound %d of %d: Count()=%d with no walk", pop, live, got)
}

// The one that matters: the memo must stay valid THROUGHOUT the run of Clean()
// calls, not merely be re-asserted afterwards. Without the exemption every
// Clean() invalidates and a concurrent Count() walks - which is the whole cost.
// Checked inside the loop, so a trailing SetCount cannot paper over it.
func TestSetCount_MemoStaysValidDuringCleanLoop(t *testing.T) {
	const live, pop = 5000, 4000
	s, dir := newTopo(t, live)
	defer os.RemoveAll(dir)

	top := int64(live - 1)
	settled := top - pop + 1
	if r, err := s.Read(settled - 1); err != nil || r.IsClean() {
		t.Fatal("setup: record below the settled count is not live")
	}
	s.SetCount(settled)

	for i := int64(0); i < pop; i++ {
		s.Clean(top - i)

		s.count_mu.Lock()
		valid, held := s.count_valid, s.count
		s.count_mu.Unlock()
		if !valid {
			t.Fatalf("memo invalidated at clean %d of %d - every Count() from here walks", i+1, pop)
		}
		if held != settled {
			t.Fatalf("memo drifted to %d during the loop, want %d", held, settled)
		}
	}

	if got := s.Count(); got != settled {
		t.Fatalf("Count() = %d, want %d", got, settled)
	}
	if want := linearCount(s); want != settled {
		t.Fatalf("a fresh walk says %d, memo says %d", want, settled)
	}
	t.Logf("memo stayed valid across all %d Clean() calls, and agrees with a fresh walk", pop)
}

// NEGATIVE CONTROL: same sequence without settling the count. Every Clean()
// invalidates, so Count() must walk - proving the test can tell the difference.
func TestSetCount_ControlWithoutSettleMustWalk(t *testing.T) {
	const live, pop = 20000, 15000
	s, dir := newTopo(t, live)
	defer os.RemoveAll(dir)

	rewind(s, live-1, pop, false)
	s.topomapping.Close()

	walked, _ := walks(s)
	if !walked {
		t.Fatal("control failed: Count() answered without walking, so the fix test proves nothing")
	}
	t.Log("control fired: without SetCount the memo is invalid and Count() walks")
}

// The exemption must not change what Count() reports. Compare the remembered
// value against a fresh walk over the same file, across mixed write patterns.
func TestSetCount_AgreesWithFreshWalk(t *testing.T) {
	cases := []struct{ live, pop int64 }{
		{100, 0}, {100, 1}, {100, 99}, {1000, 500}, {1000, 999}, {5000, 4321},
	}
	var blid [32]byte
	blid[0] = 1

	for _, c := range cases {
		s, dir := newTopo(t, c.live)
		want := rewind(s, c.live-1, c.pop, true)

		remembered := s.Count()

		// fresh instance over the same bytes: no memo, must walk
		fresh := &storetopofs{}
		if err := fresh.Open(dir); err != nil {
			t.Fatal(err)
		}
		byWalk := fresh.Count()

		if remembered != byWalk {
			t.Fatalf("live=%d pop=%d: remembered %d, fresh walk %d", c.live, c.pop, remembered, byWalk)
		}
		if c.pop > 0 && remembered != want {
			t.Fatalf("live=%d pop=%d: remembered %d, expected settled %d", c.live, c.pop, remembered, want)
		}
		s.topomapping.Close()
		fresh.topomapping.Close()
		os.RemoveAll(dir)
	}
	t.Logf("%d shapes: remembered count equals a fresh walk in every one", len(cases))
}

// A clean write BELOW the held count must still invalidate - the exemption is
// only for writes at or above it, where the region is already clean.
func TestSetCount_CleanWriteBelowCountStillInvalidates(t *testing.T) {
	const live = 500
	s, dir := newTopo(t, live)
	defer os.RemoveAll(dir)

	if got := s.Count(); got != live {
		t.Fatalf("Count() = %d, want %d", got, live)
	}
	s.Clean(live - 200) // a hole well below the count

	s.count_mu.Lock()
	valid := s.count_valid
	s.count_mu.Unlock()
	if valid {
		t.Fatal("a clean write below the count did not invalidate the memo")
	}
	if got := s.Count(); got != live {
		t.Fatalf("after re-walk Count() = %d, want %d", got, live)
	}
	t.Log("clean write below the count invalidates, as it must")
}
