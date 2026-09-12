package p2p

import "testing"
import "time"

func TestOffsetWindow_AvgIgnoresZero(t *testing.T) {
	var w offsetWindow
	if w.avg() != 0 {
		t.Fatalf("empty avg want 0 got %s", w.avg())
	}
	if got := w.add(100 * time.Millisecond); got != 100*time.Millisecond {
		t.Fatalf("single add: got %s", got)
	}
	if got := w.add(300 * time.Millisecond); got != 200*time.Millisecond {
		t.Fatalf("two-sample avg: got %s", got)
	}
}

func TestOffsetWindow_FlushClears(t *testing.T) {
	var w offsetWindow
	w.add(-6 * time.Minute)
	w.add(-6 * time.Minute)
	w.flush()
	if w.avg() != 0 {
		t.Fatalf("after flush avg want 0 got %s", w.avg())
	}
	if got := w.add(20 * time.Millisecond); got != 20*time.Millisecond {
		t.Fatalf("post-flush add should be only the fresh sample, got %s", got)
	}
}

func TestOffsetWindow_RecoverDropsStale(t *testing.T) {
	// Mirrors time_check_routine: drifted samples then a good one + flush.
	var w offsetWindow
	timeinsync := false
	for i := 0; i < 10; i++ {
		w.add(-6 * time.Minute)
	}
	good := 50 * time.Microsecond
	avg := w.add(good)
	now_in_sync := good > -clockDriftThreshold && good < clockDriftThreshold
	if !now_in_sync || timeinsync {
		t.Fatal("precondition")
	}
	if now_in_sync && !timeinsync {
		w.flush()
		avg = w.add(good)
	}
	if avg != good {
		t.Fatalf("after recover flush, avg should equal live sample %s, got %s", good, avg)
	}
}

func TestOffsetWindow_WrapAround(t *testing.T) {
	var w offsetWindow
	for i := 0; i < offsetWindowSize; i++ {
		if got := w.add(100 * time.Millisecond); got != 100*time.Millisecond {
			t.Fatalf("fill[%d]: want 100ms got %s", i, got)
		}
	}
	// Overwrite the oldest slot: 127×100ms + 228ms = 12928ms / 128 = 101ms.
	got := w.add(228 * time.Millisecond)
	want := 101 * time.Millisecond
	if got != want {
		t.Fatalf("after wrap: want %s got %s", want, got)
	}
}
