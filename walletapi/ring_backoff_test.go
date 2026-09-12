// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

// Pins the barren-backoff schedule against the daemon's recent-activity filter
// (PR #22 review finding #1 / re-review O1).
//
// GetRandomAddress (cmd/derod/rpc/rpc_dero_getrandomaddress.go) filters out any account
// whose balance changed within the last 5 blocks, so a burst of activity can transiently
// thin the candidate pool for up to 5 × config.BLOCK_TIME seconds. The exhaustion error
// must not be reachable INSIDE that window on an otherwise healthy pool: the cumulative
// consecutive-barren wait must exceed it, or a transiently filtered pool reads as
// permanently exhausted and the bound converts a recoverable send into a false error.
// The window cannot be exercised end-to-end in the simulator (the filter is disabled
// below topoheight 100 and mainnet block time makes it a 90s test), so the schedule sum
// is pinned arithmetically here against the same constants the daemon uses.

import (
	"testing"
	"time"

	"github.com/deroproject/derohe/config"
)

func Test_BarrenBackoff_Spans_Filter(t *testing.T) {
	// Sum exactly the sleeps that can occur: the exhaustion cap fires at
	// barren_passes == maxBarrenRingPasses BEFORE that pass's sleep, so the
	// realizable consecutive-barren window is sleep(1..maxBarrenRingPasses-1).
	var total time.Duration
	for i := 1; i <= maxBarrenRingPasses-1; i++ {
		d := barrenRingSleep(i)
		if d <= 0 {
			t.Fatalf("barrenRingSleep(%d) = %v, must be positive", i, d)
		}
		if d > 4*time.Second {
			t.Fatalf("barrenRingSleep(%d) = %v exceeds the 4s cap", i, d)
		}
		if prev := barrenRingSleep(i - 1); i > 1 && d < prev {
			t.Fatalf("backoff must be non-decreasing: sleep(%d)=%v < sleep(%d)=%v", i, d, i-1, prev)
		}
		total += d
	}

	filterWindow := time.Duration(5*config.BLOCK_TIME) * time.Second // daemon: old_topoheight -= 5
	if total <= filterWindow {
		t.Fatalf("consecutive-barren window %v does not span the daemon's 5-block recent-activity filter %v: a transiently filtered pool would be declared exhausted", total, filterWindow)
	}

	// first pass must stay snappy: genuine exhaustion (degraded daemon) should not pay
	// the full window before the caps can fire on the fast total-passes bound.
	if barrenRingSleep(1) != 250*time.Millisecond {
		t.Fatalf("first barren backoff = %v, want 250ms", barrenRingSleep(1))
	}

	// The per-transfer stall budget must admit one full honest consecutive-barren window
	// (or the filter-recovery path is cut short and the budget reintroduces the false
	// exhaustion error), while still hard-capping cumulative mutex-held sleep so an
	// adversarial trickle cannot multiply windows (re-review O5). The budget is scoped
	// per transfer (re-review O8), so this single-window pin is exactly the invariant
	// EVERY transfer in a multi-transfer array gets — not just the first to go barren.
	if maxRingBuildStallBudget <= total {
		t.Fatalf("stall budget %v does not admit one full consecutive-barren window %v", maxRingBuildStallBudget, total)
	}
	if maxRingBuildStallBudget > 2*total {
		t.Fatalf("stall budget %v exceeds 2x the barren window %v: documented mutex-hold cap drifted", maxRingBuildStallBudget, total)
	}
}
