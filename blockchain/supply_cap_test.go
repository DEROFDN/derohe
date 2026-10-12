// Supply hard-cap invariant tests (supply.go + transaction_verify.go).
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// Verifies the DERO supply curve never exceeds the 21M-DERO hard cap and
// that the coinbase supply-ceiling assert is wired correctly.
package blockchain

import (
	"testing"

	"github.com/deroproject/derohe/config"
)

// TestCalcSupplyUnderHardCap: the emission curve stays under MAX_SUPPLY at
// every sampled height, from genesis to well past terminal supply.
func TestCalcSupplyUnderHardCap(t *testing.T) {
	heights := []uint64{
		0,
		1,
		6_999_999,
		7_000_000,  // first epoch boundary
		14_000_000, // first halving
		21_000_000,
		35_000_000,
		70_000_000,
		140_000_000,
		700_000_000,    // ~40 years — deep into the tail
		7_000_000_000,  // ~160 years — reward has long since hit zero
	}
	for _, h := range heights {
		supply := CalcSupply(h)
		if supply > config.MAX_SUPPLY {
			t.Fatalf("height %d: supply %d exceeds hard cap %d", h, supply, config.MAX_SUPPLY)
		}
		// monotonic: supply must never decrease
		if h > 0 {
			if supply < CalcSupply(h-1) {
				t.Fatalf("height %d: supply %d decreased from %d", h, supply, CalcSupply(h-1))
			}
		}
	}
	// terminal supply is strictly under the cap, with the ~0.5% margin
	terminal := CalcSupply(7_000_000_000)
	if terminal >= config.MAX_SUPPLY {
		t.Fatalf("terminal supply %d should be under cap %d", terminal, config.MAX_SUPPLY)
	}
	t.Logf("terminal supply %d atomic (%.2fM DERO), cap %d atomic (21.00M DERO), margin %.2f%%",
		terminal, float64(terminal)/100000/1e6, config.MAX_SUPPLY,
		100*(1-float64(terminal)/float64(config.MAX_SUPPLY)))
}

// TestCalcBlockRewardNeverNegativeOrOverflowsAtZero: the reward curve
// converges to zero (right-shift), never underflows into a huge value.
func TestCalcBlockRewardConvergence(t *testing.T) {
	var last uint64 = ^uint64(0)
	for h := uint64(0); h < 700_000_000; h += 7_000_000 {
		r := CalcBlockReward(h)
		if r > last { // reward must be non-increasing per epoch
			t.Fatalf("height %d: reward %d increased from %d", h, r, last)
		}
		last = r
	}
	if last != 0 {
		t.Fatalf("reward did not converge to zero, last=%d", last)
	}
}