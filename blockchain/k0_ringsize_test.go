// K0 Fix B1 decision-rule tests (spec §9 K0, k0-fix-design.md)
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
package blockchain

import (
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/transaction"
)

func TestK0_RingSizeFloorReject(t *testing.T) {
	// testnet gate is active at genesis (K0_MIN_RING4_HEIGHT=0 -> floor)
	globals.Config = config.Testnet

	cases := []struct {
		name     string
		height   uint64
		txtype   transaction.TransactionType
		ringsize uint64
		want     bool
	}{
		{"ring2 normal post-fork", 100, transaction.NORMAL, 2, true},
		{"ring2 burn post-fork", 100, transaction.BURN_TX, 2, true},
		{"ring4 normal post-fork", 100, transaction.NORMAL, 4, false},
		{"ring16 normal post-fork", 100, transaction.NORMAL, 16, false},
		{"ring2 SC post-fork (exempt)", 100, transaction.SC_TX, 2, false},
		{"ring2 coinbase post-fork (exempt)", 100, transaction.COINBASE, 2, false},
		{"ring2 registration post-fork (exempt)", 100, transaction.REGISTRATION, 2, false},
	}
	for _, c := range cases {
		got := K0RingSizeFloorReject(c.height, c.txtype, c.ringsize)
		if got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestK0_RingSizeFloorNotActive(t *testing.T) {
	// a network with the floor set to MaxInt64 is effectively disabled
	cfg := config.Testnet
	cfg.K0_MIN_RING4_HEIGHT = 1<<62 + 1<<62 - 1 // ~MaxInt64
	globals.Config = cfg
	if K0RingSizeFloorReject(100, transaction.NORMAL, 2) {
		t.Fatal("floor disabled but reject fired")
	}
}

func TestK0_RingSizeFloorPreFork(t *testing.T) {
	// mainnet floor is 7,600,000; txs before it are unaffected
	globals.Config = config.Mainnet
	if K0RingSizeFloorReject(7_000_000, transaction.NORMAL, 2) {
		t.Fatal("pre-fork ringsize-2 NORMAL rejected (should be unaffected)")
	}
	if !K0RingSizeFloorReject(8_000_000, transaction.NORMAL, 2) {
		t.Fatal("post-fork ringsize-2 NORMAL accepted (should reject)")
	}
}
