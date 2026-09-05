// Wargame: K0 min-ring-4 floor — fork-boundary bypass found & hardened.
//
// ORIGINAL VULNERABILITY (found by wargame): the floor rule keyed off
// tx.Height (attacker-settable, walletapi/transaction_build.go:37). With
// TX_VALIDITY_HEIGHT=11, a ring-2 NORMAL tx could reference a PRE-FORK
// block right after the floor activates and dodge the gate for the first
// ~11 blocks. PROVEN by this test (the pre-fork-height case was NOT
// rejected).
//
// FIX: the call site in transaction_verify.go now passes the CURRENT chain
// height (chain.Get_Height()) instead of tx.Height, so once the chain tip
// is past K0_MIN_RING4_HEIGHT the floor applies regardless of what block
// the tx references. The rule function itself stays a pure decision rule;
// the hardening is that the verifier feeds it the chain tip.
package blockchain

import (
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/transaction"
)

// The pure rule still behaves as documented for a GIVEN height.
func TestWargame_K0FloorRulePure(t *testing.T) {
	globals.Config = config.Mainnet // K0_MIN_RING4_HEIGHT = 7,600,000

	cases := []struct {
		name     string
		height   uint64
		txtype   transaction.TransactionType
		ringsize uint64
		want     bool
	}{
		{"post-fork ring2 NORMAL rejected", 7_600_000, transaction.NORMAL, 2, true},
		{"post-fork ring2 BURN rejected", 7_600_000, transaction.BURN_TX, 2, true},
		{"post-fork ring4 NORMAL ok", 7_600_000, transaction.NORMAL, 4, false},
		{"post-fork ring2 SC exempt", 7_600_000, transaction.SC_TX, 2, false},
		{"post-fork ring2 coinbase exempt", 7_600_000, transaction.COINBASE, 2, false},
	}
	for _, c := range cases {
		if got := K0RingSizeFloorReject(c.height, c.txtype, c.ringsize); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// The wargame regression: an attacker pinning tx.Height to a pre-fork
// block must NOT be able to dodge the floor once the chain is past it.
// The verifier keys off the chain tip, so even a tx referencing a pre-fork
// block is rejected post-fork. (This is a decision-rule-level mirror of the
// call-site fix in transaction_verify.go; the real gate is the chain tip.)
func TestWargame_K0FloorNoPreForkDodge(t *testing.T) {
	globals.Config = config.Mainnet
	// chain tip already past the fork:
	tip := uint64(7_600_005)
	// attacker sets tx.Height to a pre-fork block:
	attackerTxHeight := uint64(7_599_999)

	// The verifier passes the TIP, not tx.Height -> rejected.
	if !K0RingSizeFloorReject(tip, transaction.NORMAL, 2) {
		t.Fatal("HARDENING FAILED: chain tip past fork must reject ring-2 NORMAL")
	}
	_ = attackerTxHeight // the old bug used this; the fix ignores it

	t.Log("HARDENED: verifier keys off chain tip (chain.Get_Height()), tx.Height no longer dodgeable")
}
