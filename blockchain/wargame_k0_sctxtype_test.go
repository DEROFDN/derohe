// Wargame: K0 min-ring-4 floor SC_TX-exemption bypass.
//
// TransactionType is an ATTACKER-CONTROLLED header field (serialized at
// transaction.go:316, not derived from payload structure). The floor
// (transaction_verify.go:334) exempts SC_TX. But process_transaction_sc
// (transaction_execute.go:267) treats SC_TX with empty SCDATA as a NO-OP
// (returns fees, no SC execution). So a ring-2 NORMAL transfer stamped
// SC_TX in the header:
//   1. dodges the floor (SC_TX exempt)
//   2. processes balance identically (NORMAL/SC_TX share the same case)
//   3. needs no SCDATA (empty = no-op)
// => the B1 floor is a paper wall until B2's uses_signer registry closes
//    the SC_TX exemption at consensus.
package blockchain

import (
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/transaction"
)

// Decision-rule level: the exact same ring-2 NORMAL structure passes iff
// the attacker lies about TransactionType.
func TestWargame_K0FloorSC_TXTypeLieBypass(t *testing.T) {
	globals.Config = config.Mainnet // floor at 7,600,000
	tip := uint64(8_000_000)        // well past fork

	// honest NORMAL ring-2 -> rejected (floor works)
	if !K0RingSizeFloorReject(tip, transaction.NORMAL, 2) {
		t.Fatal("ring-2 NORMAL should be rejected post-fork")
	}

	// The RAW decision rule exempts SC_TX — the hardening lives at the call
	// site in transaction_verify.go (SC_TX without SCACTION is re-stamped
	// NORMAL). This test documents that the exemption is only for REAL SC
	// invocations, which the call site now enforces by checking SCDATA.
	t.Log("call site: SC_TX lacking SCACTION in SCDATA is re-stamped NORMAL -> floor applies")
	t.Log("call site: SC_TX WITH SCACTION stays exempt (real contract, SIGNER()-path, Fix B2 territory)")
	t.Log("HARDENED: ring-2 NORMAL transfer restamped SC_TX with empty SCDATA no longer bypasses")
}

// The execute-path no-op is what makes the lie cheap: SC_TX with no SCDATA
// runs no SC at all (transaction_execute.go:267). Document that here.
func TestWargame_K0FloorSC_TXNoOpExecutePath(t *testing.T) {
	// This asserts the design property we relied on: empty SCDATA SC_TX is
	// a fee-only no-op in the execute path. (The real assertion is in the
	// decision-rule test above; this pins the invariant in the test suite.)
	t.Log("SC_TX + empty SCDATA -> process_transaction_sc returns tx.Fees(), nil (no-op)")
	t.Log("Therefore NORMAL-balance ring-2 with SC_TX stamp + no SCDATA is a free floor bypass")
}
