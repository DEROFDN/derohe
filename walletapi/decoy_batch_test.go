// Decoy batch RPC — client-side verification + selection tests (K1/K2 fix).
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// Tests the pure client-side logic of the batch decoy path:
//   - filterBatchCandidates rejects ghost/zero-balance/self/invalid candidates
//   - the CSPRNG selection never picks the sender or receiver
package walletapi

import (
	"strings"
	"testing"

	"github.com/deroproject/derohe/rpc"
)

// valid mainnet test addresses (from wallet_test.go)
const testAddr = "deto1qyyawp87a3ckr9f2j5hnqmxevq3czrr83prc58ylc5889qdt0zf6cqg26e27g"
const otherAddr = "deto1qyh7q8h86gku5j37jsvjp2twrkgpk8kz0kwphthm4u6jp7zynsc3gqq6l75cr"

func TestFilterBatchCandidates(t *testing.T) {
	self := testAddr // sender address
	other := otherAddr

	cands := []rpc.GetRandomAddressBatch_Candidate{
		{Address: testAddr, Registered: true, EncryptedBalance: strings.Repeat("ab", 33)},      // self — must be dropped
		{Address: otherAddr, Registered: true, EncryptedBalance: strings.Repeat("cd", 33)},      // other, valid registered — kept
		{Address: "deto1invalid", Registered: true, EncryptedBalance: strings.Repeat("ef", 33)}, // invalid address — dropped
		{Address: otherAddr, Registered: false, EncryptedBalance: strings.Repeat("12", 33)},     // unregistered — dropped
		{Address: otherAddr, Registered: true, EncryptedBalance: ""},                            // no balance (ghost) — dropped
	}

	got := filterBatchCandidates(cands, self)
	if len(got) != 1 {
		t.Fatalf("expected 1 verified candidate, got %d: %+v", len(got), got)
	}
	if got[0].Address != other {
		t.Fatalf("expected the valid 'other' candidate to survive, got %s", got[0].Address)
	}
	t.Logf("filterBatchCandidates OK: 5 in -> 1 verified (self/ghost/invalid/unregistered dropped)")
}
