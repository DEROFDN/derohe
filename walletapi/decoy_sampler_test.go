// Activity-matched decoy sampler tests (spec D5).
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// Verifies that SelectDecoys samples proportionally to the model weights:
// with a synthetic model where bin A has 10x the weight of bin B, the
// sampled decoys must skew ~10:1 toward bin A candidates (the posterior
// match that makes the anonymity set effective).
package walletapi

import (
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

// buildCandidate makes a batch candidate with a synthetic NonceBalance
// (uvarint NonceHeight + a REAL serialized ElGamal — zero bytes are not a
// valid ciphertext, identity is not representable in DERO's codec).
func buildCandidate(addr string, nonceHeight uint64) rpc.GetRandomAddressBatch_Candidate {
	var buf []byte
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], nonceHeight)
	buf = append(buf, tmp[:n]...)
	// real ElGamal: commit value 12345 under generator G
	eg := crypto.CommitElGamal(crypto.G, new(big.Int).SetUint64(12345))
	buf = append(buf, eg.Serialize()...)
	return rpc.GetRandomAddressBatch_Candidate{
		Address:          addr,
		Registered:       true,
		EncryptedBalance: hex.EncodeToString(buf),
	}
}

func TestCandidateRecency(t *testing.T) {
	c := buildCandidate("deto1qyyawp87a3ckr9f2j5hnqmxevq3czrr83prc58ylc5889qdt0zf6cqg26e27g", 1000)
	if got := candidateRecency(c, 1500); got != 500 {
		t.Fatalf("recency: got %d want 500", got)
	}
	// malformed -> 0
	bad := rpc.GetRandomAddressBatch_Candidate{Address: "x", Registered: true, EncryptedBalance: "zz"}
	if got := candidateRecency(bad, 1500); got != 0 {
		t.Fatalf("malformed recency: got %d want 0", got)
	}
	t.Log("candidateRecency OK")
}

func TestSelectDecoysMatchesModel(t *testing.T) {
	// model: bin A (recent, 0-10 blocks) weight 10, bin B (dormant,
	// 10+) weight 1. Participants are 10x more likely to be recent.
	model := &DecoyModel{
		Bins: []DecoyBin{
			{MinBlocks: 0, MaxBlocks: 10, Weight: 10},
			{MinBlocks: 10, MaxBlocks: 0, Weight: 1},
		},
	}

	// 100 candidates: 20 recent (nonce = current-5), 80 dormant (nonce = current-5000)
	const current = 100000
	candidates := make([]rpc.GetRandomAddressBatch_Candidate, 0, 100)
	for i := 0; i < 20; i++ {
		candidates = append(candidates, buildCandidate("deto1qyyawp87a3ckr9f2j5hnqmxevq3czrr83prc58ylc5889qdt0zf6cqg26e27g", current-5))
	}
	for i := 0; i < 80; i++ {
		candidates = append(candidates, buildCandidate("deto1qyvhk5gkrm9m7x4p2w8j3n6q1z0y5a8b7c6d4e2f1g3h5j7k9l2m4n6p8q0r2s4t6v8w0y2z", current-5000))
	}

	// draw a SUBSET (10 decoys) per trial from the 100 candidates — drawing
	// all 100 would select everything once regardless of weights
	recentDraws := 0
	totalDraws := 0
	for trial := 0; trial < 500; trial++ {
		sel := SelectDecoys(candidates, model, 10, current)
		for _, c := range sel {
			totalDraws++
			if candidateRecency(c, current) < 10 {
				recentDraws++
			}
		}
	}
	share := float64(recentDraws) / float64(totalDraws)
	// expected share: 20*10 / (20*10 + 80*1) = 200/280 = 0.714
	t.Logf("recent share over 200 trials: %.3f (expect ~0.714)", share)
	if share < 0.55 || share > 0.85 {
		t.Fatalf("sampled distribution diverges from model: recent share %.3f, want ~0.714", share)
	}

	// zero-weight bin: candidates with recency outside all bins are never drawn
	model2 := &DecoyModel{Bins: []DecoyBin{{MinBlocks: 0, MaxBlocks: 10, Weight: 1}}}
	allOld := make([]rpc.GetRandomAddressBatch_Candidate, 0, 10)
	for i := 0; i < 10; i++ {
		allOld = append(allOld, buildCandidate("deto1qyyawp87a3ckr9f2j5hnqmxevq3czrr83prc58ylc5889qdt0zf6cqg26e27g", current-5000))
	}
	if sel := SelectDecoys(allOld, model2, 5, current); len(sel) != 0 {
		t.Fatalf("expected no draws from zero-weight candidates, got %d", len(sel))
	}
	t.Log(strings.TrimSpace("SelectDecoys OK: distribution matches model, zero-weight excluded"))
}
