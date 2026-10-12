// Activity-matched decoy sampler (spec decoy-activity-distribution.md D5).
//
// Replaces uniform-over-batch decoy selection with sampling that matches
// the REAL participant activity distribution, so an observer cannot
// distinguish real sender/receiver from decoys by on-chain activity alone
// (the OSPEAD analog for DERO's account model).
//
// Model: a compact table of weights over "blocks since last appearance"
// bins, published from the D2 direct estimator (which recovers the
// participant density p(x) from ringsize-2 members — the only rings where
// BOTH members are real participants, so no deconvolution noise).
//
// The sampler consumes the batch RPC candidates (which carry the
// NonceBalance: uvarint NonceHeight + ElGamal). "Blocks since last
// appearance" = current topoheight - NonceHeight, binned, weighted.
//
// The posterior over ring members is uniform iff decoys are drawn from
// the same distribution as real participants (spec §3.1); this module
// implements that match. Pure client logic — no consensus impact.
package walletapi

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

// DecoyModel is the published activity model: weight per "blocks since
// last appearance" bin. Published per epoch from the D2 estimator; the
// weights are the participant density p(x) in each bin (normalized).
type DecoyModel struct {
	// Bins is ordered: {MinBlocks, MaxBlocks, Weight}. The last bin's
	// MaxBlocks may be 0 meaning "no upper bound".
	Bins []DecoyBin
}

type DecoyBin struct {
	MinBlocks uint64
	MaxBlocks uint64 // 0 = unbounded
	Weight    float64
}

// Normalize makes the weights sum to 1.
func (m *DecoyModel) Normalize() {
	total := 0.0
	for _, b := range m.Bins {
		total += b.Weight
	}
	if total == 0 {
		return
	}
	for i := range m.Bins {
		m.Bins[i].Weight /= total
	}
}

// binIndex returns the bin containing blocksSinceLast (or -1).
func (m *DecoyModel) binIndex(blocksSinceLast uint64) int {
	for i, b := range m.Bins {
		if blocksSinceLast >= b.MinBlocks && (b.MaxBlocks == 0 || blocksSinceLast < b.MaxBlocks) {
			return i
		}
	}
	return -1
}

// candidateRecency extracts "blocks since last appearance" from the
// candidate's embedded NonceBalance. Returns 0 on malformed data.
func candidateRecency(c rpc.GetRandomAddressBatch_Candidate, currentTopoheight uint64) (rec uint64) {
	defer func() {
		if r := recover(); r != nil {
			rec = 0 // NonceBalance.Unmarshal panics on malformed input
		}
	}()
	b, err := hex.DecodeString(c.EncryptedBalance)
	if err != nil || len(b) < 67 {
		return 0
	}
	var nb crypto.NonceBalance
	nb.Unmarshal(b)
	if currentTopoheight <= nb.NonceHeight {
		return 0
	}
	return currentTopoheight - nb.NonceHeight
}

// SelectDecoys samples up to n decoys from candidates, weighted by the
// activity model (Fisher-Yates style draws without replacement; each draw
// is weighted by the candidate's bin weight). Returns selected candidates.
// If fewer than n qualify, returns what it got.
func SelectDecoys(candidates []rpc.GetRandomAddressBatch_Candidate, model *DecoyModel, n int, currentTopoheight uint64) []rpc.GetRandomAddressBatch_Candidate {
	if model == nil || len(model.Bins) == 0 || n <= 0 || len(candidates) == 0 {
		return nil
	}
	model.Normalize()

	// precompute each candidate's bin weight
	weights := make([]float64, len(candidates))
	total := 0.0
	for i, c := range candidates {
		rec := candidateRecency(c, currentTopoheight)
		bi := model.binIndex(rec)
		if bi < 0 {
			weights[i] = 0
			continue
		}
		weights[i] = model.Bins[bi].Weight
		total += weights[i]
	}
	if total == 0 {
		return nil
	}

	// weighted draw without replacement
	idx := make([]int, len(candidates))
	for i := range idx {
		idx[i] = i
	}
	selected := make([]rpc.GetRandomAddressBatch_Candidate, 0, n)
	for len(selected) < n && len(idx) > 0 {
		// pick a candidate with probability proportional to weight
		r, err := rand.Int(rand.Reader, big.NewInt(1<<53))
		if err != nil {
			break
		}
		target := float64(r.Int64()) / float64(1<<53) * total
		acc := 0.0
		pos := -1
		for k, i := range idx {
			acc += weights[i]
			if acc >= target {
				pos = k
				break
			}
		}
		if pos < 0 {
			pos = len(idx) - 1 // rounding tail
		}
		drawn := idx[pos]
		selected = append(selected, candidates[drawn])
		// remove the drawn candidate (swap-pop) and drop its weight
		idx[pos] = idx[len(idx)-1]
		idx = idx[:len(idx)-1]
		total -= weights[drawn]
	}
	return selected
}
