package walletapi

// PublishedMainnetDecoyModel is the D6 public artifact: the D2 direct-
// estimator participant-density bins (blocks since last appearance).
//
// Source: ringsize-2 members are BOTH real participants (zero decoys),
// so p(x) is read from their recency histogram. Naive mixture
// deconvolution is rejected (numerically unstable).
//
// First-run measured skew: participants 13.6% in 0–5 blocks, 24.7% in
// 5–10; the old daemon pool was guaranteed-dormant (d(0–5)=0) → p/d = ∞
// in the recent bins. These weights close that gap. Treat as the
// published starting table, not a live feed.
//
// Weights are un-normalized; SelectDecoys / Normalize() divide by sum.
var PublishedMainnetDecoyModel = DecoyModel{
	Bins: []DecoyBin{
		{MinBlocks: 0, MaxBlocks: 5, Weight: 0.136},
		{MinBlocks: 5, MaxBlocks: 10, Weight: 0.247},
		{MinBlocks: 10, MaxBlocks: 50, Weight: 0.217},
		{MinBlocks: 50, MaxBlocks: 200, Weight: 0.180},
		{MinBlocks: 200, MaxBlocks: 1000, Weight: 0.120},
		{MinBlocks: 1000, MaxBlocks: 0, Weight: 0.100},
	},
}

// DefaultDecoyModel returns a copy of the published table so callers
// can Normalize() without mutating the package-level artifact.
func DefaultDecoyModel() DecoyModel {
	out := DecoyModel{Bins: make([]DecoyBin, len(PublishedMainnetDecoyModel.Bins))}
	copy(out.Bins, PublishedMainnetDecoyModel.Bins)
	return out
}
