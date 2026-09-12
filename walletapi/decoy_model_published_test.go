package walletapi

import "testing"

func TestPublishedMainnetDecoyModel(t *testing.T) {
	m := DefaultDecoyModel()
	if len(m.Bins) != 6 {
		t.Fatalf("bins=%d want 6", len(m.Bins))
	}
	if i := m.binIndex(0); i != 0 {
		t.Fatalf("recency 0 bin=%d want 0", i)
	}
	if i := m.binIndex(7); i != 1 {
		t.Fatalf("recency 7 bin=%d want 1", i)
	}
	if i := m.binIndex(1_000_000); i != 5 {
		t.Fatalf("recency 1e6 bin=%d want last", i)
	}
	sum := 0.0
	for _, b := range m.Bins {
		if b.Weight <= 0 {
			t.Fatalf("non-positive weight %+v", b)
		}
		sum += b.Weight
	}
	if sum < 0.99 || sum > 1.01 {
		t.Fatalf("weights sum %f want ~1", sum)
	}
	m.Normalize()
	sum = 0
	for _, b := range m.Bins {
		sum += b.Weight
	}
	if sum < 0.999 || sum > 1.001 {
		t.Fatalf("normalized sum %f", sum)
	}
	if PublishedMainnetDecoyModel.Bins[0].Weight != 0.136 {
		t.Fatal("DefaultDecoyModel mutated the published table")
	}
}
