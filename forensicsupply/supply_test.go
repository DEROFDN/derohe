package forensicsupply

import (
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestPinnedNetCreatedFloor(t *testing.T) {
	if NetCreatedFloorAtomicUnits != 1_888_651_730_000 {
		t.Fatalf("net created floor = %d, want 1888651730000", NetCreatedFloorAtomicUnits)
	}
	if GrossCreatedFloorAtomicUnits-VerifiedBurnAtomicUnits != NetCreatedFloorAtomicUnits {
		t.Fatal("net created floor does not equal gross floor less verified burn")
	}
}

func TestIsActiveMainnetHF3Gate(t *testing.T) {
	const hf3Height int64 = 7_504_640
	tests := []struct {
		name      string
		network   string
		simulator bool
		height    uint64
		hf3Height int64
		want      bool
	}{
		{name: "mainnet before activation", network: "mainnet", height: uint64(hf3Height - 1), hf3Height: hf3Height},
		{name: "mainnet at activation", network: "mainnet", height: uint64(hf3Height), hf3Height: hf3Height, want: true},
		{name: "mainnet after activation", network: "mainnet", height: uint64(hf3Height + 1), hf3Height: hf3Height, want: true},
		{name: "testnet never inherits mainnet record", network: "testnet", height: uint64(hf3Height + 1), hf3Height: hf3Height},
		{name: "simulator retaining mainnet config", network: "mainnet", simulator: true, height: uint64(hf3Height + 1), hf3Height: hf3Height},
		{name: "missing activation height fails closed", network: "mainnet", height: uint64(hf3Height + 1)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := IsActive(test.network, test.simulator, test.height, test.hf3Height)
			if got != test.want {
				t.Fatalf("IsActive() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestPinnedSupplyMatchesTrackedFlowEvidence(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "docs", "forensics", "TRACKED-FLOW.html"))
	if err != nil {
		t.Fatalf("read tracked-flow evidence: %v", err)
	}

	rungPattern := regexp.MustCompile(`<tr data-lad="[1-4]" data-amt="([0-9]+(?:\.[0-9]+)?)">`)
	rungs := rungPattern.FindAllSubmatch(contents, -1)
	if len(rungs) != 46 {
		t.Fatalf("tracked-flow rung rows = %d, want 46", len(rungs))
	}

	scale := new(big.Rat).SetInt(new(big.Int).SetUint64(AtomicUnitsPerDERO))
	grossAtomic := new(big.Int)
	for _, rung := range rungs {
		amount, ok := new(big.Rat).SetString(string(rung[1]))
		if !ok {
			t.Fatalf("invalid tracked-flow rung amount %q", rung[1])
		}
		amount.Mul(amount, scale)
		if !amount.IsInt() {
			t.Fatalf("rung amount %q is not an integer number of atomic units", rung[1])
		}
		grossAtomic.Add(grossAtomic, amount.Num())
	}
	if !grossAtomic.IsUint64() || grossAtomic.Uint64() != GrossCreatedFloorAtomicUnits {
		t.Fatalf("tracked-flow gross amount = %s atomic units, want %d", grossAtomic, GrossCreatedFloorAtomicUnits)
	}

	burnPattern := regexp.MustCompile(`<span><b>Burned</b>\s*([0-9,]+)</span>`)
	burns := burnPattern.FindAllSubmatch(contents, -1)
	if len(burns) != 1 {
		t.Fatalf("tracked-flow verified burn entries = %d, want 1", len(burns))
	}
	burnDERO, err := strconv.ParseUint(strings.ReplaceAll(string(burns[0][1]), ",", ""), 10, 64)
	if err != nil {
		t.Fatalf("parse tracked-flow burn amount: %v", err)
	}
	if burnDERO > ^uint64(0)/AtomicUnitsPerDERO {
		t.Fatal("tracked-flow burn overflows atomic units")
	}
	if got := burnDERO * AtomicUnitsPerDERO; got != VerifiedBurnAtomicUnits {
		t.Fatalf("tracked-flow burn = %d atomic units, want %d", got, VerifiedBurnAtomicUnits)
	}
	if got := grossAtomic.Uint64() - VerifiedBurnAtomicUnits; got != NetCreatedFloorAtomicUnits {
		t.Fatalf("tracked-flow net floor = %d atomic units, want %d", got, NetCreatedFloorAtomicUnits)
	}
}
