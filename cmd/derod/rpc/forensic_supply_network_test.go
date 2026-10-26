package rpc

import (
	"testing"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/forensicsupply"
)

func TestGetInfoSupplyFieldsAtReferenceHeight(t *testing.T) {
	const referenceHeight int64 = 7_545_119
	total, spendable, record, err := getInfoSupplyFields("mainnet", false, referenceHeight, 7_504_640)
	if err != nil {
		t.Fatalf("getInfoSupplyFields() error = %v", err)
	}
	if total != 16_756_595 {
		t.Fatalf("total_supply = %d DERO, want 16756595", total)
	}
	if spendable != 35_643_112 {
		t.Fatalf("spendable_supply = %d DERO, want 35643112", spendable)
	}
	if record == nil || record.NetCreatedFloorAtomicUnits != forensicsupply.NetCreatedFloorAtomicUnits {
		t.Fatalf("forensic record = %+v, want net floor %d", record, forensicsupply.NetCreatedFloorAtomicUnits)
	}
}

func TestGetInfoSupplyFieldsGatesFloorByNetworkAndHF3(t *testing.T) {
	const hf3Height int64 = 7_504_640
	tests := []struct {
		name      string
		network   string
		simulator bool
		height    int64
		hf3Height int64
		wantFloor bool
		wantError bool
	}{
		{name: "mainnet before HF3", network: "mainnet", height: hf3Height - 1, hf3Height: hf3Height},
		{name: "mainnet at HF3", network: "mainnet", height: hf3Height, hf3Height: hf3Height, wantFloor: true},
		{name: "testnet at HF3", network: "testnet", height: hf3Height, hf3Height: hf3Height},
		{name: "simulator retaining mainnet config", network: "mainnet", simulator: true, height: hf3Height, hf3Height: hf3Height},
		{name: "mainnet with invalid HF3 height", network: "mainnet", height: hf3Height, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			total, spendable, record, err := getInfoSupplyFields(test.network, test.simulator, test.height, test.hf3Height)
			if test.wantError {
				if err == nil || total != 0 || spendable != 0 || record != nil {
					t.Fatalf("invalid HF3 config returned total=%d spendable=%d record=%v err=%v", total, spendable, record, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("getInfoSupplyFields() error = %v", err)
			}

			scheduled := blockchain.CalcSupply(uint64(test.height)) / forensicsupply.AtomicUnitsPerDERO
			if total != scheduled {
				t.Fatalf("total_supply = %d, want scheduled supply %d", total, scheduled)
			}
			wantSpendable := scheduled
			if test.wantFloor {
				wantSpendable = (blockchain.CalcSupply(uint64(test.height)) + forensicsupply.NetCreatedFloorAtomicUnits) / forensicsupply.AtomicUnitsPerDERO
			}
			if spendable != wantSpendable {
				t.Fatalf("spendable_supply = %d, want %d", spendable, wantSpendable)
			}
			if (record != nil) != test.wantFloor {
				t.Fatalf("forensic record present = %t, want %t", record != nil, test.wantFloor)
			}
		})
	}
}

func TestGetInfoSupplyFieldsRejectsNegativeHeight(t *testing.T) {
	if total, spendable, record, err := getInfoSupplyFields("mainnet", false, -1, 7_504_640); err == nil || total != 0 || spendable != 0 || record != nil {
		t.Fatalf("negative height returned total=%d spendable=%d record=%v err=%v", total, spendable, record, err)
	}
}

func TestGetInfoForensicSupplyAppliesHF3GateAndSimulatorIdentity(t *testing.T) {
	const hf3Height int64 = 7_504_640
	tests := []struct {
		name      string
		config    string
		simulator bool
		height    int64
		wantEntry bool
	}{
		{name: "mainnet at HF3", config: "mainnet", height: hf3Height, wantEntry: true},
		{name: "mainnet before HF3", config: "mainnet", height: hf3Height - 1},
		{name: "mainnet simulator at HF3", config: "mainnet", simulator: true, height: hf3Height},
		{name: "testnet at HF3", config: "testnet", height: hf3Height},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record, err := getInfoForensicSupply(tt.config, tt.simulator, tt.height, hf3Height)
			if err != nil {
				t.Fatalf("getInfoForensicSupply(): %v", err)
			}
			if (record != nil) != tt.wantEntry {
				t.Fatalf("record presence = %t, want %t", record != nil, tt.wantEntry)
			}
		})
	}
}
