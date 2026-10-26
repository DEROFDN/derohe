package rpc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/deroproject/derohe/forensicsupply"
)

func TestCurrentForensicSupplyRecordReconcilesPinnedValues(t *testing.T) {
	record, err := CurrentForensicSupplyRecord()
	if err != nil {
		t.Fatalf("CurrentForensicSupplyRecord() error = %v", err)
	}

	if record.GrossCreatedFloorAtomicUnits != 2_388_651_730_000 {
		t.Fatalf("gross created floor = %d atomic units, want 2388651730000", record.GrossCreatedFloorAtomicUnits)
	}
	if record.VerifiedBurnAtomicUnits != 500_000_000_000 {
		t.Fatalf("verified burn = %d atomic units, want 500000000000", record.VerifiedBurnAtomicUnits)
	}
	if record.NetCreatedFloorAtomicUnits != 1_888_651_730_000 {
		t.Fatalf("net created floor = %d atomic units, want 1888651730000", record.NetCreatedFloorAtomicUnits)
	}
	if record.NetCreatedFloorAtomicUnits != forensicsupply.NetCreatedFloorAtomicUnits {
		t.Fatalf("record net floor = %d, shared supply floor = %d", record.NetCreatedFloorAtomicUnits, forensicsupply.NetCreatedFloorAtomicUnits)
	}
	if record.AtomicUnitsPerDERO != 100_000 {
		t.Fatalf("atomic units per DERO = %d, want 100000", record.AtomicUnitsPerDERO)
	}
	if record.RecordVersion != "mainnet-hf3-floor-v1" {
		t.Fatalf("record version = %q, want mainnet-hf3-floor-v1", record.RecordVersion)
	}
	if record.BurnAttributionProven {
		t.Fatal("record claims the verified burn is attributable to exploit wallets")
	}
	if !strings.Contains(record.Scope, "burn attribution to exploit wallets is unproven") {
		t.Fatalf("scope omits the attribution caveat: %q", record.Scope)
	}
	if len(record.EvidenceReferences) != 3 || record.EvidenceReferences[0] != "docs/forensics/DERO-STATEMENT_2608.md" {
		t.Fatalf("unexpected evidence references: %v", record.EvidenceReferences)
	}
	if err := record.Validate(); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
}

func TestForensicEvidenceReferencesExist(t *testing.T) {
	record, err := CurrentForensicSupplyRecord()
	if err != nil {
		t.Fatalf("CurrentForensicSupplyRecord() error = %v", err)
	}
	for _, reference := range record.EvidenceReferences {
		if !strings.HasPrefix(reference, "docs/forensics/") {
			t.Fatalf("evidence reference is outside docs/forensics: %q", reference)
		}
		if _, err := os.Stat(filepath.Join("..", reference)); err != nil {
			t.Fatalf("evidence reference %q is not present in the repository: %v", reference, err)
		}
	}
}

func TestForensicSupplyForNetworkGatesMainnetAfterHF3(t *testing.T) {
	const hf3Height int64 = 7_504_640
	tests := []struct {
		name       string
		network    string
		simulator  bool
		height     int64
		wantRecord bool
	}{
		{name: "testnet omitted", network: "testnet", height: hf3Height + 1},
		{name: "simulator with mainnet config omitted", network: "mainnet", simulator: true, height: hf3Height + 1},
		{name: "simulator label omitted", network: "Simulator", height: hf3Height + 1},
		{name: "mainnet before activation omitted", network: "mainnet", height: hf3Height - 1},
		{name: "mainnet at activation included", network: "mainnet", height: hf3Height, wantRecord: true},
		{name: "mainnet after activation included", network: "mainnet", height: hf3Height + 1, wantRecord: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record, err := ForensicSupplyForNetwork(test.network, test.simulator, test.height, hf3Height)
			if err != nil {
				t.Fatalf("ForensicSupplyForNetwork() error = %v", err)
			}
			if (record != nil) != test.wantRecord {
				t.Fatalf("record present = %t, want %t", record != nil, test.wantRecord)
			}
		})
	}
}

func TestForensicSupplyForNetworkFailsClosedOnInvalidMainnetForkHeight(t *testing.T) {
	if record, err := ForensicSupplyForNetwork("mainnet", false, 8_000_000, 0); err == nil || record != nil {
		t.Fatalf("invalid mainnet HF3 height returned record=%v, err=%v; want no record and error", record, err)
	}
}

func TestForensicSupplyRecordRejectsInconsistentNetFloor(t *testing.T) {
	record, err := CurrentForensicSupplyRecord()
	if err != nil {
		t.Fatalf("CurrentForensicSupplyRecord() error = %v", err)
	}
	record.NetCreatedFloorAtomicUnits++
	if err := record.Validate(); err == nil {
		t.Fatal("Validate() accepted a net floor that does not equal gross less verified burns")
	}
}

func TestForensicSupplyRecordRejectsClaimedBurnAttribution(t *testing.T) {
	record, err := CurrentForensicSupplyRecord()
	if err != nil {
		t.Fatalf("CurrentForensicSupplyRecord() error = %v", err)
	}
	record.BurnAttributionProven = true
	if err := record.Validate(); err == nil {
		t.Fatal("Validate() accepted an unproven burn attribution claim")
	}
}

func TestGetInfoForensicSupplyRecordJSONRoundTrip(t *testing.T) {
	record, err := ForensicSupplyForNetwork("mainnet", false, 7_504_640, 7_504_640)
	if err != nil || record == nil {
		t.Fatalf("mainnet gate returned record=%v, err=%v", record, err)
	}

	encoded, err := json.Marshal(GetInfo_Result{ForensicSupply: record})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if !strings.Contains(string(encoded), `"created_supply_floor"`) {
		t.Fatalf("JSON omitted created_supply_floor: %s", encoded)
	}
	if !strings.Contains(string(encoded), `"burn_attribution_proven":false`) {
		t.Fatalf("JSON omitted the unproven-attribution flag: %s", encoded)
	}

	var decoded GetInfo_Result
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if !reflect.DeepEqual(decoded.ForensicSupply, record) {
		t.Fatalf("JSON round trip changed forensic record: got %+v, want %+v", decoded.ForensicSupply, record)
	}
}

func TestGetInfoOmitsForensicSupplyRecordWhenGateIsClosed(t *testing.T) {
	encoded, err := json.Marshal(GetInfo_Result{})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(encoded), `"created_supply_floor"`) {
		t.Fatalf("JSON included inactive created_supply_floor: %s", encoded)
	}
}
