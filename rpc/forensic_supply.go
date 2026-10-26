// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

import (
	"fmt"

	"github.com/deroproject/derohe/forensicsupply"
)

const (
	forensicSupplyRecordVersion = "mainnet-hf3-floor-v1"
	forensicSupplyMetric        = "created_supply_floor_net_of_verified_burns"
	forensicSupplyScope         = "Forensic floor; excludes undecoded affected transactions; not a balance census, an estimate of outstanding exploit coins, or a circulating-supply estimate; burn attribution to exploit wallets is unproven."
)

// ForensicSupplyRecord is a read-only, evidence-backed report. It does not
// change the emission schedule, balances, or consensus state. Any update must
// include the supporting forensic material and a new record version.
type ForensicSupplyRecord struct {
	RecordVersion                string   `json:"record_version"`
	Metric                       string   `json:"metric"`
	AtomicUnitsPerDERO           uint64   `json:"atomic_units_per_dero"`
	GrossCreatedFloorAtomicUnits uint64   `json:"gross_created_floor_atomic_units"`
	VerifiedBurnAtomicUnits      uint64   `json:"verified_burn_atomic_units"`
	NetCreatedFloorAtomicUnits   uint64   `json:"net_created_floor_atomic_units"`
	BurnAttributionProven        bool     `json:"burn_attribution_proven"`
	Scope                        string   `json:"scope"`
	EvidenceReferences           []string `json:"evidence_references"`
}

// Validate prevents a malformed or internally inconsistent record from being
// advertised by DERO.GetInfo.
func (r ForensicSupplyRecord) Validate() error {
	if r.RecordVersion != forensicSupplyRecordVersion || r.Metric != forensicSupplyMetric {
		return fmt.Errorf("invalid forensic supply record identity")
	}
	if r.AtomicUnitsPerDERO != forensicsupply.AtomicUnitsPerDERO {
		return fmt.Errorf("invalid forensic supply unit scale")
	}
	if r.GrossCreatedFloorAtomicUnits != forensicsupply.GrossCreatedFloorAtomicUnits ||
		r.VerifiedBurnAtomicUnits != forensicsupply.VerifiedBurnAtomicUnits ||
		r.NetCreatedFloorAtomicUnits != forensicsupply.NetCreatedFloorAtomicUnits {
		return fmt.Errorf("forensic supply values do not match the pinned record")
	}
	if r.GrossCreatedFloorAtomicUnits < r.VerifiedBurnAtomicUnits {
		return fmt.Errorf("verified burns exceed the gross created-supply floor")
	}
	if r.NetCreatedFloorAtomicUnits != r.GrossCreatedFloorAtomicUnits-r.VerifiedBurnAtomicUnits {
		return fmt.Errorf("forensic net floor does not reconcile to gross less verified burns")
	}
	if r.BurnAttributionProven {
		return fmt.Errorf("burn attribution is not established")
	}
	if r.Scope != forensicSupplyScope {
		return fmt.Errorf("forensic supply record is missing scope")
	}
	expectedReferences := [...]string{
		"docs/forensics/DERO-STATEMENT_2608.md",
		"docs/forensics/TRACKED-FLOW.html",
		"docs/forensics/PUBLIC-EXPLAINER.html",
	}
	if len(r.EvidenceReferences) != len(expectedReferences) {
		return fmt.Errorf("forensic supply record has an unexpected evidence-reference count")
	}
	for i, expected := range expectedReferences {
		if r.EvidenceReferences[i] != expected {
			return fmt.Errorf("forensic supply record has an unexpected evidence reference")
		}
	}
	return nil
}

// CurrentForensicSupplyRecord returns the evidence-bounded mainnet record.
// The constants are atomic DERO units (100,000 per DERO); 14 undecoded
// affected transactions are intentionally excluded from this floor.
func CurrentForensicSupplyRecord() (ForensicSupplyRecord, error) {
	if forensicsupply.GrossCreatedFloorAtomicUnits < forensicsupply.VerifiedBurnAtomicUnits {
		return ForensicSupplyRecord{}, fmt.Errorf("forensic supply inputs underflow")
	}

	record := ForensicSupplyRecord{
		RecordVersion:                forensicSupplyRecordVersion,
		Metric:                       forensicSupplyMetric,
		AtomicUnitsPerDERO:           forensicsupply.AtomicUnitsPerDERO,
		GrossCreatedFloorAtomicUnits: forensicsupply.GrossCreatedFloorAtomicUnits,
		VerifiedBurnAtomicUnits:      forensicsupply.VerifiedBurnAtomicUnits,
		NetCreatedFloorAtomicUnits:   forensicsupply.NetCreatedFloorAtomicUnits,
		BurnAttributionProven:        false,
		Scope:                        forensicSupplyScope,
		EvidenceReferences: []string{
			"docs/forensics/DERO-STATEMENT_2608.md",
			"docs/forensics/TRACKED-FLOW.html",
			"docs/forensics/PUBLIC-EXPLAINER.html",
		},
	}
	if err := record.Validate(); err != nil {
		return ForensicSupplyRecord{}, err
	}
	return record, nil
}

// ForensicSupplyForNetwork exposes the record only for mainnet after the HF3
// activation height. Testnet and simulator GetInfo responses omit it.
func ForensicSupplyForNetwork(network string, simulator bool, height, hf3Height int64) (*ForensicSupplyRecord, error) {
	if !forensicsupply.IsMainnet(network, simulator) {
		return nil, nil
	}
	if hf3Height <= 0 {
		return nil, fmt.Errorf("invalid mainnet HF3 activation height")
	}
	if height < hf3Height || !forensicsupply.IsActive(network, simulator, uint64(height), hf3Height) {
		return nil, nil
	}

	record, err := CurrentForensicSupplyRecord()
	if err != nil {
		return nil, err
	}
	return &record, nil
}
