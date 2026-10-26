// Copyright 2017-2026 DERO Project. All rights reserved.
// Use of this source code in any form is governed by the RESEARCH license.
// The license can be found in the LICENSE file.

// Package forensicsupply holds the pinned, evidence-bounded supply figures
// reported by the mainnet daemon. It does not affect consensus accounting.
package forensicsupply

const (
	// MainnetNetworkName is the network for which this forensic record applies.
	MainnetNetworkName = "mainnet"

	// AtomicUnitsPerDERO is the daemon's base-unit scale.
	AtomicUnitsPerDERO uint64 = 100_000

	// GrossCreatedFloorAtomicUnits is the recovered created-coin floor.
	// It excludes affected transactions that could not be decoded.
	GrossCreatedFloorAtomicUnits uint64 = 2_388_651_730_000

	// VerifiedBurnAtomicUnits is the chain-verified burn from the same era.
	// Attribution to exploit wallets is not established.
	VerifiedBurnAtomicUnits uint64 = 500_000_000_000

	// NetCreatedFloorAtomicUnits is gross created floor less the verified burn.
	NetCreatedFloorAtomicUnits uint64 = GrossCreatedFloorAtomicUnits - VerifiedBurnAtomicUnits
)

// IsMainnet reports whether the configured chain is the real mainnet, not a
// simulator that happens to retain mainnet configuration values.
func IsMainnet(network string, simulator bool) bool {
	return network == MainnetNetworkName && !simulator
}

// IsActive reports whether mainnet's post-HF3 forensic supply figures apply.
// Invalid or absent activation heights fail closed.
func IsActive(network string, simulator bool, height uint64, hf3Height int64) bool {
	if !IsMainnet(network, simulator) || hf3Height <= 0 {
		return false
	}
	return height >= uint64(hf3Height)
}
