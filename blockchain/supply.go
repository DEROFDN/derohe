package blockchain

import (
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/forensicsupply"
)

func CalcSupply(height uint64) uint64 {
	supply := config.PREMINE
	// all registered accounts < block 144000 got an initial balance of 0.002 Dero to claim previous chain balance
	// there were 1358698 such accounts, so total of 271739600 was added to the supply
	supply += 271739600
	remainingBlocks := height
	epochStartHeight := uint64(0)

	for remainingBlocks > 0 {
		blocksInEpoch := RewardReductionInterval
		if remainingBlocks < blocksInEpoch {
			blocksInEpoch = remainingBlocks
		}

		supply += CalcBlockReward(epochStartHeight) * blocksInEpoch

		remainingBlocks -= blocksInEpoch
		epochStartHeight += RewardReductionInterval
	}

	return supply
}

// SpendableSupplyForNetwork reports the height-based supply estimate. On
// mainnet it adds the pinned net-created floor only at or after HF3. This is
// reporting logic only; CalcSupply and consensus issuance remain unchanged.
func SpendableSupplyForNetwork(height uint64, network string, simulator bool, hf3Height int64) uint64 {
	supply := CalcSupply(height)
	if !forensicsupply.IsActive(network, simulator, height, hf3Height) {
		return supply
	}
	return supply + forensicsupply.NetCreatedFloorAtomicUnits
}

// SpendableSupply retains the legacy mainnet-oriented helper for callers that
// lack network context. It reports the supplied height, not the next block.
func SpendableSupply(height uint64) uint64 {
	return SpendableSupplyForNetwork(height, forensicsupply.MainnetNetworkName, false, config.Mainnet.MAJOR_HF3_HEIGHT)
}
