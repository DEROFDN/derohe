package blockchain

import (
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/transaction"
)

func hf3ActiveAtHeight(height uint64) bool {
	activationHeight := globals.Config.MAJOR_HF3_HEIGHT
	return activationHeight >= 0 && height >= uint64(activationHeight)
}

func nextCandidateHeight(chain *Blockchain) uint64 {
	height := chain.Get_Height()
	if height < 0 {
		return 0
	}
	return uint64(height) + 1
}

func transactionValidationCacheKey(tx *transaction.Transaction, validationHeight uint64) crypto.Hash {
	if tx == nil {
		return crypto.Hash{}
	}
	txHash := tx.GetHash()
	if !hf3ActiveAtHeight(validationHeight) {
		return txHash
	}
	return transactionValidationCacheKeyFromSerialized(txHash, tx.Serialize(), validationHeight)
}

func transactionValidationCacheKeyFromSerialized(txHash crypto.Hash, serialized []byte, validationHeight uint64) crypto.Hash {
	if hf3ActiveAtHeight(validationHeight) {
		return crypto.Keccak256(serialized)
	}
	return txHash
}

func hf3AffectedParity(txHash crypto.Hash, blockHeight uint64) (bool, bool) {
	if hf3ActiveAtHeight(blockHeight) {
		return false, false
	}
	data, ok := HF3_Affected_Txs[txHash.String()]
	if !ok || data == nil {
		return false, false
	}
	return (blockHeight > data.Height) == data.Tx_Parity, true
}
