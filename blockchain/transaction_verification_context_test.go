package blockchain

import (
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
)

func TestTransactionValidationCacheKeyUsesBlockHeight(t *testing.T) {
	oldActivation := globals.Config.MAJOR_HF3_HEIGHT
	globals.Config.MAJOR_HF3_HEIGHT = 100
	defer func() { globals.Config.MAJOR_HF3_HEIGHT = oldActivation }()

	var txHash crypto.Hash
	txHash[0] = 1
	proofA := []byte("same-prefix|proof-a")
	proofB := []byte("same-prefix|proof-b")

	legacyA := transactionValidationCacheKeyFromSerialized(txHash, proofA, 99)
	legacyB := transactionValidationCacheKeyFromSerialized(txHash, proofB, 99)
	if legacyA != txHash || legacyB != txHash || legacyA != legacyB {
		t.Fatal("pre-HF3 cache key must retain historical transaction-ID behavior")
	}

	postA := transactionValidationCacheKeyFromSerialized(txHash, proofA, 100)
	postB := transactionValidationCacheKeyFromSerialized(txHash, proofB, 100)
	if postA == postB {
		t.Fatal("post-HF3 cache key must distinguish serialized proof variants")
	}
	if postA != crypto.Keccak256(proofA) {
		t.Fatal("post-HF3 cache key is not the hash of the serialized transaction")
	}
}

func TestHF3AffectedParityIsScopedToHistoricalBlockHeight(t *testing.T) {
	oldActivation := globals.Config.MAJOR_HF3_HEIGHT
	globals.Config.MAJOR_HF3_HEIGHT = 100
	defer func() { globals.Config.MAJOR_HF3_HEIGHT = oldActivation }()

	var txHash crypto.Hash
	txHash[0] = 0x42
	key := txHash.String()
	oldData, hadOldData := HF3_Affected_Txs[key]
	HF3_Affected_Txs[key] = &HF3_Tx_Data{Height: 50, Tx_Parity: true}
	defer func() {
		if hadOldData {
			HF3_Affected_Txs[key] = oldData
		} else {
			delete(HF3_Affected_Txs, key)
		}
	}()

	parity, ok := hf3AffectedParity(txHash, 51)
	if !ok || !parity {
		t.Fatal("expected the historical parity override at block height 51")
	}
	parity, ok = hf3AffectedParity(txHash, 100)
	if ok || parity {
		t.Fatal("HF3 parity override must not apply at or after activation")
	}
}
