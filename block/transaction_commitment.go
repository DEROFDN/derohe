package block

import (
	"crypto/sha256"
	"encoding/binary"
)

const transactionBodiesCommitmentDomain = "DERO/HF4/TX-BODIES\x00"

// SerializedTransactionsCommitment binds the exact ordered transaction bodies,
// including proofs, into the v4 block header's existing Proof field.
func SerializedTransactionsCommitment(serializedTransactions [][]byte) (root [32]byte) {
	h := sha256.New()
	_, _ = h.Write([]byte(transactionBodiesCommitmentDomain))

	var size [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(size[:], uint64(len(serializedTransactions)))
	_, _ = h.Write(size[:n])

	for _, tx := range serializedTransactions {
		n = binary.PutUvarint(size[:], uint64(len(tx)))
		_, _ = h.Write(size[:n])
		_, _ = h.Write(tx)
	}

	copy(root[:], h.Sum(nil))
	return root
}
