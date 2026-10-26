package block

import "testing"

func TestSerializedTransactionsCommitmentBindsBodiesAndOrder(t *testing.T) {
	first := SerializedTransactionsCommitment([][]byte{[]byte("core|proof-a"), []byte("other|proof")})
	changedProof := SerializedTransactionsCommitment([][]byte{[]byte("core|proof-b"), []byte("other|proof")})
	reordered := SerializedTransactionsCommitment([][]byte{[]byte("other|proof"), []byte("core|proof-a")})

	if first == changedProof {
		t.Fatal("commitment did not bind transaction proof bytes")
	}
	if first == reordered {
		t.Fatal("commitment did not bind transaction order")
	}

	bl := Block{Major_Version: 4, Proof: first}
	originalID := bl.GetHash()
	bl.Proof = changedProof
	if bl.GetHash() == originalID {
		t.Fatal("v4 block ID did not change with the transaction-body commitment")
	}
}

func TestSerializedTransactionsCommitmentSHA256Vector(t *testing.T) {
	got := SerializedTransactionsCommitment([][]byte{{0x01, 0x02}, {0x03}})
	want := [32]byte{
		0x1f, 0x89, 0x2f, 0xcf, 0x24, 0xb3, 0x6f, 0x7d,
		0x2e, 0x76, 0xef, 0xc3, 0x37, 0xb6, 0x7d, 0x3a,
		0xdc, 0xfd, 0x31, 0xa9, 0xbb, 0x64, 0x6d, 0xa0,
		0x68, 0x50, 0x9a, 0x72, 0x2c, 0x44, 0x69, 0xe3,
	}
	if got != want {
		t.Fatalf("commitment vector mismatch: got %x, want %x", got, want)
	}
}
