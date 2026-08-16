package transaction

import (
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
)

func TestRegistrationHashPoWSolved(t *testing.T) {
	hash := func(b0, b1, b2, b3 byte) crypto.Hash {
		var h crypto.Hash
		h[0] = b0
		h[1] = b1
		h[2] = b2
		h[3] = b3
		return h
	}

	tests := []struct {
		name string
		hash crypto.Hash
		bits int
		want bool
	}{
		{name: "24-bit target, 24-bit winner", hash: hash(0, 0, 0, 0x10), bits: 24, want: true},
		{name: "24-bit target, no leading zeros", hash: hash(1, 0, 0, 0), bits: 24, want: false},
		{name: "24-bit target, second byte set", hash: hash(0, 1, 0, 0), bits: 24, want: false},
		{name: "28-bit target, high nibble set fails", hash: hash(0, 0, 0, 0x10), bits: 28, want: false},
		{name: "28-bit target, low nibble set passes", hash: hash(0, 0, 0, 0x0F), bits: 28, want: true},
		{name: "28-bit target, all zero passes", hash: hash(0, 0, 0, 0), bits: 28, want: true},
		{name: "28-bit target, full fourth byte set fails", hash: hash(0, 0, 0, 0xFF), bits: 28, want: false},
		{name: "28-bit winner also satisfies 24 bits", hash: hash(0, 0, 0, 0x0F), bits: 24, want: true},
		{name: "out of range bits rejected", hash: hash(0, 0, 0, 0), bits: 300, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := registrationHashPoWSolved(tt.hash, tt.bits); got != tt.want {
				t.Fatalf("registrationHashPoWSolved(%x, %d) = %v, want %v", tt.hash, tt.bits, got, tt.want)
			}
		})
	}
}

func TestRegistrationPoWSolvedTypeCheck(t *testing.T) {
	tx := &Transaction{Transaction_Prefix: Transaction_Prefix{Version: 1, TransactionType: NORMAL}}
	if tx.RegistrationPoWSolved(RegistrationPoWLeadingZeroBits) {
		t.Fatal("non-registration tx must never solve registration PoW")
	}
	reg := &Transaction{Transaction_Prefix: Transaction_Prefix{Version: 1, TransactionType: REGISTRATION}}
	if !reg.RegistrationPoWSolved(0) {
		t.Fatal("registration tx must solve a zero-bit target")
	}
}
