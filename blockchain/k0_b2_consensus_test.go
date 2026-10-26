// K0 Fix B2 consensus-rule tests (spec k0-fix-design.md):
// SC_INSTALL at ringsize 2 rejected when the contract never calls SIGNER().
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
package blockchain

import (
	"strings"
	"testing"

	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

// makeTestSCArguments builds the SCDATA argument set for an SC_INSTALL tx.
func makeTestSCArguments(code string) rpc.Arguments {
	return rpc.Arguments{
		rpc.Argument{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_INSTALL)},
		rpc.Argument{Name: rpc.SCCODE, DataType: rpc.DataString, Value: code},
	}
}

func TestK0SCInstallRing2Reject_NoSignerRejected(t *testing.T) {
	// contract never calls SIGNER() -> ringsize-2 install rejected
	code := `
Function Initialize() Uint64
	10 STORE("owner", "alice")
	20 RETURN 0
End Function`
	tx := &transaction.Transaction{}
	tx.TransactionType = transaction.SC_TX
	tx.SCDATA = makeTestSCArguments(code)
	if err := k0SCInstallRing2Reject(tx); err == nil {
		t.Fatal("no-SIGNER contract install at ringsize 2 should be rejected")
	} else if !strings.Contains(err.Error(), "K0 B2") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestK0SCInstallRing2Reject_SignerAllowed(t *testing.T) {
	// contract calls SIGNER() -> ringsize-2 install allowed (owner-gated)
	code := `
Function Initialize() Uint64
	10 STORE("owner", SIGNER())
	20 RETURN 0
End Function`
	tx := &transaction.Transaction{}
	tx.TransactionType = transaction.SC_TX
	tx.SCDATA = makeTestSCArguments(code)
	if err := k0SCInstallRing2Reject(tx); err != nil {
		t.Fatalf("SIGNER contract install at ringsize 2 should be allowed: %v", err)
	}
}

func TestK0SCInstallRing2Reject_NoSCDATAAllowed(t *testing.T) {
	// SC_TX with no SCDATA isn't a real install; the no-op path handles it.
	tx := &transaction.Transaction{}
	tx.TransactionType = transaction.SC_TX
	tx.SCDATA = rpc.Arguments{}
	if err := k0SCInstallRing2Reject(tx); err != nil {
		t.Fatalf("no-SCDATA SC_TX should not be rejected by B2 install rule: %v", err)
	}
}

func TestK0SCInstallRing2Reject_CaseInsensitiveSigner(t *testing.T) {
	// lowercase signer() must be detected (dispatch is case-insensitive)
	code := `
Function Initialize() Uint64
	10 STORE("owner", signer())
	20 RETURN 0
End Function`
	tx := &transaction.Transaction{}
	tx.TransactionType = transaction.SC_TX
	tx.SCDATA = makeTestSCArguments(code)
	if err := k0SCInstallRing2Reject(tx); err != nil {
		t.Fatalf("lowercase signer() contract should be allowed: %v", err)
	}
}
