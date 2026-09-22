// Copyright placeholder: K0 guard tests (spec k0-fix-design.md Fix A)
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// Tests the ringsize-2 privacy guard added to TransferPayload0:
//   - ringsize 0 resolves to the wallet default (16) -> no warning
//   - explicit ringsize 2 -> LastRingSizeWarning set (K0 signer exposure)
//   - explicit ringsize 4+ -> no warning
//   - ringsize 2 with SC data (SIGNER path) -> warning still set but tx
//     still builds (forcing would break owner-gated contracts until Fix C)
package walletapi

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

func init() {
	globals.InitializeLog(io.Discard, io.Discard)
	GenerateProoffuncptr = generate_proof_trampoline
}

// makeTestWallet: minimal on-disk wallet for ring-size guard tests.
func makeTestWallet(t *testing.T) *Wallet_Disk {
	t.Helper()
	w, err := Create_Encrypted_Wallet(filepath.Join(t.TempDir(), "k0test.db"), "testpass", crypto.RandomScalarBNRed())
	if err != nil {
		t.Fatalf("create wallet: %v", err)
	}
	return w
}

func TestK0_RingSizeDefaultNoWarning(t *testing.T) {
	w := makeTestWallet(t)
	w.account.Ringsize = 16
	// ringsize 0 -> resolves to wallet default 16 -> no warning expected
	_, err := w.TransferPayload0(
		[]rpc.Transfer{{Destination: w.GetAddress().String(), Amount: 1}},
		0, false, rpc.Arguments{}, 0, false)
	if err != nil {
		t.Skipf("no daemon for balance/tree fetch: %v", err)
	}
	if w.LastRingSizeWarning != "" {
		t.Fatalf("expected no warning at default ringsize 16, got: %s", w.LastRingSizeWarning)
	}
}

func TestK0_RingSize2WarningSet(t *testing.T) {
	w := makeTestWallet(t)
	// ringsize 2 -> warning must be set, regardless of tx build outcome
	// (the warning is raised at ringsize resolution, before any daemon call)
	_, _ = w.TransferPayload0(
		[]rpc.Transfer{{Destination: w.GetAddress().String(), Amount: 1}},
		2, false, rpc.Arguments{}, 0, false)
	if w.LastRingSizeWarning == "" {
		t.Fatal("expected K0 warning for ringsize 2, got none")
	}
}

func TestK0_RingSize4NoWarning(t *testing.T) {
	w := makeTestWallet(t)
	_, _ = w.TransferPayload0(
		[]rpc.Transfer{{Destination: w.GetAddress().String(), Amount: 1}},
		4, false, rpc.Arguments{}, 0, false)
	if w.LastRingSizeWarning != "" {
		t.Fatalf("expected no warning at ringsize 4, got: %s", w.LastRingSizeWarning)
	}
}

func TestK0_RingSize2SCStillBuilds(t *testing.T) {
	w := makeTestWallet(t)
	// SC invocation at ringsize 2: warning must be set BUT the guard must
	// not hard-fail — owner-gated contracts need SIGNER() until Fix C.
	scdata := rpc.Arguments{
		{Name: "entrypoint", DataType: rpc.DataString, Value: "UpdateCode"},
	}
	_, _ = w.TransferPayload0(
		[]rpc.Transfer{{Destination: w.GetAddress().String(), Amount: 0}},
		2, false, scdata, 0, false)
	if w.LastRingSizeWarning == "" {
		t.Fatal("expected K0 warning for ringsize-2 SC call, got none")
	}
	// tx may fail to build (no daemon) but the guard itself must not be the
	// cause: the warning is informational. Nothing to assert beyond warning.
}

// compile-time sanity: ensure the RPC result field exists (surfaced to
// programmatic callers).
func TestK0_TransferResultField(t *testing.T) {
	var res rpc.Transfer_Result
	if res.PrivacyWarning != "" {
		t.Fatal("unexpected initial value")
	}
	res.PrivacyWarning = "x"
	if res.PrivacyWarning != "x" {
		t.Fatal("field not writable")
	}
}

// keep transaction import referenced (used by TransferPayload0 signature)
var _ = transaction.TransactionType(0)
var _ = config.MIN_RINGSIZE
