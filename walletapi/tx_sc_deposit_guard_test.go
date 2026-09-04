package walletapi

import "os"
import "path/filepath"
import "strings"
import "testing"

import "github.com/deroproject/derohe/globals"
import "github.com/deroproject/derohe/rpc"
import "github.com/go-logr/logr/funcr"

// Test_SCDeposit_Guard_Refuses_Defaulted_Ringsize is the PORTABLE tripwire for the
// SC-deposit build-time refusal in TransferPayload0.
//
// It lives in package walletapi on purpose: the behavioural proof in
// cmd/simulator/blackhole_test.go does not travel with this file into a fork that
// vendors only walletapi, and downstream forks have already restructured
// TransferPayload0's body (DHEBP/derohe splits it into a delegator plus
// TransferPayload0WithOptions), so a mid-function guard can be lost in a merge with
// nothing going red.
//
// RUN IT TARGETED, and put THIS command in CI, not `go test ./walletapi/`:
//
//	go test ./walletapi/ -run Test_SCDeposit_Guard -count=1
//
// package walletapi has no green state to regress from: at the f7a56db baseline,
// with none of this patch applied, `go test ./walletapi/` already fails
// Test_Payload_TX and Test_Creation_TX_morecheck on receiver-balance expectations
// (verified in a detached baseline worktree, not assumed). A package-level exit
// code is therefore pinned at 1 and cannot gate anything; the -run form above is
// the gate.
//
// This test needs no chain and no balance: the guard returns
// before any ring/proof work, so if the guard is dropped or bypassed the call
// proceeds and fails with some OTHER error, which this test rejects by message.
func Test_SCDeposit_Guard_Refuses_Defaulted_Ringsize(t *testing.T) {
	db := filepath.Join(os.TempDir(), "dero_scdeposit_guard_test.db")
	os.Remove(db)
	defer os.Remove(db)

	w, err := Create_Encrypted_Wallet_Random(db, "QWER")
	if err != nil {
		t.Fatalf("cannot create wallet: %s", err)
	}
	defer w.Close_Encrypted_Wallet()

	if w.account.Ringsize == 2 {
		w.SetRingSize(16)
	}

	scdata := rpc.Arguments{
		{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
		{Name: "entrypoint", DataType: rpc.DataString, Value: "Deposit"},
	}
	// destination is irrelevant: the guard fires before the address is ever parsed.
	dest := w.GetAddress().String()
	burning := []rpc.Transfer{{Destination: dest, Amount: 0, Burn: 1000}}

	_, err = w.TransferPayload0(burning, 0, false, scdata, 0, false)
	if err == nil {
		t.Fatalf("a defaulted-ringsize SC deposit was BUILT; the unrefundable shape must be refused at build time")
	}
	if !strings.Contains(err.Error(), "cannot be refunded if the call fails") {
		t.Fatalf("SC-deposit guard is gone or was bypassed: got %q, expected the deposit refusal", err)
	}
}

// Test_SCDeposit_Guard_Warns_On_Explicit_Ringsize pins the OTHER half of the guard:
// an explicitly requested ring >2 deposit is honoured, but it must SAY SO through a
// logger that actually emits. The warning originally used package walletapi's own
// `logger`, which wallet.go declares as logr.Discard() and which nothing in the tree
// ever assigns -- so it was discarded in every binary at every verbosity, and this
// test would have been red. It asserts against globals.Logger, the sink every derohe
// binary wires up in globals.InitializeLog.
func Test_SCDeposit_Guard_Warns_On_Explicit_Ringsize(t *testing.T) {
	db := filepath.Join(os.TempDir(), "dero_scdeposit_warn_test.db")
	os.Remove(db)
	defer os.Remove(db)

	w, err := Create_Encrypted_Wallet_Random(db, "QWER")
	if err != nil {
		t.Fatalf("cannot create wallet: %s", err)
	}
	defer w.Close_Encrypted_Wallet()

	var captured []string
	saved := globals.Logger
	globals.Logger = funcr.New(func(prefix, args string) { captured = append(captured, args) }, funcr.Options{})
	defer func() { globals.Logger = saved }()

	scdata := rpc.Arguments{
		{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
		{Name: "entrypoint", DataType: rpc.DataString, Value: "Deposit"},
	}
	burning := []rpc.Transfer{{Destination: w.GetAddress().String(), Amount: 0, Burn: 1000}}

	// ring 8 passed by name: NOT refused, but it must not be silent either. the call
	// itself is expected to fail later (offline wallet, no balance); irrelevant here.
	_, _ = w.TransferPayload0(burning, 8, false, scdata, 0, false)

	found := false
	for _, line := range captured {
		if strings.Contains(line, "UNREFUNDABLE") {
			found = true
		}
	}
	if !found {
		t.Fatalf("explicit ring >2 SC deposit was accepted SILENTLY; captured=%v", captured)
	}

	// ...and it must not pay for the warning with a privacy leak. globals.Logger is
	// tee'd into a PLAINTEXT json logfile beside the (encrypted) wallet db, at a level
	// no flag can suppress, so the burn amount and the target scid must never appear.
	for _, line := range captured {
		if strings.Contains(line, "1000") || strings.Contains(line, "scid") {
			t.Fatalf("SC-deposit warning leaked the deposit amount or the target scid into the plaintext logfile: %q", line)
		}
	}
}
