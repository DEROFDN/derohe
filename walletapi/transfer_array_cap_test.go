// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

import (
	"strings"
	"testing"

	"github.com/deroproject/derohe/rpc"
)

// Test_TransferArrayCap_FailsClosed locks the wallet-side cap on the transfer array
// (PR #22 re-review O13).
//
// Assembly cost — and the transfer_mutex hold — scales linearly in len(transfers):
// each transfer owns a full stall budget plus its pass-capped RPCs. The consensus
// 300KB tx-size limit fires only at verification/broadcast, AFTER the whole assembly
// loop has run, so without a wallet-side gate an oversized array would pay the entire
// N × per-transfer worst case under the mutex and only then be rejected. The cap is
// request validation: it must fire BEFORE any daemon RPC or sleep — offline in-memory
// wallet, no chain (same pattern as the other pre-build guards).
func Test_TransferArrayCap_FailsClosed(t *testing.T) {
	w, err := Create_Encrypted_Wallet_From_Recovery_Words_Memory("", "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly")
	if err != nil {
		t.Fatalf("cannot create in-memory wallet: %s", err)
	}
	defer w.Close_Encrypted_Wallet()

	dest := w.GetAddress().String() // any valid address; the guard fires before it is used

	transfers := make([]rpc.Transfer, MaxTransfersPerBuild+1)
	for i := range transfers {
		transfers[i] = rpc.Transfer{Destination: dest, Amount: 0}
	}

	// one past the cap MUST fail closed before any network activity, naming the cap.
	tx, err := w.TransferPayload0WithOptions(transfers, 2, false, rpc.Arguments{}, 0, false, TransferOptions{})
	if err == nil || tx != nil {
		t.Fatalf("array of %d transfers must fail the build cap, got err=%v tx=%v", len(transfers), err, tx != nil)
	}
	if !strings.Contains(err.Error(), "too many transfers") {
		t.Fatalf("over-cap rejection should name the transfer cap, got: %v", err)
	}

	// exactly at the cap must NOT trip the guard: the build proceeds and fails later,
	// differently, on the offline network call — the cap rejects only what could never
	// broadcast (necessary condition of the consensus size limit; the per-payload size
	// floor behind that arithmetic is pinned on a real built transaction by
	// Test_Ring2PayloadFloor_JustifiesTransferCap in cmd/simulator).
	if _, aerr := w.TransferPayload0WithOptions(transfers[:MaxTransfersPerBuild], 2, false, rpc.Arguments{}, 0, false, TransferOptions{}); aerr != nil &&
		strings.Contains(aerr.Error(), "too many transfers") {
		t.Fatalf("array exactly at the cap wrongly tripped the transfer cap: %v", aerr)
	}
}
