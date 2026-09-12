// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

import (
	"strings"
	"testing"

	"github.com/deroproject/derohe/rpc"
)

// Test_AttributionAnonymous_Ring2_FailsClosed locks the fail-closed guard for anonymous
// attribution at ring 2 (PR #22 review finding #8).
//
// At ring 2 there are no decoy slots (witness_index[2:] is empty), so the build branch
// `opts.Attribution == AttributionAnonymous && len(witness_index) > 2` is never taken and
// attribution silently falls through to honest (witness_index[1]). Without an explicit
// guard, a caller that asked for anonymity would broadcast a verifiably-attributed transfer
// while believing it was anonymized. The guard rejects the combination before building.
//
// This is a pure parameter-validation guard that fires BEFORE any daemon/network call
// (wallet_transfer.go, right after ring-size validation), so it runs on an OFFLINE in-memory
// wallet with no chain — fast and deterministic.
func Test_AttributionAnonymous_Ring2_FailsClosed(t *testing.T) {
	w, err := Create_Encrypted_Wallet_From_Recovery_Words_Memory("", "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly")
	if err != nil {
		t.Fatalf("cannot create in-memory wallet: %s", err)
	}
	defer w.Close_Encrypted_Wallet()

	dest := w.GetAddress().String() // any valid address; the guard fires before it is used

	anon := TransferOptions{Attribution: AttributionAnonymous}

	// ring 2 explicit → MUST hard-error before building, naming the ring-size cause.
	tx, err := w.TransferPayload0WithOptions(
		[]rpc.Transfer{{Destination: dest, Amount: 1}}, 2, false, rpc.Arguments{}, 0, false, anon)
	if err == nil || tx != nil {
		t.Fatalf("anonymous attribution at ring 2 MUST fail closed before building, got err=%v tx=%v", err, tx != nil)
	}
	if !strings.Contains(err.Error(), "anonymous attribution requires ring size") {
		t.Fatalf("ring-2 anon rejection should explain the ring-size cause, got: %v", err)
	}

	// honest mode at ring 2 must be UNAFFECTED by the guard (it errors later, on the offline
	// network call, NOT with the anonymous-attribution message).
	if _, herr := w.TransferPayload0WithOptions(
		[]rpc.Transfer{{Destination: dest, Amount: 1}}, 2, false, rpc.Arguments{}, 0, false, TransferOptions{}); herr != nil &&
		strings.Contains(herr.Error(), "anonymous attribution requires ring size") {
		t.Fatalf("honest mode at ring 2 wrongly tripped the anonymous-attribution guard: %v", herr)
	}

	// anonymous at ring 4 must NOT trip the guard (it proceeds past validation and fails later
	// on the offline network call, never with the anonymous-attribution message).
	if _, aerr := w.TransferPayload0WithOptions(
		[]rpc.Transfer{{Destination: dest, Amount: 1}}, 4, false, rpc.Arguments{}, 0, false, anon); aerr != nil &&
		strings.Contains(aerr.Error(), "anonymous attribution requires ring size") {
		t.Fatalf("anonymous mode at ring 4 wrongly tripped the ring-2 guard: %v", aerr)
	}
}
