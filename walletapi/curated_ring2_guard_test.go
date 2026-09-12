// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

import (
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

// Test_CuratedRing2Guard_FailsClosed locks the fail-closed guard for Strict decoy
// curation at ring 2 (PR #22 review finding #2).
//
// At ring 2 the ring-assembly loop (`for ringsize != 2`) never runs, so
// curatedRingCandidates — the only decoy validator — is never invoked: without an
// explicit guard, RingPreference{PreferredDecoys: [garbage], Strict: true} builds and
// can broadcast with no error, while the identical input at ring 4 is a hard error.
// The guard rejects Strict curation before the ringsize branch. Non-Strict curation at
// ring 2 stays permitted (documented lenient contract; decoys are unplaceable and the
// build proceeds without them).
//
// Like the anonymous-attribution ring-2 guard, this is pure parameter validation that
// fires BEFORE any daemon/network call — offline in-memory wallet, no chain.
func Test_CuratedRing2Guard_FailsClosed(t *testing.T) {
	w, err := Create_Encrypted_Wallet_From_Recovery_Words_Memory("", "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly")
	if err != nil {
		t.Fatalf("cannot create in-memory wallet: %s", err)
	}
	defer w.Close_Encrypted_Wallet()

	dest := w.GetAddress().String() // any valid address; the guard fires before it is used

	strictGarbage := TransferOptions{Ring: &RingPreference{
		PreferredDecoys: []string{"not_an_address"},
		Strict:          true,
	}}

	// Strict curation at ring 2 MUST hard-error before building, naming the ring-size cause.
	tx, err := w.TransferPayload0WithOptions(
		[]rpc.Transfer{{Destination: dest, Amount: 1}}, 2, false, rpc.Arguments{}, 0, false, strictGarbage)
	if err == nil || tx != nil {
		t.Fatalf("strict curation at ring 2 MUST fail closed before building, got err=%v tx=%v", err, tx != nil)
	}
	if !strings.Contains(err.Error(), "strict decoy curation requires ring size") {
		t.Fatalf("ring-2 strict-curation rejection should explain the ring-size cause, got: %v", err)
	}

	// non-Strict decoys at ring 2 must NOT trip the guard (lenient contract: decoys are
	// unplaceable and dropped; the build errors later on the offline network call).
	lenient := TransferOptions{Ring: &RingPreference{PreferredDecoys: []string{"not_an_address"}}}
	if _, lerr := w.TransferPayload0WithOptions(
		[]rpc.Transfer{{Destination: dest, Amount: 1}}, 2, false, rpc.Arguments{}, 0, false, lenient); lerr != nil &&
		strings.Contains(lerr.Error(), "strict decoy curation requires ring size") {
		t.Fatalf("non-Strict curation at ring 2 wrongly tripped the strict-curation guard: %v", lerr)
	}

	// Strict at ring 4 must NOT trip the ring-2 guard (it proceeds past the guard and fails
	// later — offline network gate or decoy validation — never with the guard message).
	if _, serr := w.TransferPayload0WithOptions(
		[]rpc.Transfer{{Destination: dest, Amount: 1}}, 4, false, rpc.Arguments{}, 0, false, strictGarbage); serr != nil &&
		strings.Contains(serr.Error(), "strict decoy curation requires ring size") {
		t.Fatalf("strict curation at ring 4 wrongly tripped the ring-2 guard: %v", serr)
	}

	// A nil Ring and an empty PreferredDecoys slice curate nothing — the guard must not fire.
	for _, opts := range []TransferOptions{{}, {Ring: &RingPreference{Strict: true}}} {
		if _, nerr := w.TransferPayload0WithOptions(
			[]rpc.Transfer{{Destination: dest, Amount: 1}}, 2, false, rpc.Arguments{}, 0, false, opts); nerr != nil &&
			strings.Contains(nerr.Error(), "strict decoy curation requires ring size") {
			t.Fatalf("empty curation at ring 2 wrongly tripped the strict-curation guard: %v", nerr)
		}
	}

	// Validation parity when curatedRingCandidates IS invoked (ring-agnostic, no daemon):
	// parse and self checks fire before any RPC, so they are directly testable offline.
	var zeroscid crypto.Hash
	if _, _, cerr := w.curatedRingCandidates(zeroscid, "", &RingPreference{
		PreferredDecoys: []string{"not_an_address"}, Strict: true}, 126, nil, nil); cerr == nil ||
		!strings.Contains(cerr.Error(), "not a valid address") {
		t.Fatalf("strict garbage decoy must fail parse validation, got: %v", cerr)
	}
	if _, _, cerr := w.curatedRingCandidates(zeroscid, "", &RingPreference{
		PreferredDecoys: []string{w.GetAddress().String()}, Strict: true}, 126, nil, nil); cerr == nil ||
		!strings.Contains(cerr.Error(), "your own address") {
		t.Fatalf("strict self decoy must fail validation, got: %v", cerr)
	}
}
