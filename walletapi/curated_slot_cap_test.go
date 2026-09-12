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

// Test_CuratedDecoySlotCap pins the decoy slot-capacity contract (PR #22 re-review O9).
//
// A ring places at most ringsize-2 curated decoys (sender and recipient hold the other
// two positions). Before this fix, VALID decoys beyond that capacity were accepted by
// validation and then simply never read by the assembly loop (it stops the instant the
// ring fills) — a silent curation shortfall the drop funnel could not see, because the
// funnel only recorded REJECTED decoys. Post-fix contract:
//   - Strict over-supply is a hard error, both at the TransferPayload0WithOptions
//     pre-guard (supplied count vs slots) and inside curatedRingCandidates (defense in
//     depth for direct callers);
//   - lenient over-supply drops the surplus WITH a per-decoy record, feeding the
//     pre-signing "reduced curation" summary — never a silent truncation.
//
// Offline, no daemon: the registration probe is bypassed with a pre-seeded verdicts
// memo (the memo is keyed on the canonical base form, exactly as the validator writes
// it), so the slot logic is exercised in isolation.
func Test_CuratedDecoySlotCap(t *testing.T) {
	w, err := Create_Encrypted_Wallet_From_Recovery_Words_Memory("", "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly")
	if err != nil {
		t.Fatalf("cannot create in-memory wallet: %s", err)
	}
	defer w.Close_Encrypted_Wallet()

	mkdecoy := func() string {
		wd, err := Create_Encrypted_Wallet_Random_Memory("")
		if err != nil {
			t.Fatalf("cannot create decoy wallet: %s", err)
		}
		t.Cleanup(wd.Close_Encrypted_Wallet)
		return wd.GetAddress().String()
	}
	d1, d2 := mkdecoy(), mkdecoy()

	// canonical base form, exactly as curatedRingCandidates stores verdicts.
	canonOf := func(a string) string {
		addr, err := rpc.NewAddress(a)
		if err != nil {
			t.Fatalf("bad decoy fixture %q: %s", a, err)
		}
		canon := addr.BaseAddress()
		canon.Proof = false
		canon.Mainnet = w.GetNetwork()
		return canon.String()
	}
	verdicts := map[string]bool{canonOf(d1): true, canonOf(d2): true} // both "registered"

	var zeroscid crypto.Hash

	// ── lenient over-supply: surplus decoy is dropped WITH a record, curation = slots ──
	drops := map[string]string{}
	func() {
		defer func() { _ = recover() }() // nil rpc client: the post-validation random fetch
		alist, curated, cerr := w.curatedRingCandidates(zeroscid, "", &RingPreference{
			PreferredDecoys: []string{d1, d2}}, 1 /* slots */, verdicts, drops)
		if cerr != nil {
			t.Errorf("lenient over-supply must not error, got: %v", cerr)
		}
		if curated != 1 || len(alist) < 1 || alist[0] != canonOf(d1) {
			t.Errorf("want the first decoy placed and curated=1, got curated=%d alist=%v", curated, alist)
		}
	}()
	reason, recorded := drops[d2]
	if len(drops) != 1 || !recorded || !strings.Contains(reason, "no decoy slot") {
		t.Fatalf("surplus valid decoy must be recorded dropped with the slot reason, got: %v", drops)
	}

	// ── strict over-supply inside the validator: hard error, nothing placed ──
	if _, _, cerr := w.curatedRingCandidates(zeroscid, "", &RingPreference{
		PreferredDecoys: []string{d1, d2}, Strict: true}, 1 /* slots */, verdicts, nil); cerr == nil ||
		!strings.Contains(cerr.Error(), "too many preferred decoys") {
		t.Fatalf("strict over-supply must hard-error on the slot cap, got: %v", cerr)
	}

	// ── strict over-supply pre-guard: count-checked before any validation or RPC ──
	dest := w.GetAddress().String() // any parseable destination; the guard fires first
	if _, gerr := w.TransferPayload0WithOptions(
		[]rpc.Transfer{{Destination: dest, Amount: 1}}, 4, false, rpc.Arguments{}, 0, false,
		TransferOptions{Ring: &RingPreference{PreferredDecoys: []string{d1, d2, "third"}, Strict: true}}); gerr == nil ||
		!strings.Contains(gerr.Error(), "too many preferred decoys for ring size 4") {
		t.Fatalf("strict 3 decoys at ring 4 (2 slots) must fail the pre-guard, got: %v", gerr)
	}

	// exactly filling the slots must NOT trip the guard (it proceeds and fails later,
	// offline, with an unrelated error).
	if _, gerr := w.TransferPayload0WithOptions(
		[]rpc.Transfer{{Destination: dest, Amount: 1}}, 4, false, rpc.Arguments{}, 0, false,
		TransferOptions{Ring: &RingPreference{PreferredDecoys: []string{d1, d2}, Strict: true}}); gerr != nil &&
		strings.Contains(gerr.Error(), "too many preferred decoys") {
		t.Fatalf("strict 2 decoys at ring 4 wrongly tripped the slot pre-guard: %v", gerr)
	}

	// lenient over-supply must NOT trip the guard either (surplus is dropped/recorded).
	if _, gerr := w.TransferPayload0WithOptions(
		[]rpc.Transfer{{Destination: dest, Amount: 1}}, 4, false, rpc.Arguments{}, 0, false,
		TransferOptions{Ring: &RingPreference{PreferredDecoys: []string{d1, d2, "third"}}}); gerr != nil &&
		strings.Contains(gerr.Error(), "too many preferred decoys") {
		t.Fatalf("lenient over-supply at ring 4 wrongly tripped the strict slot pre-guard: %v", gerr)
	}
}
