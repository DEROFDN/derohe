// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

import (
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
)

// Pins the lenient drop record against silent wallet-side curation loss
// (PR #22 review finding #3 / re-review O7).
//
// Lenient mode drops a decoy for four reasons: unparseable, own address, duplicate,
// or a daemon unregistered verdict. The pre-signing "reduced curation" summary is
// derived from the drops record, so a reason that does not write the record recreates
// the finding-#3 failure class for that reason: an all-dropped lenient list would sign
// a fully random ring the caller believes curated, with zero signal — reachable on a
// healthy chain with a healthy daemon (e.g. every ambient decoy from the #23 CLI
// duplicating the recipient). The three wallet-side reasons fire before any RPC, so
// they are pinned offline; the unregistered reason is exercised on the sim chain in
// curated_probe_classification_test.go.
func Test_LenientDecoyDrops_AreRecorded(t *testing.T) {
	w, err := Create_Encrypted_Wallet_From_Recovery_Words_Memory("", "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly")
	if err != nil {
		t.Fatalf("cannot create in-memory wallet: %s", err)
	}
	defer w.Close_Encrypted_Wallet()

	w2, err := Create_Encrypted_Wallet_From_Recovery_Words_Memory("", "perfil lujo faja puma favor pedir detalle doble carbón neón paella cuarto ánimo cuento conga correr dental moneda león donar entero logro realidad acceso doble")
	if err != nil {
		t.Fatalf("cannot create second in-memory wallet: %s", err)
	}
	defer w2.Close_Encrypted_Wallet()

	var zeroscid crypto.Hash
	self := w.GetAddress().String()
	recipient := w2.GetAddress().String()

	// Every decoy below is rejected BEFORE the registration probe (parse, self, and
	// recipient-duplicate checks are pure wallet-side validation), so this runs offline
	// and no RPC error can mask a missing record. Offline, the validator's TRAILING
	// Random_ring_members fetch panics on the nil rpc client — but that fetch runs after
	// the whole validation loop, so every drop decision has already been recorded, which
	// is exactly what this test pins. The panic is absorbed; the drops map is the output.
	validateLenient := func(drops map[string]string) {
		defer func() { _ = recover() }() // nil rpc client: the post-validation random fetch
		if _, curated, cerr := w.curatedRingCandidates(zeroscid, recipient, &RingPreference{
			PreferredDecoys: []string{"not_an_address", self, recipient},
		}, 126, nil, drops); cerr != nil {
			t.Errorf("lenient wallet-side rejections must not error, got: %v", cerr)
		} else if curated != 0 {
			t.Errorf("all decoys are invalid, want curated=0, got %d", curated)
		}
	}
	drops := map[string]string{}
	validateLenient(drops)
	// The core O7 assertion: curation shrank to zero, and EVERY drop left a record the
	// caller's summary can see — none of the three wallet-side reasons is silent.
	if len(drops) != 3 {
		t.Fatalf("want 3 recorded drops (unparseable/self/duplicate), got %d: %v", len(drops), drops)
	}
	for decoy, wantReason := range map[string]string{
		"not_an_address": "parseable",
		self:             "own address",
		recipient:        "duplicate",
	} {
		reason, recorded := drops[decoy]
		if !recorded {
			t.Fatalf("drop of %q not recorded: %v", decoy, drops)
		}
		if !strings.Contains(reason, wantReason) {
			t.Fatalf("drop of %q recorded with reason %q, want it to name %q", decoy, reason, wantReason)
		}
	}

	// Re-validation must not double-count: the assembly loop calls the validator once
	// per pass, and the summary reports supplied decoys, not passes.
	validateLenient(drops)
	if len(drops) != 3 {
		t.Fatalf("drops record must stay keyed per supplied decoy across passes, got %d entries: %v", len(drops), drops)
	}

	// Strict never records a drop — it hard-errors on the first bad decoy instead, so a
	// Strict build can never reach the reduced-curation summary with a non-empty record.
	strictDrops := map[string]string{}
	if _, _, cerr := w.curatedRingCandidates(zeroscid, recipient, &RingPreference{
		PreferredDecoys: []string{"not_an_address"}, Strict: true,
	}, 126, nil, strictDrops); cerr == nil {
		t.Fatal("strict unparseable decoy must hard-error")
	}
	if len(strictDrops) != 0 {
		t.Fatalf("strict mode must not record drops, got: %v", strictDrops)
	}
}
