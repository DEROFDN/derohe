// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/derohe/walletapi"
)

// Test_CuratedRing_AltEncoding_NoDuplicate_A2 is the teeth-test for the canonicalization
// fix in curatedRingCandidates (PR #22 review finding #1).
//
// A ring member is identified by its PUBLIC KEY, not its address string. An integrated
// address (or any payment-id encoding) of an account already in the ring — the recipient,
// the sender, or an already-curated decoy — is a DIFFERENT string but the SAME pubkey.
// Before the fix, the wallet's string-keyed distinctness checks let such an alt-encoding
// through as a "distinct" decoy, placing the same pubkey in the ring twice. The wallet
// signed it; consensus then rejected it at transaction_verify.go (duplicate ring member)
// AFTER the user had signed.
//
// It exercises SIX alt-encoding vectors as independent subtests, each supplying the
// poisoned encoding as a leading curated decoy (with only one other real decoy, ring 8) so
// the buggy path must consume and place it before random members fill the ring:
//   - recipient-alt:               integrated encoding of the recipient
//   - sender-alt:                  integrated encoding of the sender (self)
//   - decoy-vs-decoy:              two integrated encodings of the SAME extra decoy
//   - cross-network-recipient-alt: a wrong-network HRP encoding of the recipient pubkey
//   - deroproof-recipient-alt:     a deroproof-HRP encoding of the recipient (defense-in-depth)
//   - deroproof-decoy-alt:         deroproof + plain of the SAME extra decoy — THE deroproof
//     teeth (#13); the only deroproof axis the caller-side
//     line-482 backstop does NOT guard, so curatedRingCandidates'
//     pubkey-keyed distinctness is the sole defense
//
// Each asserts the built ring has NO duplicate pubkey and exactly `ring` distinct members —
// i.e. the alt-encoding was canonicalized away, not placed. With the canonicalization
// reverted, the ring carries a duplicate pubkey (fewer than `ring` distinct keys) — caught.
//
// NOTE: like every in-process simulator test here this spins a chain on the fixed RPC port
// rpcport_test and the shared simulator data-dir, so it must be run WITHOUT -race and not
// concurrently with the other chain-spin-up tests in this package (the project's standing
// simulator-flake constraint — no per-pid isolation in the test harness).
func Test_CuratedRing_AltEncoding_NoDuplicate_A2(t *testing.T) {
	globals.Arguments["--testnet"] = true
	globals.Arguments["--simulator"] = true

	walletapi.Initialize_LookupTable(1, 1<<17)

	const ring = 8

	mkwallet := func(name, seedHex string) *walletapi.Wallet_Disk {
		db := filepath.Join(os.TempDir(), "a2alt_"+name+".db")
		os.Remove(db)
		t.Cleanup(func() { os.Remove(db) })
		seed, err := hex.DecodeString(seedHex)
		if err != nil {
			t.Fatalf("decode seed %s: %s", name, err)
		}
		w, err := walletapi.Create_Encrypted_Wallet(db, WALLET_PASSWORD, new(crypto.BNRed).SetBytes(seed))
		if err != nil {
			t.Fatalf("create wallet %s: %s", name, err)
		}
		return w
	}

	wgenesis := mkwallet("genesis", genesis_seed)
	wsrc := mkwallet("src", wallets_seeds[0])
	wrecipient := mkwallet("dst", wallets_seeds[1])
	// Register only ONE real decoy. With ring=8 and sender+recipient fixed, 6 decoy slots
	// remain; supplying the integrated-recipient as the FIRST curated decoy forces the buggy
	// path to consume and place it (it is not crowded out by other curated members), so a
	// missing canonicalization produces a real duplicate pubkey in the ring. The remaining
	// slots top up from random members.
	var regDecoys []*walletapi.Wallet_Disk
	regDecoys = append(regDecoys, mkwallet("rdecoy0", wallets_seeds[2]))
	// a second registered decoy, used only by the decoy-vs-decoy vector below (two different
	// integrated encodings of THIS account must collapse to one ring slot).
	wdecoyDup := mkwallet("rdecoyDup", wallets_seeds[3])

	genesis_tx := transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, Value: 2012345}}
	copy(genesis_tx.MinerAddress[:], wgenesis.GetAddress().PublicKey.EncodeCompressed())
	config.Testnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	config.Mainnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	genesis_block := blockchain.Generate_Genesis_Block()
	config.Testnet.Genesis_Block_Hash = genesis_block.GetHash()
	config.Mainnet.Genesis_Block_Hash = genesis_block.GetHash()

	chain, rpcserver, _ := simulator_chain_start()
	defer simulator_chain_stop(chain, rpcserver)
	globals.Arguments["--daemon-address"] = rpcport_test
	go walletapi.Keep_Connectivity()

	toRegister := append([]*walletapi.Wallet_Disk{wsrc, wrecipient, wdecoyDup}, regDecoys...)
	for _, w := range toRegister {
		if err := chain.Add_TX_To_Pool(w.GetRegistrationTX()); err != nil {
			t.Fatalf("regtx: %s", err)
		}
	}
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	for _, w := range append(toRegister, wgenesis) {
		w.SetDaemonAddress(rpcport)
		w.SetOnlineMode()
	}
	for i := 0; i < 8; i++ {
		simulator_chain_mineblock(chain, wsrc.GetAddress(), t)
	}
	time.Sleep(time.Second)
	if err := wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatalf("src sync: %s", err)
	}

	recipient := wrecipient.GetAddress().String()

	wsrc.SetRingSize(ring)

	// integratedOf returns an integrated-address encoding (same pubkey, different string)
	// of the given base address, carrying a distinct destination-port argument.
	integratedOf := func(t *testing.T, base rpc.Address, port uint64) string {
		a := base // value copy
		a.Arguments = rpc.Arguments{{Name: rpc.RPC_DESTINATION_PORT, DataType: rpc.DataUint64, Value: port}}
		s := a.String()
		if s == base.String() {
			t.Fatalf("integrated encoding produced the same string as the base address; test premise broken")
		}
		if pa, err := rpc.NewAddress(s); err != nil {
			t.Fatalf("alt encoding not parseable: %s", err)
		} else if pa.BaseAddress().String() != base.BaseAddress().String() {
			t.Fatalf("alt encoding does not canonicalize to the same base key")
		}
		return s
	}

	// pubkeyHex of an account, for counting appearances in the built ring.
	pubkeyHex := func(w *walletapi.Wallet_Disk) string {
		return hex.EncodeToString(w.GetAddress().PublicKey.EncodeCompressed())
	}

	// build runs one transfer with the given curated decoys and returns the built tx, asserting
	// the build succeeds (non-strict: a poisoned alt-encoding is dropped + a random member tops up).
	build := func(t *testing.T, label string, preferred []string) *transaction.Transaction {
		frame := make([]byte, 64)
		if _, err := rand.Read(frame); err != nil {
			t.Fatal(err)
		}
		scdata := buildActionlessSCDATABodyA2(frame)
		tx, err := wsrc.TransferPayload0WithOptions(
			[]rpc.Transfer{{Destination: recipient, Amount: 1}}, ring, false, scdata, 0, false,
			walletapi.TransferOptions{Ring: &walletapi.RingPreference{PreferredDecoys: preferred, Strict: false}})
		if err != nil || tx == nil {
			t.Fatalf("%s: build with an alt-encoded decoy should SUCCEED (drop+substitute), got err=%v", label, err)
		}
		return tx
	}

	// assertNoDup is THE invariant consensus enforces (transaction_verify.go): every ring slot
	// is a DISTINCT pubkey, and the ring carries exactly `ring` distinct members. With the
	// canonicalization reverted, the poisoned alt-encoding lands the same pubkey twice and
	// this fails. wantOnce names accounts that MUST appear exactly once (not doubled via decoy).
	assertNoDup := func(t *testing.T, label string, tx *transaction.Transaction, wantOnce map[string]string) {
		for _, pl := range tx.Payloads {
			keys := map[string]bool{}
			counts := map[string]int{}
			for _, p := range pl.Statement.Publickeylist {
				k := hex.EncodeToString((*crypto.Point)(p).EncodeCompressed())
				if keys[k] {
					t.Fatalf("%s: DUPLICATE ring member pubkey %s — an alt-encoding was placed in the ring "+
						"as a distinct decoy; consensus would reject this tx AFTER signing", label, k[:16])
				}
				keys[k] = true
				counts[k]++
			}
			if len(keys) != int(ring) {
				t.Fatalf("%s: ring has %d distinct pubkeys, expected %d (a collapsed duplicate shrank the ring)", label, len(keys), ring)
			}
			for who, key := range wantOnce {
				if counts[key] != 1 {
					t.Fatalf("%s: %s pubkey appears %d times in the ring, expected exactly 1", label, who, counts[key])
				}
			}
		}
	}

	recipientBase := wrecipient.GetAddress()
	senderBase := wsrc.GetAddress()
	dupDecoyBase := wdecoyDup.GetAddress()

	// Each vector is an independent subtest so a failure in one is reported without masking
	// the others — the canonicalization fix must close ALL of them, not just the recipient.

	// VECTOR 1 — alt-encoded RECIPIENT as the first curated decoy. seen[recipientBase] must
	// reject it (wallet_transfer.go: seen seeded with recipientBase). recipient appears once.
	t.Run("recipient-alt", func(t *testing.T) {
		preferred := []string{integratedOf(t, recipientBase, 0xDEAD)}
		for _, d := range regDecoys {
			preferred = append(preferred, d.GetAddress().String())
		}
		tx := build(t, "recipient-alt", preferred)
		assertNoDup(t, "recipient-alt", tx, map[string]string{"recipient": pubkeyHex(wrecipient)})
	})

	// VECTOR 2 — alt-encoded SENDER as the first curated decoy. The sender is already in the
	// ring (slot 0); an alt-encoding must be rejected by the `base == self` check (self =
	// BaseAddress().String()). Reverting canonicalization (raw d == self) slips the integrated
	// string through and doubles the sender's pubkey. sender appears once.
	t.Run("sender-alt", func(t *testing.T) {
		preferred := []string{integratedOf(t, senderBase, 0xBEEF)}
		for _, d := range regDecoys {
			preferred = append(preferred, d.GetAddress().String())
		}
		tx := build(t, "sender-alt", preferred)
		assertNoDup(t, "sender-alt", tx, map[string]string{"sender": pubkeyHex(wsrc)})
	})

	// VECTOR 3 — DECOY-vs-DECOY: two DIFFERENT integrated encodings of the SAME registered
	// account (wdecoyDup), supplied as the first two curated decoys. The second must collapse
	// into the first via seen[base]. Reverting canonicalization lets both through as distinct
	// strings and doubles that pubkey. The shared decoy pubkey appears exactly once.
	t.Run("decoy-vs-decoy", func(t *testing.T) {
		preferred := []string{
			integratedOf(t, dupDecoyBase, 0x1111),
			integratedOf(t, dupDecoyBase, 0x2222),
		}
		tx := build(t, "decoy-vs-decoy", preferred)
		assertNoDup(t, "decoy-vs-decoy", tx, map[string]string{"shared-decoy": pubkeyHex(wdecoyDup)})
	})

	// VECTOR 4 — CROSS-NETWORK alt-encoding of the recipient. BaseAddress() preserves the
	// Mainnet flag and MarshalText picks the HRP from it (rpc/address.go), so a wrong-network
	// encoding of an in-ring pubkey (here the testnet recipient rendered with the mainnet
	// `dero` HRP) is a DIFFERENT string but the SAME 33-byte pubkey — which consensus keys on
	// (transaction_verify.go). The fix network-pins the canonical key to the wallet's network,
	// so this collapses onto the recipient. Without that pin it slips every string check and
	// doubles the recipient pubkey.
	t.Run("cross-network-recipient-alt", func(t *testing.T) {
		altNet := recipientBase.BaseAddress()
		altNet.Mainnet = !altNet.Mainnet // flip testnet(deto) -> mainnet(dero), same pubkey
		altStr := altNet.String()
		if pa, err := rpc.NewAddress(altStr); err != nil {
			t.Fatalf("cross-network alt not parseable: %s", err)
		} else if hex.EncodeToString(pa.PublicKey.EncodeCompressed()) != pubkeyHex(wrecipient) {
			t.Fatalf("cross-network alt does not carry the recipient pubkey")
		}
		preferred := []string{altStr}
		for _, d := range regDecoys {
			preferred = append(preferred, d.GetAddress().String())
		}
		tx := build(t, "cross-network-recipient-alt", preferred)
		assertNoDup(t, "cross-network-recipient-alt", tx, map[string]string{"recipient": pubkeyHex(wrecipient)})
	})

	// deroproofOf returns a deroproof-HRP encoding (same pubkey, different string) of the given
	// base address. MarshalText forces hrp="deroproof" whenever a.Proof is set (rpc/address.go:
	// 53-54), OVERRIDING the dero/deto network HRP — so this is yet another DIFFERENT string for
	// the SAME 33-byte pubkey (PublicKey is always encoded, :58). This axis is nastier than the
	// integrated/cross-network ones: BaseAddress() PRESERVES Proof (Clone, :97), and a parsed
	// deroproof address comes back with Proof=true (:168-169), so the PRE-#13 string fix
	// (BaseAddress + pin Mainnet) STILL re-renders it as "deroproof..." (Proof never cleared) —
	// a distinct string that slips a string-keyed seen-set.
	//
	// SOURCE NOTE: UnmarshalText unconditionally decodes Arguments for the deroproof HRP
	// (rpc/address.go:174-177), and Arguments.UnmarshalBinary on an EMPTY byte slice returns EOF
	// (rpc/rpc.go:226) — so a BARE-pubkey deroproof string does NOT round-trip. A real deroproof
	// address always carries a proof argument, so we attach one (cleared again by BaseAddress in
	// the wallet). This makes the poison stress BOTH the Proof axis AND the Arguments axis at once.
	deroproofOf := func(t *testing.T, base rpc.Address, port uint64) string {
		a := base.BaseAddress()
		a.Proof = true
		a.Arguments = rpc.Arguments{{Name: rpc.RPC_DESTINATION_PORT, DataType: rpc.DataUint64, Value: port}}
		s := a.String()
		if len(s) < 9 || s[:9] != "deroproof" {
			t.Fatalf("expected a deroproof-prefixed string, got %q", s)
		}
		pa, err := rpc.NewAddress(s)
		if err != nil {
			t.Fatalf("deroproof encoding not parseable: %s", err)
		}
		if !pa.Proof {
			t.Fatalf("parsed deroproof address did not carry Proof=true")
		}
		if pa.BaseAddress().String() == base.BaseAddress().String() {
			t.Fatalf("deroproof encoding rendered the same string as the base; test premise broken")
		}
		if hex.EncodeToString(pa.PublicKey.EncodeCompressed()) != hex.EncodeToString(base.PublicKey.EncodeCompressed()) {
			t.Fatalf("deroproof encoding does not carry the base pubkey")
		}
		return s
	}

	// VECTOR 5 — DEROPROOF recipient poison (defense-in-depth). A deroproof encoding of the
	// recipient as the first curated decoy. The recipient is multiply-defended (the #13 pubkey
	// seen-seed, canon.Proof=false making the emitted base collide with the recipient's clean
	// string, AND the caller-side `k != receiver` backstop at wallet_transfer.go:474), so this
	// is GREEN under the fix and stays GREEN even under partial reverts — it documents that the
	// recipient deroproof axis is closed, but it is NOT the teeth (see VECTOR 6).
	t.Run("deroproof-recipient-alt", func(t *testing.T) {
		preferred := []string{deroproofOf(t, recipientBase, 0xC0FFEE)}
		for _, d := range regDecoys {
			preferred = append(preferred, d.GetAddress().String())
		}
		tx := build(t, "deroproof-recipient-alt", preferred)
		assertNoDup(t, "deroproof-recipient-alt", tx, map[string]string{"recipient": pubkeyHex(wrecipient)})
	})

	// VECTOR 6 — DEROPROOF decoy canonicalizes & is PLACED (THE deroproof teeth, #13), asserted in
	// STRICT mode so the regression is DETERMINISTIC. A deroproof encoding of an extra decoy
	// (wdecoyDup) as the sole curated decoy. The fix that closes the deroproof axis is
	// `canon.Proof = false` at wallet_transfer.go:140 — without it the emitted ring string stays
	// "deroproof…", which the BASE-tree registration probe at :144 REJECTS (a deroproof HRP is not
	// a usable ring entry — GetEncryptedBalanceAtTopoHeight cannot resolve it).
	//
	// ARCHITECTURAL NOTE (verified by mutation, see the re-review report): the deroproof axis
	// canNOT be made to PLACE A DUPLICATE by reverting #13 in isolation — the caller-side string
	// deduplicator at wallet_transfer.go:470-473 collapses any two same-pubkey entries, because
	// canon.Proof=false makes BOTH emit the identical clean base string. So the meaningful
	// regression a broken deroproof fix causes is a REJECTED/DROPPED decoy, not a duplicate. We
	// assert it in STRICT mode: under the fix the deroproof decoy canonicalizes to the clean base,
	// passes the probe, and the build SUCCEEDS with wdecoyDup placed exactly once; drop
	// `canon.Proof=false` and Strict turns the failed registration probe into a HARD ERROR
	// (wallet_transfer.go:145-147) — the build fails. Strict makes the RED unconditional (no
	// dependence on whether a random top-up happens to re-draw the dropped decoy).
	t.Run("deroproof-decoy-alt", func(t *testing.T) {
		preferred := []string{deroproofOf(t, dupDecoyBase, 0x3333)} // deroproof encoding of wdecoyDup
		frame := make([]byte, 64)
		if _, err := rand.Read(frame); err != nil {
			t.Fatal(err)
		}
		scdata := buildActionlessSCDATABodyA2(frame)
		tx, err := wsrc.TransferPayload0WithOptions(
			[]rpc.Transfer{{Destination: recipient, Amount: 1}}, ring, false, scdata, 0, false,
			walletapi.TransferOptions{Ring: &walletapi.RingPreference{PreferredDecoys: preferred, Strict: true}})
		if err != nil || tx == nil {
			t.Fatalf("deroproof-decoy-alt: STRICT build with a deroproof decoy should SUCCEED "+
				"(it must canonicalize Proof away to a registered base); got err=%v — this means "+
				"canon.Proof=false is NOT applied and the deroproof axis is OPEN", err)
		}
		// corroborate: the deroproof decoy's pubkey landed in the ring exactly once (clean base).
		assertNoDup(t, "deroproof-decoy-alt", tx, map[string]string{"deroproof-decoy": pubkeyHex(wdecoyDup)})
	})
}
