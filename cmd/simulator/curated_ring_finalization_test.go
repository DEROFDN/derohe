package main

// A2 — base-SCID curated-ring finalization gate.
//
// The curated-decoy engine (feat/curated-decoy-attribution: curatedRingCandidates +
// TransferPayload0WithOptions) places user-supplied PreferredDecoys into the ring, each
// validated registered on the base balance tree before signing. This test makes the A2
// claim PROVEN-RUN:
//
//   A base-SCID transfer whose ring members are CURATED (user-supplied via RingPreference,
//   not drawn from DERO.GetRandomAddress) and which carries an action-less SCDATA body builds,
//   passes full non-coinbase consensus verification INCLUDING bulletproof verification
//   (skip_proof=false — Verify_Transaction_NonCoinbase, transaction_verify.go:200-201), mines,
//   and is persisted into a mined block — i.e. the curated ring is consensus-valid, not merely
//   wallet-valid.
//
// This is the load-bearing precondition for the rotating-identity ("Gatling") design's
// curated-disjoint-ring allocator: if a self-chosen ring did not finalize, the whole
// disjoint-ring mitigation would be unbuildable. It does. The companion negative-control test
// (Test_CuratedRing_NegativeControls_A2) makes the registration-probe / fail-closed branches
// PROVEN-RUN rather than EXPECTED-BY-INSPECTION.
//
// Scope honesty (audit-tightened):
//   - Single-node simulator. "FINALIZED" = PERSISTED into ONE mined block (Block_tx_store),
//     0-conf on a difficulty-1 sim — NOT a multi-node finality claim. Multi-node fork-choice and
//     fee competition are out of scope (Gate-3 / the declined R1 probe).
//   - The sim bypasses ONLY PoW/miniblock verify (blockchain.go:580,682,1193) and the low-fee
//     floor (blockchain.go:1271). Proof/ring verification is NOT bypassed — that is why
//     "consensus-valid" is justified.
//   - BASE-SCID ONLY. For a zero-SCID transfer the curation registration-probe
//     (wallet_transfer.go:108) is REDUNDANT with the unconditional ring-assembly re-probe
//     (wallet_transfer.go:429) and with the consensus base-tree check (no SCID-fallback fires,
//     transaction_verify.go:374 gated on !SCID.IsZero()). The probe's necessity as the SOLE
//     wallet-side defense is load-bearing only on the NON-zero-SCID path, which this test does
//     NOT execute (EXPECTED-BY-INSPECTION, not run here).
//   - Sender balance delta is display-only; the absolute fee is not mainnet-representative
//     (fee floor bypassed in sim).

import (
	"bytes"
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

// buildActionlessSCDATABody mirrors the carrier wire shape: the body rides under the
// INV-4-locked arg name "B" as a DataString, hex-encoded so a non-UTF-8 frame survives CBOR.
// CRITICAL (INV-1): no SCACTION key, so the tx takes the action-less short-circuit and cannot
// trigger the blackhole burn at any ring size.
func buildActionlessSCDATABodyA2(frame []byte) rpc.Arguments {
	return rpc.Arguments{
		rpc.Argument{Name: "B", DataType: rpc.DataString, Value: hex.EncodeToString(frame)},
	}
}

func Test_CuratedRing_Finalizes_A2(t *testing.T) {
	globals.Arguments["--testnet"] = true
	globals.Arguments["--simulator"] = true

	walletapi.Initialize_LookupTable(1, 1<<17)

	const ring = 8 // ring > 4 so curated decoys fill real slots beyond sender+recipient
	// We need genesis + sender + recipient + enough registered decoys to fill the ring.
	// Exactly ring-2: that is the ring's decoy capacity (sender and recipient hold the
	// other two slots), and Strict over-supply is a hard error — this fixture originally
	// supplied `ring` decoys and the surplus two were validated then silently never
	// placed, the precise silent-truncation defect the slot-capacity guard now rejects.
	const decoyCount = ring - 2

	// Create wallets directly (the Test_Creation_TX pattern) — self-contained, no register_wallets
	// (which spins up RPC/XSWD servers and touches the simulator's package logger).
	mkwallet := func(name, seedHex string) *walletapi.Wallet_Disk {
		db := filepath.Join(os.TempDir(), "a2_curated_"+name+".db")
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
	var decoys []*walletapi.Wallet_Disk
	for i := 0; i < decoyCount && 2+i < len(wallets_seeds); i++ {
		decoys = append(decoys, mkwallet(fmt.Sprintf("decoy%d", i), wallets_seeds[2+i]))
	}
	if len(decoys) < ring-2 {
		t.Fatalf("not enough seeds to curate a ring of %d (have %d decoys)", ring, len(decoys))
	}

	// Fix genesis to our genesis wallet (the wiring/creation-test pattern).
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

	// Register sender, recipient, and every curated decoy — they MUST be registered accounts
	// for the curated ring to be consensus-valid (the precise thing A2 proves).
	allToRegister := append([]*walletapi.Wallet_Disk{wsrc, wrecipient}, decoys...)
	for _, w := range allToRegister {
		if err := chain.Add_TX_To_Pool(w.GetRegistrationTX()); err != nil {
			t.Fatalf("regtx: %s", err)
		}
	}
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)

	for _, w := range append(allToRegister, wgenesis) {
		w.SetDaemonAddress(rpcport)
		w.SetOnlineMode()
	}

	// Fund the sender: mine several blocks to it so it has a mature, spendable balance.
	for i := 0; i < 8; i++ {
		simulator_chain_mineblock(chain, wsrc.GetAddress(), t)
	}
	time.Sleep(time.Second)
	if err := wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatalf("src sync: %s", err)
	}
	if bal, _ := wsrc.Get_Balance(); bal == 0 {
		t.Fatalf("sender has zero balance after funding; cannot send an Amount>=1 carrier")
	}

	// Curate the ring from the specific registered decoy wallets (NOT via GetRandomAddress).
	recipient := wrecipient.GetAddress().String()
	var preferred []string
	for _, d := range decoys {
		preferred = append(preferred, d.GetAddress().String())
	}

	opts := walletapi.TransferOptions{
		Ring: &walletapi.RingPreference{
			PreferredDecoys: preferred,
			Strict:          true, // hard-fail if any curated decoy is not consensus-valid — exactly the A2 claim
		},
	}

	frame := make([]byte, 1200)
	if _, err := rand.Read(frame); err != nil {
		t.Fatal(err)
	}
	scdata := buildActionlessSCDATABodyA2(frame)
	if scdata.Has(rpc.SCACTION, rpc.DataUint64) {
		t.Fatal("INV-1: carrier SCDATA must not contain SCACTION")
	}

	wsrc.SetRingSize(ring)
	pre_src, _ := wsrc.Get_Balance()

	// THE CURATED-RING CARRIER: action-less SCDATA + Amount:1 to recipient, ring members CURATED.
	tx, err := wsrc.TransferPayload0WithOptions(
		[]rpc.Transfer{{Destination: recipient, Amount: 1}},
		ring, false, scdata, 0, false, opts)
	if err != nil {
		// In Strict mode this errors if ANY curated decoy is not registered/valid — so a failure
		// here would mean the curated ring could not even be assembled into a buildable tx.
		t.Fatalf("A2 BUILD: curated-ring carrier did not build (strict curated decoys, ring %d): %s", ring, err)
	}

	// Submit the WIRE form (the daemon needs the expanded publickeylist pointers).
	var dtx transaction.Transaction
	if err := dtx.Deserialize(tx.Serialize()); err != nil {
		t.Fatalf("deserialize curated carrier: %s", err)
	}
	txhash := dtx.GetHash()

	// Capture the ring members from the BUILT tx. The serialized wire form stores the ring as
	// compact index POINTERS (resolved back to keys only by the daemon at verify time), so a tx
	// read back from the block store has an empty Publickeylist. The full points live on the
	// freshly-built tx's Statement.Publickeylist — that is the authoritative record of which ring
	// members the curated-selection path actually placed.
	builtRingKeys := map[string]bool{}
	for _, payload := range tx.Payloads {
		for _, p := range payload.Statement.Publickeylist {
			builtRingKeys[hex.EncodeToString((*crypto.Point)(p).EncodeCompressed())] = true
		}
	}

	// CONSENSUS ACCEPTANCE: if any curated ring member were not a real registered account, the
	// verifier would reject here (this is the exact "passes wallet, rejects at consensus" failure
	// the engine's registration-probe is meant to prevent — proven NOT to happen).
	if err := chain.Add_TX_To_Pool(&dtx); err != nil {
		t.Fatalf("A2 CONSENSUS: node REJECTED the curated-ring carrier (a curated decoy was not consensus-valid?): %s", err)
	}

	// Mine it + a few more so it persists and the transfer matures.
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	for i := 0; i < 4; i++ {
		simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	}
	wsrc.Sync_Wallet_Memory_With_Daemon()

	// FINALIZATION: read the tx back from the persisted block store. Block_tx_store.ReadTX reads
	// ONLY from txs that landed in MINED blocks, so a successful read is itself proof the
	// curated-ring carrier FINALIZED into a block, not merely sat in the mempool.
	tx_bytes, err := chain.Store.Block_tx_store.ReadTX(txhash)
	if err != nil || len(tx_bytes) == 0 {
		t.Fatalf("A2 FINALIZATION: curated-ring carrier %x not found in the persisted block store (never mined into a block): %v", txhash, err)
	}
	var finalized_tx transaction.Transaction
	if err := finalized_tx.Deserialize(tx_bytes); err != nil {
		t.Fatalf("A2 FINALIZATION: persisted curated carrier failed to deserialize: %s", err)
	}

	// BIND CURATION TO FINALIZATION (audit fix #5): the ring is read off the BUILT tx (`tx`),
	// while finalization is proven off the PERSISTED tx (`finalized_tx`). Those are only the same
	// transaction if their hashes match — the tx hash commits the serialized ring pointers, so
	// equal hashes mean the keys we counted are the keys that finalized. Assert it explicitly
	// rather than leaving it implicit.
	if finalized_tx.GetHash() != txhash {
		t.Fatalf("A2 BIND: persisted tx hash %x != built+submitted tx hash %x — the curated ring read off the built tx is not provably the ring that finalized", finalized_tx.GetHash(), txhash)
	}

	// PROVE THE RING WAS ACTUALLY CURATED (not random fallback), POSITIONALLY (audit fix #6):
	// a ring of size `ring` has exactly `ring - 2` decoy slots; sender sits at witness_index[0]
	// and recipient at witness_index[1] (PROVEN-SOURCE transaction_build.go:85,100). The
	// curated-selection path places preferred decoys FIRST, so every decoy slot must hold a
	// member of our preferred set — zero random fallback. We assert SUBSET-EQUALITY (every
	// non-sender/non-recipient ring member is one of our preferred decoys, and all `ring - 2`
	// slots are filled from them), not a bare count, so the proof survives a future ring-size or
	// pool-size change. Compare on raw compressed public-key hex (HRP-independent).
	senderKey := hex.EncodeToString(wsrc.GetAddress().PublicKey.EncodeCompressed())
	recipientKey := hex.EncodeToString(wrecipient.GetAddress().PublicKey.EncodeCompressed())
	preferredKeys := map[string]bool{}
	for _, d := range preferred {
		if da, perr := rpc.NewAddress(d); perr == nil {
			preferredKeys[hex.EncodeToString(da.PublicKey.EncodeCompressed())] = true
		}
	}
	curatedSeen := 0
	for k := range builtRingKeys {
		switch {
		case k == senderKey || k == recipientKey:
			// the two fixed slots — expected
		case preferredKeys[k]:
			curatedSeen++ // a curated decoy slot
		default:
			t.Fatalf("A2 CURATION: ring contains member %s that is neither sender, recipient, nor a preferred decoy — random fallback contaminated the curated ring", k)
		}
	}
	wantCurated := ring - 2 // sender + recipient occupy the other two slots
	if curatedSeen != wantCurated {
		t.Fatalf("A2 CURATION: %d curated decoys landed in the ring, want all %d decoy slots curated (random fallback filled %d slots)", curatedSeen, wantCurated, wantCurated-curatedSeen)
	}

	// INV-4 readback: the action-less body reads back byte-equal off the finalized tx.
	if !dtx.SCDATA.Has("B", rpc.DataString) {
		t.Fatalf("INV-4: finalized carrier missing SCDATA arg \"B\"")
	}
	bodyHex, _ := finalized_tx.SCDATA.Value("B", rpc.DataString).(string)
	gotFrame, derr := hex.DecodeString(bodyHex)
	if derr != nil || !bytes.Equal(gotFrame, frame) {
		t.Fatalf("INV-4: body readback mismatch off the finalized curated carrier (err=%v)", derr)
	}

	post_src, _ := wsrc.Get_Balance()
	t.Log(fmt.Sprintf("A2 PROVEN-RUN (base-SCID curated-ring finalization): curated ring (size %d, %d/%d decoy slots "+
		"filled from the preferred set, zero random fallback) + action-less SCDATA carrier passed full non-coinbase "+
		"consensus verification incl. bulletproof (skip_proof=false, transaction_verify.go:200-201), mined, and was "+
		"persisted into a mined block (Block_tx_store); body byte-equal readback; built-ring hash == finalized-ring hash. "+
		"sender %d->%d (delta display-only; fee floor bypassed in sim, absolute fee NOT mainnet-representative). "+
		"Scope: single-node sim, FINALIZED = persisted into one mined block (0-conf), not multi-node finality; sim "+
		"bypasses ONLY PoW/miniblock verify + low-fee floor — proof/ring verification is NOT bypassed.",
		ring, curatedSeen, ring-2, pre_src, post_src))
}

// Test_CuratedRing_NegativeControls_A2 makes the registration-probe / fail-closed branches
// PROVEN-RUN (audit fixes #3, #4) — the failures the curation guard exists to prevent:
//
//	(a) Strict:true + an UNREGISTERED preferred decoy → TransferPayload0WithOptions hard-errors
//	    BEFORE signing (wallet_transfer.go:108-111), returning no tx.
//	(b) Strict:false + an UNREGISTERED preferred decoy → the bad decoy is skipped, a random member
//	    fills the slot, the build succeeds, and only the REGISTERED preferred decoys appear in the
//	    ring (curatedSeen == registered count, < decoy slots).
//	(c) A never-mined carrier → Block_tx_store.ReadTX returns not-found, proving the positive
//	    test's finalization assertion is non-vacuous (ReadTX does not always succeed).
//
// Without these, the positive test's consensus-rejection and finalization branches are
// EXPECTED-BY-INSPECTION; this test makes them demonstrably falsifiable.
func Test_CuratedRing_NegativeControls_A2(t *testing.T) {
	globals.Arguments["--testnet"] = true
	globals.Arguments["--simulator"] = true

	walletapi.Initialize_LookupTable(1, 1<<17)

	const ring = 8

	mkwallet := func(name, seedHex string) *walletapi.Wallet_Disk {
		db := filepath.Join(os.TempDir(), "a2neg_"+name+".db")
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
	// Registered decoys: only ring-3 of them, so even a fully-curated ring needs ONE more slot
	// than we have registered decoys — that slot is where the unregistered decoy (rejected) vs a
	// random member (substituted) shows up.
	var regDecoys []*walletapi.Wallet_Disk
	for i := 0; i < ring-3 && 2+i < len(wallets_seeds); i++ {
		regDecoys = append(regDecoys, mkwallet(fmt.Sprintf("rdecoy%d", i), wallets_seeds[2+i]))
	}
	// The unregistered decoy: created, NEVER registered on-chain.
	wUnreg := mkwallet("unreg", wallets_seeds[len(wallets_seeds)-1])

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

	// Register sender, recipient, and ONLY the registered decoys — wUnreg is deliberately left out.
	toRegister := append([]*walletapi.Wallet_Disk{wsrc, wrecipient}, regDecoys...)
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
	var regPreferred []string
	for _, d := range regDecoys {
		regPreferred = append(regPreferred, d.GetAddress().String())
	}
	// preferred set that INCLUDES the unregistered decoy.
	preferredWithUnreg := append(append([]string{}, regPreferred...), wUnreg.GetAddress().String())

	frame := make([]byte, 64)
	if _, err := rand.Read(frame); err != nil {
		t.Fatal(err)
	}
	scdata := buildActionlessSCDATABodyA2(frame)
	wsrc.SetRingSize(ring)

	// (a) STRICT + unregistered decoy → build MUST hard-error before signing, no tx.
	strictTx, strictErr := wsrc.TransferPayload0WithOptions(
		[]rpc.Transfer{{Destination: recipient, Amount: 1}}, ring, false, scdata, 0, false,
		walletapi.TransferOptions{Ring: &walletapi.RingPreference{PreferredDecoys: preferredWithUnreg, Strict: true}})
	if strictErr == nil || strictTx != nil {
		t.Fatalf("NEG(a): Strict-mode build with an unregistered preferred decoy MUST hard-error before signing, got err=%v tx=%v", strictErr, strictTx != nil)
	}
	t.Logf("NEG(a) OK: Strict-mode unregistered decoy rejected before signing: %v", strictErr)

	// (b) NON-STRICT + unregistered decoy → build SUCCEEDS, the unregistered decoy is dropped and a
	// random member fills the slot. Only the REGISTERED preferred decoys appear in the ring.
	lenientTx, lenientErr := wsrc.TransferPayload0WithOptions(
		[]rpc.Transfer{{Destination: recipient, Amount: 1}}, ring, false, scdata, 0, false,
		walletapi.TransferOptions{Ring: &walletapi.RingPreference{PreferredDecoys: preferredWithUnreg, Strict: false}})
	if lenientErr != nil || lenientTx == nil {
		t.Fatalf("NEG(b): non-Strict build with an unregistered decoy should SUCCEED (skip+substitute), got err=%v", lenientErr)
	}
	lenientRingKeys := map[string]bool{}
	for _, pl := range lenientTx.Payloads {
		for _, p := range pl.Statement.Publickeylist {
			lenientRingKeys[hex.EncodeToString((*crypto.Point)(p).EncodeCompressed())] = true
		}
	}
	if lenientRingKeys[hex.EncodeToString(wUnreg.GetAddress().PublicKey.EncodeCompressed())] {
		t.Fatalf("NEG(b): the UNREGISTERED decoy appears in the non-Strict ring — it must have been dropped, not placed")
	}
	regSeen := 0
	for _, d := range regPreferred {
		da, _ := rpc.NewAddress(d)
		if lenientRingKeys[hex.EncodeToString(da.PublicKey.EncodeCompressed())] {
			regSeen++
		}
	}
	if regSeen != len(regPreferred) {
		t.Fatalf("NEG(b): expected all %d registered preferred decoys in the ring, saw %d", len(regPreferred), regSeen)
	}
	t.Logf("NEG(b) OK: non-Strict dropped the unregistered decoy, kept all %d registered preferred, random-filled the rest", regSeen)

	// (c) NEVER-MINED control → the lenient tx was built but never submitted/mined; ReadTX MUST
	// return not-found, proving the positive test's finalization assertion is non-vacuous.
	var lenientD transaction.Transaction
	if err := lenientD.Deserialize(lenientTx.Serialize()); err != nil {
		t.Fatalf("deserialize lenient tx: %s", err)
	}
	if b, err := chain.Store.Block_tx_store.ReadTX(lenientD.GetHash()); err == nil && len(b) > 0 {
		t.Fatalf("NEG(c): a never-mined tx was found in Block_tx_store — the finalization assertion is vacuous (ReadTX always succeeds)")
	}
	t.Logf("NEG(c) OK: a never-mined carrier is absent from Block_tx_store — finalization assertion is non-vacuous")
}
