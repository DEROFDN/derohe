package main

// A2 — curated-ring finalization gate.
//
// The curated-decoy engine (feat/curated-decoy-attribution: curatedRingCandidates +
// TransferPayload0WithOptions) validates each preferred decoy is registered on the base
// balance tree BEFORE signing, on the reasoning that a decoy which passes the wallet but is
// not a real registered account would be rejected by the consensus verifier after the user
// has already signed. That reasoning is sound by inspection — this test makes it PROVEN-RUN:
//
//   A transfer whose ring members are CURATED (user-supplied via RingPreference, not drawn
//   from DERO.GetRandomAddress) and which also carries an action-less SCDATA body must build,
//   be accepted into the pool, mine, and FINALIZE into a block — i.e. the curated ring is
//   consensus-valid, not merely wallet-valid.
//
// This is the load-bearing precondition for the rotating-identity ("Gatling") design's
// curated-disjoint-ring allocator: if a self-chosen ring did not finalize, the whole
// disjoint-ring mitigation would be unbuildable. It does.
//
// Scope honesty: single-node simulator. "FINALIZED" here means PERSISTED into a mined block
// (Block_tx_store), proving consensus ACCEPTANCE of the curated ring + action-less carrier.
// It is 0-conf on a difficulty-1 sim that bypasses PoW/miniblock verify and the low-fee floor;
// multi-node fork-choice and fee-competition are out of scope (Gate-3 / the declined R1 probe).

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
	const decoyCount = ring // a generous curation pool (more than ring-2 needed)

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

	// PROVE THE RING WAS ACTUALLY CURATED (not random fallback): a ring of size `ring` has
	// exactly `ring - 2` decoy slots (sender at witness_index[0], recipient at witness_index[1]
	// are fixed). The curated-selection path places preferred decoys FIRST, so all `ring - 2`
	// decoy slots must be filled from our preferred set — zero random fallback. We supply more
	// preferred decoys (`ring`) than there are slots, so a fully-curated ring sees exactly
	// `ring - 2` of them placed. Compare on the raw compressed public-key hex (HRP-independent).
	_ = finalized_tx // finalization already proven by the successful ReadTX above
	curatedSeen := 0
	for _, d := range preferred {
		da, perr := rpc.NewAddress(d)
		if perr != nil {
			continue
		}
		if builtRingKeys[hex.EncodeToString(da.PublicKey.EncodeCompressed())] {
			curatedSeen++
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
	t.Log(fmt.Sprintf("A2 PROVEN-RUN: curated ring (size %d, %d/%d preferred decoys placed) + action-less SCDATA carrier "+
		"FINALIZED into a block, consensus-accepted, body byte-equal readback; sender %d->%d (debit incl. Amount+fee). "+
		"Scope: single-node sim persistence (0-conf, PoW/fee-floor bypassed); not a multi-node finality claim.",
		ring, curatedSeen, len(preferred), pre_src, post_src))
}
