// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package main

// Scarce-band rescue (PR #22 review finding #1, re-review O3).
//
// The <=40 scarcity fast-path in TransferPayload0WithOptions arms the base-tree fill only
// when the SCID tree's random tail is <= 40. A token tree with MORE than 40 members but
// FEWER than the ring needs sits in a structural dead zone: the fast path never arms, yet
// the tree can never fill the ring. Upstream hung there forever; the first cut of the
// exhaustion bound converted the hang into a false "pool exhausted" error. The stall
// rescue (base_rescue in wallet_transfer.go) must instead fill the ring from the base
// tree — the same fill the fast path uses — after consecutive barren passes prove the
// tree is starved.
//
// The band is built ON CHAIN, not mocked: executing a token transfer Puts EVERY ring
// member into the token tree (blockchain/transaction_execute.go — homomorphic changes
// touch all members), so one mined tx with three ring-32 token payloads seeds the
// token's tree with well over 40 but under 126 distinct decoy-capable leaves: the fast
// path stays dark on every pass (the daemon samples ~100 draws over ~92 leaves, far
// above 40), yet a ring-128 build needs 126 decoys — the tree alone can never satisfy
// it, since sender and recipient are also leaves. The margin matters: with a band only
// slightly above 40, per-pass sampling variance can dip under the threshold and arm the
// legacy fast path, masking the dead zone.
//
// Pre-rescue this build errors "candidate pool exhausted" in seconds; post-rescue it must
// SUCCEED via base fill. The simulator runs below topoheight 100 where the daemon's
// recent-activity filter is disabled, so the band here is purely structural — the
// filter-induced variant of the same band is covered by the backoff-window pin in
// walletapi/ring_backoff_test.go.

import (
	"encoding/hex"
	"fmt"
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

func Test_RingScarceBand_RescuesViaBaseTree(t *testing.T) {
	globals.Arguments["--testnet"] = true
	globals.Arguments["--simulator"] = true

	walletapi.Initialize_LookupTable(1, 1<<17)

	const seedRing = 32 // three payloads at 32 seed <= 92 distinct decoy-capable leaves
	const ring = 128    // needs 126 decoys: strictly more than the seeded tree can hold

	mkwallet := func(name, seedHex string) *walletapi.Wallet_Disk {
		db := filepath.Join(os.TempDir(), "band_"+name+".db")
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

	for _, w := range []*walletapi.Wallet_Disk{wsrc, wrecipient} {
		if err := chain.Add_TX_To_Pool(w.GetRegistrationTX()); err != nil {
			t.Fatalf("regtx: %s", err)
		}
	}
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)

	for _, w := range []*walletapi.Wallet_Disk{wgenesis, wsrc, wrecipient} {
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
	if bal, _ := wsrc.Get_Balance(); bal == 0 {
		t.Fatalf("sender has zero base balance after funding")
	}

	// The token tree must belong to a DEPLOYED contract: block commit walks every touched
	// SC tree and panics on a missing SC_META entry (blockchain.go, sc_meta.Get in
	// Add_Complete_Block), so a fabricated SCID verifies and pools but can never mine.
	// The simulator installs the hardcoded nameservice contract at SCID [31]=1 at genesis
	// (blockchain/hardcoded_contracts.go); its tree starts with zero ACCOUNT leaves
	// (GetRandomAddress skips non-pubkey keys such as the SC code), which is exactly the
	// empty token tree the seed transfer needs.
	var tokenSCID crypto.Hash
	tokenSCID[31] = 0x01

	// ── seed: three ring-32 token payloads, mined, populate the token tree ──
	wsrc.SetRingSize(seedRing)
	seedtx, err := wsrc.TransferPayload0(
		[]rpc.Transfer{
			{Destination: wrecipient.GetAddress().String(), Amount: 1},
			{SCID: tokenSCID, Destination: wrecipient.GetAddress().String(), Amount: 0},
			{SCID: tokenSCID, Destination: wrecipient.GetAddress().String(), Amount: 0},
			{SCID: tokenSCID, Destination: wrecipient.GetAddress().String(), Amount: 0},
		},
		seedRing, false, rpc.Arguments{}, 0, false)
	if err != nil {
		t.Fatalf("seed token tx build failed: %s", err)
	}
	// the pool wants the WIRE form (ring as index pointers, built on serialize)
	var seeddtx transaction.Transaction
	if err := seeddtx.Deserialize(seedtx.Serialize()); err != nil {
		t.Fatalf("seed tx deserialize: %s", err)
	}
	if err := chain.Add_TX_To_Pool(&seeddtx); err != nil {
		t.Fatalf("seed token tx rejected by pool: %s", err)
	}
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	time.Sleep(time.Second)
	if err := wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatalf("src re-sync: %s", err)
	}

	// precondition: the seeded tree must actually sit in the dead band — random tail > 40
	// (fast path stays dark) and distinct decoy capacity < ring-2 (tree can never fill it).
	tail := len(wsrc.Random_ring_members(tokenSCID))
	if tail <= 40 || tail > 3*seedRing-2 {
		t.Fatalf("precondition broken: token tail %d not in the dead band (41..%d)", tail, 3*seedRing-2)
	}

	// ── the dead-band build: must terminate AND succeed via the stall rescue ──
	wsrc.SetRingSize(ring)
	type result struct {
		tx  *transaction.Transaction
		err error
	}
	done := make(chan result, 1)
	go func() {
		tx, err := wsrc.TransferPayload0(
			[]rpc.Transfer{
				{Destination: wrecipient.GetAddress().String(), Amount: 1},
				{SCID: tokenSCID, Destination: wrecipient.GetAddress().String(), Amount: 0},
			},
			ring, false, rpc.Arguments{}, 0, false)
		done <- result{tx, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("dead-band token ring build failed (expected stall rescue to fill from base tree): %s", r.err)
		}
		if r.tx == nil {
			t.Fatal("nil tx without error")
		}
		for i := range r.tx.Payloads {
			if n := len(r.tx.Payloads[i].Statement.Publickeylist); n != ring {
				t.Fatalf("payload %d ring is %d, want %d", i, n, ring)
			}
		}
		t.Logf("dead-band ring assembled at %d (token tail was %d) via stall rescue", ring, tail)
	case <-time.After(120 * time.Second):
		t.Fatal("dead-band ring assembly did not terminate")
	}
}
