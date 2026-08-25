// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package main

// Ring-assembly termination gate (PR #22 review finding #1).
//
// The ring-assembly loop in TransferPayload0WithOptions (wallet_transfer.go) collects
// ringsize-2 DISTINCT members through a deduplicator that persists across passes. On a
// non-zero SCID the per-member balance probe cannot error (unregistered accounts get
// synthesized zero balances with err=nil, daemon_communication.go), so when the distinct
// candidate pool is smaller than the ring AND the <=40 base-tree top-up is skipped, no
// pass can make progress once the pool drains — the loop spins forever HOLDING
// w.transfer_mutex, wedging every transfer build on the wallet.
//
// The starved configuration must be a TOKEN ring: the base (zero-SCID) tree can never
// starve because genesis processes the hardcoded premine list — 1326 registered accounts
// before the first block (blockchain/transaction_execute.go:82-111, premine/list.txt) —
// which fills any legal ring. This test builds the deterministic token-path trap:
//
//   - transfer SCID = a nonexistent token tree (zero on-chain holders, the scarcest pool:
//     the daemon's GetRandomAddress on that tree returns an empty list, status OK);
//   - 41 curated decoys, all registered on the base tree (Strict-valid), so the combined
//     candidate count exceeds the <=40 threshold and the base-tree top-up NEVER fires;
//   - ring 64: candidates = 41 decoys forever, ring sticks at 43 of 64. Zero progress
//     every pass after the first.
//
// Pre-fix the build never returns — this test's own timeout is the only bound (the suite
// has none), and its firing is the live reproduction of the hang. Post-fix the build must
// SUCCEED: the top-up threshold measures only the random tail (empty here), the base-tree
// rescue fires, and base members legally fill the token ring with synthesized zero
// balances — which is simultaneously the regression assertion for the tail-only fix.
//
// Scope honesty:
//   - The exhaustion-ERROR branch of the bound cannot fire on a healthy chain (the base
//     rescue always fills a legal ring from the 1326-account premine floor); it guards
//     daemon degradation (Random_ring_members swallows RPC errors into empty lists) and
//     is covered by inspection, not run here.
//   - Single-node simulator; consensus-side verification of the built tx is out of scope
//     (the curated finalization tests cover that).

import (
	crand "crypto/rand"
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

func Test_RingPoolExhaustion_Terminates(t *testing.T) {
	globals.Arguments["--testnet"] = true
	globals.Arguments["--simulator"] = true

	walletapi.Initialize_LookupTable(1, 1<<17)

	const ring = 64
	const decoyCount = 41 // > 40: defeats the base-tree top-up threshold, yet 41+2 < 64

	mkwallet := func(name, seedHex string) *walletapi.Wallet_Disk {
		db := filepath.Join(os.TempDir(), "exh_"+name+".db")
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

	// 41 decoys: the fixed seed table has 22 entries; synthesize the surplus randomly.
	var decoys []*walletapi.Wallet_Disk
	for i := 0; i < decoyCount; i++ {
		if 2+i < len(wallets_seeds) {
			decoys = append(decoys, mkwallet(fmt.Sprintf("decoy%d", i), wallets_seeds[2+i]))
		} else {
			seedb := make([]byte, 32)
			if _, err := crand.Read(seedb); err != nil {
				t.Fatal(err)
			}
			decoys = append(decoys, mkwallet(fmt.Sprintf("decoy%d", i), hex.EncodeToString(seedb)))
		}
	}

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

	allToRegister := append([]*walletapi.Wallet_Disk{wsrc, wrecipient}, decoys...)
	for _, w := range allToRegister {
		if err := chain.Add_TX_To_Pool(w.GetRegistrationTX()); err != nil {
			t.Fatalf("regtx: %s", err)
		}
	}
	// One block takes all pending registrations (miner includes up to 100 regtxs/block);
	// Regpool_List_TX stays stale after inclusion, so it cannot be used as a drain check.
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)

	for _, w := range append(allToRegister, wgenesis) {
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

	// Prove the synthetic-seed decoys really registered (base-tree probe of the last one);
	// an unregistered decoy would make Strict validation error out and mask the hang.
	var zeroscid crypto.Hash
	if _, _, _, _, err := wsrc.GetEncryptedBalanceAtTopoHeight(zeroscid, -1, decoys[len(decoys)-1].GetAddress().String()); err != nil {
		t.Fatalf("decoy registration did not land: %s", err)
	}

	// A nonexistent token tree: zero holders, the scarcest possible pool. Sending
	// Amount 0 of it is cryptographically valid (the sender's synthesized balance is zero).
	var tokenSCID crypto.Hash
	tokenSCID[31] = 0x45

	var preferred []string
	for _, d := range decoys {
		preferred = append(preferred, d.GetAddress().String())
	}
	opts := walletapi.TransferOptions{
		Ring: &walletapi.RingPreference{
			PreferredDecoys: preferred,
			Strict:          true, // all 41 are base-registered, so validation passes every pass
		},
	}

	wsrc.SetRingSize(ring)

	// The build MUST be bounded by the test itself: pre-fix it never returns and holds
	// transfer_mutex, so a bare call would wedge the whole test binary.
	type result struct {
		tx  *transaction.Transaction
		err error
	}
	done := make(chan result, 1)
	// transfers[0] must be base: the upfront self-balance check (wallet_transfer.go, the
	// GetSelfEncryptedBalanceAtTopoHeight call) probes transfers[0].SCID WITHOUT the
	// zero-balance synthesis and errors for a token the sender never held. The token ride
	// as transfers[1] reaches the ring loop through the synthesizing per-transfer probes.
	go func() {
		tx, err := wsrc.TransferPayload0WithOptions(
			[]rpc.Transfer{
				{Destination: wrecipient.GetAddress().String(), Amount: 1},
				{SCID: tokenSCID, Destination: wrecipient.GetAddress().String(), Amount: 0},
			},
			ring, false, rpc.Arguments{}, 0, false, opts)
		done <- result{tx, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("token ring build failed (expected base-tree rescue to fill it): %s", r.err)
		}
		if r.tx == nil {
			t.Fatal("nil tx without error")
		}
		for i := range r.tx.Payloads {
			if n := len(r.tx.Payloads[i].Statement.Publickeylist); n != ring {
				t.Fatalf("payload %d ring is %d, want %d", i, n, ring)
			}
		}
		t.Logf("token ring assembled at %d via base-tree rescue; build terminated", ring)
	case <-time.After(120 * time.Second):
		t.Fatal("ring assembly did not terminate — hang regression (wallet_transfer.go ring loop)")
	}
}
