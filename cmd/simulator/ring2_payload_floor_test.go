// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package main

// Ring-2 payload size floor (PR #22 re-review O13).
//
// walletapi.MaxTransfersPerBuild caps the transfer array BEFORE assembly so the
// transfer_mutex hold bound has a constant multiplier — the consensus tx-size limit
// (STARGATE_HE_MAX_TX_SIZE) cannot do that job because it is enforced at
// verification/broadcast, after assembly already paid the full per-transfer cost.
// The cap claims to be a NECESSARY condition of the consensus limit: every payload
// serializes to more than STARGATE_HE_MAX_TX_SIZE/MaxTransfersPerBuild bytes even in
// the minimal configuration, so no array longer than the cap could ever broadcast and
// the cap rejects nothing previously usable.
//
// This test pins that arithmetic on a REAL transaction in its wire form (the same
// bytes blockchain.go:Add_TX_To_Pool measures): a single-payload ring-2 base transfer
// — the smallest payload the wallet can produce (fewest ring keys, fewest per-member
// commitments, smallest CT proof) — must exceed the per-payload floor the cap assumes.

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

func Test_Ring2PayloadFloor_JustifiesTransferCap(t *testing.T) {
	globals.Arguments["--testnet"] = true
	globals.Arguments["--simulator"] = true

	walletapi.Initialize_LookupTable(1, 1<<17)

	mkwallet := func(name, seedHex string) *walletapi.Wallet_Disk {
		db := filepath.Join(os.TempDir(), "floor_"+name+".db")
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

	// the minimal payload: ring 2, one base transfer, no SC data
	wsrc.SetRingSize(2)
	tx, err := wsrc.TransferPayload0(
		[]rpc.Transfer{{Destination: wrecipient.GetAddress().String(), Amount: 1}},
		2, false, rpc.Arguments{}, 0, false)
	if err != nil {
		t.Fatalf("ring-2 build failed: %s", err)
	}

	// measure the WIRE form — the bytes the consensus size check sees
	wire := tx.Serialize()
	var wtx transaction.Transaction
	if err := wtx.Deserialize(wire); err != nil {
		t.Fatalf("wire round-trip: %s", err)
	}
	if len(wtx.Payloads) != 1 {
		t.Fatalf("expected the minimal single-payload tx, got %d payloads", len(wtx.Payloads))
	}

	const floor = config.STARGATE_HE_MAX_TX_SIZE / walletapi.MaxTransfersPerBuild
	if uint64(len(wire)) <= floor {
		t.Fatalf("minimal ring-2 payload is %d bytes, want > %d: MaxTransfersPerBuild=%d is NOT a necessary condition of the %d-byte consensus limit — lower the cap",
			len(wire), floor, walletapi.MaxTransfersPerBuild, config.STARGATE_HE_MAX_TX_SIZE)
	}
	t.Logf("minimal ring-2 tx: %d bytes wire (> %d-byte floor); cap %d × floor = consensus limit %d",
		len(wire), floor, walletapi.MaxTransfersPerBuild, config.STARGATE_HE_MAX_TX_SIZE)
}
