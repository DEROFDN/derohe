// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/transaction"
)

// Test_CuratedProbe_Classification locks the decoy-probe error classification
// (PR #22 review finding #3).
//
// The registration probe in curatedRingCandidates cannot see WHY
// GetEncryptedBalanceAtTopoHeight failed: for a decoy address (never self, always
// zero SCID) both a genuine "Account Unregistered" daemon verdict and a transport
// failure return as an opaque error. Treating every failure as "decoy invalid" means
// a transient daemon/RPC blip in non-Strict mode silently drops EVERY preferred decoy
// and the user signs a fully random ring believing curation was applied.
//
// Post-fix contract, pinned here:
//   - "Account Unregistered" verdict → unchanged: Strict hard-errors, lenient skips;
//   - any other probe failure → hard error in BOTH modes ("could not verify …"), never
//     a silent drop.
//
// The transport failure is injected deterministically: the client websocket is closed
// directly, which leaves IsDaemonOnline() true (it only checks WS/RPC non-nil), so the
// failure occurs genuinely inside the probe's rpc_client.Call. Keep_Connectivity is
// deliberately NOT started — it has no quit path and would heal the connection on a
// ~5s cadence, racing the assertion. Shares the fixed rpcport — must NOT run in
// parallel with other simulator-backed tests.
func Test_CuratedProbe_Classification(t *testing.T) {
	Initialize_LookupTable(1, 1<<17)

	mkwallet := func(name, words string) *Wallet_Disk {
		db := filepath.Join(os.TempDir(), "probe_cls_"+name+".db")
		os.Remove(db)
		t.Cleanup(func() { os.Remove(db) })
		w, err := Create_Encrypted_Wallet_From_Recovery_Words(db, "QWER", words)
		if err != nil {
			t.Fatalf("cannot create wallet %s: %s", name, err)
		}
		return w
	}

	wsrc := mkwallet("src", "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly")
	wdecoy := mkwallet("decoy", "Dekade Spagat Bereich Radclub Yeti Dialekt Unimog Nomade Anlage Hirte Besitz Märzluft Krabbe Nabel Halsader Chefarzt Hering tauchen Neuerung Reifen Umgang Hürde Alchimie Amnesie Reifen")
	wgenesis := mkwallet("genesis", "perfil lujo faja puma favor pedir detalle doble carbón neón paella cuarto ánimo cuento conga correr dental moneda león donar entero logro realidad acceso doble")

	// wunreg supplies a valid, never-registered address (in-memory, no chain presence).
	wunreg, err := Create_Encrypted_Wallet_Random_Memory("")
	if err != nil {
		t.Fatalf("cannot create in-memory wallet: %s", err)
	}
	defer wunreg.Close_Encrypted_Wallet()

	genesis_tx := transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, Value: 2012345}}
	copy(genesis_tx.MinerAddress[:], wgenesis.account.Keys.Public.EncodeCompressed())
	config.Testnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	config.Mainnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	genesis_block := blockchain.Generate_Genesis_Block()
	config.Testnet.Genesis_Block_Hash = genesis_block.GetHash()
	config.Mainnet.Genesis_Block_Hash = genesis_block.GetHash()

	chain, rpcserver, _ := simulator_chain_start()
	defer simulator_chain_stop(chain, rpcserver)
	globals.Arguments["--daemon-address"] = rpcport

	if err := chain.Add_TX_To_Pool(wsrc.GetRegistrationTX()); err != nil {
		t.Fatalf("regtx src: %s", err)
	}
	if err := chain.Add_TX_To_Pool(wdecoy.GetRegistrationTX()); err != nil {
		t.Fatalf("regtx decoy: %s", err)
	}
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)

	wsrc.SetDaemonAddress(rpcport)
	wsrc.SetOnlineMode()

	// Synchronous connect, no Keep_Connectivity (see doc comment).
	if err := Connect(""); err != nil {
		t.Fatalf("cannot connect to sim daemon: %s", err)
	}

	var zeroscid crypto.Hash
	registered := wdecoy.GetAddress().String()
	unregistered := wunreg.GetAddress().String()

	// ── healthy connection: the verdict path is unchanged ──

	if _, curated, err := wsrc.curatedRingCandidates(zeroscid, "", &RingPreference{
		PreferredDecoys: []string{unregistered}}, 126, nil, nil); err != nil || curated != 0 {
		t.Fatalf("lenient unregistered decoy must be skipped without error, got curated=%d err=%v", curated, err)
	}
	if _, _, err := wsrc.curatedRingCandidates(zeroscid, "", &RingPreference{
		PreferredDecoys: []string{unregistered}, Strict: true}, 126, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "not registered") {
		t.Fatalf("strict unregistered decoy must hard-error with the registration verdict, got: %v", err)
	}
	if _, curated, err := wsrc.curatedRingCandidates(zeroscid, "", &RingPreference{
		PreferredDecoys: []string{registered}}, 126, nil, nil); err != nil || curated != 1 {
		t.Fatalf("registered decoy must validate on a healthy connection, got curated=%d err=%v", curated, err)
	}

	// ── transport failure: probe errors must surface, never silently drop curation ──

	rpc_client.WS.Close()
	if !IsDaemonOnline() {
		t.Fatal("injection premise broken: IsDaemonOnline must stay true after WS.Close")
	}

	if _, curated, err := wsrc.curatedRingCandidates(zeroscid, "", &RingPreference{
		PreferredDecoys: []string{registered}}, 126, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "could not verify preferred decoy") {
		t.Fatalf("lenient mode silently abandoned curation on a transport failure (finding #3): curated=%d err=%v", curated, err)
	}
	if _, _, err := wsrc.curatedRingCandidates(zeroscid, "", &RingPreference{
		PreferredDecoys: []string{registered}, Strict: true}, 126, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "could not verify preferred decoy") {
		t.Fatalf("strict mode must report the probe failure, not a registration verdict, got: %v", err)
	}
}
