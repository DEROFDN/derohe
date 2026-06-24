// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

// Test_AttributionSelf_WritesSenderSlot is the behavioral proof of the AttributionSelf
// engine branch (transaction_build.go): a transfer built with opts.Attribution ==
// AttributionSelf writes the SENDER's own ring slot index into the receiver-readable
// attribution byte (witness_index[0]), deliberately self-doxxing — the opposite of the
// honest default (which writes the receiver slot, witness_index[1]).
//
// It drives the REAL build + receiver-decode path on a simulated chain (cloning the
// scrub test's harness) and asserts the decrypted attribution byte equals the sender's
// slot in the built ring. A ring > 2 is used so the sender slot is a meaningful, distinct
// index; the test re-randomizes the ring until the sender lands in a NON-ZERO slot so the
// "byte == senderSlot" assertion has real teeth (slot 0 is the all-zero default a broken
// branch would also produce). MUTATION CHECK: change the engine branch to write
// witness_index[1] and this test goes RED.
//
// Shares the fixed rpcport with the other sim-chain tests, so it must NOT run in parallel.
func Test_AttributionSelf_WritesSenderSlot(t *testing.T) {

	time.Sleep(time.Millisecond)

	Initialize_LookupTable(1, 1<<17)

	wsrc_temp_db := filepath.Join(os.TempDir(), "self_attr_test_wallet_src.db")
	wdst_temp_db := filepath.Join(os.TempDir(), "self_attr_test_wallet_dst.db")

	os.Remove(wsrc_temp_db)
	os.Remove(wdst_temp_db)

	wsrc, err := Create_Encrypted_Wallet_From_Recovery_Words(wsrc_temp_db, "QWER", "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly")
	if err != nil {
		t.Fatalf("Cannot create encrypted wallet, err %s", err)
	}

	wdst, err := Create_Encrypted_Wallet_From_Recovery_Words(wdst_temp_db, "QWER", "Dekade Spagat Bereich Radclub Yeti Dialekt Unimog Nomade Anlage Hirte Besitz Märzluft Krabbe Nabel Halsader Chefarzt Hering tauchen Neuerung Reifen Umgang Hürde Alchimie Amnesie Reifen")
	if err != nil {
		t.Fatalf("Cannot create encrypted wallet, err %s", err)
	}

	wgenesis, err := Create_Encrypted_Wallet_From_Recovery_Words(wdst_temp_db, "QWER", "perfil lujo faja puma favor pedir detalle doble carbón neón paella cuarto ánimo cuento conga correr dental moneda león donar entero logro realidad acceso doble")
	if err != nil {
		t.Fatalf("Cannot create encrypted wallet, err %s", err)
	}

	// fix genesis tx and genesis tx hash
	genesis_tx := transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, Value: 2012345}}
	copy(genesis_tx.MinerAddress[:], wgenesis.account.Keys.Public.EncodeCompressed())

	config.Testnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	config.Mainnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())

	genesis_block := blockchain.Generate_Genesis_Block()
	config.Testnet.Genesis_Block_Hash = genesis_block.GetHash()
	config.Mainnet.Genesis_Block_Hash = genesis_block.GetHash()

	chain, rpcserver, params := simulator_chain_start()
	_ = params

	defer func() {
		simulator_chain_stop(chain, rpcserver)
		wsrc.Close_Encrypted_Wallet()
		wdst.Close_Encrypted_Wallet()
		os.Remove(wsrc_temp_db)
		os.Remove(wdst_temp_db)
	}()

	globals.Arguments["--daemon-address"] = rpcport

	go Keep_Connectivity()

	if err := chain.Add_TX_To_Pool(wsrc.GetRegistrationTX()); err != nil {
		t.Fatalf("Cannot add regtx to pool err %s", err)
	}
	if err := chain.Add_TX_To_Pool(wdst.GetRegistrationTX()); err != nil {
		t.Fatalf("Cannot add regtx to pool err %s", err)
	}

	for i := 0; i < 5; i++ {
		simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	}

	wgenesis.SetDaemonAddress(rpcport)
	wsrc.SetDaemonAddress(rpcport)
	wdst.SetDaemonAddress(rpcport)
	wgenesis.SetOnlineMode()
	wsrc.SetOnlineMode()
	wdst.SetOnlineMode()

	time.Sleep(time.Second * 2)
	if err = wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatalf("Wallet sync error err %s", err)
	}
	if err = wdst.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatalf("Wallet sync error err %s", err)
	}

	testPayload := rpc.Arguments{
		{Name: rpc.RPC_COMMENT, DataType: rpc.DataString, Value: "self probe"},
		{Name: rpc.RPC_DESTINATION_PORT, DataType: rpc.DataUint64, Value: uint64(123456789)},
	}

	const rs = 4 // ring > 2 so the sender slot is a distinct, meaningful index

	// build with AttributionSelf, re-randomizing the ring until the SENDER lands in a
	// non-zero slot (so "byte == senderSlot" cannot be a coincidence with the all-zero
	// default a broken/honest branch would write).
	var tx *transaction.Transaction
	senderSlot := -1
	srcKey := wsrc.account.Keys.Public.EncodeCompressed()
	for attempt := 0; attempt < 64; attempt++ {
		var berr error
		tx, berr = wsrc.TransferPayload0WithOptions(
			[]rpc.Transfer{{Destination: wdst.GetAddress().String(), Amount: 90000, Payload_RPC: testPayload}},
			rs, false, rpc.Arguments{}, 0, false, TransferOptions{Attribution: AttributionSelf})
		if berr != nil {
			t.Fatalf("cannot create self-attributed transaction: %s", berr)
		}
		if got := len(tx.Payloads[0].Statement.Publickeylist); got != rs {
			t.Fatalf("built ring size %d, expected %d", got, rs)
		}
		senderSlot = -1
		for i, p := range tx.Payloads[0].Statement.Publickeylist {
			if string((*crypto.Point)(p).EncodeCompressed()) == string(srcKey) {
				senderSlot = i
				break
			}
		}
		if senderSlot < 0 {
			t.Fatalf("sender pubkey not found in built ring")
		}
		if senderSlot != 0 {
			break // a non-zero sender slot gives the assertion teeth
		}
	}
	if senderSlot == 0 {
		t.Fatalf("could not build a ring with the sender in a non-zero slot after 64 attempts; "+
			"the byte==senderSlot assertion would have no teeth")
	}

	// decrypt the receiver's payload directly from the built tx (the same 4-line ECDH the
	// scrub test uses) and assert the attribution byte points at the SENDER's own slot.
	rp := tx.Payloads[0].RPCPayload
	ephemeral_pub := new(bn256.G1)
	if err := ephemeral_pub.DecodeCompressed(rp[:33]); err != nil {
		t.Fatalf("cannot decode ephemeral pubkey from built tx: %s", err)
	}
	plain := append([]byte{}, rp[33:]...) // copy: EncryptDecryptUserData mutates in place
	shared_key := crypto.GenerateSharedSecret(wdst.account.Keys.Secret.BigInt(), ephemeral_pub)
	crypto.EncryptDecryptUserData(crypto.Keccak256(shared_key[:], wdst.GetAddress().PublicKey.EncodeCompressed()), plain)
	attrByte := int(plain[0])

	if attrByte != senderSlot {
		t.Fatalf("AttributionSelf must point the byte at the SENDER slot %d, got %d "+
			"(honest mode would write the receiver slot — this is the mutation guard)", senderSlot, attrByte)
	}
}

// Test_AttributionSelf_EndToEnd_ScrubHolds is the end-to-end (build → broadcast → mined →
// receiver-decode) companion to Test_AttributionSelf_WritesSenderSlot, closing the teeth
// gap that the build-only test leaves open (redteam O3): no prior test scanned a
// self-attributed tx through the REAL daemon_communication.go decode path.
//
// It pins the DESIGN-INTENDED behavior (SCOPE-self-attribution.md VERIFY step 2): a CURRENT,
// up-to-date wallet still hides the byte even when the SENDER deliberately chose Self —
// because the #21 scrub keys off ring>2 (sender-chosen ⇒ unverified), NOT off the mode. So
// at ring 4 a Self-attributed transfer must STILL decode with entry.Sender == "" and the
// exported entry.Data[0] == 0. This is the opposite of O1's framing of a "broken feature":
// the current-wallet no-op is the intended, preserved guarantee; Self's only effect is the
// permanent on-chain raw byte for a non-blanking / old / future-break reader — exactly what
// the warning claims and exactly what attributionResultLine now says.
//
// TEETH: this would go RED if a future change made Self bypass the scrub (e.g. forced
// SenderVerified=true, or exported the raw payload for self-mode), which is the silent
// self-doxx-against-current-wallets regression the design forbids. It also gives O3 the
// missing build→decode coverage: the engine writes slot 0, but the receiver layer must be
// shown to consume it coherently with what the CLI reports.
//
// Shares the fixed rpcport with the other sim-chain tests, so it must NOT run in parallel.
func Test_AttributionSelf_EndToEnd_ScrubHolds(t *testing.T) {

	time.Sleep(time.Millisecond)

	Initialize_LookupTable(1, 1<<17)

	wsrc_temp_db := filepath.Join(os.TempDir(), "self_e2e_test_wallet_src.db")
	wdst_temp_db := filepath.Join(os.TempDir(), "self_e2e_test_wallet_dst.db")

	os.Remove(wsrc_temp_db)
	os.Remove(wdst_temp_db)

	wsrc, err := Create_Encrypted_Wallet_From_Recovery_Words(wsrc_temp_db, "QWER", "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly")
	if err != nil {
		t.Fatalf("Cannot create encrypted wallet, err %s", err)
	}

	wdst, err := Create_Encrypted_Wallet_From_Recovery_Words(wdst_temp_db, "QWER", "Dekade Spagat Bereich Radclub Yeti Dialekt Unimog Nomade Anlage Hirte Besitz Märzluft Krabbe Nabel Halsader Chefarzt Hering tauchen Neuerung Reifen Umgang Hürde Alchimie Amnesie Reifen")
	if err != nil {
		t.Fatalf("Cannot create encrypted wallet, err %s", err)
	}

	wgenesis, err := Create_Encrypted_Wallet_From_Recovery_Words(wdst_temp_db, "QWER", "perfil lujo faja puma favor pedir detalle doble carbón neón paella cuarto ánimo cuento conga correr dental moneda león donar entero logro realidad acceso doble")
	if err != nil {
		t.Fatalf("Cannot create encrypted wallet, err %s", err)
	}

	genesis_tx := transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, Value: 2012345}}
	copy(genesis_tx.MinerAddress[:], wgenesis.account.Keys.Public.EncodeCompressed())

	config.Testnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	config.Mainnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())

	genesis_block := blockchain.Generate_Genesis_Block()
	config.Testnet.Genesis_Block_Hash = genesis_block.GetHash()
	config.Mainnet.Genesis_Block_Hash = genesis_block.GetHash()

	chain, rpcserver, params := simulator_chain_start()
	_ = params

	defer func() {
		simulator_chain_stop(chain, rpcserver)
		wsrc.Close_Encrypted_Wallet()
		wdst.Close_Encrypted_Wallet()
		os.Remove(wsrc_temp_db)
		os.Remove(wdst_temp_db)
	}()

	globals.Arguments["--daemon-address"] = rpcport

	go Keep_Connectivity()

	if err := chain.Add_TX_To_Pool(wsrc.GetRegistrationTX()); err != nil {
		t.Fatalf("Cannot add regtx to pool err %s", err)
	}
	if err := chain.Add_TX_To_Pool(wdst.GetRegistrationTX()); err != nil {
		t.Fatalf("Cannot add regtx to pool err %s", err)
	}

	for i := 0; i < 5; i++ {
		simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	}

	wgenesis.SetDaemonAddress(rpcport)
	wsrc.SetDaemonAddress(rpcport)
	wdst.SetDaemonAddress(rpcport)
	wgenesis.SetOnlineMode()
	wsrc.SetOnlineMode()
	wdst.SetOnlineMode()

	time.Sleep(time.Second * 2)
	if err = wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatalf("Wallet sync error err %s", err)
	}
	if err = wdst.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatalf("Wallet sync error err %s", err)
	}

	testPayload := rpc.Arguments{
		{Name: rpc.RPC_COMMENT, DataType: rpc.DataString, Value: "self e2e probe"},
		{Name: rpc.RPC_DESTINATION_PORT, DataType: rpc.DataUint64, Value: uint64(123456789)},
	}

	const rs = 4 // ring > 2: the scrub branch the design must preserve even under Self

	// Build a SELF-attributed transfer, re-randomizing until the sender lands in a NON-ZERO
	// slot so the BUILT byte is provably the sender slot (not a coincidental 0). We then
	// assert that despite the sender choosing Self, the receiver STILL scrubs.
	var tx *transaction.Transaction
	senderSlot := -1
	srcKey := wsrc.account.Keys.Public.EncodeCompressed()
	for attempt := 0; attempt < 64; attempt++ {
		var berr error
		tx, berr = wsrc.TransferPayload0WithOptions(
			[]rpc.Transfer{{Destination: wdst.GetAddress().String(), Amount: 90000, Payload_RPC: testPayload}},
			rs, false, rpc.Arguments{}, 10000, false, TransferOptions{Attribution: AttributionSelf})
		if berr != nil {
			t.Fatalf("cannot create self-attributed transaction: %s", berr)
		}
		if got := len(tx.Payloads[0].Statement.Publickeylist); got != rs {
			t.Fatalf("built ring size %d, expected %d", got, rs)
		}
		senderSlot = -1
		for i, p := range tx.Payloads[0].Statement.Publickeylist {
			if string((*crypto.Point)(p).EncodeCompressed()) == string(srcKey) {
				senderSlot = i
				break
			}
		}
		if senderSlot < 0 {
			t.Fatalf("sender pubkey not found in built ring")
		}
		if senderSlot != 0 {
			break // a non-zero sender slot proves the built byte really is the sender slot
		}
	}
	if senderSlot == 0 {
		t.Fatalf("could not build a ring with the sender in a non-zero slot after 64 attempts")
	}

	// Sanity: the BUILT byte really is the (non-zero) sender slot before broadcast — so any
	// post-decode scrub is the receiver layer's doing, not an already-zero byte.
	{
		rp := tx.Payloads[0].RPCPayload
		eph := new(bn256.G1)
		if err := eph.DecodeCompressed(rp[:33]); err != nil {
			t.Fatalf("cannot decode ephemeral pubkey from built tx: %s", err)
		}
		plain := append([]byte{}, rp[33:]...)
		sk := crypto.GenerateSharedSecret(wdst.account.Keys.Secret.BigInt(), eph)
		crypto.EncryptDecryptUserData(crypto.Keccak256(sk[:], wdst.GetAddress().PublicKey.EncodeCompressed()), plain)
		if int(plain[0]) != senderSlot {
			t.Fatalf("pre-broadcast self byte = %d, expected sender slot %d", int(plain[0]), senderSlot)
		}
	}

	// Broadcast → mine → receiver scans via the REAL decode path.
	var dtx transaction.Transaction
	dtx.Deserialize(tx.Serialize())

	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	wsrc.Sync_Wallet_Memory_With_Daemon()
	wdst.Sync_Wallet_Memory_With_Daemon()

	if err := chain.Add_TX_To_Pool(&dtx); err != nil {
		t.Fatalf("cannot add self-attributed transfer to pool: %s", err)
	}
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	wgenesis.Sync_Wallet_Memory_With_Daemon()

	time.Sleep(time.Second)
	wdst.Sync_Wallet_Memory_With_Daemon()

	minHeight := uint64(0)
	maxHeight := uint64(chain.Get_Height()) + 1
	dstEntries := wdst.Show_Transfers(crypto.ZEROHASH, false, true, false, minHeight, maxHeight, "", "", 0, 0)
	if len(dstEntries) != 1 {
		t.Fatalf("receiver expected exactly 1 incoming transfer, got %d", len(dstEntries))
	}
	e := dstEntries[0]

	// the payload itself must survive decode (scrub only touches the leading slot byte).
	args, perr := e.ProcessPayload()
	if perr != nil {
		t.Fatalf("self-attributed payload did not parse after decode: %s", perr)
	}
	if !args.HasValue(rpc.RPC_COMMENT, rpc.DataString) {
		t.Fatalf("decrypted self payload lost its comment arg")
	}

	// THE DESIGN-INTENDED INVARIANT: even though the SENDER chose Self (built byte == its own
	// non-zero slot), a CURRENT wallet at ring>2 still treats the byte as unverified and
	// scrubs it. Self does NOT defeat #21 against an up-to-date recipient — coherent with
	// what the CLI reports ("a current wallet still hides it") and with the warning.
	if e.RingSize != rs {
		t.Fatalf("decoded ring size %d, expected %d", e.RingSize, rs)
	}
	if e.SenderVerified {
		t.Fatalf("ring>2 self-attributed: SenderVerified must be false (sender-chosen byte is unverified)")
	}
	if e.Sender != "" {
		t.Fatalf("ring>2 self-attributed: entry.Sender must be scrubbed to empty even under Self, got %q", e.Sender)
	}
	if len(e.Data) == 0 {
		t.Fatalf("entry.Data unexpectedly empty")
	}
	if e.Data[0] != 0x00 {
		t.Fatalf("ring>2 self-attributed: exported entry.Data[0] must be zeroed (scrub holds under Self), got 0x%02x", e.Data[0])
	}
}
