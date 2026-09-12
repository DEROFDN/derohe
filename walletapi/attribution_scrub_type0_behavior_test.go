// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package walletapi

import (
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
)

// Test_Attribution_Scrub_Behavior_Type0 is the legacy-decode-path companion to
// Test_Attribution_Scrub_Behavior. That test drives the CBOR_V2 receive-decode branch
// (TransferPayload0 always emits V2). The receiver, however, dispatches on the
// sender-controlled RPCType byte, so the legacy type-0 (ENCRYPTED_DEFAULT_PAYLOAD_CBOR)
// decode branch in daemon_communication.go is equally reachable — and its export scrub was
// covered only by a textual grep, not a behavioral assertion. Forging entry.Sender at the
// type-0 site (grep patterns intact) previously left every test GREEN.
//
// This test builds a REAL, consensus-valid transaction whose payload uses the legacy type-0
// encoding (via the buildLegacyPayloadCBOR seam — the payload bytes are bound into the txid
// the proof signs, so the encoding cannot be swapped after the fact), mines it, syncs the
// receiver, and asserts on the EXPORTED entry that the unverified sender attribution is
// scrubbed exactly as the V2 path is asserted today:
//   - entry.PayloadType == ENCRYPTED_DEFAULT_PAYLOAD_CBOR   (proves the type-0 branch ran)
//   - entry.SenderVerified == false                          (ring > 2, sender-chosen index)
//   - entry.Sender == ""                                     (claimed sender blanked)
//   - entry.Data[0] == 0x00                                  (attribution slot byte zeroed)
//   - the decrypted payload still parses                     (control: not a vacuous pass)
func Test_Attribution_Scrub_Behavior_Type0(t *testing.T) {

	time.Sleep(time.Millisecond)

	Initialize_LookupTable(1, 1<<17)

	wsrc_temp_db := filepath.Join(os.TempDir(), "scrub_type0_wallet_src.db")
	wdst_temp_db := filepath.Join(os.TempDir(), "scrub_type0_wallet_dst.db")

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
		{Name: rpc.RPC_COMMENT, DataType: rpc.DataString, Value: "type0 scrub probe"},
		{Name: rpc.RPC_DESTINATION_PORT, DataType: rpc.DataUint64, Value: uint64(123456789)},
	}

	const rs = 4 // ring > 2: sender attribution index is unauthenticated and must be scrubbed

	wsrc.Sync_Wallet_Memory_With_Daemon()
	wdst.Sync_Wallet_Memory_With_Daemon()

	wsrc.account.Ringsize = rs

	// Build the transfer with the LEGACY type-0 payload encoding. The seam only changes the
	// payload bytes; the ring, statement and zk-proof are built exactly as in production, so
	// the tx passes consensus verification. The honest pre-scrub attribution byte is the
	// receiver's own ring slot (transaction_build.go). At ring 4 that slot is 0 in ~25% of
	// permutations, where the byte is ALREADY 0x00 and the entry.Data[0]==0 assertion would
	// pass even with a broken scrub. Rebuild (re-randomizing the ring) until the receiver
	// lands in a NON-ZERO slot: then entry.Data[0]==0 can only be the scrub's doing.
	var tx *transaction.Transaction
	recvSlot := -1
	for attempt := 0; attempt < 64; attempt++ {
		buildLegacyPayloadCBOR = true
		var berr error
		tx, berr = wsrc.TransferPayload0([]rpc.Transfer{{Destination: wdst.GetAddress().String(), Amount: 90000, Payload_RPC: testPayload}}, 0, false, rpc.Arguments{}, 10000, false)
		buildLegacyPayloadCBOR = false
		if berr != nil {
			t.Fatalf("cannot create type-0 transaction, err %s", berr)
		}
		if got := len(tx.Payloads[0].Statement.Publickeylist); got != rs {
			t.Fatalf("built ring size %d, expected %d", got, rs)
		}
		if tx.Payloads[0].RPCType != transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR {
			t.Fatalf("seam did not emit type-0: RPCType=%d, expected %d", tx.Payloads[0].RPCType, transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR)
		}
		recvSlot = -1
		dstKey := wdst.account.Keys.Public.EncodeCompressed()
		for i, p := range tx.Payloads[0].Statement.Publickeylist {
			if string((*crypto.Point)(p).EncodeCompressed()) == string(dstKey) {
				recvSlot = i
				break
			}
		}
		if recvSlot < 0 {
			t.Fatalf("receiver pubkey not found in built ring")
		}
		if recvSlot != 0 {
			break // need a non-zero honest attribution byte for real teeth
		}
	}
	if recvSlot == 0 {
		t.Fatalf("could not build a ring with the receiver in a non-zero slot after 64 attempts; " +
			"the entry.Data[0]==0 assertion would have no teeth")
	}

	var dtx transaction.Transaction
	dtx.Deserialize(tx.Serialize())

	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	wsrc.Sync_Wallet_Memory_With_Daemon()
	wdst.Sync_Wallet_Memory_With_Daemon()

	if err := chain.Add_TX_To_Pool(&dtx); err != nil {
		t.Fatalf("cannot add type-0 transfer to pool, err %s", err)
	}

	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
	wgenesis.Sync_Wallet_Memory_With_Daemon()

	time.Sleep(time.Second)
	wdst.Sync_Wallet_Memory_With_Daemon()

	minHeight := uint64(0)
	maxHeight := uint64(chain.Get_Height()) + 1

	dstEntries := wdst.Show_Transfers(crypto.ZEROHASH, false, true, false, minHeight, maxHeight, "", "", 0, 0)
	if len(dstEntries) != 1 {
		t.Fatalf("receiver expected 1 transfer, got %d", len(dstEntries))
	}

	e := dstEntries[0]

	// CONTROL: the entry must have been produced by the legacy type-0 decode branch. Without
	// this, a test that never exercised type-0 could still pass — the whole point of F2.
	if e.PayloadType != transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR {
		t.Fatalf("entry did NOT traverse the type-0 decode path: PayloadType=%d, expected %d",
			e.PayloadType, transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR)
	}

	// CONTROL: the decrypted payload must survive the scrub intact (scrub only touches the
	// leading attribution slot byte). A garbled decode would fail here, so the scrub
	// assertions below cannot pass merely because decoding produced junk.
	args, err := e.ProcessPayload()
	if err != nil {
		t.Fatalf("type-0 payload did not parse after decode: %s", err)
	}
	if !args.HasValue(rpc.RPC_COMMENT, rpc.DataString) {
		t.Fatalf("type-0 decrypted payload lost its comment arg after scrub")
	}

	if e.RingSize != rs {
		t.Fatalf("entry RingSize %d, expected %d", e.RingSize, rs)
	}
	if e.SenderVerified {
		t.Fatalf("ring %d: SenderVerified must be false for a sender-chosen attribution index", rs)
	}
	if e.Sender != "" {
		t.Fatalf("ring %d: unverified Sender must be scrubbed to empty, got %q", rs, e.Sender)
	}
	if len(e.Data) == 0 {
		t.Fatalf("ring %d: entry.Data unexpectedly empty", rs)
	}
	if e.Data[0] != 0x00 {
		t.Fatalf("ring %d: attribution slot byte entry.Data[0] must be zeroed, got 0x%02x — "+
			"it re-derives the claimed sender via the public Publickeylist", rs, e.Data[0])
	}
}
