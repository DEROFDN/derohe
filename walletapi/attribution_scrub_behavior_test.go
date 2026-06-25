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
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

// Test_Attribution_Scrub_Behavior is the behavioral companion to the source-level
// grep guard (Test_AttributionExportGuard_UnverifiedSlotByteScrubbed). The grep guard
// proves the scrub TEXT is present at both decode sites; this test drives the REAL
// receiver decode path end-to-end on a simulated chain and asserts the scrub's effect
// on the exported Entry fields. A logically-wrong-but-textually-present scrub (inverted
// condition, wrong index, wrong RingSize comparison) passes the grep guard but FAILS here.
//
// It asserts the contract for both cases:
//   - ring == 2 (verified, structural): entry.Sender is populated, entry.Data[0] (the
//     attribution slot byte) is preserved, SenderVerified == true.
//   - ring  > 2 (unverified, sender-chosen byte): entry.Sender == "", entry.Data[0] == 0,
//     SenderVerified == false. The decrypted Payload (parsed args) survives in both cases.
func Test_Attribution_Scrub_Behavior(t *testing.T) {

	time.Sleep(time.Millisecond)

	Initialize_LookupTable(1, 1<<17)

	wsrc_temp_db := filepath.Join(os.TempDir(), "scrub_test_wallet_src.db")
	wdst_temp_db := filepath.Join(os.TempDir(), "scrub_test_wallet_dst.db")
	wgenesis_temp_db := filepath.Join(os.TempDir(), "scrub_test_wallet_genesis.db")

	os.Remove(wsrc_temp_db)
	os.Remove(wdst_temp_db)
	os.Remove(wgenesis_temp_db)

	wsrc, err := Create_Encrypted_Wallet_From_Recovery_Words(wsrc_temp_db, "QWER", "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly")
	if err != nil {
		t.Fatalf("Cannot create encrypted wallet, err %s", err)
	}

	wdst, err := Create_Encrypted_Wallet_From_Recovery_Words(wdst_temp_db, "QWER", "Dekade Spagat Bereich Radclub Yeti Dialekt Unimog Nomade Anlage Hirte Besitz Märzluft Krabbe Nabel Halsader Chefarzt Hering tauchen Neuerung Reifen Umgang Hürde Alchimie Amnesie Reifen")
	if err != nil {
		t.Fatalf("Cannot create encrypted wallet, err %s", err)
	}

	wgenesis, err := Create_Encrypted_Wallet_From_Recovery_Words(wgenesis_temp_db, "QWER", "perfil lujo faja puma favor pedir detalle doble carbón neón paella cuarto ánimo cuento conga correr dental moneda león donar entero logro realidad acceso doble")
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
		wgenesis.Close_Encrypted_Wallet()
		os.Remove(wsrc_temp_db)
		os.Remove(wdst_temp_db)
		os.Remove(wgenesis_temp_db)
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
		{Name: rpc.RPC_COMMENT, DataType: rpc.DataString, Value: "scrub probe"},
		{Name: rpc.RPC_DESTINATION_PORT, DataType: rpc.DataUint64, Value: uint64(123456789)},
	}

	// send one transfer at each ring size: index 0 = ring 2 (verified control),
	// index 1 = ring 4 (unverified, triggers the scrub).
	ringSizes := []int{2, 4}

	for idx, rs := range ringSizes {
		wsrc.Sync_Wallet_Memory_With_Daemon()
		wdst.Sync_Wallet_Memory_With_Daemon()

		wsrc.account.Ringsize = rs

		// The honest pre-scrub attribution byte is witness_index[1] (transaction_build.go:187) —
		// the RECEIVER's OWN ring slot index. At ring 4 the receiver lands in slot 0 in 25% of
		// valid permutations, in which case the honest byte is ALREADY 0x00 and a post-decode
		// entry.Data[0]==0 assertion passes EVEN IF THE SCRUB IS BROKEN (coincidence, not the
		// scrub). To give the ring>2 assertion real teeth we rebuild (re-randomizing the ring)
		// until the receiver lands in a NON-ZERO slot: then entry.Data[0]==0 can ONLY be the
		// scrub's doing. Ring 2 is exempt — its byte is protocol-pinned, not scrub-asserted.
		var tx *transaction.Transaction
		recvSlot := -1
		for attempt := 0; attempt < 64; attempt++ {
			var berr error
			tx, berr = wsrc.TransferPayload0([]rpc.Transfer{{Destination: wdst.GetAddress().String(), Amount: 90000, Payload_RPC: testPayload}}, 0, false, rpc.Arguments{}, 10000, false)
			if berr != nil {
				t.Fatalf("ring %d (send %d): cannot create transaction, err %s", rs, idx, berr)
			}
			if got := len(tx.Payloads[0].Statement.Publickeylist); got != rs {
				t.Fatalf("ring %d (send %d): built ring size %d, expected %d", rs, idx, got, rs)
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
				t.Fatalf("ring %d (send %d): receiver pubkey not found in built ring", rs, idx)
			}
			if rs == 2 || recvSlot != 0 {
				break // ring 2 needs no teeth; ring>2 needs a non-zero honest byte
			}
		}
		if rs > 2 && recvSlot == 0 {
			t.Fatalf("ring %d (send %d): could not build a ring with the receiver in a non-zero slot "+
				"after 64 attempts; the entry.Data[0]==0 assertion would have no teeth", rs, idx)
		}

		// BEHAVIORAL GUARD (honest attribution invariant): for a ring > 2 honest transfer,
		// decrypt the receiver's payload directly from the built tx and assert the plaintext
		// attribution byte points at the RECEIVER's own ring slot (witness_index[1]), never
		// the sender's slot 0. This pins the same invariant the source-grep guard
		// (Test_AttributionGuard_HonestWritesReceiverIndex) protects, but behaviorally — so a
		// regression that reassigns attrIndex with `=` below the matched `:=` line (which the
		// grep cannot see) fails here. recvSlot is guaranteed non-zero by the loop above, so
		// "byte == recvSlot" is a real assertion, not a coincidence with the sender slot.
		if rs > 2 {
			rp := tx.Payloads[0].RPCPayload
			ephemeral_pub := new(bn256.G1)
			if err := ephemeral_pub.DecodeCompressed(rp[:33]); err != nil {
				t.Fatalf("ring %d: cannot decode ephemeral pubkey from built tx: %s", rs, err)
			}
			plain := append([]byte{}, rp[33:]...) // copy: EncryptDecryptUserData mutates in place
			shared_key := crypto.GenerateSharedSecret(wdst.account.Keys.Secret.BigInt(), ephemeral_pub)
			crypto.EncryptDecryptUserData(crypto.Keccak256(shared_key[:], wdst.GetAddress().PublicKey.EncodeCompressed()), plain)
			honestByte := int(plain[0])
			if honestByte == 0 {
				t.Fatalf("ring %d: honest attribution byte is 0 (the SENDER slot) — a sender-revealing "+
					"regression; honest mode must point at the receiver slot %d", rs, recvSlot)
			}
			if honestByte != recvSlot {
				t.Fatalf("ring %d: honest attribution byte is %d, expected the receiver's own slot %d "+
					"(witness_index[1]); honest mode must write the receiver slot, not slot %d", rs, honestByte, recvSlot, honestByte)
			}
		}

		var dtx transaction.Transaction
		dtx.Deserialize(tx.Serialize())

		simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
		wsrc.Sync_Wallet_Memory_With_Daemon()
		wdst.Sync_Wallet_Memory_With_Daemon()

		if err := chain.Add_TX_To_Pool(&dtx); err != nil {
			t.Fatalf("ring %d (send %d): cannot add transfer to pool, err %s", rs, idx, err)
		}

		simulator_chain_mineblock(chain, wgenesis.GetAddress(), t)
		wgenesis.Sync_Wallet_Memory_With_Daemon()
	}

	time.Sleep(time.Second)
	wdst.Sync_Wallet_Memory_With_Daemon()

	minHeight := uint64(0)
	maxHeight := uint64(chain.Get_Height()) + 1

	dstEntries := wdst.Show_Transfers(crypto.ZEROHASH, false, true, false, minHeight, maxHeight, "", "", 0, 0)
	if len(dstEntries) != len(ringSizes) {
		t.Fatalf("receiver expected %d transfers, got %d", len(ringSizes), len(dstEntries))
	}

	var sawVerified, sawUnverified bool
	for _, e := range dstEntries {
		// the decrypted payload must survive intact regardless of scrub: the comment
		// arg parses in both cases (scrub only touches the leading attribution slot byte).
		args, err := e.ProcessPayload()
		if err != nil {
			t.Fatalf("ring %d: payload did not parse after decode: %s", e.RingSize, err)
		}
		if !args.HasValue(rpc.RPC_COMMENT, rpc.DataString) {
			t.Fatalf("ring %d: decrypted payload lost its comment arg after scrub", e.RingSize)
		}

		switch e.RingSize {
		case 2:
			sawVerified = true
			if !e.SenderVerified {
				t.Fatalf("ring 2: SenderVerified must be true (structural attribution)")
			}
			if e.Sender == "" {
				t.Fatalf("ring 2: verified Sender must be populated, got empty")
			}
			if len(e.Data) == 0 {
				t.Fatalf("ring 2: entry.Data unexpectedly empty")
			}
			// ring-2 attribution byte is protocol-pinned and intentionally preserved:
			// the receiver overrides sender_idx to the counterparty slot, so a zero
			// here would only be coincidental. The contract is that it is NOT scrubbed,
			// which is proven by Sender being populated above.
		default: // ring > 2
			sawUnverified = true
			if e.SenderVerified {
				t.Fatalf("ring %d: SenderVerified must be false for sender-chosen attribution", e.RingSize)
			}
			if e.Sender != "" {
				t.Fatalf("ring %d: unverified Sender must be scrubbed to empty, got %q", e.RingSize, e.Sender)
			}
			if len(e.Data) == 0 {
				t.Fatalf("ring %d: entry.Data unexpectedly empty", e.RingSize)
			}
			if e.Data[0] != 0x00 {
				t.Fatalf("ring %d: attribution slot byte entry.Data[0] must be zeroed, got 0x%02x — "+
					"it re-derives the claimed sender via the public Publickeylist", e.RingSize, e.Data[0])
			}
		}
	}

	if !sawVerified {
		t.Fatalf("no ring-2 (verified) transfer observed; control case did not run")
	}
	if !sawUnverified {
		t.Fatalf("no ring>2 (unverified) transfer observed; scrub case did not run")
	}
}
