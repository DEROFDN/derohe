// Copyright 2017-2018 DERO Project. All rights reserved.
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
	"reflect"
	"testing"
	"time"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

// This will test that the payload can be decrypted by sender and receiver
func Test_Payload_TX(t *testing.T) {

	time.Sleep(time.Millisecond)

	Initialize_LookupTable(1, 1<<17)

	wsrc_temp_db := filepath.Join(os.TempDir(), "1dero_temporary_test_wallet_src.db")
	wdst_temp_db := filepath.Join(os.TempDir(), "1dero_temporary_test_wallet_dst.db")

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
		wsrc.Close_Encrypted_Wallet()
		wdst.Close_Encrypted_Wallet()
		wgenesis.Close_Encrypted_Wallet()
		simulator_chain_stop(chain, rpcserver)
		os.Remove(wsrc_temp_db) // cleanup after test
		os.Remove(wdst_temp_db)
	}()

	connectivity := Start_Connectivity()
	defer connectivity.Stop()

	t.Logf("src %s\n", wsrc.GetAddress())
	t.Logf("dst %s\n", wdst.GetAddress())

	if err := chain.Add_TX_To_Pool(wsrc.GetRegistrationTX()); err != nil {
		t.Fatalf("Cannot add regtx to pool err %s", err)
	}
	if err := chain.Add_TX_To_Pool(wdst.GetRegistrationTX()); err != nil {
		t.Fatalf("Cannot add regtx to pool err %s", err)
	}

	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t) // mine a block at tip
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t) // mine a block at tip
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t) // mine a block at tip
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t) // mine a block at tip
	simulator_chain_mineblock(chain, wgenesis.GetAddress(), t) // mine a block at tip

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

	wsrc.account.Ringsize = 2
	wdst.account.Ringsize = 2

	var testPayload = rpc.Arguments{
		{
			Name:     rpc.RPC_COMMENT,
			DataType: rpc.DataString,
			Value:    "hello dero, test comment",
		},
		{
			Name:     rpc.RPC_DESTINATION_PORT,
			DataType: rpc.DataUint64,
			Value:    uint64(123456789),
		},
	}

	expectedTransfers := 8
	expectedSenderBalance := expectedSimulatorRegistrationBalance

	for i := 0; i < expectedTransfers; i++ {
		wsrc.Sync_Wallet_Memory_With_Daemon()
		wdst.Sync_Wallet_Memory_With_Daemon()

		t.Logf("Chain height %d\n", chain.Get_Height())

		tx, err := wsrc.TransferPayload0([]rpc.Transfer{{Destination: wdst.GetAddress().String(), Amount: 90000, Payload_RPC: testPayload}}, 0, false, rpc.Arguments{}, 10000, false)
		if err != nil {
			t.Fatalf("Cannot create transaction %d, err %s", i, err)
		}

		var dtx transaction.Transaction
		dtx.Deserialize(tx.Serialize())
		expectedSenderBalance -= 90000 + tx.Fees()

		simulator_chain_mineblock(chain, wgenesis.GetAddress(), t) // mine a block at tip
		wsrc.Sync_Wallet_Memory_With_Daemon()
		wdst.Sync_Wallet_Memory_With_Daemon()

		if err := chain.Add_TX_To_Pool(&dtx); err != nil {
			t.Fatalf("Cannot add transfer tx %d to pool, err %s", i, err)
		}

		simulator_chain_mineblock(chain, wgenesis.GetAddress(), t) // mine a block at tip
		wgenesis.Sync_Wallet_Memory_With_Daemon()
	}

	wdst.Sync_Wallet_Memory_With_Daemon()
	wsrc.Sync_Wallet_Memory_With_Daemon()

	expectedReceiverBalance := expectedSimulatorRegistrationBalance + uint64(expectedTransfers)*90000
	if wdst.account.Balance_Mature != expectedReceiverBalance {
		t.Fatalf("Failed receiver balance check, expected %d actual %d", expectedReceiverBalance, wdst.account.Balance_Mature)
	}

	if wsrc.account.Balance_Mature != expectedSenderBalance {
		t.Fatalf("Failed sender balance check, expected %d actual %d", expectedSenderBalance, wsrc.account.Balance_Mature)
	}

	time.Sleep(time.Second)

	minHeight := uint64(0)
	maxHeight := uint64(chain.Get_Height()) + 1
	coinbase := false

	// Check receiver
	dstEntries := wdst.Show_Transfers(crypto.ZEROHASH, coinbase, true, false, minHeight, maxHeight, "", "", 0, 0)
	if len(dstEntries) != expectedTransfers {
		t.Fatalf("Receiver transfer missing, expected %d actual %d", expectedTransfers, len(dstEntries))
	}

	for i, transfer := range dstEntries {
		args, err := transfer.ProcessPayload()
		if err != nil {
			t.Fatalf("Could not process receiver payload %d: %s", i, err)
		}

		if !args.HasValue(rpc.RPC_COMMENT, rpc.DataString) {
			t.Fatalf("Receiver transfer %d does not have string comment", i)
		}

		if !args.HasValue(rpc.RPC_DESTINATION_PORT, rpc.DataUint64) {
			t.Fatalf("Receiver transfer %d does not have uint64 dst port", i)
		}

		if !reflect.DeepEqual(args.Value(rpc.RPC_COMMENT, rpc.DataString), testPayload.Value(rpc.RPC_COMMENT, rpc.DataString)) {
			t.Fatalf("Receiver transfer %d comment is not equal", i)
		}

		if !reflect.DeepEqual(args.Value(rpc.RPC_DESTINATION_PORT, rpc.DataUint64), testPayload.Value(rpc.RPC_DESTINATION_PORT, rpc.DataUint64)) {
			t.Fatalf("Receiver transfer %d dst port is not equal", i)
		}
	}

	// Check sender
	srcEntries := wsrc.Show_Transfers(crypto.ZEROHASH, coinbase, false, true, minHeight, maxHeight, "", "", 0, 0)
	if len(srcEntries) != expectedTransfers {
		t.Fatalf("Sender transfer missing, expected %d actual %d", expectedTransfers, len(srcEntries))
	}

	for i, transfer := range srcEntries {
		args, err := transfer.ProcessPayload()
		if err != nil {
			t.Fatalf("Could not process sender payload %d: %s", i, err)
		}

		if !args.HasValue(rpc.RPC_COMMENT, rpc.DataString) {
			t.Fatalf("Sender transfer %d does not have string comment", i)
		}

		if !args.HasValue(rpc.RPC_DESTINATION_PORT, rpc.DataUint64) {
			t.Fatalf("Sender transfer %d does not have uint64 dst port", i)
		}

		if !reflect.DeepEqual(args.Value(rpc.RPC_COMMENT, rpc.DataString), testPayload.Value(rpc.RPC_COMMENT, rpc.DataString)) {
			t.Fatalf("Sender transfer %d comment is not equal", i)
		}

		if !reflect.DeepEqual(args.Value(rpc.RPC_DESTINATION_PORT, rpc.DataUint64), testPayload.Value(rpc.RPC_DESTINATION_PORT, rpc.DataUint64)) {
			t.Fatalf("Sender transfer %d dst port is not equal", i)
		}
	}
}
