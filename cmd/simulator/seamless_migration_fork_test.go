package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/dvm"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/derohe/walletapi"
	"github.com/deroproject/graviton"
	"golang.org/x/xerrors"
)

func newMigrationSimulatorWallet(t *testing.T, name string) *walletapi.Wallet_Disk {
	t.Helper()
	wallet, err := walletapi.Create_Encrypted_Wallet(filepath.Join(t.TempDir(), name+".db"), "test-only", crypto.RandomScalarBNRed())
	if err != nil {
		t.Fatalf("create %s wallet: %v", name, err)
	}
	return wallet
}

func syncMigrationSimulatorWallet(t *testing.T, wallet *walletapi.Wallet_Disk) {
	t.Helper()
	if err := wallet.Sync_Wallet_Memory_With_Daemon(); err != nil {
		t.Fatalf("sync wallet %s: %v", wallet.GetAddress().String(), err)
	}
}

// connectSimulatorDaemon waits for the simulator RPC server to accept the
// websocket connection and then keeps the shared wallet connection alive.
func connectSimulatorDaemon(t *testing.T, rpcPort string) {
	t.Helper()
	globals.Arguments["--daemon-address"] = rpcPort
	walletapi.SetDaemonAddress(rpcPort)

	deadline := time.Now().Add(10 * time.Second)
	var err error
	for {
		if err = walletapi.Connect(rpcPort); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("connect simulator daemon at %s: %v", rpcPort, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	go walletapi.Keep_Connectivity()
}

func closeSimulatorWallets(wallets ...*walletapi.Wallet_Disk) {
	for _, wallet := range wallets {
		if wallet != nil {
			wallet.Close_Encrypted_Wallet()
		}
	}
}

func migrationSimulatorBalance(t *testing.T, wallet *walletapi.Wallet_Disk) uint64 {
	t.Helper()
	var native crypto.Hash
	balance, _, err := wallet.GetDecryptedBalanceAtTopoHeight(native, -1, wallet.GetAddress().String())
	if err != nil {
		t.Fatalf("read wallet balance %s: %v", wallet.GetAddress().String(), err)
	}
	return balance
}

func awaitMigrationSpendableBalance(t *testing.T, chain *blockchain.Blockchain, miner, wallet *walletapi.Wallet_Disk, minimum uint64) {
	t.Helper()
	var native crypto.Hash
	const maxAdvance = 6
	for attempt := 0; attempt < maxAdvance; attempt++ {
		_, nonce, _, _, err := wallet.GetEncryptedBalanceAtTopoHeight(native, -1, wallet.GetAddress().String())
		if err != nil {
			t.Fatalf("read source nonce before migration re-inclusion: %v", err)
		}
		daemonTopo := walletapi.Get_Daemon_TopoHeight()
		selectedTopo := int64(-1)
		if daemonTopo >= int64(nonce)+3 {
			selectedTopo = daemonTopo - 3
		}
		balance, _, err := wallet.GetDecryptedBalanceAtTopoHeight(native, selectedTopo, wallet.GetAddress().String())
		if err == nil && balance >= minimum {
			return
		}
		if attempt == maxAdvance-1 {
			t.Fatalf("wallet spend snapshot at topoheight %d has balance %d; want at least %d after %d advances (err=%v)", selectedTopo, balance, minimum, maxAdvance, err)
		}
		simulator_chain_mineblock(chain, miner.GetAddress(), t)
		syncMigrationSimulatorWallet(t, wallet)
	}
}

func migrationSimulatorCallArgs() rpc.Arguments {
	return rpc.Arguments{
		{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
		{Name: rpc.SCID, DataType: rpc.DataHash, Value: rpc.SeamlessMigrationSCID()},
		{Name: rpc.SCENTRYPOINT, DataType: rpc.DataString, Value: rpc.SeamlessMigrationEntrypoint},
	}
}

func assertMigrationSCDATA(t *testing.T, tx transaction.Transaction, recipient string) {
	t.Helper()
	if tx.TransactionType != transaction.SC_TX {
		t.Fatalf("migration call encoded as transaction type %d, want SC_TX", tx.TransactionType)
	}
	if len(tx.SCDATA) != 3 {
		t.Fatalf("migration SCDATA has %d entries, want only SC_ACTION, SC_ID, and entrypoint", len(tx.SCDATA))
	}
	seen := make(map[string]bool, 3)
	for _, arg := range tx.SCDATA {
		if seen[arg.Name] {
			t.Fatalf("duplicate migration SCDATA field %q", arg.Name)
		}
		seen[arg.Name] = true
		switch arg.Name {
		case rpc.SCACTION:
			value, ok := arg.Value.(uint64)
			if arg.DataType != rpc.DataUint64 || !ok || rpc.SC_ACTION(value) != rpc.SC_CALL {
				t.Fatalf("invalid migration SC_ACTION: %+v", arg)
			}
		case rpc.SCID:
			value, ok := arg.Value.(crypto.Hash)
			if arg.DataType != rpc.DataHash || !ok || value != rpc.SeamlessMigrationSCID() {
				t.Fatalf("invalid migration SC_ID: %+v", arg)
			}
		case rpc.SCENTRYPOINT:
			value, ok := arg.Value.(string)
			if arg.DataType != rpc.DataString || !ok || value != rpc.SeamlessMigrationEntrypoint {
				t.Fatalf("invalid migration entrypoint: %+v", arg)
			}
		default:
			t.Fatalf("unexpected public migration SCDATA field: %+v", arg)
		}
		if value, ok := arg.Value.(string); ok && strings.Contains(value, recipient) {
			t.Fatalf("recipient address leaked into migration SCDATA: %+v", arg)
		}
	}
	if len(seen) != 3 {
		t.Fatalf("migration SCDATA fields missing: got %v", seen)
	}
}

func submitMigrationSimulatorCall(t *testing.T, chain *blockchain.Blockchain, miner, source, destination *walletapi.Wallet_Disk, amount uint64) (uint64, *transaction.Transaction) {
	t.Helper()
	tx, err := source.TransferPayload0(
		[]rpc.Transfer{{Destination: destination.GetAddress().String(), Amount: amount}},
		rpc.SeamlessMigrationMinRingSize, false,
		migrationSimulatorCallArgs(),
		0, false,
	)
	if err != nil {
		t.Fatalf("build migration call: %v", err)
	}
	fee := tx.Fees()
	var decoded transaction.Transaction
	if err := decoded.Deserialize(tx.Serialize()); err != nil {
		t.Fatalf("deserialize migration transaction: %v", err)
	}
	assertMigrationSCDATA(t, decoded, destination.GetAddress().String())
	if len(decoded.Payloads) != 1 {
		t.Fatalf("wallet built %d payloads for native-only migration", len(decoded.Payloads))
	}
	if decoded.Payloads[0].BurnValue != 0 || decoded.Payloads[0].Statement.RingSize < rpc.SeamlessMigrationMinRingSize {
		t.Fatalf("migration exposed a public BurnValue or used a small ring: burn=%d ring=%d", decoded.Payloads[0].BurnValue, decoded.Payloads[0].Statement.RingSize)
	}
	if err := chain.Add_TX_To_Pool(&decoded); err != nil {
		var native crypto.Hash
		_, currentNonce, _, _, currentErr := source.GetEncryptedBalanceAtTopoHeight(native, -1, source.GetAddress().String())
		daemonTopo := walletapi.Get_Daemon_TopoHeight()
		selectedTopo := int64(-1)
		if currentErr == nil && daemonTopo >= int64(currentNonce)+3 {
			selectedTopo = daemonTopo - 3
		}
		_, selectedNonce, _, _, selectedErr := source.GetEncryptedBalanceAtTopoHeight(native, selectedTopo, source.GetAddress().String())
		t.Fatalf("admit migration call at height %d: %v (current nonce=%d err=%v; selected topo=%d nonce=%d err=%v; daemon topo=%d)", chain.Get_Height()+1, err, currentNonce, currentErr, selectedTopo, selectedNonce, selectedErr, daemonTopo)
	}
	simulator_chain_mineblock(chain, miner.GetAddress(), t)
	return fee, &decoded
}

func insertMigrationSimulatorTipHint(t *testing.T, chain *blockchain.Blockchain, miner *walletapi.Wallet_Disk, height uint64, tip crypto.Hash) {
	t.Helper()
	hint := block.Block{Height: height, Tips: []crypto.Hash{tip}}
	miniblock := blockchain.ConvertBlockToMiniblock(hint, miner.GetAddress())
	if err, inserted := chain.InsertMiniBlock(miniblock); err != nil || !inserted {
		t.Fatalf("insert migration reorg tip hint: %v (inserted=%t)", err, inserted)
	}
}

func assertMigrationContractPresent(t *testing.T, chain *blockchain.Blockchain, present bool) {
	t.Helper()
	topo := chain.Load_TOPO_HEIGHT()
	record, err := chain.Store.Topo_store.Read(topo)
	if err != nil {
		t.Fatalf("read topological record: %v", err)
	}
	ss, err := chain.Store.Balance_store.LoadSnapshot(record.State_Version)
	if err != nil {
		t.Fatalf("load top snapshot: %v", err)
	}
	metaTree, err := ss.GetTree(config.SC_META)
	if err != nil {
		t.Fatalf("load SC metadata: %v", err)
	}
	scid := rpc.SeamlessMigrationSCID()
	metaBytes, err := metaTree.Get(dvm.SC_Meta_Key(scid))
	if !present {
		if !xerrors.Is(err, graviton.ErrNotFound) {
			t.Fatalf("expected no migration contract before activation, got metadata lookup error: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("migration contract missing after activation: %v", err)
	}
	var meta dvm.SC_META_DATA
	if err := meta.UnmarshalBinaryGood(metaBytes); err != nil {
		t.Fatalf("decode migration metadata: %v", err)
	}
	if !meta.NoSigner() {
		t.Fatal("migration metadata lacks NoSigner")
	}
	dataTree, err := ss.GetTree(string(scid[:]))
	if err != nil {
		t.Fatalf("load migration data tree: %v", err)
	}
	hash, err := dataTree.Hash()
	if err != nil {
		t.Fatalf("hash migration data tree: %v", err)
	}
	if meta.DataHash != hash {
		t.Fatalf("migration data hash mismatch: meta=%x tree=%x", meta.DataHash, hash)
	}
	codeBytes, err := dataTree.Get(dvm.SC_Code_Key(scid))
	if err != nil {
		t.Fatalf("read migration code: %v", err)
	}
	var code dvm.Variable
	if err := code.UnmarshalBinary(codeBytes); err != nil {
		t.Fatalf("decode migration code: %v", err)
	}
	if code.ValueString != dvm.SeamlessMigrationContract {
		t.Fatal("persisted migration code differs from the embedded contract")
	}
	var native crypto.Hash
	dataWrapper := &dvm.Tree_Wrapper{Tree: dataTree, Entries: map[string][]byte{}}
	if balance, _ := dvm.LoadSCAssetValue(dataWrapper, scid, native); balance != 0 {
		t.Fatalf("stateless migration marker accumulated %d native DERO", balance)
	}
}

func TestSeamlessMigrationAtHF4AndLaterBlock(t *testing.T) {
	oldTestnet, oldMainnet := config.Testnet, config.Mainnet
	oldConfig := globals.Config
	oldArgs := globals.Arguments
	config.Testnet.MAJOR_HF4_HEIGHT = 3
	t.Cleanup(func() {
		config.Testnet, config.Mainnet = oldTestnet, oldMainnet
		globals.Config = oldConfig
		globals.Arguments = oldArgs
	})

	walletapi.Initialize_LookupTable(1, 1<<17)
	genesis := newMigrationSimulatorWallet(t, "migration-genesis")
	source := newMigrationSimulatorWallet(t, "migration-source")
	destination := newMigrationSimulatorWallet(t, "migration-destination")
	refund := newMigrationSimulatorWallet(t, "migration-refund")
	unregistered := newMigrationSimulatorWallet(t, "migration-unregistered")
	decoys := make([]*walletapi.Wallet_Disk, int(rpc.SeamlessMigrationMinRingSize)-4)
	for i := range decoys {
		decoys[i] = newMigrationSimulatorWallet(t, fmt.Sprintf("migration-decoy-%02d", i))
	}

	genesisTx := transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, Value: 2012345}}
	copy(genesisTx.MinerAddress[:], genesis.GetAddress().PublicKey.EncodeCompressed())
	config.Testnet.Genesis_Tx = fmt.Sprintf("%x", genesisTx.Serialize())
	config.Mainnet.Genesis_Tx = fmt.Sprintf("%x", genesisTx.Serialize())
	genesisBlock := blockchain.Generate_Genesis_Block()
	config.Testnet.Genesis_Block_Hash = genesisBlock.GetHash()
	config.Mainnet.Genesis_Block_Hash = genesisBlock.GetHash()

	chain, rpcServer, params := simulator_chain_start()
	if chain == nil || rpcServer == nil {
		t.Fatal("start local simulator chain")
	}
	t.Cleanup(func() { simulator_chain_stop(chain, rpcServer) })
	rpcPort := params["rpcport"].(string)
	connectSimulatorDaemon(t, rpcPort)

	registeredWallets := []*walletapi.Wallet_Disk{genesis, source, destination, refund}
	registeredWallets = append(registeredWallets, decoys...)
	for _, wallet := range registeredWallets {
		wallet.SetNetwork(false)
		wallet.SetDaemonAddress(rpcPort)
		wallet.SetOnlineMode()
	}
	unregistered.SetNetwork(false)
	t.Cleanup(func() {
		closeSimulatorWallets(append(registeredWallets, unregistered)...)
	})

	for _, wallet := range registeredWallets[1:] {
		if err := chain.Add_TX_To_Pool(wallet.GetRegistrationTX()); err != nil {
			t.Fatalf("add registration for %s: %v", wallet.GetAddress().String(), err)
		}
	}
	simulator_chain_mineblock(chain, genesis.GetAddress(), t)
	for _, wallet := range registeredWallets {
		syncMigrationSimulatorWallet(t, wallet)
	}

	// Fund the source from the synthetic genesis allocation.
	fundTx, err := genesis.TransferPayload0([]rpc.Transfer{{Destination: source.GetAddress().String(), Amount: 500000}}, rpc.SeamlessMigrationMinRingSize, false, rpc.Arguments{}, 0, false)
	if err != nil {
		t.Fatalf("build source funding transfer: %v", err)
	}
	var decodedFunding transaction.Transaction
	if err := decodedFunding.Deserialize(fundTx.Serialize()); err != nil {
		t.Fatal(err)
	}
	if err := chain.Add_TX_To_Pool(&decodedFunding); err != nil {
		t.Fatalf("admit source funding: %v", err)
	}
	simulator_chain_mineblock(chain, genesis.GetAddress(), t)
	syncMigrationSimulatorWallet(t, source)
	if got := migrationSimulatorBalance(t, source); got < 100000 {
		t.Fatalf("source funding insufficient for migration test: %d", got)
	}

	activation := uint64(config.Testnet.MAJOR_HF4_HEIGHT)
	for uint64(chain.Get_Height()+1) < activation {
		simulator_chain_mineblock(chain, genesis.GetAddress(), t)
	}
	if uint64(chain.Get_Height()) != activation-1 {
		t.Fatalf("expected parent height %d, got %d", activation-1, chain.Get_Height())
	}
	assertMigrationContractPresent(t, chain, false)

	// Build a competing HF4 activation block without the migration call. It will
	// be added after the successful branch so the simulator exercises a real
	// side-branch reorganization, not only deterministic snapshot replay.
	preActivationTip := chain.Get_Top_ID()
	emptyActivationBlock, _, err := chain.Create_new_miner_block(genesis.GetAddress())
	if err != nil {
		t.Fatalf("create empty HF4 branch block: %v", err)
	}
	if emptyActivationBlock.Bl.Height != activation || len(emptyActivationBlock.Txs) != 0 || len(emptyActivationBlock.Bl.Tips) != 1 || emptyActivationBlock.Bl.Tips[0] != preActivationTip {
		t.Fatalf("empty HF4 branch candidate has unexpected shape: height=%d txs=%d tips=%v", emptyActivationBlock.Bl.Height, len(emptyActivationBlock.Txs), emptyActivationBlock.Bl.Tips)
	}
	emptyActivationBlock.Bl.MiniBlocks = append(emptyActivationBlock.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*emptyActivationBlock.Bl, genesis.GetAddress()))
	emptyActivationID := emptyActivationBlock.Bl.GetHash()

	const firstAmount = uint64(25000)
	destinationBefore := migrationSimulatorBalance(t, destination)
	sourceBefore := migrationSimulatorBalance(t, source)
	firstFee, firstTx := submitMigrationSimulatorCall(t, chain, genesis, source, destination, firstAmount)
	syncMigrationSimulatorWallet(t, source)
	syncMigrationSimulatorWallet(t, destination)
	if got, want := migrationSimulatorBalance(t, destination), destinationBefore+firstAmount; got != want {
		t.Fatalf("activation-block migration credited %d; want %d", got, want)
	}
	if got, want := migrationSimulatorBalance(t, source), sourceBefore-firstAmount-firstFee; got != want {
		t.Fatalf("source debit %d; want amount plus fee = %d", sourceBefore-got, firstAmount+firstFee)
	}
	assertMigrationContractPresent(t, chain, true)
	// Clear any stale in-memory copy left by the simulator so the later
	// re-admission check proves the orphaned-block duplicate guard.
	if chain.Mempool.Mempool_TX_Exist(firstTx.GetHash()) {
		if removed := chain.Mempool.Mempool_Delete_TX(firstTx.GetHash()); removed == nil {
			t.Fatal("migration transaction was present in the mempool but could not be removed")
		}
	}

	// Add the prebuilt competing HF4 block, then extend that branch. The new
	// height must reorg away from the successful migration block and restore
	// the source/destination balances from the shared pre-activation parent.
	migrationActivationID := chain.Get_Top_ID()
	if chain.Get_Height() != int64(activation) || migrationActivationID == emptyActivationID {
		t.Fatalf("successful migration branch is not canonical at HF4: height=%d tip=%s", chain.Get_Height(), migrationActivationID)
	}
	if err, accepted := chain.Add_Complete_Block(emptyActivationBlock); err != nil || !accepted {
		t.Fatalf("add competing empty HF4 block: %v (accepted=%t)", err, accepted)
	}
	if chain.Get_Top_ID() != migrationActivationID || !chain.Is_Block_Tip(emptyActivationID) || len(chain.Get_TIPS()) != 2 {
		t.Fatalf("expected two activation-height branch tips while migration branch remains canonical: top=%s tips=%v", chain.Get_Top_ID(), chain.Get_TIPS())
	}

	insertMigrationSimulatorTipHint(t, chain, genesis, activation+1, emptyActivationID)
	reorgCandidate, _, err := chain.Create_new_miner_block(genesis.GetAddress())
	if err != nil {
		t.Fatalf("create block extending empty HF4 branch: %v", err)
	}
	if reorgCandidate.Bl.Height != activation+1 || len(reorgCandidate.Bl.Tips) != 1 || reorgCandidate.Bl.Tips[0] != emptyActivationID || len(reorgCandidate.Txs) != 0 {
		t.Fatalf("reorg candidate does not extend the empty branch: height=%d tips=%v txs=%d", reorgCandidate.Bl.Height, reorgCandidate.Bl.Tips, len(reorgCandidate.Txs))
	}
	reorgCandidate.Bl.MiniBlocks = append(reorgCandidate.Bl.MiniBlocks, blockchain.ConvertBlockToMiniblock(*reorgCandidate.Bl, genesis.GetAddress()))
	reorgBlockID := reorgCandidate.Bl.GetHash()
	if err, accepted := chain.Add_Complete_Block(reorgCandidate); err != nil || !accepted {
		t.Fatalf("add block extending empty HF4 branch: %v (accepted=%t)", err, accepted)
	}
	if chain.Get_Height() != int64(activation+1) || chain.Get_Top_ID() != reorgBlockID {
		t.Fatalf("empty branch did not become canonical: height=%d tip=%s want height=%d tip=%s", chain.Get_Height(), chain.Get_Top_ID(), activation+1, reorgBlockID)
	}
	canonicalActivation, err := chain.Store.Topo_store.Read(int64(activation))
	if err != nil {
		t.Fatalf("read canonical HF4 activation block after reorg: %v", err)
	}
	if canonicalActivation.BLOCK_ID != emptyActivationID {
		t.Fatalf("canonical HF4 block after reorg is %s; want competing branch %s", canonicalActivation.BLOCK_ID, emptyActivationID)
	}
	syncMigrationSimulatorWallet(t, source)
	syncMigrationSimulatorWallet(t, destination)
	if got := migrationSimulatorBalance(t, source); got != sourceBefore {
		t.Fatalf("source balance after reorg is %d; want restored pre-migration balance %d", got, sourceBefore)
	}
	if got := migrationSimulatorBalance(t, destination); got != destinationBefore {
		t.Fatalf("destination balance after reorg is %d; want pre-migration balance %d", got, destinationBefore)
	}
	assertMigrationContractPresent(t, chain, true)

	if err := chain.Add_TX_To_Pool(firstTx); err == nil || !strings.Contains(err.Error(), "rejected Already mined in some block") {
		t.Fatalf("orphaned migration transaction re-admission error = %v; want Already mined in some block", err)
	}
	// The ordinary wallet builder intentionally selects a recent historical
	// balance snapshot. After a short reorg that snapshot can predate funding;
	// extend the winning branch until its normal snapshot contains the restored
	// source balance rather than bypassing the wallet's standard transfer path.
	awaitMigrationSpendableBalance(t, chain, genesis, source, sourceBefore)
	// A transaction stored in an orphaned block cannot be re-added by hash, so
	// build a fresh signed call against the restored source balance. It must
	// credit the destination exactly once on the winning branch.
	reincludeFee, reincludeTx := submitMigrationSimulatorCall(t, chain, genesis, source, destination, firstAmount)
	if reincludeTx.GetHash() == firstTx.GetHash() {
		t.Fatal("post-reorg migration unexpectedly reused the orphaned transaction hash")
	}
	syncMigrationSimulatorWallet(t, source)
	syncMigrationSimulatorWallet(t, destination)
	if got, want := migrationSimulatorBalance(t, destination), destinationBefore+firstAmount; got != want {
		t.Fatalf("post-reorg migration credited %d; want exactly %d", got-destinationBefore, firstAmount)
	}
	if got, want := migrationSimulatorBalance(t, source), sourceBefore-firstAmount-reincludeFee; got != want {
		t.Fatalf("post-reorg migration source balance %d; want %d", got, want)
	}
	assertMigrationContractPresent(t, chain, true)

	// The entrypoint remains callable after the activation block and reorg.
	simulator_chain_mineblock(chain, genesis.GetAddress(), t)
	syncMigrationSimulatorWallet(t, source)
	syncMigrationSimulatorWallet(t, destination)
	const laterAmount = uint64(7000)
	laterBefore := migrationSimulatorBalance(t, destination)
	laterFee, _ := submitMigrationSimulatorCall(t, chain, genesis, source, destination, laterAmount)
	if laterFee == 0 {
		t.Fatal("later migration call unexpectedly had zero fee")
	}
	syncMigrationSimulatorWallet(t, source)
	syncMigrationSimulatorWallet(t, destination)
	if got, want := migrationSimulatorBalance(t, destination), laterBefore+laterAmount; got != want {
		t.Fatalf("post-activation migration credited %d; want %d", got, want)
	}
	assertMigrationContractPresent(t, chain, true)

	// A normal confidential transfer to an unregistered recipient must fail
	// without spending the source balance. There is no DVM refund path.
	const failedAmount = uint64(5000)
	sourceBeforeFailure := migrationSimulatorBalance(t, source)
	destinationBeforeFailure := migrationSimulatorBalance(t, destination)
	refundBeforeFailure := migrationSimulatorBalance(t, refund)
	failedTx, err := source.TransferPayload0(
		[]rpc.Transfer{{Destination: unregistered.GetAddress().String(), Amount: failedAmount}},
		rpc.SeamlessMigrationMinRingSize, false,
		migrationSimulatorCallArgs(),
		0, false,
	)
	var rejection error
	if err != nil {
		rejection = err
	} else {
		var decodedFailure transaction.Transaction
		if err := decodedFailure.Deserialize(failedTx.Serialize()); err != nil {
			t.Fatalf("deserialize unregistered-recipient migration: %v", err)
		}
		rejection = chain.Add_TX_To_Pool(&decodedFailure)
	}
	if rejection == nil || !strings.Contains(strings.ToLower(rejection.Error()), "unregistered") {
		t.Fatalf("unregistered-recipient migration rejection = %v; want an unregistered-recipient error", rejection)
	}
	syncMigrationSimulatorWallet(t, source)
	syncMigrationSimulatorWallet(t, destination)
	syncMigrationSimulatorWallet(t, refund)
	if got := migrationSimulatorBalance(t, source); got != sourceBeforeFailure {
		t.Fatalf("rejected migration changed source balance from %d to %d", sourceBeforeFailure, got)
	}
	if got := migrationSimulatorBalance(t, destination); got != destinationBeforeFailure {
		t.Fatalf("rejected migration credited destination: before=%d after=%d", destinationBeforeFailure, got)
	}
	if got := migrationSimulatorBalance(t, refund); got != refundBeforeFailure {
		t.Fatalf("rejected migration credited unrelated refund account: before=%d after=%d", refundBeforeFailure, got)
	}

	// Consensus also rejects a crafted migration call that puts a clear address
	// back into SCDATA, even though its confidential transfer proof is valid.
	leakedArgs := migrationSimulatorCallArgs()
	leakedArgs = append(leakedArgs, rpc.Argument{Name: "destination", DataType: rpc.DataString, Value: unregistered.GetAddress().String()})
	leakedTx, err := source.TransferPayload0(
		[]rpc.Transfer{{Destination: destination.GetAddress().String(), Amount: failedAmount}},
		rpc.SeamlessMigrationMinRingSize, false, leakedArgs, 0, false,
	)
	if err != nil {
		t.Fatalf("build malformed-SCDATA adversarial transaction: %v", err)
	}
	var decodedLeak transaction.Transaction
	if err := decodedLeak.Deserialize(leakedTx.Serialize()); err != nil {
		t.Fatalf("deserialize malformed-SCDATA transaction: %v", err)
	}
	if err := chain.Add_TX_To_Pool(&decodedLeak); err == nil {
		t.Fatal("consensus accepted a migration call with public destination SCDATA")
	}
	syncMigrationSimulatorWallet(t, source)
	syncMigrationSimulatorWallet(t, destination)
	if got := migrationSimulatorBalance(t, source); got != sourceBeforeFailure {
		t.Fatalf("malformed-SCDATA rejection changed source balance from %d to %d", sourceBeforeFailure, got)
	}
	if got := migrationSimulatorBalance(t, destination); got != destinationBeforeFailure {
		t.Fatalf("malformed-SCDATA rejection credited destination: before=%d after=%d", destinationBeforeFailure, got)
	}
	assertMigrationAddressUnregistered(t, chain, unregistered.GetAddress())
	assertMigrationContractPresent(t, chain, true)
}

func assertMigrationAddressUnregistered(t *testing.T, chain *blockchain.Blockchain, address rpc.Address) {
	t.Helper()
	record, err := chain.Store.Topo_store.Read(chain.Load_TOPO_HEIGHT())
	if err != nil {
		t.Fatalf("read topological record: %v", err)
	}
	ss, err := chain.Store.Balance_store.LoadSnapshot(record.State_Version)
	if err != nil {
		t.Fatalf("load top snapshot: %v", err)
	}
	balanceTree, err := ss.GetTree(config.BALANCE_TREE)
	if err != nil {
		t.Fatalf("load balance tree: %v", err)
	}
	if _, err := balanceTree.Get(address.Compressed()); !xerrors.Is(err, graviton.ErrNotFound) {
		t.Fatalf("failed migration unexpectedly registered destination: %v", err)
	}
}
