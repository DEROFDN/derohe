package dvm

import (
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

func installMigrationInSimulator(t *testing.T, sim *Simulator) crypto.Hash {
	t.Helper()
	parsed, _, err := ParseSmartContract(SeamlessMigrationContract)
	if err != nil {
		t.Fatalf("parse embedded migration contract: %v", err)
	}
	if ContractUsesSigner(parsed) {
		t.Fatal("migration contract must not call SIGNER")
	}

	scid := rpc.SeamlessMigrationSCID()
	dataTree := Wrapped_tree(sim.cache, sim.ss, scid)
	if err := dataTree.Put(SC_Code_Key(scid), Variable{Type: String, ValueString: SeamlessMigrationContract}.MarshalBinaryPanic()); err != nil {
		t.Fatalf("write migration code: %v", err)
	}
	for key, value := range dataTree.Entries {
		if err := dataTree.Tree.Put([]byte(key), value); err != nil {
			t.Fatalf("commit migration code: %v", err)
		}
	}
	sim.cache[scid] = dataTree.Tree

	meta := SC_META_DATA{}
	meta.SetNoSigner()
	if meta.DataHash, err = dataTree.Tree.Hash(); err != nil {
		t.Fatalf("hash migration code: %v", err)
	}
	if err := sim.sc_tree.Put(SC_Meta_Key(scid), meta.MarshalBinaryGood()); err != nil {
		t.Fatalf("write migration metadata: %v", err)
	}
	return scid
}

func migrationCallData() rpc.Arguments {
	return rpc.Arguments{
		{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
		{Name: rpc.SCID, DataType: rpc.DataHash, Value: rpc.SeamlessMigrationSCID()},
		{Name: rpc.SCENTRYPOINT, DataType: rpc.DataString, Value: rpc.SeamlessMigrationEntrypoint},
	}
}

func TestSeamlessMigrationIsStatelessAndDoesNotHandleValue(t *testing.T) {
	if strings.Contains(SeamlessMigrationContract, "DEROVALUE") || strings.Contains(SeamlessMigrationContract, "SEND_DERO_TO_ADDRESS") {
		t.Fatal("migration contract must not read or forward a public DVM value")
	}

	sim := SimulatorInitialize(nil, 100)
	scid := installMigrationInSimulator(t, sim)
	before, err := sim.balance_tree.Hash()
	if err != nil {
		t.Fatalf("hash balance tree before call: %v", err)
	}
	dataBefore, err := sim.cache[scid].Hash()
	if err != nil {
		t.Fatalf("hash migration data tree before call: %v", err)
	}
	metaBefore, err := sim.sc_tree.Hash()
	if err != nil {
		t.Fatalf("hash SC metadata tree before call: %v", err)
	}
	if _, _, err := sim.RunSC(map[crypto.Hash]uint64{}, migrationCallData(), nil, 0); err != nil {
		t.Fatalf("execute stateless migration marker: %v", err)
	}
	after, err := sim.balance_tree.Hash()
	if err != nil {
		t.Fatalf("hash balance tree after call: %v", err)
	}
	if before != after {
		t.Fatal("migration marker changed DERO balances; only the base-layer confidential transfer may move value")
	}
	dataAfter, err := sim.cache[scid].Hash()
	if err != nil {
		t.Fatalf("hash migration data tree after call: %v", err)
	}
	if dataBefore != dataAfter {
		t.Fatal("migration marker changed contract storage")
	}
	metaAfter, err := sim.sc_tree.Hash()
	if err != nil {
		t.Fatalf("hash SC metadata tree after call: %v", err)
	}
	if metaBefore != metaAfter {
		t.Fatal("migration marker changed SC metadata")
	}
	dataTree := Wrapped_tree(sim.cache, sim.ss, scid)
	var native crypto.Hash
	balance, _ := LoadSCAssetValue(dataTree, scid, native)
	if balance != 0 {
		t.Fatalf("stateless migration marker accumulated %d native DERO", balance)
	}
}

func TestMigrationRejectsDVMExternalTransfers(t *testing.T) {
	if err := SanityCheckNoExternalTransfers(&Tree_Wrapper{}); err != nil {
		t.Fatalf("empty migration transfer list rejected: %v", err)
	}
	withOutput := &Tree_Wrapper{Transfere: []TransferExternal{{Address: "recipient", Amount: 1}}}
	if err := SanityCheckNoExternalTransfers(withOutput); err == nil {
		t.Fatal("migration DVM external transfer was accepted")
	}
}
