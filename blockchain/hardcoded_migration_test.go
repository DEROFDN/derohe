package blockchain

import (
	"bytes"
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/dvm"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/graviton"
)

func installMigrationSnapshot(t *testing.T, store *graviton.Store, height uint64) (uint64, []byte, [32]byte, string) {
	t.Helper()
	ss, err := store.LoadSnapshot(0)
	if err != nil {
		t.Fatal(err)
	}
	balanceTree, err := ss.GetTree(config.BALANCE_TREE)
	if err != nil {
		t.Fatal(err)
	}
	scMeta, err := ss.GetTree(config.SC_META)
	if err != nil {
		t.Fatal(err)
	}
	cache := map[crypto.Hash]*graviton.Tree{}
	if err := (&Blockchain{}).install_hardcoded_contracts(cache, ss, balanceTree, scMeta, height); err != nil {
		t.Fatalf("install at height %d: %v", height, err)
	}
	scid := rpc.SeamlessMigrationSCID()
	dataTree, ok := cache[scid]
	if !ok {
		t.Fatalf("migration contract not installed at height %d", height)
	}
	version, err := graviton.Commit(dataTree, balanceTree, scMeta)
	if err != nil {
		t.Fatalf("commit snapshot at height %d: %v", height, err)
	}
	committed, err := store.LoadSnapshot(version)
	if err != nil {
		t.Fatal(err)
	}
	committedMeta, err := committed.GetTree(config.SC_META)
	if err != nil {
		t.Fatal(err)
	}
	metaBytes, err := committedMeta.Get(dvm.SC_Meta_Key(scid))
	if err != nil {
		t.Fatal(err)
	}
	var meta dvm.SC_META_DATA
	if err := meta.UnmarshalBinaryGood(metaBytes); err != nil {
		t.Fatal(err)
	}
	committedData, err := committed.GetTree(string(scid[:]))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := committedData.Hash()
	if err != nil {
		t.Fatal(err)
	}
	codeBytes, err := committedData.Get(dvm.SC_Code_Key(scid))
	if err != nil {
		t.Fatal(err)
	}
	var code dvm.Variable
	if err := code.UnmarshalBinary(codeBytes); err != nil {
		t.Fatal(err)
	}
	if !meta.NoSigner() {
		t.Fatal("hardcoded migration metadata does not set NoSigner")
	}
	if meta.DataHash != hash {
		t.Fatalf("migration metadata hash mismatch: meta=%x tree=%x", meta.DataHash, hash)
	}
	return version, metaBytes, hash, code.ValueString
}

func TestHardcodedMigrationInstallsAtHF4AndSurvivesReorg(t *testing.T) {
	oldHF4 := globals.Config.MAJOR_HF4_HEIGHT
	oldHF1 := globals.Config.HF1_HEIGHT
	globals.Config.MAJOR_HF4_HEIGHT = 5
	globals.Config.HF1_HEIGHT = 100
	t.Cleanup(func() {
		globals.Config.MAJOR_HF4_HEIGHT = oldHF4
		globals.Config.HF1_HEIGHT = oldHF1
	})

	// It must not exist before activation.
	preStore, err := graviton.NewMemStore()
	if err != nil {
		t.Fatal(err)
	}
	preSS, err := preStore.LoadSnapshot(0)
	if err != nil {
		t.Fatal(err)
	}
	preBalance, err := preSS.GetTree(config.BALANCE_TREE)
	if err != nil {
		t.Fatal(err)
	}
	preMeta, err := preSS.GetTree(config.SC_META)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&Blockchain{}).install_hardcoded_contracts(map[crypto.Hash]*graviton.Tree{}, preSS, preBalance, preMeta, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := preMeta.Get(dvm.SC_Meta_Key(rpc.SeamlessMigrationSCID())); err == nil {
		t.Fatal("migration contract installed before HF4")
	}

	// Canonical branch installs the contract exactly at HF4.
	storeA, err := graviton.NewMemStore()
	if err != nil {
		t.Fatal(err)
	}
	versionA, metaA, hashA, codeA := installMigrationSnapshot(t, storeA, 5)
	if codeA != dvm.SeamlessMigrationContract {
		t.Fatal("installed migration source differs from embedded source")
	}

	// A post-activation snapshot must retain the contract when no installation
	// event fires at the next height.
	postSS, err := storeA.LoadSnapshot(versionA)
	if err != nil {
		t.Fatal(err)
	}
	postBalance, err := postSS.GetTree(config.BALANCE_TREE)
	if err != nil {
		t.Fatal(err)
	}
	postMeta, err := postSS.GetTree(config.SC_META)
	if err != nil {
		t.Fatal(err)
	}
	postCache := map[crypto.Hash]*graviton.Tree{}
	if err := (&Blockchain{}).install_hardcoded_contracts(postCache, postSS, postBalance, postMeta, 6); err != nil {
		t.Fatal(err)
	}
	if _, err := postMeta.Get(dvm.SC_Meta_Key(rpc.SeamlessMigrationSCID())); err != nil {
		t.Fatalf("contract disappeared after activation: %v", err)
	}

	// A reorg back to the pre-HF4 parent followed by replaying the activation
	// block must deterministically recreate the same code and metadata root.
	storeB, err := graviton.NewMemStore()
	if err != nil {
		t.Fatal(err)
	}
	_, metaB, hashB, codeB := installMigrationSnapshot(t, storeB, 5)
	if !bytes.Equal(metaA, metaB) || hashA != hashB || codeA != codeB {
		t.Fatal("HF4 reorg replay produced different migration contract state")
	}
}
