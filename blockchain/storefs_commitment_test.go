package blockchain

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestBlockScopedTransactionStore(t *testing.T) {
	store := &storefs{basedir: t.TempDir()}
	var blockID [32]byte
	blockID[0], blockID[31] = 0x12, 0x34
	body := []byte("serialized tx body")

	if err := store.WriteTXForBlock(blockID, 7, body); err != nil {
		t.Fatalf("write block-scoped tx: %v", err)
	}
	got, err := store.ReadTXForBlock(blockID, 7)
	if err != nil {
		t.Fatalf("read block-scoped tx: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("read body %q, want %q", got, body)
	}
	if err := store.WriteTXForBlock(blockID, 7, body); err != nil {
		t.Fatalf("idempotent block-scoped write: %v", err)
	}
	if err := store.WriteTXForBlock(blockID, 7, []byte("different body")); err == nil {
		t.Fatal("conflicting body for the same block/index was accepted")
	}

	var alternateBlockID [32]byte
	alternateBlockID[0], alternateBlockID[31] = 0x56, 0x78
	alternateBody := []byte("alternate proof variant")
	if err := store.WriteTXForBlock(alternateBlockID, 7, alternateBody); err != nil {
		t.Fatalf("same transaction position in another block must be independent: %v", err)
	}
	gotAlternate, err := store.ReadTXForBlock(alternateBlockID, 7)
	if err != nil || string(gotAlternate) != string(alternateBody) {
		t.Fatalf("read alternate block body = %q, %v", gotAlternate, err)
	}

	var missing [32]byte
	if _, err := store.ReadTXForBlock(missing, 0); !os.IsNotExist(err) {
		t.Fatalf("missing block-scoped transaction error = %v, want os.ErrNotExist", err)
	}
}

func TestReadTXDistinguishesMissingFromUnreadableLegacyEntry(t *testing.T) {
	store := &storefs{basedir: t.TempDir()}
	var hash [32]byte
	hash[0], hash[16] = 0x01, 0x02

	if _, err := store.ReadTX(hash); !os.IsNotExist(err) {
		t.Fatalf("missing transaction error = %v, want os.ErrNotExist", err)
	}

	legacyDir := store.getpath(hash)
	if err := os.MkdirAll(legacyDir, 0700); err != nil {
		t.Fatal(err)
	}
	legacyFile := filepath.Join(legacyDir, fmt.Sprintf("%x.tx", hash[:]))
	if err := os.Mkdir(legacyFile, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.getpathtx(hash), 0700); err != nil {
		t.Fatal(err)
	}
	newFile := filepath.Join(store.getpathtx(hash), fmt.Sprintf("%x.tx", hash[:]))
	if err := os.WriteFile(newFile, []byte("new-layout body"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.ReadTX(hash); err == nil || os.IsNotExist(err) {
		t.Fatalf("unreadable legacy entry did not fail closed: %v", err)
	}
}
