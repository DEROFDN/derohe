package dvm

// ErrorRevertHF3 credits a burned deposit back to the signer. It switches on the
// asset being refunded: the zero SCID (plain DERO), the called contract's own
// asset, and any other asset. Only the zero-SCID branch is reachable from the
// existing chain-level tests, so the two token branches are exercised here
// directly against real graviton trees.

import "math/big"
import "testing"

import "github.com/deroproject/graviton"
import "github.com/deroproject/derohe/cryptography/bn256"
import "github.com/deroproject/derohe/cryptography/crypto"

// signer_key returns a valid compressed account key and its point.
func signer_key(t *testing.T) ([33]byte, *bn256.G1) {
	t.Helper()
	secret := crypto.RandomScalar()
	point := new(bn256.G1).ScalarMult(crypto.G, secret)

	var compressed [33]byte
	var p crypto.Point
	p.G1() // ensure type is initialised before use
	copy(compressed[:], point.EncodeCompressed())
	return compressed, point
}

// seed_balance puts an account holding `amount` into tree, the same shape
// transaction_execute.go writes.
func seed_balance(t *testing.T, tree *graviton.Tree, signer [33]byte, key *bn256.G1, amount uint64) {
	t.Helper()
	balance := crypto.ConstructElGamal(key, crypto.ElGamal_BASE_G)
	balance = balance.Plus(new(big.Int).SetUint64(amount))
	nb := crypto.NonceBalance{NonceHeight: 0, Balance: balance}
	if err := tree.Put(signer[:], nb.Serialize()); err != nil {
		t.Fatalf("seed balance: %s", err)
	}
}

// expect_balance asserts the account in tree holds exactly `amount`, by
// rebuilding the expected ciphertext from the same deterministic operations.
func expect_balance(t *testing.T, tree *graviton.Tree, signer [33]byte, key *bn256.G1, amount uint64, label string) {
	t.Helper()
	got, err := tree.Get(signer[:])
	if err != nil {
		t.Fatalf("%s: signer absent from tree: %s", label, err)
	}
	want := crypto.ConstructElGamal(key, crypto.ElGamal_BASE_G)
	want = want.Plus(new(big.Int).SetUint64(amount))
	wnb := crypto.NonceBalance{NonceHeight: 0, Balance: want}
	if string(got) != string(wnb.Serialize()) {
		t.Fatalf("%s: balance mismatch -- expected the account to hold %d after the refund", label, amount)
	}
}

// Test_ErrorRevertHF3_Credits_Token_Assets drives all three switch branches.
func Test_ErrorRevertHF3_Credits_Token_Assets(t *testing.T) {
	store, err := graviton.NewMemStore()
	if err != nil {
		t.Fatalf("memstore: %s", err)
	}
	gv, err := store.LoadSnapshot(0)
	if err != nil {
		t.Fatalf("snapshot: %s", err)
	}

	signer, key := signer_key(t)

	var zeroscid crypto.Hash
	scid := crypto.Hash{0x11}  // the contract being called
	other := crypto.Hash{0x22} // an unrelated asset the signer also holds

	balance_tree, err := gv.GetTree("balance")
	if err != nil {
		t.Fatalf("balance tree: %s", err)
	}
	scid_tree, err := gv.GetTree(string(scid[:]))
	if err != nil {
		t.Fatalf("scid tree: %s", err)
	}
	other_tree, err := gv.GetTree(string(other[:]))
	if err != nil {
		t.Fatalf("other tree: %s", err)
	}

	const start = 1000
	const burn_dero = 300
	const burn_scid = 40
	const burn_other = 7

	seed_balance(t, balance_tree, signer, key, start)
	seed_balance(t, scid_tree, signer, key, start)
	seed_balance(t, other_tree, signer, key, start)

	// The default branch reads the asset tree from the SNAPSHOT, not from the
	// caller's cache, so the seed must be committed for it to be visible.
	version, err := graviton.Commit(balance_tree, scid_tree, other_tree)
	if err != nil {
		t.Fatalf("commit seeds: %s", err)
	}
	if gv, err = store.LoadSnapshot(version); err != nil {
		t.Fatalf("reload snapshot: %s", err)
	}
	if balance_tree, err = gv.GetTree("balance"); err != nil {
		t.Fatalf("balance tree reload: %s", err)
	}
	if scid_tree, err = gv.GetTree(string(scid[:])); err != nil {
		t.Fatalf("scid tree reload: %s", err)
	}

	// cache[scid] is what the `case scid:` branch credits into; the `default:`
	// branch must find `other` itself, so it is deliberately left out of cache.
	cache := map[crypto.Hash]*graviton.Tree{scid: scid_tree}

	incoming := map[crypto.Hash]uint64{
		zeroscid: burn_dero,
		scid:     burn_scid,
		other:    burn_other,
	}

	ErrorRevertHF3(gv, cache, balance_tree, signer, scid, incoming)

	expect_balance(t, balance_tree, signer, key, start+burn_dero, "zero SCID (plain DERO)")
	expect_balance(t, scid_tree, signer, key, start+burn_scid, "called contract's own asset")
	expect_balance(t, cache[other], signer, key, start+burn_other, "unrelated asset")

	if _, ok := cache[other]; !ok {
		t.Fatalf("the default branch must materialise the unrelated asset tree into the cache")
	}
}

// Test_ErrorRevertHF3_Skips_Unknown_Signer proves the refund is a no-op rather
// than a panic or a credit to nobody when the signer holds no account in the
// asset's tree. This is the negative control for the test above.
func Test_ErrorRevertHF3_Skips_Unknown_Signer(t *testing.T) {
	store, err := graviton.NewMemStore()
	if err != nil {
		t.Fatalf("memstore: %s", err)
	}
	gv, err := store.LoadSnapshot(0)
	if err != nil {
		t.Fatalf("snapshot: %s", err)
	}

	signer, _ := signer_key(t)
	scid := crypto.Hash{0x11}

	balance_tree, err := gv.GetTree("balance")
	if err != nil {
		t.Fatalf("balance tree: %s", err)
	}
	scid_tree, err := gv.GetTree(string(scid[:]))
	if err != nil {
		t.Fatalf("scid tree: %s", err)
	}

	// signer is seeded NOWHERE, so every branch must skip.
	cache := map[crypto.Hash]*graviton.Tree{scid: scid_tree}
	incoming := map[crypto.Hash]uint64{scid: 40}

	ErrorRevertHF3(gv, cache, balance_tree, signer, scid, incoming)

	if _, err := scid_tree.Get(signer[:]); err == nil {
		t.Fatalf("refund credited an account that never existed in the tree")
	}
}
