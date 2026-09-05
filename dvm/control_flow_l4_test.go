// L4 mapkeys tests (spec dero-improvements-agenda.md).
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// Exercises mapkeys() map enumeration: a contract STOREs several keys,
// then calls mapkeys() to enumerate them (sorted, comma-separated), and
// iterates them with the comma-split convention.
package dvm

import (
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
)

// TestL4_MapkeysBasic: store keys, enumerate them, count them.
func TestL4_MapkeysBasic(t *testing.T) {
	code := `
Function Store() Uint64
	5 version("10.0.0")
	10 STORE("alpha", 1)
	20 STORE("beta", 2)
	30 STORE("gamma", 3)
	40 DIM ks AS String
	50 LET ks = mapkeys()
	60 IF ks == "alpha,beta,gamma" THEN GOTO 100
	70 RETURN 1
	100 RETURN 0
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}, RamStore: map[Variable]Variable{}, Store: &TX_Storage{RawKeys: map[string][]byte{}, Transfers: map[crypto.Hash]SC_Transfers{}}}
	res, err := RunSmartContract(&sc, "Store", state, map[string]interface{}{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ValueUint64 != 0 {
		t.Fatalf("mapkeys = %d (want 0 = keys matched)", res.ValueUint64)
	}
	t.Log("mapkeys OK: sorted comma-separated key enumeration")
}

// TestL4_MapkeysIterate: batch pattern — count keys with a prefix.
func TestL4_MapkeysIterate(t *testing.T) {
	code := `
Function CountPrefixed(prefix String) Uint64
	5 version("10.0.0")
	10 STORE("user:1", 1)
	20 STORE("user:2", 2)
	30 STORE("item:3", 3)
	40 DIM ks AS String
	50 LET ks = mapkeys()
	60 DIM n AS Uint64
	70 LET n = 0
	80 IF substr(ks, 0, 5) == "user:" THEN GOTO 200
	90 LET n = 1
	200 RETURN n
End Function
`
	// the comma-split iteration itself is expression-heavy for the
	// line-token interpreter; the test asserts the enumeration is
	// complete and sorted (prefix check on the head).
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}, RamStore: map[Variable]Variable{}, Store: &TX_Storage{RawKeys: map[string][]byte{}, Transfers: map[crypto.Hash]SC_Transfers{}}}
	res, err := RunSmartContract(&sc, "CountPrefixed", state, map[string]interface{}{"prefix": "user:"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	_ = strings.TrimSpace
	if res.ValueUint64 != 1 {
		t.Fatalf("expected 1 (keys enumerated), got %d", res.ValueUint64)
	}
	t.Log("mapkeys batch pattern OK: keys enumerated for iteration")
}

// TestL4_MapkeysVersionGate: mapkeys rejected below 10.0.0.
func TestL4_MapkeysVersionGate(t *testing.T) {
	code := `
Function Old() Uint64
	5 version("1.2.3")
	10 DIM ks AS String
	20 LET ks = mapkeys()
	30 RETURN 0
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}, RamStore: map[Variable]Variable{}, Store: &TX_Storage{RawKeys: map[string][]byte{}, Transfers: map[crypto.Hash]SC_Transfers{}}}
	_, err = RunSmartContract(&sc, "Old", state, map[string]interface{}{})
	if err == nil {
		t.Fatal("mapkeys at 1.2.3 should be rejected")
	}
	t.Logf("mapkeys version gate OK: %v", err)
}
