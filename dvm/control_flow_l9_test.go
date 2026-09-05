// L9 signed-integer tests (spec dero-improvements-agenda.md).
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// Exercises the Int type: DIM i AS Int, negative literals, signed
// arithmetic (subtraction below zero, division), comparisons, Int params,
// and the version gate.
package dvm

import (
	"fmt"
	"testing"
)

// TestL9_IntBasics: signed values, negative literals, delta accounting.
func TestL9_IntBasics(t *testing.T) {
	code := `
Function Delta() Uint64
	5 version("10.0.0")
	10 DIM balance AS Int
	20 DIM fee AS Int
	30 LET balance = 100
	40 LET fee = -30
	50 LET balance = balance + fee
	60 IF balance == 70 THEN GOTO 100
	70 RETURN 1
	100 IF balance - 100 == -30 THEN GOTO 200
	110 RETURN 2
	200 RETURN 0
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	res, err := RunSmartContract(&sc, "Delta", state, map[string]interface{}{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ValueUint64 != 0 {
		t.Fatalf("Delta = %d, want 0", res.ValueUint64)
	}
	t.Log("Int basics OK: negative literals + signed delta")
}

// TestL9_NegativeLiteral: unary minus in expressions.
func TestL9_NegativeLiteral(t *testing.T) {
	code := `
Function Neg() Uint64
	5 version("10.0.0")
	10 DIM x AS Int
	20 LET x = -5
	30 IF x == -5 THEN GOTO 100
	40 RETURN 1
	100 IF -x == 5 THEN GOTO 200
	110 RETURN 2
	200 IF x * -1 == 5 THEN GOTO 300
	210 RETURN 3
	300 RETURN 0
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	res, err := RunSmartContract(&sc, "Neg", state, map[string]interface{}{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ValueUint64 != 0 {
		t.Fatalf("Neg = %d, want 0", res.ValueUint64)
	}
	t.Log("negative literal OK: -5, -x, x * -1")
}

// TestL9_IntParam: Int function parameter.
func TestL9_IntParam(t *testing.T) {
	code := `
Function Diff(a Int, b Int) Int
	5 version("10.0.0")
	10 RETURN a - b
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	res, err := RunSmartContract(&sc, "Diff", state, map[string]interface{}{"a": "10", "b": "25"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ValueInt64 != -15 {
		t.Fatalf("Diff(10,25) = %d, want -15", res.ValueInt64)
	}
	t.Log("Int param OK: negative return value")
}

// TestL9_VersionGate: Int type requires 10.0.0.
func TestL9_VersionGate(t *testing.T) {
	code := `
Function Old() Uint64
	5 version("1.2.3")
	10 DIM i AS Int
	20 RETURN 0
End Function
`
	_, err := cfRun(t, code, "Old", nil)
	if err == nil {
		t.Fatal("Int at 1.2.3 should be rejected")
	}
	t.Logf("Int version gate OK: %v", err)
}

var _ = fmt.Sprintf
