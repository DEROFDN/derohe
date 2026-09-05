// L3 array tests (spec dero-improvements-agenda.md).
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// Exercises RAM arrays: DIM a(n), a[i] get/set, arrlen, iteration with
// FOR (L1), and the version gate. Arrays are Locals-only (never STORE'd)
// so this is consensus-neutral.
package dvm

import (
	"strings"
	"testing"
)

// TestL3_ArrayBasics: DIM a(5), set elements, read them, arrlen.
func TestL3_ArrayBasics(t *testing.T) {
	code := `
Function Arr() Uint64
	5 version("10.0.0")
	10 DIM a(5) AS Uint64
	20 LET a[0] = 10
	30 LET a[1] = 20
	40 LET a[2] = a[0] + a[1]
	50 IF arrlen("a") != 6 THEN GOTO 900
	60 RETURN a[2]
	900 RETURN 999
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	res, err := RunSmartContract(&sc, "Arr", state, map[string]interface{}{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ValueUint64 != 30 {
		t.Fatalf("array sum = %d, want 30", res.ValueUint64)
	}
	t.Logf("array basics OK: a[2]=a[0]+a[1]=%d, len=6", res.ValueUint64)
}

// TestL3_ArrayForLoop: fill an array in a FOR loop (L1 + L3 compose).
func TestL3_ArrayForLoop(t *testing.T) {
	code := `
Function Fill() Uint64
	5 version("10.0.0")
	10 DIM a(10) AS Uint64
	20 DIM i AS Uint64
	30 DIM total AS Uint64
	40 LET total = 0
	50 FOR i = 0 TO 10
	60   LET a[i] = i * i
	70   LET total = total + a[i]
	80 NEXT i
	90 RETURN total
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	res, err := RunSmartContract(&sc, "Fill", state, map[string]interface{}{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// sum of squares 0..10 = 385
	if res.ValueUint64 != 385 {
		t.Fatalf("sum of squares = %d, want 385", res.ValueUint64)
	}
	t.Logf("FOR+array OK: sum(i^2, 0..10)=%d", res.ValueUint64)
}

// TestL3_StringArray: string arrays.
func TestL3_StringArray(t *testing.T) {
	code := `
Function StrArr() Uint64
	5 version("10.0.0")
	10 DIM s(2) AS String
	20 LET s[0] = "hello"
	30 LET s[1] = "world"
	40 IF s[0] == "hello" THEN GOTO 100
	50 RETURN 1
	100 IF s[1] == "world" THEN GOTO 200
	110 RETURN 2
	200 RETURN 0
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	res, err := RunSmartContract(&sc, "StrArr", state, map[string]interface{}{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ValueUint64 != 0 {
		t.Fatalf("string array check = %d, want 0", res.ValueUint64)
	}
	t.Log("string arrays OK")
}

// TestL3_VersionGate: DIM a(n) rejected below 10.0.0.
func TestL3_VersionGate(t *testing.T) {
	code := `
Function Old() Uint64
	5 version("1.2.3")
	10 DIM a(5) AS Uint64
	20 RETURN 0
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	_, err = RunSmartContract(&sc, "Old", state, map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "DIM arrays") {
		t.Fatalf("DIM a(n) at 1.2.3 should be rejected, got: %v", err)
	}
	t.Logf("array version gate OK: %v", err)
}
