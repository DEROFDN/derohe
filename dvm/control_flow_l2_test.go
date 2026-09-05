// L2 subroutines tests (spec dero-improvements-agenda.md).
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// Exercises GOSUB/RETURN through RunSmartContract: subroutine call,
// shared-Locals communication, nested GOSUB, GOSUB inside a FOR loop,
// and the version gate.
package dvm

import (
	"fmt"
	"testing"
)

// TestL2_Gosub: a subroutine computes a helper value via shared Locals.
func TestL2_Gosub(t *testing.T) {
	code := `
Function UseHelper(x Uint64) Uint64
	5 version("10.0.0")
	10 DIM r AS Uint64
	20 LET r = 0
	30 GOSUB 100
	40 RETURN r
	100 LET r = x * 2
	110 RETURN
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	run := func(x uint64) uint64 {
		state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
		res, err := RunSmartContract(&sc, "UseHelper", state, map[string]interface{}{"x": fmt.Sprintf("%d", x)})
		if err != nil {
			t.Fatalf("run(%d): %v", x, err)
		}
		return res.ValueUint64
	}
	if got := run(5); got != 10 {
		t.Fatalf("UseHelper(5) = %d, want 10", got)
	}
	if got := run(21); got != 42 {
		t.Fatalf("UseHelper(21) = %d, want 42", got)
	}
	t.Log("GOSUB/RETURN OK: shared-Locals helper")
}

// TestL2_NestedGosub: GOSUB inside a GOSUB (call stack nests).
func TestL2_NestedGosub(t *testing.T) {
	code := `
Function Nested() Uint64
	5 version("10.0.0")
	10 DIM total AS Uint64
	20 LET total = 0
	30 GOSUB 100
	40 RETURN total
	100 LET total = total + 1
	110 GOSUB 200
	120 RETURN
	200 LET total = total + 10
	210 RETURN
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	res, err := RunSmartContract(&sc, "Nested", state, map[string]interface{}{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ValueUint64 != 11 {
		t.Fatalf("nested GOSUB total = %d, want 11 (1 + 10)", res.ValueUint64)
	}
	t.Logf("nested GOSUB OK: total=%d", res.ValueUint64)
}

// TestL2_GosubInFor: GOSUB inside a FOR loop body (control flow mixes).
func TestL2_GosubInFor(t *testing.T) {
	code := `
Function SumHelper() Uint64
	5 version("10.0.0")
	10 DIM i AS Uint64
	20 DIM total AS Uint64
	30 LET total = 0
	40 FOR i = 1 TO 3
	50   GOSUB 100
	60 NEXT i
	70 RETURN total
	100 LET total = total + i
	110 RETURN
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	res, err := RunSmartContract(&sc, "SumHelper", state, map[string]interface{}{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// 1+2+3 = 6
	if res.ValueUint64 != 6 {
		t.Fatalf("GOSUB-in-FOR total = %d, want 6", res.ValueUint64)
	}
	t.Logf("GOSUB-in-FOR OK: total=%d", res.ValueUint64)
}

// TestL2_FunctionReturnStillWorks: existing function RETURN unaffected.
func TestL2_FunctionReturnStillWorks(t *testing.T) {
	code := `
Function Plain(x Uint64) Uint64
	10 RETURN x * 3
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	res, err := RunSmartContract(&sc, "Plain", state, map[string]interface{}{"x": "7"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ValueUint64 != 21 {
		t.Fatalf("Plain(7) = %d, want 21", res.ValueUint64)
	}
	t.Log("function RETURN unaffected by L2 (no CallStack)")
}

// TestL2_VersionGate: GOSUB rejected below 10.0.0.
func TestL2_VersionGate(t *testing.T) {
	code := `
Function Old() Uint64
	5 version("1.2.3")
	10 GOSUB 100
	20 RETURN 0
	100 RETURN
End Function
`
	_, err := cfRun(t, code, "Old", nil)
	if err == nil {
		t.Fatal("GOSUB at version 1.2.3 should be rejected")
	}
	t.Logf("GOSUB version gate OK: %v", err)
}
