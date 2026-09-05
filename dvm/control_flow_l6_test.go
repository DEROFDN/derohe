// L6 boolean type tests (spec dero-improvements-agenda.md).
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// Exercises the Bool type: DIM b AS Bool, TRUE/FALSE constants, boolean
// assignment from comparisons, logical AND/OR, NOT, and bool parameters.
package dvm

import (
	"fmt"
	"testing"
)

// TestL6_BoolBasics: DIM Bool, assign TRUE/FALSE and comparison results.
func TestL6_BoolBasics(t *testing.T) {
	code := `
Function Check(x Uint64) Uint64
	5 version("10.0.0")
	10 DIM b AS Bool
	20 LET b = TRUE
	30 IF b != 1 THEN GOTO 900
	40 LET b = FALSE
	50 IF b != 0 THEN GOTO 900
	60 LET b = (x > 3)
	70 IF b == 1 THEN GOTO 100
	80 RETURN 0
	100 RETURN 1
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	run := func(x uint64) uint64 {
		state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
		res, err := RunSmartContract(&sc, "Check", state, map[string]interface{}{"x": fmt.Sprintf("%d", x)})
		if err != nil {
			t.Fatalf("run(%d): %v", x, err)
		}
		return res.ValueUint64
	}
	if got := run(5); got != 1 {
		t.Fatalf("Check(5) = %d, want 1", got)
	}
	if got := run(2); got != 0 {
		t.Fatalf("Check(2) = %d, want 0", got)
	}
	t.Log("Bool basics OK: TRUE/FALSE constants + comparison assignment")
}

// TestL6_BoolLogic: && and || with bool values.
func TestL6_BoolLogic(t *testing.T) {
	code := `
Function Logic(x Uint64) Uint64
	5 version("10.0.0")
	10 DIM a AS Bool
	20 DIM b AS Bool
	30 LET a = (x > 0)
	40 LET b = (x < 10)
	50 IF a && b THEN GOTO 100
	60 RETURN 0
	100 IF a || FALSE THEN GOTO 200
	110 RETURN 2
	200 IF !(b == FALSE) THEN GOTO 300
	210 RETURN 3
	300 RETURN 1
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	res, err := RunSmartContract(&sc, "Logic", state, map[string]interface{}{"x": "5"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ValueUint64 != 1 {
		t.Fatalf("Logic(5) = %d, want 1 (all branches)", res.ValueUint64)
	}
	t.Log("Bool logic OK: && / || / !")
}

// TestL6_BoolParam: Bool function parameter.
func TestL6_BoolParam(t *testing.T) {
	code := `
Function Pass(flag Bool) Uint64
	5 version("10.0.0")
	10 IF flag == TRUE THEN GOTO 100
	20 RETURN 0
	100 RETURN 1
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	run := func(flag string) uint64 {
		state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
		res, err := RunSmartContract(&sc, "Pass", state, map[string]interface{}{"flag": flag})
		if err != nil {
			t.Fatalf("run(%s): %v", flag, err)
		}
		return res.ValueUint64
	}
	if got := run("1"); got != 1 {
		t.Fatalf("Pass(TRUE) = %d, want 1", got)
	}
	if got := run("0"); got != 0 {
		t.Fatalf("Pass(FALSE) = %d, want 0", got)
	}
	t.Log("Bool parameter OK")
}

// TestL6_VersionGate: Bool type requires 10.0.0.
func TestL6_VersionGate(t *testing.T) {
	code := `
Function Old() Uint64
	5 version("1.2.3")
	10 DIM b AS Bool
	20 RETURN 0
End Function
`
	_, err := cfRun(t, code, "Old", nil)
	if err == nil {
		t.Fatal("Bool at 1.2.3 should be rejected")
	}
	t.Logf("Bool version gate OK: %v", err)
}
