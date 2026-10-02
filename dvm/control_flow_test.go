// L1 structured control flow tests (spec dero-improvements-agenda.md).
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// Exercises FOR/NEXT, WHILE/WEND and block IF/ELSE/ENDIF through
// RunSmartContract, plus nesting, STEP, and the version gate (all new
// keywords require version("10.0.0")).
package dvm

import (
	"fmt"
	"testing"
)

func cfRun(t *testing.T, code, entrypoint string, args map[string]interface{}) (result Variable, err error) {
	t.Helper()
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	return RunSmartContract(&sc, entrypoint, state, args)
}

// TestL1_ForNext: sum 1..5 with FOR/NEXT (step 1).
func TestL1_ForNext(t *testing.T) {
	code := `
Function Sum() Uint64
	5 version("10.0.0")
	10 DIM total AS Uint64
	20 DIM i AS Uint64
	30 LET total = 0
	40 FOR i = 1 TO 5
	50   LET total = total + i
	60 NEXT i
	70 RETURN total
End Function
`
	res, err := cfRun(t, code, "Sum", nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Type != Uint64 || res.ValueUint64 != 15 {
		t.Fatalf("FOR sum = %+v, want 15", res)
	}
	t.Logf("FOR/NEXT OK: sum(1..5)=%d", res.ValueUint64)
}

// TestL1_ForStep: sum 0,2,4 (STEP 2).
func TestL1_ForStep(t *testing.T) {
	code := `
Function SumEven() Uint64
	5 version("10.0.0")
	10 DIM total AS Uint64
	20 DIM i AS Uint64
	30 LET total = 0
	40 FOR i = 0 TO 4 STEP 2
	50   LET total = total + i
	60 NEXT i
	70 RETURN total
End Function
`
	res, err := cfRun(t, code, "SumEven", nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ValueUint64 != 6 {
		t.Fatalf("STEP sum = %d, want 6", res.ValueUint64)
	}
	t.Logf("FOR/STEP OK: 0+2+4=%d", res.ValueUint64)
}

// TestL1_WhileWend: count down from 10 while > 0, using WHILE/WEND.
func TestL1_WhileWend(t *testing.T) {
	code := `
Function CountDown() Uint64
	5 version("10.0.0")
	10 DIM count AS Uint64
	20 DIM steps AS Uint64
	30 LET count = 10
	40 LET steps = 0
	50 WHILE count > 0
	60   LET count = count - 1
	70   LET steps = steps + 1
	80 WEND
	90 RETURN steps
End Function
`
	res, err := cfRun(t, code, "CountDown", nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ValueUint64 != 10 {
		t.Fatalf("WHILE steps = %d, want 10", res.ValueUint64)
	}
	t.Logf("WHILE/WEND OK: %d iterations", res.ValueUint64)
}

// TestL1_BlockIfElse: block IF/ELSE/ENDIF branches.
func TestL1_BlockIfElse(t *testing.T) {
	code := `
Function Pick(x Uint64) Uint64
	5 version("10.0.0")
	10 IF x > 3 THEN
	20   RETURN 1
	30 ELSE
	40   RETURN 0
	50 ENDIF
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	run := func(x uint64) uint64 {
		state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
		res, err := RunSmartContract(&sc, "Pick", state, map[string]interface{}{"x": fmt.Sprintf("%d", x)})
		if err != nil {
			t.Fatalf("run(%d): %v", x, err)
		}
		return res.ValueUint64
	}
	if got := run(5); got != 1 {
		t.Fatalf("Pick(5) = %d, want 1", got)
	}
	if got := run(2); got != 0 {
		t.Fatalf("Pick(2) = %d, want 0", got)
	}
	t.Log("block IF/ELSE/ENDIF OK: both branches")
}

// TestL1_BlockIfNoElse: IF without ELSE falls through on false.
func TestL1_BlockIfNoElse(t *testing.T) {
	code := `
Function Check(x Uint64) Uint64
	5 version("10.0.0")
	10 DIM r AS Uint64
	20 LET r = 0
	30 IF x > 3 THEN
	40   LET r = 1
	50 ENDIF
	60 RETURN r
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
		t.Fatalf("Check(2) = %d, want 0 (no ELSE should fall through)", got)
	}
	t.Log("block IF (no ELSE) OK: falls through on false")
}

// TestL1_Nested: FOR inside WHILE (loop frames nest correctly).
func TestL1_Nested(t *testing.T) {
	code := `
Function Nested() Uint64
	5 version("10.0.0")
	10 DIM outer AS Uint64
	20 DIM inner AS Uint64
	30 DIM total AS Uint64
	40 LET total = 0
	50 LET outer = 0
	60 WHILE outer < 3
	70   FOR inner = 1 TO 2
	80     LET total = total + inner
	90   NEXT inner
	100  LET outer = outer + 1
	110 WEND
	120 RETURN total
End Function
`
	res, err := cfRun(t, code, "Nested", nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// 3 outer iterations x (1+2) each = 9
	if res.ValueUint64 != 9 {
		t.Fatalf("nested total = %d, want 9", res.ValueUint64)
	}
	t.Logf("nested FOR-in-WHILE OK: total=%d", res.ValueUint64)
}

// TestL1_VersionGate: new keywords rejected below 10.0.0.
func TestL1_VersionGate(t *testing.T) {
	code := `
Function Old() Uint64
	5 version("1.2.3")
	10 DIM i AS Uint64
	20 FOR i = 1 TO 2
	30 NEXT i
	40 RETURN 0
End Function
`
	_, err := cfRun(t, code, "Old", nil)
	if err == nil {
		t.Fatal("FOR at version 1.2.3 should be rejected")
	}
	t.Logf("version gate OK: %v", err)
}

// TestL1_NoVersion: no version() call at all -> rejected.
func TestL1_NoVersion(t *testing.T) {
	code := `
Function NoVer() Uint64
	10 DIM i AS Uint64
	20 FOR i = 1 TO 2
	30 NEXT i
	40 RETURN 0
End Function
`
	_, err := cfRun(t, code, "NoVer", nil)
	if err == nil {
		t.Fatal("FOR without version() should be rejected")
	}
	t.Logf("no-version gate OK: %v", err)
}
