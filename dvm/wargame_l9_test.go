// Wargame: L9 signed-integer overflow + division edge cases.
//
// Findings pinned:
//
// 1. SILENT OVERFLOW: int64 ADD/SUB/MUL have no overflow check
//    (dvm.go evalBinaryExpr int64 block). max+1 wraps to min silently,
//    min-1 wraps to max. A contract computing balance+delta with a huge
//    signed value silently corrupts state — no panic, no error, wrong
//    value stored. The uint64 path has the same pre-existing gap; the
//    signed path wraps on BOTH ends.
//
// 2. MinInt64 / -1: Go panics on integer division overflow. It IS
//    recovered by RunSmartContract's recover() -> deterministic rejection
//    (good), but the intrinsic should reject it explicitly for
//    determinism rather than relying on the panic->recover path.
package dvm

import (
	"testing"
)

func runL9(t *testing.T, code string) (Variable, error) {
	t.Helper()
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	return RunSmartContract(&sc, "F", state, map[string]interface{}{})
}

// TestWargameL9SilentOverflow: max+1 and min-1 must NOT silently wrap.
func TestWargameL9SilentOverflow(t *testing.T) {
	code := `
Function F() Uint64
	5 version("10.0.0")
	10 DIM x AS Int
	20 LET x = 9223372036854775807
	30 LET x = x + 1
	40 IF x == -9223372036854775808 THEN GOTO 200
	50 RETURN 1
	200 RETURN 0
End Function
`
	res, err := runL9(t, code)
	if err != nil {
		t.Logf("WARGAME FIXED: int64 max+1 overflow rejected deterministically (%v)", err)
		return
	}
	if res.ValueUint64 == 0 {
		t.Fatal("WARGAME: int64 max+1 still silently wraps to min — overflow check missing")
	}
	t.Fatal("overflow not rejected — check is ineffective")
}

// TestWargameL9MinIntDivNeg1: MinInt64 / -1 is a Go panic; must be
// rejected deterministically, not crash.
func TestWargameL9MinIntDivNeg1(t *testing.T) {
	code := `
Function F() Uint64
	5 version("10.0.0")
	10 DIM x AS Int
	20 DIM y AS Int
	30 LET x = -9223372036854775808
	40 LET y = -1
	50 LET x = x / y
	60 RETURN 1
End Function
`
	_, err := runL9(t, code)
	if err != nil {
		t.Logf("WARGAME FIXED: MinInt64/-1 rejected deterministically (%v)", err)
		return
	}
	t.Fatal("WARGAME: MinInt64/-1 executed without rejection — division overflow is silent")
}
