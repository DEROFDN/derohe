// L7 CONST + L8 version auto-gate tests (spec dero-improvements-agenda.md).
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// Exercises CONST declarations (uint64 + string), constant use in
// expressions, immutability (LET on a const rejected), and the L8 gate:
// new syntax requires version("10.0.0").
package dvm

import (
	"strings"
	"testing"
)

// TestL7_ConstUint: CONST integer, used in arithmetic.
func TestL7_ConstUint(t *testing.T) {
	code := `
Function UseConst() Uint64
	5 version("10.0.0")
	10 CONST BASE = 100
	20 CONST SCALE = 3
	30 DIM r AS Uint64
	40 LET r = BASE * SCALE + 1
	50 RETURN r
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	res, err := RunSmartContract(&sc, "UseConst", state, map[string]interface{}{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ValueUint64 != 301 {
		t.Fatalf("CONST arithmetic = %d, want 301", res.ValueUint64)
	}
	t.Log("CONST uint OK: BASE*SCALE+1 = 301")
}

// TestL7_ConstString: CONST string literal, used in comparison.
func TestL7_ConstString(t *testing.T) {
	code := `
Function UseStr() Uint64
	5 version("10.0.0")
	10 CONST DOMAIN = "relayos"
	20 DIM s AS String
	30 LET s = DOMAIN + ":settle"
	40 IF s == "relayos:settle" THEN GOTO 100
	50 RETURN 1
	100 RETURN 0
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	res, err := RunSmartContract(&sc, "UseStr", state, map[string]interface{}{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ValueUint64 != 0 {
		t.Fatalf("CONST string = %d, want 0", res.ValueUint64)
	}
	t.Log("CONST string OK: domain concat + compare")
}

// TestL7_ConstImmutable: LET on a const rejected.
func TestL7_ConstImmutable(t *testing.T) {
	code := `
Function TryMutate() Uint64
	5 version("10.0.0")
	10 CONST BASE = 100
	20 LET BASE = 200
	30 RETURN BASE
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	_, err = RunSmartContract(&sc, "TryMutate", state, map[string]interface{}{})
	if err == nil {
		t.Fatal("LET on a CONST should be rejected")
	}
	t.Logf("CONST immutability OK: %v", err)
}

// TestL8_VersionGate: CONST requires version("10.0.0").
func TestL8_VersionGate(t *testing.T) {
	code := `
Function Old() Uint64
	5 version("1.2.3")
	10 CONST BASE = 100
	20 RETURN BASE
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	_, err = RunSmartContract(&sc, "Old", state, map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "CONST") {
		t.Fatalf("CONST at 1.2.3 should be rejected, got: %v", err)
	}
	t.Logf("L8 version gate OK: %v", err)
}

// TestL8_NoVersion: no version() call -> new syntax rejected.
func TestL8_NoVersion(t *testing.T) {
	code := `
Function NoVer() Uint64
	10 CONST BASE = 100
	20 RETURN BASE
End Function
`
	sc, pos, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse (%s): %v", pos, err)
	}
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	_, err = RunSmartContract(&sc, "NoVer", state, map[string]interface{}{})
	if err == nil {
		t.Fatal("CONST without version() should be rejected")
	}
	t.Logf("L8 no-version gate OK: %v", err)
}
