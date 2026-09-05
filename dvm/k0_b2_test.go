// K0 Fix B2 tests (spec k0-fix-design.md, dvm-basic-improvements.md):
// NoSigner meta bit + SIGNER() auto-detection + 33-byte wire preservation.
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
package dvm

import (
	"bytes"
	"testing"
)

// --- ContractUsesSigner detection ---

func TestContractUsesSigner_DetectsCall(t *testing.T) {
	code := `
Function Initialize() Uint64
	10 STORE("owner", SIGNER())
	20 RETURN 0
End Function
Function TransferOwnership() Uint64
	30 IF SIGNER() != LOAD("owner") THEN GOTO 900
	40 RETURN 0
	900 RETURN 1
End Function`
	sc, _, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !ContractUsesSigner(sc) {
		t.Fatal("SIGNER() present but not detected")
	}
}

func TestContractUsesSigner_NoFalsePositive(t *testing.T) {
	code := `
Function Initialize() Uint64
	10 STORE("owner", "alice")
	20 RETURN 0
End Function
Function OwnerAction() Uint64
	30 IF LOAD("owner") == "alice" THEN GOTO 40
	35 RETURN 1
	40 RETURN 0
End Function`
	sc, _, err := ParseSmartContract(code)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ContractUsesSigner(sc) {
		t.Fatal("no SIGNER() call but detected as using signer")
	}
}

func TestContractUsesSigner_CaseInsensitive(t *testing.T) {
	// DVM dispatch lowercases function names; SIGNER/signer/Signer all resolve.
	for _, s := range []string{"SIGNER()", "signer()", "Signer()"} {
		code := "Function F() Uint64\n10 dim x as String\n20 LET x = " + s + "\n30 RETURN 0\nEnd Function"
		sc, _, err := ParseSmartContract(code)
		if err != nil {
			t.Fatalf("parse %s: %v", s, err)
		}
		if !ContractUsesSigner(sc) {
			t.Fatalf("%s not detected", s)
		}
	}
}

// --- SC_META_DATA NoSigner bit ---

func TestSCMetaNoSignerBit(t *testing.T) {
	meta := SC_META_DATA{}
	if meta.NoSigner() {
		t.Fatal("fresh meta should not have NoSigner")
	}
	meta.SetNoSigner()
	if !meta.NoSigner() {
		t.Fatal("SetNoSigner did not stick")
	}
	if meta.IsPrivate() {
		t.Fatal("NoSigner bit must not imply private")
	}
	// 33-byte wire format preserved.
	if got := meta.MarshalBinary(); len(got) != 33 {
		t.Fatalf("wire length = %d, want 33", len(got))
	}
	if got := meta.MarshalBinaryGood(); len(got) != 33 {
		t.Fatalf("wire length (good) = %d, want 33", len(got))
	}
}

func TestSCMetaPrivateAndNoSignerCoexist(t *testing.T) {
	meta := SC_META_DATA{Type: SC_META_TYPE_PRIVATE}
	meta.SetNoSigner()
	if !meta.IsPrivate() {
		t.Fatal("private flag lost when NoSigner set")
	}
	if !meta.NoSigner() {
		t.Fatal("NoSigner lost when private set")
	}
	// Round-trip both serializations.
	var m2 SC_META_DATA
	if err := m2.UnmarshalBinary(meta.MarshalBinary()); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !m2.IsPrivate() || !m2.NoSigner() {
		t.Fatal("round-trip lost flags")
	}
	var m3 SC_META_DATA
	if err := m3.UnmarshalBinaryGood(meta.MarshalBinaryGood()); err != nil {
		t.Fatalf("unmarshal good: %v", err)
	}
	if !m3.IsPrivate() || !m3.NoSigner() {
		t.Fatal("round-trip (good) lost flags")
	}
}

func TestSCMeta33ByteCompatibility(t *testing.T) {
	// A pre-B2 meta (Type=0 or 1, 33 bytes) unmarshals with NoSigner=false —
	// existing on-chain metadata stays valid, existing contracts keep
	// uses_signer=true behavior.
	legacy := []byte{0}
	legacy = append(legacy, make([]byte, 32)...)
	var m SC_META_DATA
	if err := m.UnmarshalBinary(legacy); err != nil {
		t.Fatalf("legacy unmarshal: %v", err)
	}
	if m.NoSigner() {
		t.Fatal("legacy meta must default to uses_signer (NoSigner unset)")
	}
	if m.IsPrivate() {
		t.Fatal("Type=0 legacy must be open")
	}

	legacyPrivate := append([]byte{1}, make([]byte, 32)...)
	var mp SC_META_DATA
	if err := mp.UnmarshalBinary(legacyPrivate); err != nil {
		t.Fatalf("legacy private unmarshal: %v", err)
	}
	if !mp.IsPrivate() {
		t.Fatal("legacy private lost")
	}
	if mp.NoSigner() {
		t.Fatal("legacy private must default uses_signer")
	}
}

func TestSCMetaMarshalDeterminism(t *testing.T) {
	meta := SC_META_DATA{Type: SC_META_TYPE_PRIVATE | SC_META_NOSIGNER}
	b1 := meta.MarshalBinary()
	b2 := meta.MarshalBinary()
	if !bytes.Equal(b1, b2) {
		t.Fatal("MarshalBinary not deterministic")
	}
}
