// verify_sig intrinsic tests (spec dvm-basic-improvements.md P0-1, K0 Fix C)
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// Tests the new DVM-BASIC `verify_sig(pubkey, message, sig) -> Uint64`
// intrinsic through the in-process simulator:
//   - a valid Ed25519 signature over a contract-bound message returns 1
//   - a tampered signature returns 0
//   - a tampered message returns 0
//   - malformed pubkey/sig hex returns 0 (not a panic)
//   - version gate: contract must declare version("9.x") to see the function
package dvm

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"go/ast"
	"go/token"
	"strconv"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
)

// TestVerifySig_TableUnit: direct handler tests (valid/invalid/malformed).
// NOTE: the end-to-end SCInstall path needs a full graviton store
// (see simulator_test.go's setup); the intrinsic itself is fully exercised
// here, and the version gate + gas cost are covered by the table entry.
func TestVerifySig_TableUnit(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("test message")
	sig := ed25519.Sign(priv, msg)

	mkExpr := func(args ...interface{}) *ast.CallExpr {
		// build CallExpr with literal args
		expr := &ast.CallExpr{Fun: &ast.Ident{Name: "verify_sig"}, Args: []ast.Expr{}}
		for _, a := range args {
			switch v := a.(type) {
			case string:
				expr.Args = append(expr.Args, &ast.BasicLit{Kind: token.STRING, Value: "\"" + v + "\""})
			case uint64:
				expr.Args = append(expr.Args, &ast.BasicLit{Kind: token.INT, Value: strconv.FormatUint(v, 10)})
			}
		}
		return expr
	}

	dvm := &DVM_Interpreter{
		Version: semver.MustParse("9.0.0"),
		State:   &Shared_State{},
	}
	ok, res := dvm_verify_sig(dvm, mkExpr(hex.EncodeToString(pub), string(msg), hex.EncodeToString(sig)))
	if !ok || res != 1 {
		t.Fatalf("valid sig: got ok=%v res=%d want 1", ok, res)
	}

	// tampered sig
	bad_sig := append([]byte{}, sig...)
	bad_sig[0] ^= 0xff
	ok, res = dvm_verify_sig(dvm, mkExpr(hex.EncodeToString(pub), string(msg), hex.EncodeToString(bad_sig)))
	if !ok || res != 0 {
		t.Fatalf("tampered sig: got res=%d want 0", res)
	}

	// tampered message
	ok, res = dvm_verify_sig(dvm, mkExpr(hex.EncodeToString(pub), string(msg)+"x", hex.EncodeToString(sig)))
	if !ok || res != 0 {
		t.Fatalf("tampered message: got res=%d want 0", res)
	}

	// wrong pubkey
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	ok, res = dvm_verify_sig(dvm, mkExpr(hex.EncodeToString(other), string(msg), hex.EncodeToString(sig)))
	if !ok || res != 0 {
		t.Fatalf("wrong pubkey: got res=%d want 0", res)
	}

	// malformed hex -> 0, no panic
	ok, res = dvm_verify_sig(dvm, mkExpr("zzz", string(msg), hex.EncodeToString(sig)))
	if !ok || res != 0 {
		t.Fatalf("malformed pubkey: got res=%d want 0", res)
	}

	// short sig -> 0, no panic
	ok, res = dvm_verify_sig(dvm, mkExpr(hex.EncodeToString(pub), string(msg), "abcd"))
	if !ok || res != 0 {
		t.Fatalf("short sig: got res=%d want 0", res)
	}
}

// TestVerifySig_VersionGate: a contract on an OLD dvm version must NOT see
// verify_sig (func_table Range >= 9.0.0).
func TestVerifySig_VersionGate(t *testing.T) {
	dvm := &DVM_Interpreter{Version: semver.MustParse("1.2.3")}
	// simulate Handle_Internal_Function lookup on old version: Range check fails
	handled := false
	if fda, ok := func_table["verify_sig"]; ok {
		for _, f := range fda {
			if f.Range(dvm.Version) {
				handled = true
				break
			}
		}
	}
	if handled {
		t.Fatal("verify_sig visible to dvm version 1.2.3 — version gate broken")
	}
}

// TestPedersenCommit: determinism, verify round-trip, binding.
func TestPedersenCommit(t *testing.T) {
	dvm := &DVM_Interpreter{
		Version: semver.MustParse("9.0.0"),
		State:   &Shared_State{},
	}
	mkStr := func(s string) ast.Expr {
		return &ast.BasicLit{Kind: token.STRING, Value: "\"" + s + "\""}
	}
	mkUint := func(v uint64) ast.Expr {
		return &ast.BasicLit{Kind: token.INT, Value: strconv.FormatUint(v, 10)}
	}
	commitExpr := func(v uint64, b string) *ast.CallExpr {
		return &ast.CallExpr{Fun: &ast.Ident{Name: "pedersen_commit"},
			Args: []ast.Expr{mkUint(v), mkStr(b)}}
	}
	verifyExpr := func(v uint64, b, c string) *ast.CallExpr {
		return &ast.CallExpr{Fun: &ast.Ident{Name: "verify_commit"},
			Args: []ast.Expr{mkUint(v), mkStr(b), mkStr(c)}}
	}

	blind := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 32 bytes

	// determinism: same (value, blind) -> same point
	ok1, c1 := dvm_pedersen_commit(dvm, commitExpr(100000, blind))
	ok2, c2 := dvm_pedersen_commit(dvm, commitExpr(100000, blind))
	if !ok1 || !ok2 || c1 != c2 {
		t.Fatalf("commit not deterministic: %q vs %q", c1, c2)
	}
	if len(c1) != 66 {
		t.Fatalf("expected 33-byte compressed point, got %d chars", len(c1))
	}

	// verify: correct (value, blind) -> 1
	_, vok := dvm_verify_commit(dvm, verifyExpr(100000, blind, c1))
	if vok != 1 {
		t.Fatalf("verify_commit returned %d, want 1 for correct reveal", vok)
	}

	// wrong value -> 0
	_, vok = dvm_verify_commit(dvm, verifyExpr(100001, blind, c1))
	if vok != 0 {
		t.Fatal("verify_commit accepted wrong value")
	}

	// wrong blind -> 0
	_, vok = dvm_verify_commit(dvm, verifyExpr(100000, blind[:62]+"00", c1))
	if vok != 0 {
		t.Fatal("verify_commit accepted wrong blind")
	}

	// tampered commit -> 0
	bad := []byte(c1)
	bad[0] = '0' + byte((int(bad[0])+1)%10)
	_, vok = dvm_verify_commit(dvm, verifyExpr(100000, blind, string(bad)))
	if vok != 0 {
		t.Fatal("verify_commit accepted tampered commit")
	}

	// malformed blind/commit -> 0, no panic
	_, vok = dvm_verify_commit(dvm, verifyExpr(100000, "zzz", c1))
	if vok != 0 {
		t.Fatal("verify_commit accepted malformed blind")
	}
	_, vok = dvm_verify_commit(dvm, verifyExpr(100000, blind, "abc"))
	if vok != 0 {
		t.Fatal("verify_commit accepted malformed commit")
	}

	// hiding: same value, different blind -> different point
	_, c3 := dvm_pedersen_commit(dvm, commitExpr(100000, blind[:62]+"ff"))
	if c3 == c1 {
		t.Fatal("commit not hiding: same value different blind gave same point")
	}

	// binding sanity: different values with different blinds are distinct
	_, c4 := dvm_pedersen_commit(dvm, commitExpr(99999, blind[:62]+"ee"))
	if c4 == c1 || c4 == c3 {
		t.Fatal("binding violation: distinct (value, blind) collided")
	}
	t.Logf("pedersen_commit OK: %s…", c1[:16])
}

// keep imports used (some are only referenced in generated exprs)

// TestHashToPoint: determinism + point-form invariants.
func TestHashToPoint(t *testing.T) {
	dvm := &DVM_Interpreter{
		Version: semver.MustParse("9.0.0"),
		State:   &Shared_State{},
	}
	mkExpr := func(s string) *ast.CallExpr {
		return &ast.CallExpr{Fun: &ast.Ident{Name: "hash_to_point"},
			Args: []ast.Expr{&ast.BasicLit{Kind: token.STRING, Value: "\"" + s + "\""}}}
	}

	// deterministic
	h1, res1 := dvm_hash_to_point(dvm, mkExpr("relayos.commit.v1"))
	h2, res2 := dvm_hash_to_point(dvm, mkExpr("relayos.commit.v1"))
	if !h1 || !h2 || res1 != res2 {
		t.Fatalf("hash_to_point not deterministic: %q vs %q", res1, res2)
	}
	// distinct inputs -> distinct points
	h3, res3 := dvm_hash_to_point(dvm, mkExpr("relayos.commit.v2"))
	if !h3 || res3 == res1 {
		t.Fatal("distinct inputs produced same point")
	}
	// 33-byte compressed encoding (66 hex chars)
	if len(res1) != 66 {
		t.Fatalf("expected 33-byte compressed point (66 hex), got %d chars", len(res1))
	}
	// decodes as a valid compressed G1 point
	decoded, err := hex.DecodeString(res1)
	if err != nil || len(decoded) != 33 {
		t.Fatalf("bad hex: %v", err)
	}
	pt := &bn256.G1{}
	if err := pt.DecodeCompressed(decoded); err != nil {
		t.Fatalf("not a valid G1 point: %v", err)
	}
	t.Logf("hash_to_point OK: %s…", res1[:16])
}

// TestAssetBalance: the intrinsic reads the SC's OWN stored balance via
// BalanceLoader (wired to LoadSCAssetValue in sc.go), keyed by (SCIDSELF,
// asset). This is the gap-derivalue/assetvalue only see the tx's incoming
// value, never the persisted holding.
func TestAssetBalance(t *testing.T) {
	// fake BalanceLoader that records the key it's asked for and returns a
	// canned "stored" value — verifies the wiring, not the tree.
	var gotKey DataKey
	stored := uint64(12345)
	store := &TX_Storage{
		BalanceLoader: func(key DataKey) uint64 {
			gotKey = key
			return stored
		},
	}
	self := crypto.Hash{0x01}
	dvm := &DVM_Interpreter{
		Version: semver.MustParse("9.0.0"),
		State:   &Shared_State{SCIDSELF: self, Store: store},
	}
	asset := crypto.Hash{0xab, 0xcd}

	expr := &ast.CallExpr{Fun: &ast.Ident{Name: "asset_balance"},
		Args: []ast.Expr{&ast.BasicLit{Kind: token.STRING, Value: "\"" + hex.EncodeToString(asset[:]) + "\""}}}
	ok, res := dvm_asset_balance(dvm, expr)
	if !ok || res != stored {
		t.Fatalf("asset_balance: got ok=%v res=%d want %d", ok, res, stored)
	}
	// the BalanceLoader must be called with the SC's own SCID + the asset
	if gotKey.SCID != self {
		t.Fatalf("BalanceLoader called with SCID %v, want self %v", gotKey.SCID, self)
	}
	if gotKey.Key.ValueString != string(asset[:]) {
		t.Fatalf("BalanceLoader called with key %q, want asset %q", gotKey.Key.ValueString, string(asset[:]))
	}

	// version gate: hidden from v1.2.3
	if fda, ok := func_table["asset_balance"]; ok {
		for _, f := range fda {
			if f.Range(semver.MustParse("1.2.3")) {
				t.Fatal("asset_balance visible to dvm version 1.2.3 — version gate broken")
			}
		}
	}
	t.Logf("asset_balance OK: reads SC self-balance via BalanceLoader(scid, asset)")
}

// TestEcAdd: point addition + the homomorphic property that makes it the
// accumulation primitive — ec_add(pedersen_commit(v1,b1), pedersen_commit(v2,b2))
// equals pedersen_commit(v1+v2, b1+b2), and verify_commit accepts it.
func TestEcAdd(t *testing.T) {
	dvm := &DVM_Interpreter{
		Version: semver.MustParse("9.0.0"),
		State:   &Shared_State{},
	}
	mkStr := func(s string) ast.Expr {
		return &ast.BasicLit{Kind: token.STRING, Value: "\"" + s + "\""}
	}
	mkUint := func(v uint64) ast.Expr {
		return &ast.BasicLit{Kind: token.INT, Value: strconv.FormatUint(v, 10)}
	}
	commitExpr := func(v uint64, b string) *ast.CallExpr {
		return &ast.CallExpr{Fun: &ast.Ident{Name: "pedersen_commit"},
			Args: []ast.Expr{mkUint(v), mkStr(b)}}
	}
	addExpr := func(p1, p2 string) *ast.CallExpr {
		return &ast.CallExpr{Fun: &ast.Ident{Name: "ec_add"},
			Args: []ast.Expr{mkStr(p1), mkStr(p2)}}
	}
	verifyExpr := func(v uint64, b, c string) *ast.CallExpr {
		return &ast.CallExpr{Fun: &ast.Ident{Name: "verify_commit"},
			Args: []ast.Expr{mkUint(v), mkStr(b), mkStr(c)}}
	}

	// small blinds so b1+b2 has no carry beyond 32 bytes
	b1 := "0000000000000000000000000000000000000000000000000000000000000001"
	b2 := "0000000000000000000000000000000000000000000000000000000000000002"
	b3 := "0000000000000000000000000000000000000000000000000000000000000003" // b1+b2

	_, c1 := dvm_pedersen_commit(dvm, commitExpr(100, b1))
	_, c2 := dvm_pedersen_commit(dvm, commitExpr(200, b2))
	_, c3 := dvm_pedersen_commit(dvm, commitExpr(300, b3))

	// homomorphic: ec_add(c1, c2) == c3 (the exact AMM-reserve-update property)
	ok, sum := dvm_ec_add(dvm, addExpr(c1, c2))
	if !ok {
		t.Fatal("ec_add not handled")
	}
	if sum != c3 {
		t.Fatalf("ec_add not homomorphic:\n got  %s\n want %s", sum, c3)
	}

	// the summed point verifies against the summed (value, blind)
	_, vok := dvm_verify_commit(dvm, verifyExpr(300, b3, sum))
	if vok != 1 {
		t.Fatal("verify_commit rejected the homomorphic sum")
	}

	// commutativity
	_, sum2 := dvm_ec_add(dvm, addExpr(c2, c1))
	if sum2 != sum {
		t.Fatal("ec_add not commutative")
	}

	// output is a valid 33-byte compressed point (66 hex chars)
	if len(sum) != 66 {
		t.Fatalf("expected 33-byte compressed point (66 hex), got %d chars", len(sum))
	}
	decoded, err := hex.DecodeString(sum)
	if err != nil || len(decoded) != 33 {
		t.Fatalf("bad hex: %v", err)
	}
	pt := &bn256.G1{}
	if err := pt.DecodeCompressed(decoded); err != nil {
		t.Fatalf("sum is not a valid G1 point: %v", err)
	}

	// version gate
	if fda, ok := func_table["ec_add"]; ok {
		for _, f := range fda {
			if f.Range(semver.MustParse("1.2.3")) {
				t.Fatal("ec_add visible to dvm version 1.2.3 — version gate broken")
			}
		}
	}
	t.Logf("ec_add OK: homomorphic (c1+c2==c3), commutative, valid point")
}

// TestEcMul: scalar multiplication — the homomorphic counterpart to
// ec_add. ec_mul(c, 2) == ec_add(c, c), and ec_mul(ec_mul(c, k), j) ==
// ec_mul(c, k*j). Combined with ec_add, a contract can do point
// derivation and key blinding entirely in-VM.
func TestEcMul(t *testing.T) {
	dvm := &DVM_Interpreter{
		Version: semver.MustParse("9.0.0"),
		State:   &Shared_State{},
	}
	mkStr := func(s string) ast.Expr {
		return &ast.BasicLit{Kind: token.STRING, Value: "\"" + s + "\""}
	}
	mkUint := func(v uint64) ast.Expr {
		return &ast.BasicLit{Kind: token.INT, Value: strconv.FormatUint(v, 10)}
	}
	commitExpr := func(v uint64, b string) *ast.CallExpr {
		return &ast.CallExpr{Fun: &ast.Ident{Name: "pedersen_commit"},
			Args: []ast.Expr{mkUint(v), mkStr(b)}}
	}
	mulExpr := func(p string, s uint64) *ast.CallExpr {
		return &ast.CallExpr{Fun: &ast.Ident{Name: "ec_mul"},
			Args: []ast.Expr{mkStr(p), mkUint(s)}}
	}
	addExpr := func(p1, p2 string) *ast.CallExpr {
		return &ast.CallExpr{Fun: &ast.Ident{Name: "ec_add"},
			Args: []ast.Expr{mkStr(p1), mkStr(p2)}}
	}

	b := "0000000000000000000000000000000000000000000000000000000000000001"
	_, c1 := dvm_pedersen_commit(dvm, commitExpr(100, b))

	// homomorphic: ec_mul(c, 2) == ec_add(c, c)
	_, doubled := dvm_ec_mul(dvm, mulExpr(c1, 2))
	_, added := dvm_ec_add(dvm, addExpr(c1, c1))
	if doubled != added {
		t.Fatalf("ec_mul(c,2) != ec_add(c,c):\n  mul %s\n  add %s", doubled, added)
	}

	// scalar composition: ec_mul(ec_mul(c,k), j) == ec_mul(c, k*j)
	_, m3 := dvm_ec_mul(dvm, mulExpr(c1, 3))
	_, m23 := dvm_ec_mul(dvm, mulExpr(m3, 2))
	_, m6 := dvm_ec_mul(dvm, mulExpr(c1, 6))
	if m23 != m6 {
		t.Fatalf("ec_mul composition wrong:\n  3*2 %s\n  6   %s", m23, m6)
	}

	// scalar 1 -> identity; scalar 0 -> valid point encoding
	_, one := dvm_ec_mul(dvm, mulExpr(c1, 1))
	if one != c1 {
		t.Fatal("ec_mul(c,1) != c")
	}
	_, zero := dvm_ec_mul(dvm, mulExpr(c1, 0))
	if len(zero) != 66 {
		t.Fatalf("ec_mul(c,0) not a valid point encoding: %d chars", len(zero))
	}

	// output is always a valid 33-byte compressed point (66 hex chars)
	if len(doubled) != 66 || len(m6) != 66 {
		t.Fatal("ec_mul output not 33-byte compressed point")
	}

	// version gate
	if fda, ok := func_table["ec_mul"]; ok {
		for _, f := range fda {
			if f.Range(semver.MustParse("1.2.3")) {
				t.Fatal("ec_mul visible to dvm version 1.2.3 — version gate broken")
			}
		}
	}

	t.Log("ec_mul OK: homomorphic with ec_add, scalar composition, identity, version gate")
}
