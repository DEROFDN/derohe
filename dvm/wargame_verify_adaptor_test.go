// Wargame: verify_adaptor malleability + non-canonical input gaps.
//
// Two findings pinned:
//
// 1. SCALAR MALLEABILITY: s' is taken raw from sig_bytes[:64] with no
//    s' < n (group order) check. ScalarMult internally reduces mod n, so
//    s' and s'+n produce the SAME point -> a signature with a non-canonical
//    (s >= n) scalar still verifies as 1. A canonical form should reject
//    s >= n (low-s normalization, BIP-340-style) so the encoded signature
//    is unique and non-malleable.
//
// 2. NON-CANONICAL POINT DECODE: P and R are decoded with
//    DecodeCompressed + err==nil, which ACCEPTS x >= p encodings (the
//    chain-split class the I3/v9 PRs close with strictDecodeG1). A strict
//    decoder (clean-room Rust) rejects such encodings -> divergence.
package dvm

import (
	"encoding/hex"
	"go/ast"
	"math/big"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/deroproject/derohe/cryptography/bn256"
)

func TestWargameVerifyAdaptorScalarMalleability(t *testing.T) {
	dvm := &DVM_Interpreter{
		Version: semver.MustParse("10.0.0"),
		State:   &Shared_State{},
	}
	msg := []byte("relayos:atomic-swap:leg-1:nonce-42")
	pub, msgHex, sig, _ := buildAdaptorSig(t, msg)

	call := func(pubh, msgh, sigh string) uint64 {
		expr := &ast.CallExpr{Fun: &ast.Ident{Name: "verify_adaptor"},
			Args: []ast.Expr{mkStrExpr(pubh), mkStrExpr(msgh), mkStrExpr(sigh)}}
		_, res := dvm_verify_adaptor(dvm, expr)
		return res
	}

	// base: valid -> 1
	if res := call(pub, msgHex, sig); res != 1 {
		t.Fatalf("valid adaptor: got %d want 1", res)
	}

	// FINDING: add n to s (non-canonical scalar, s >= n). Still verifies.
	sigBytes, _ := hex.DecodeString(sig)
	s := new(big.Int).SetBytes(sigBytes[:64])
	s.Add(s, bn256.Order) // s + n
	mal := make([]byte, 130)
	spb := s.Bytes()
	padded := make([]byte, 64)
	copy(padded[64-len(spb):], spb)
	copy(mal[:64], padded)
	copy(mal[64:], sigBytes[64:])
	malHex := hex.EncodeToString(mal)

	if res := call(pub, msgHex, malHex); res != 0 {
		t.Fatalf("malleated s+n accepted as 1 — low-s check not enforced")
	}
	t.Logf("WARGAME FIXED: s+n malleation now rejected (res=0) — low-s scalar enforced")
}

func TestWargameVerifyAdaptorNonCanonicalPoint(t *testing.T) {
	dvm := &DVM_Interpreter{
		Version: semver.MustParse("10.0.0"),
		State:   &Shared_State{},
	}
	msg := []byte("relayos:atomic-swap:leg-1:nonce-42")
	_, msgHex, sig, _ := buildAdaptorSig(t, msg)

	call := func(pubh, msgh, sigh string) uint64 {
		expr := &ast.CallExpr{Fun: &ast.Ident{Name: "verify_adaptor"},
			Args: []ast.Expr{mkStrExpr(pubh), mkStrExpr(msgh), mkStrExpr(sigh)}}
		_, res := dvm_verify_adaptor(dvm, expr)
		return res
	}

	// x >= p compressed encoding (p is the bn256 base-field modulus)
	P_HEX := "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47"
	xGtP := "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd48" + "00"

	// FINDING: non-canonical pubkey (x > p) — DecodeCompressed accepts it.
	// dvm_verify_adaptor decodes P with err==nil only; a strict decoder
	// (Rust clean-room, strictDecodeG1) REJECTS x >= p -> divergence.
	res := call(xGtP, msgHex, sig)
	t.Logf("WARGAME: verify_adaptor with x>p pubkey returns %d (strict decoder would reject the encoding outright)", res)
	_ = P_HEX
}
