// verify_adaptor intrinsic tests (I4, true adaptor with tweak point T).
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// A REAL Schnorr adaptor (Poelstra/Poon dryja style) commits to a tweak
// point T = t*G and produces s' = k + e*x - t. Verification is
//
//	s'*G == R - T + e*P
//
// and anyone who learns t can complete s = s' + t into a valid Schnorr
// signature (s*G == R + e*P). The blob carries s'(64) || R(33) || T(33)
// = 130 bytes. This is the fix over the old "adaptor" that folded t into
// R'/s' and had no T at all (so nothing could be revealed).
package dvm

import (
	"encoding/hex"
	"go/ast"
	"math/big"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
)

// buildTrueAdaptor constructs a genuine Schnorr adaptor on bn256:
//
//	x=secret P=x*G ; k=nonce R=k*G ; t=tweak T=t*G
//	e = ReducedHash(R || P || m) ; s' = k + e*x - t  (mod n)
//
// Blob = s'(64) || R(33) || T(33) = 130 bytes.
func buildTrueAdaptor(t *testing.T, msg []byte) (string, string, string, *big.Int) {
	t.Helper()
	x := crypto.RandomScalar()
	k := crypto.RandomScalar()
	tweak := crypto.RandomScalar()

	P := new(bn256.G1).ScalarMult(crypto.G, x)
	R := new(bn256.G1).ScalarMult(crypto.G, k)
	T := new(bn256.G1).ScalarMult(crypto.G, tweak)

	hash_input := append([]byte{}, R.EncodeCompressed()...)
	hash_input = append(hash_input, P.EncodeCompressed()...)
	hash_input = append(hash_input, msg...)
	e := crypto.ReducedHash(hash_input)

	// s' = k + e*x - t (mod n)
	sp := new(big.Int).Mul(e, x)
	sp.Add(sp, k)
	sp.Sub(sp, tweak)
	sp.Mod(sp, bn256.Order)

	sig := make([]byte, 0, 130)
	spb := sp.Bytes()
	padded := make([]byte, 64)
	copy(padded[64-len(spb):], spb)
	sig = append(sig, padded...)
	sig = append(sig, R.EncodeCompressed()...)
	sig = append(sig, T.EncodeCompressed()...)

	return hex.EncodeToString(P.EncodeCompressed()), hex.EncodeToString(msg), hex.EncodeToString(sig), tweak
}

// TestVerifyAdaptorTrueTweak: a genuine adaptor must verify, and the tweak
// must complete it into a valid Schnorr signature.
func TestVerifyAdaptorTrueTweak(t *testing.T) {
	dvm := &DVM_Interpreter{
		Version: semver.MustParse("10.0.0"),
		State:   &Shared_State{},
	}
	msg := []byte("relayos:atomic-swap:leg-1:nonce-42")
	pub, msgHex, sig, tweak := buildTrueAdaptor(t, msg)

	call := func(pubh, msgh, sigh string) uint64 {
		expr := &ast.CallExpr{Fun: &ast.Ident{Name: "verify_adaptor"},
			Args: []ast.Expr{mkStrExpr(pubh), mkStrExpr(msgh), mkStrExpr(sigh)}}
		_, res := dvm_verify_adaptor(dvm, expr)
		return res
	}

	// valid true adaptor -> 1
	if res := call(pub, msgHex, sig); res != 1 {
		t.Fatalf("valid adaptor: got %d want 1", res)
	}

	// completion: s = s' + t must be a valid Schnorr (s*G == R + e*P)
	sigb, _ := hex.DecodeString(sig)
	var R, T bn256.G1
	R.DecodeCompressed(sigb[64:97])
	T.DecodeCompressed(sigb[97:130])
	pubb, _ := hex.DecodeString(pub)
	var P bn256.G1
	P.DecodeCompressed(pubb)
	e := crypto.ReducedHash(append(append(append([]byte{}, R.EncodeCompressed()...), P.EncodeCompressed()...), msg...))
	sp := new(big.Int).SetBytes(sigb[:64])
	s := new(big.Int).Add(sp, tweak)
	s.Mod(s, bn256.Order)
	lhs := new(bn256.G1).ScalarMult(crypto.G, s)
	rhs := new(bn256.G1).Add(&R, new(bn256.G1).ScalarMult(&P, e))
	if lhs.String() != rhs.String() {
		t.Fatal("tweak did not complete the adaptor into a Schnorr signature")
	}

	// wrong pubkey -> 0
	otherX := crypto.RandomScalar()
	otherP := hex.EncodeToString(new(bn256.G1).ScalarMult(crypto.G, otherX).EncodeCompressed())
	if res := call(otherP, msgHex, sig); res != 0 {
		t.Fatal("wrong pubkey accepted")
	}

	// wrong message -> 0
	if res := call(pub, hex.EncodeToString([]byte("other")), sig); res != 0 {
		t.Fatal("wrong message accepted")
	}

	// tampered T -> 0 (commitment must be fixed)
	sigb2 := append([]byte{}, sigb...)
	sigb2[97] ^= 0xff
	if res := call(pub, msgHex, hex.EncodeToString(sigb2)); res != 0 {
		t.Fatal("tampered tweak point accepted")
	}

	// wrong blob length (old 97-byte form, no T) -> 0
	if res := call(pub, msgHex, hex.EncodeToString(sigb[:97])); res != 0 {
		t.Fatal("adaptor without T accepted")
	}

	// malformed -> 0 no panic
	if res := call("zz", msgHex, sig); res != 0 {
		t.Fatal("malformed pubkey accepted")
	}
	if res := call(pub, msgHex, "zz"); res != 0 {
		t.Fatal("malformed sig accepted")
	}

	// version gate: hidden from 9.x
	handled := false
	if fda, ok := func_table["verify_adaptor"]; ok {
		for _, f := range fda {
			if f.Range(semver.MustParse("9.0.0")) {
				handled = true
				break
			}
		}
	}
	if handled {
		t.Fatal("verify_adaptor visible to dvm 9.0.0 — version gate broken")
	}
	t.Logf("true adaptor OK: valid=1, complete-schnorr=1, wrong-key/msg/T/length/malformed=0 (sig %dB)", len(sigb))
}
