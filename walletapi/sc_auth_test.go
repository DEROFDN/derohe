// SCAuthKey helper tests (K0 Fix C wallet-side half).
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// Direct unit tests for walletapi/sc_auth.go: key generation, signing,
// the SignSCData message convention, and VerifySCData (the client-side
// mirror of the contract's verify_sig check).
package walletapi

import (
	"strings"
	"testing"
)

func TestSCAuthKeyRoundTrip(t *testing.T) {
	key, err := NewSCAuthKey()
	if err != nil {
		t.Fatal(err)
	}
	pubHex := key.PublicKeyHex()
	if len(pubHex) != 64 { // 32 bytes hex
		t.Fatalf("pubkey hex len %d, want 64", len(pubHex))
	}

	// sign + verify round-trip
	msg := []byte("relayos:test-scid:OwnerAction:n-fixc-1")
	sig := key.SignMessage(msg)
	if len(sig) != 128 { // 64 bytes hex
		t.Fatalf("signature hex len %d, want 128", len(sig))
	}
	if !VerifySCData(pubHex, sig, string(msg)) {
		t.Fatal("VerifySCData failed on a valid signature")
	}

	// tampered message -> rejected
	if VerifySCData(pubHex, sig, string(msg)+"x") {
		t.Fatal("VerifySCData accepted tampered message")
	}

	// tampered signature -> rejected
	tampered := []byte(sig)
	tampered[0] ^= 0xff
	if VerifySCData(pubHex, string(tampered), string(msg)) {
		t.Fatal("VerifySCData accepted tampered signature")
	}

	// wrong key -> rejected
	other, _ := NewSCAuthKey()
	if VerifySCData(other.PublicKeyHex(), sig, string(msg)) {
		t.Fatal("VerifySCData accepted wrong public key")
	}

	// malformed inputs -> rejected (no panic)
	if VerifySCData("zz", sig, string(msg)) {
		t.Fatal("VerifySCData accepted malformed pubkey")
	}
	if VerifySCData(pubHex, "zz", string(msg)) {
		t.Fatal("VerifySCData accepted malformed sig")
	}
	t.Log("SCAuthKey round-trip OK: sign/verify, tamper/wrong-key/malformed all rejected")
}

func TestSignSCDataMessageConvention(t *testing.T) {
	key, _ := NewSCAuthKey()
	pub, sig, message := key.SignSCData("relayos", "scid123", "OwnerAction", "n-fixc-2")

	// the message the contract reconstructs: domain:scid:entrypoint:args
	want := "relayos:scid123:OwnerAction:n-fixc-2"
	if message != want {
		t.Fatalf("message convention: got %q want %q", message, want)
	}
	if !VerifySCData(pub, sig, message) {
		t.Fatal("SignSCData produced an invalid signature")
	}

	// the domain binding matters: same args under a different domain fails
	if VerifySCData(pub, sig, strings.Replace(message, "relayos", "other", 1)) {
		t.Fatal("signature not bound to domain")
	}
	t.Log("SignSCData message convention OK: domain:scid:entrypoint:args, domain-bound")
}
