// SC-auth signing for verify_sig-based contract authorization (K0 Fix C).
//
// The DVM's verify_sig intrinsic (DVM v9) lets a contract authorize callers
// by Ed25519 signature carried in encrypted SCDATA — so owner-gated
// entrypoints can run at ringsize >= 4, no SIGNER()/ringsize-2 exposure.
// The contract stores a public key at setup; callers prove authorization
// by signing a contract-defined message.
//
// This is the wallet-side half: an SC-auth Ed25519 keypair (separate from
// the DERO spend key — DERO keys are bn256 scalars, not Ed25519) plus a
// signing helper that produces the (pubkey, signature) SCDATA pair.
//
// The message convention is the contract's choice; the helper signs what
// the contract demands. Recommended convention (matches the verify_sig
// security notes): message = domain || scid || entrypoint || args, so the
// signature is bound to the specific call context. The wallet cannot sign
// the txid (it doesn't exist pre-build); a contract that wants txid
// binding can include a caller-supplied nonce in the message and check it.
package walletapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// SCAuthKey is the wallet's app-level Ed25519 keypair for SC authorization.
// Generated once, persisted (encrypted with the wallet) by the caller.
type SCAuthKey struct {
	Private ed25519.PrivateKey
}

// NewSCAuthKey generates a fresh SC-auth keypair.
func NewSCAuthKey() (*SCAuthKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	_ = pub
	return &SCAuthKey{Private: priv}, nil
}

// PublicKeyHex returns the hex-encoded 32-byte Ed25519 public key — this
// is what the contract stores at setup.
func (k *SCAuthKey) PublicKeyHex() string {
	return hex.EncodeToString(k.Private.Public().(ed25519.PublicKey))
}

// SignMessage signs a message; returns hex-encoded 64-byte signature.
func (k *SCAuthKey) SignMessage(msg []byte) string {
	return hex.EncodeToString(ed25519.Sign(k.Private, msg))
}

// SignSCData builds the standard authorization message for a contract call
// and signs it. message = domain || ":" || scid || ":" || entrypoint || ":" || args
// The contract must reconstruct the same string and pass it to verify_sig.
// Returns (pubkey_hex, sig_hex, message) for SCDATA.
func (k *SCAuthKey) SignSCData(domain, scid, entrypoint, args string) (pubkeyHex, sigHex, message string) {
	message = fmt.Sprintf("%s:%s:%s:%s", domain, scid, entrypoint, args)
	return k.PublicKeyHex(), k.SignMessage([]byte(message)), message
}

// VerifySCData is the client-side mirror of the contract's verify_sig check
// (useful for tests and for the wallet to self-check before broadcasting).
func VerifySCData(pubkeyHex, sigHex, message string) bool {
	pub, err := hex.DecodeString(pubkeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, []byte(message), sig)
}
