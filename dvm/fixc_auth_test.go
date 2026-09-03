// K0 Fix C demo: wallet-signed SC authorization via verify_sig (DVM v9).
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// The full Fix C flow in the simulator:
//   1. A contract is installed with the owner's Ed25519 public key.
//   2. The wallet (walletapi.SCAuthKey helper) signs the call message
//      domain:scid:entrypoint:nonce.
//   3. The caller submits (nonce, pubkey, signature) in SCDATA at
//      ringsize >= 4 — no SIGNER(), no ringsize-2 exposure.
//   4. The contract's verify_sig checks the signature AND that the pubkey
//      matches the stored owner, then authorizes.
package dvm

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

// fixCContractCode: owner-gated action authorized by Ed25519 signature
// (verify_sig), message = domain:scid:entrypoint:nonce. No SIGNER() —
// the caller stays anonymous at ringsize >= 4.
const fixCContractCode = `
Function Initialize(owner_pubkey String) Uint64
	5 version("9.0.0")
	10 STORE("owner", owner_pubkey)
	20 STORE("authorized", 0)
	30 RETURN 0
End Function
Function OwnerAction(nonce String, pubkey String, sig String) Uint64
	5 version("9.0.0")
	10 dim msg as String
	20 LET msg = "relayos:" + SCID() + ":OwnerAction:" + nonce
	30 IF verify_sig(pubkey, msg, sig) != 1 THEN GOTO 900
	40 IF pubkey != LOAD("owner") THEN GOTO 900
	50 STORE("authorized", 1)
	60 RETURN 0
	900 RETURN 1
End Function
Function StateGet() Uint64
	10 RETURN LOAD("authorized")
End Function
`

// TestFixC_WalletSignedAuthorization: install with owner pubkey, wallet
// signs the call, contract authorizes; wrong key / tampered sig rejected.
func TestFixC_WalletSignedAuthorization(t *testing.T) {
	s := SimulatorInitialize(nil, 0)
	addr, err := rpc.NewAddress(strings.TrimSpace("deto1qy0ehnqjpr0wxqnknyc66du2fsxyktppkr8m8e6jvplp954klfjz2qqdzcd8p"))
	if err != nil {
		t.Fatal(err)
	}
	var zerohash crypto.Hash
	s.AccountAddBalance(*addr, zerohash, 5000)

	// the owner's SC-auth keypair (mirrors walletapi.SCAuthKey; the dvm test
	// cannot import walletapi — walletapi imports dvm)
	ownerPub, ownerPriv, _ := ed25519.GenerateKey(rand.Reader)
	ownerPubHex := hex.EncodeToString(ownerPub)

	// install with the owner's public key
	scid, _, _, err := s.SCInstall(fixCContractCode, map[crypto.Hash]uint64{}, rpc.Arguments{
		rpc.Argument{Name: "owner_pubkey", DataType: rpc.DataString, Value: ownerPubHex},
	}, addr, 0)
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	// a different key (attacker) — must be rejected
	atkPub, atkPriv, _ := ed25519.GenerateKey(rand.Reader)

	nonce := "n-fixc-0001"

	// helper to drive an OwnerAction call
	runOwnerAction := func(pubkeyHex, sigHex string) uint64 {
		_, _, err = s.RunSC(map[crypto.Hash]uint64{}, rpc.Arguments{
			rpc.Argument{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
			rpc.Argument{Name: rpc.SCID, DataType: rpc.DataHash, Value: scid},
			rpc.Argument{Name: "entrypoint", DataType: rpc.DataString, Value: "OwnerAction"},
			rpc.Argument{Name: "nonce", DataType: rpc.DataString, Value: nonce},
			rpc.Argument{Name: "pubkey", DataType: rpc.DataString, Value: pubkeyHex},
			rpc.Argument{Name: "sig", DataType: rpc.DataString, Value: sigHex},
		}, addr, 0)
		return readAuthorized(s, scid)
	}

	// message convention: domain:scid:entrypoint:nonce (must match the
	// contract's reconstruction). SCID() in the DVM returns the RAW 32
	// bytes as a String (dvm_functions.go dvm_scid), NOT hex — the signed
	// message must use the same encoding or verify_sig sees a different msg.
	signMsg := func(priv ed25519.PrivateKey, scid crypto.Hash, nonce string) string {
		return "relayos:" + string(scid[:]) + ":OwnerAction:" + nonce
	}

	// 1) attacker key: signature valid but pubkey != stored owner -> rejected
	atkMsg := signMsg(atkPriv, scid, nonce)
	atkSig := ed25519.Sign(atkPriv, []byte(atkMsg))
	if got := runOwnerAction(hex.EncodeToString(atkPub), hex.EncodeToString(atkSig)); got != 0 {
		t.Fatalf("attacker key authorized the action (authorized=%d, want 0)", got)
	}

	// 2) owner key, correct message -> authorized
	ownerMsg := signMsg(ownerPriv, scid, nonce)
	ownerSig := ed25519.Sign(ownerPriv, []byte(ownerMsg))
	if !ed25519.Verify(ownerPub, []byte(ownerMsg), ownerSig) {
		t.Fatal("ed25519 sanity failed")
	}
	if got := runOwnerAction(ownerPubHex, hex.EncodeToString(ownerSig)); got != 1 {
		t.Fatalf("owner signature did not authorize (authorized=%d, want 1)", got)
	}

	// 3) owner key, TAMPERED signature -> rejected (state stays 1 from step 2)
	tampered := append([]byte{}, ownerSig...)
	tampered[0] ^= 0xff
	if got := runOwnerAction(ownerPubHex, hex.EncodeToString(tampered)); got != 1 {
		t.Fatalf("tampered sig changed state (authorized=%d, want still 1)", got)
	}

	t.Logf("Fix C OK: attacker rejected, owner authorized, tampered sig rejected (scid %s)", scid.String())
}

// readAuthorized reads the contract's "authorized" state via the simulator.
// The DVM persists SC variables in a per-SCID graviton tree, keyed by
// DataKey{SCID, Key: Variable}.MarshalBinaryPanic() — same path the
// interpreter's diskloader uses (sc.go LoadSCValue).
func readAuthorized(s *Simulator, scid crypto.Hash) uint64 {
	data_tree := Wrapped_tree(s.cache, s.ss, scid)
	key := DataKey{SCID: scid, Key: Variable{Type: String, ValueString: "authorized"}}.MarshalBinaryPanic()
	if v, found := LoadSCValue(data_tree, scid, key); found {
		return v.ValueUint64
	}
	return 0
}
