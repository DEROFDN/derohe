// Wargame: verify_proof CHAIN-BINDING GAP (documented finding, spec v0.9).
//
// The intrinsic verifies a bulletproof against a FULLY CALLER-SUPPLIED
// context: the tx (tx_hex), the payload index, and the expanded ring
// (ctx_hex: Publickeylist/CLn/CRn per member). It performs ZERO chain-state
// lookups — no merkle-root check (the on-chain path requires the statement's
// Roothash to equal the chain's actual root at transaction_verify.go:424)
// and no ring-member/balance expansion from the balance tree
// (transaction_verify.go:429+).
//
// RESULT: verify_proof proves ONLY that "a bulletproof exists that is
// internally consistent with the caller-supplied statement". It CANNOT tell
// a fabricated-but-self-consistent proof (fake roothash, fake ring, fake
// balances — never mined, never on any chain) from a real one. A contract
// gating a payout on verify_proof()==1 can be triggered by a fabricated tx
// whose ring/balances/roothash the attacker made up.
//
// This test pins the gap: a tx whose roothash is random bytes (never a
// chain root) and whose decoy balances are fabricated VERIFIES as 1.
//
// FIX DIRECTION (documented in the PR body): the intrinsic must be a
// daemon-side hook that resolves tx.BLID's snapshot, checks the merkle root,
// and expands the ring from the balance tree — i.e. exactly the binding the
// on-chain verifier applies. As specified, it is a tautology machine.
package dvm

import (
	"encoding/hex"
	"go/ast"
	"go/token"
	"strconv"
	"testing"

	"github.com/blang/semver/v4"
)

// TestVerifyProofChainBindingGap demonstrates that verify_proof accepts a
// tx whose state reference (roothash) has never existed on any chain.
func TestVerifyProofChainBindingGap(t *testing.T) {
	tx := buildValidTx(t) // roothash = 0x00,0x01,...,0x1f — fabricated, never a chain root

	// capture the expanded context the contract would pass (ring|CLn|CRn)
	var ctx string
	for i, pk := range tx.Payloads[0].Statement.Publickeylist {
		ctx += hex.EncodeToString(pk.EncodeCompressed())
		ctx += hex.EncodeToString(tx.Payloads[0].Statement.CLn[i].EncodeCompressed())
		ctx += hex.EncodeToString(tx.Payloads[0].Statement.CRn[i].EncodeCompressed())
	}
	txhex := hex.EncodeToString(tx.Serialize())

	call := func(txhex string, idx uint64, ctxhex string) uint64 {
		dvm := &DVM_Interpreter{
			Version: semver.MustParse("10.0.0"),
			State:   &Shared_State{},
		}
		expr := &ast.CallExpr{Fun: &ast.Ident{Name: "verify_proof"},
			Args: []ast.Expr{mkHexExpr(txhex), &ast.BasicLit{Kind: token.INT, Value: strconv.FormatUint(idx, 10)}, mkHexExpr(ctxhex)}}
		_, res := dvm_verify_proof(dvm, expr)
		return res
	}

	// THE FINDING: this "valid" tx references a roothash that is NOT any
	// chain's merkle root, and its decoy ring members carry FABRICATED
	// encrypted balances (CommitElGamal(ring, 12345) in buildValidTx). The
	// on-chain verifier rejects such a tx at transaction_verify.go:424
	// (merkle mismatch) BEFORE ever touching the proof. The intrinsic has no
	// chain handle, so it cannot apply that check — it returns 1.
	if res := call(txhex, 0, ctx); res != 1 {
		t.Fatalf("fabricated-state tx: verify_proof=%d want 1 (documented chain-binding gap)", res)
	}
	t.Logf("WARGAME: verify_proof accepts a never-mined tx (fabricated roothash + fabricated decoy balances) — chain-binding gap confirmed")

	// Sanity: a genuinely tampered proof is still rejected (crypto binding
	// works); it is the CHAIN binding that is missing.
	raw := tx.Serialize()
	tampered := append([]byte{}, raw...)
	tampered[len(tampered)/2] ^= 0xff
	if res := call(hex.EncodeToString(tampered), 0, ctx); res != 0 {
		t.Fatal("tampered tx accepted — crypto binding broken (should be impossible)")
	}
	t.Logf("crypto binding intact: tampered tx rejected; only the chain binding is absent")

	// Reference: the crypto-level proof really does verify — this is a
	// GENERATED proof over the fabricated statement, so Verify is expected
	// true. The gap is that nothing in the intrinsic ties Roothash/ring to
	// real chain state.
	if !tx.Payloads[0].Proof.Verify(tx.Payloads[0].SCID, 0, &tx.Payloads[0].Statement, tx.GetHash(), tx.Payloads[0].BurnValue) {
		t.Fatal("generated proof failed crypto Verify — test setup broken")
	}
	t.Logf("proof is cryptographically self-consistent — hence the intrinsic accepts it; only a chain-state binding would reject it")
}
