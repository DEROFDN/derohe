// verify_proof intrinsic tests (spec verify-proof-design.md, P1-1).
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// Builds a valid NORMAL tx (aggregate Bulletproof), serializes it, and
// drives the dvm_verify_proof handler directly: valid -> 1, tampered -> 0,
// malformed -> 0 (no panic), bad index -> 0, version gate.
package dvm

import (
	"encoding/hex"
	"go/ast"
	"go/token"
	"math/big"
	"strconv"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

// buildValidTx constructs a deterministic valid NORMAL tx with a verified
// aggregate bulletproof (same construction as the conformance suite).
func buildValidTx(t *testing.T) *transaction.Transaction {
	t.Helper()
	const ringSize = 16
	const value = uint64(100000)
	const fees = uint64(1000)
	const burn = uint64(0)

	sender_secret := crypto.RandomScalar()
	var roothash crypto.Hash
	for i := range roothash {
		roothash[i] = byte(i)
	}

	// parity constraint: sender and receiver at opposite parity
	wi := []int{0, 3} // sender at 0 (even), receiver at 3 (odd)

	// ring keys: sender's key IS sender_secret*G; receiver = secret 1;
	// decoys = hash-to-point (unknown secrets, fine — they're decoys)
	ring := make([]*bn256.G1, ringSize)
	ebals := make([]*crypto.ElGamal, ringSize)
	anonNext := 2
	sender_pub := new(bn256.G1).ScalarMult(crypto.G, sender_secret)
	const balanceAfter = uint64(500000)
	for i := 0; i < ringSize; i++ {
		switch i {
		case wi[0]:
			ring[i] = sender_pub
		case wi[1]:
			ring[i] = new(bn256.G1).ScalarMult(crypto.G, new(big.Int).SetInt64(1))
		default:
			ring[i] = new(bn256.G1).ScalarMult(crypto.HashToPoint(crypto.HashtoNumber([]byte("anon"+strconv.Itoa(anonNext)))), new(big.Int).SetInt64(int64(anonNext)))
			anonNext++
		}
	}
	for i := 0; i < ringSize; i++ {
		if i == wi[0] {
			ebals[i] = crypto.CommitElGamal(ring[i], new(big.Int).SetUint64(balanceAfter+value+fees+burn))
		} else {
			ebals[i] = crypto.CommitElGamal(ring[i], new(big.Int).SetUint64(12345))
		}
	}

	// r: deterministic per (roothash, ring, sender key)
	rinputs := append([]byte{}, roothash[:]...)
	for _, pk := range ring {
		rinputs = append(rinputs, pk.EncodeCompressed()...)
	}
	renc := new(bn256.G1).ScalarMult(crypto.HashToPoint(crypto.HashtoNumber(append([]byte(crypto.PROTOCOL_CONSTANT), rinputs...))), sender_secret)
	r := crypto.ReducedHash(renc.EncodeCompressed())

	var C []*bn256.G1
	var D bn256.G1
	D.ScalarMult(crypto.G, r)
	for i := 0; i < ringSize; i++ {
		var x bn256.G1
		switch {
		case i == wi[0]:
			x.ScalarMult(crypto.G, new(big.Int).SetInt64(-int64(value)-int64(fees)-int64(burn)))
		case i == wi[1]:
			x.ScalarMult(crypto.G, new(big.Int).SetInt64(int64(value)))
		default:
			x.ScalarMult(crypto.G, new(big.Int).SetInt64(0))
		}
		x.Add(&x, new(bn256.G1).ScalarMult(ring[i], r))
		C = append(C, &x)
	}

	var CLn, CRn []*bn256.G1
	for i := 0; i < ringSize; i++ {
		var ll, rr bn256.G1
		ll.Add(ebals[i].Left, C[i])
		CLn = append(CLn, &ll)
		rr.Add(ebals[i].Right, &D)
		CRn = append(CRn, &rr)
	}

	max_bits := 48
	for ; max_bits%8 != 0; max_bits++ {
	}
	stmt := crypto.Statement{CLn: CLn, CRn: CRn, C: C, D: &D, Publickeylist: ring, Fees: fees}
	copy(stmt.Roothash[:], roothash[:])
	stmt.Bytes_per_publickey = byte(max_bits / 8)

	witness := crypto.Witness{
		SecretKey:      sender_secret,
		R:              r,
		TransferAmount: value,
		Balance:        balanceAfter,
		Index:          wi,
	}

	uinput := append([]byte(crypto.PROTOCOL_CONSTANT), roothash[:]...)
	var scid crypto.Hash
	uinput = append(uinput, scid[:]...)
	uinput = append(uinput, []byte("0")...)
	u := new(bn256.G1).ScalarMult(crypto.HashToPoint(crypto.HashtoNumber(uinput)), sender_secret)

	tx := transaction.Transaction{}
	tx.Version = 1
	tx.Height = 100
	copy(tx.BLID[:], roothash[:])
	tx.TransactionType = transaction.NORMAL
	asset := transaction.AssetPayload{}
	asset.SCID = scid
	asset.BurnValue = burn
	asset.RPCType = transaction.ENCRYPTED_DEFAULT_PAYLOAD_CBOR_V2
	asset.RPCPayload = make([]byte, transaction.PAYLOAD_LIMIT)
	asset.Statement = stmt
	tx.Payloads = append(tx.Payloads, asset)

	proof := crypto.GenerateProof(scid, 0, &asset.Statement, &witness, u, tx.GetHash(), burn)
	asset.Proof = proof
	tx.Payloads[0] = asset

	if !proof.Verify(scid, 0, &asset.Statement, tx.GetHash(), burn) {
		t.Fatal("generated proof did not verify")
	}
	return &tx
}

func mkHexExpr(s string) ast.Expr {
	return &ast.BasicLit{Kind: token.STRING, Value: "\"" + s + "\""}
}

func TestVerifyProof(t *testing.T) {
	dvm := &DVM_Interpreter{
		Version: semver.MustParse("10.0.0"),
		State:   &Shared_State{},
	}
	call := func(txhex string, idx uint64, ctxhex string) uint64 {
		expr := &ast.CallExpr{Fun: &ast.Ident{Name: "verify_proof"},
			Args: []ast.Expr{mkHexExpr(txhex), &ast.BasicLit{Kind: token.INT, Value: strconv.FormatUint(idx, 10)}, mkHexExpr(ctxhex)}}
		_, res := dvm_verify_proof(dvm, expr)
		return res
	}

	tx := buildValidTx(t)

	// the expanded statement context the contract expects — capture BEFORE
	// serialize (Serialize replaces Publickeylist with pointers and drops
	// CLn/CRn): per member [ring(33) | CLn(33) | CRn(33)]
	var ctx string
	for i, pk := range tx.Payloads[0].Statement.Publickeylist {
		ctx += hex.EncodeToString(pk.EncodeCompressed())
		ctx += hex.EncodeToString(tx.Payloads[0].Statement.CLn[i].EncodeCompressed())
		ctx += hex.EncodeToString(tx.Payloads[0].Statement.CRn[i].EncodeCompressed())
	}

	raw := tx.Serialize()
	txhex := hex.EncodeToString(raw)

	// valid tx + correct context -> 1
	if res := call(txhex, 0, ctx); res != 1 {
		t.Fatalf("valid tx: verify_proof=%d want 1", res)
	}

	// wrong context (flip a byte in the middle of the ring section) -> 0
	ctxb := []byte(ctx)
	ctxb[len(ctxb)/2] ^= 0xff
	wrongCtx := string(ctxb)
	if res := call(txhex, 0, wrongCtx); res != 0 {
		t.Fatal("wrong context: verify_proof accepted")
	}

	// context size mismatch -> 0
	if res := call(txhex, 0, ctx[:99*2]); res != 0 {
		t.Fatal("context size mismatch: verify_proof accepted")
	}

	// tampered byte -> 0 (flip a byte in the middle)
	tampered := append([]byte{}, raw...)
	tampered[len(tampered)/2] ^= 0xff
	if res := call(hex.EncodeToString(tampered), 0, ctx); res != 0 {
		t.Fatal("tampered tx: verify_proof accepted")
	}

	// malformed hex -> 0, no panic
	if res := call("zzz", 0, ctx); res != 0 {
		t.Fatal("malformed hex: verify_proof should return 0")
	}

	// bad index -> 0
	if res := call(txhex, 5, ctx); res != 0 {
		t.Fatal("bad scid_index: verify_proof should return 0")
	}

	// version gate: hidden from 9.x contracts
	handled := false
	if fda, ok := func_table["verify_proof"]; ok {
		for _, f := range fda {
			if f.Range(semver.MustParse("9.0.0")) {
				handled = true
				break
			}
		}
	}
	if handled {
		t.Fatal("verify_proof visible to dvm version 9.0.0 — version gate broken")
	}
	t.Logf("verify_proof OK: valid=1 tampered=0 malformed=0 badidx=0 version-gated (tx %dB)", len(raw))
}

func TestVerifyProofRoothashBind(t *testing.T) {
	tx := buildValidTx(t)
	var ctx string
	for i, pk := range tx.Payloads[0].Statement.Publickeylist {
		ctx += hex.EncodeToString(pk.EncodeCompressed())
		ctx += hex.EncodeToString(tx.Payloads[0].Statement.CLn[i].EncodeCompressed())
		ctx += hex.EncodeToString(tx.Payloads[0].Statement.CRn[i].EncodeCompressed())
	}
	txhex := hex.EncodeToString(tx.Serialize())

	var want crypto.Hash
	copy(want[:], tx.Payloads[0].Statement.Roothash[:])
	var other crypto.Hash
	for i := range other {
		other[i] = byte(0xaa)
	}

	call := func(blid crypto.Hash) uint64 {
		dvm := &DVM_Interpreter{
			Version: semver.MustParse("10.0.0"),
			State:   &Shared_State{Chain_inputs: &Blockchain_Input{BLID: blid}},
		}
		expr := &ast.CallExpr{Fun: &ast.Ident{Name: "verify_proof"},
			Args: []ast.Expr{mkHexExpr(txhex), &ast.BasicLit{Kind: token.INT, Value: "0"}, mkHexExpr(ctx)}}
		_, res := dvm_verify_proof(dvm, expr)
		return res
	}

	if res := call(want); res != 1 {
		t.Fatalf("matching BLID: got %d want 1", res)
	}
	if res := call(other); res != 0 {
		t.Fatal("mismatched BLID accepted — roothash bind broken")
	}
	t.Log("verify_proof roothash bind OK")
}

func BenchmarkVerifyProof(b *testing.B) {
	tproxy := &testing.T{}
	tx := buildValidTx(tproxy)
	var ctx string
	for i, pk := range tx.Payloads[0].Statement.Publickeylist {
		ctx += hex.EncodeToString(pk.EncodeCompressed())
		ctx += hex.EncodeToString(tx.Payloads[0].Statement.CLn[i].EncodeCompressed())
		ctx += hex.EncodeToString(tx.Payloads[0].Statement.CRn[i].EncodeCompressed())
	}
	txhex := hex.EncodeToString(tx.Serialize())
	dvm := &DVM_Interpreter{Version: semver.MustParse("10.0.0"), State: &Shared_State{}}
	expr := &ast.CallExpr{Fun: &ast.Ident{Name: "verify_proof"},
		Args: []ast.Expr{mkHexExpr(txhex), &ast.BasicLit{Kind: token.INT, Value: "0"}, mkHexExpr(ctx)}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, res := dvm_verify_proof(dvm, expr)
		if res != 1 {
			b.Fatalf("verify failed at i=%d", i)
		}
	}
}
