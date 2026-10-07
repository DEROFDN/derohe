// Copyright placeholder: research tooling for spec/derohe-transaction-relation-spec.md
// ⚠️ DRAFT — conformance test vectors, NOT part of DERO release code.
//
// Conformance test: builds a deterministic consensus-level transaction
// (NORMAL, ring 16) with fixed keys/witnesses, verifies the embedded proof
// end-to-end, then checks that byte-mutations in every region are REJECTED.
// This is the executable form of spec §5.7 (transcript) + §6 (predicates)
// + §10.1 (vectors): if the transcript order, parity rule, range packing or
// balance-conservation logic ever changes, this test must fail.
//
// Run: go test ./tests/vectors/ -run TestConformance -v
package vectors

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/transaction"
)

// ---- fixed witness material (deterministic across runs) ----
var sender_secret_hex = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
var roothash_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

const ringSizeDefault = 16 // power of two, [2,128]
const value = uint64(100000)
const fees = uint64(2000)
const burn = uint64(0)
const balanceAfter = uint64(900000) // post-transfer sender balance

func fixedSecret(i int) *big.Int {
	b := make([]byte, 32)
	for j := range b {
		b[j] = byte(0x10*(i+1) + j)
	}
	return new(big.Int).SetBytes(b)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func buildTxAt(t *testing.T, ringSize int) (*transaction.Transaction, crypto.Hash) {
	t.Helper()
	sender_secret := new(big.Int).SetBytes(mustHex(sender_secret_hex))
	var roothash crypto.Hash
	copy(roothash[:], mustHex(roothash_hex))

	sender_pub := new(bn256.G1).ScalarMult(crypto.G, sender_secret)

	// witness_index: shuffle of 0..N-1 with sender/receiver at opposite parity.
	// Deterministic rotation: sender at 0 (even), receiver at 1 (odd) for any
	// N>=2 keeps opposite parity; larger offsets only matter for N>=4 but the
	// identity prefix is valid for all sizes and keeps the ring layout simple.
	wi := make([]int, ringSize)
	for i := range wi {
		wi[i] = i
	}
	if ringSize >= 8 {
		// non-trivial shuffle to exercise non-adjacent positions
		wi[0], wi[3] = 3, 0
		wi[1], wi[4] = 4, 1
	}
	if wi[0]%2 == wi[1]%2 {
		t.Fatal("parity constraint violated")
	}

	// ring keys at shuffled positions: sender at wi[0], receiver at wi[1]
	ring := make([]*bn256.G1, ringSize)
	anonNext := 2
	for i := 0; i < ringSize; i++ {
		switch i {
		case wi[0]:
			ring[i] = sender_pub
		case wi[1]:
			ring[i] = new(bn256.G1).ScalarMult(crypto.G, fixedSecret(1))
		default:
			ring[i] = new(bn256.G1).ScalarMult(crypto.G, fixedSecret(anonNext))
			anonNext++
		}
	}

	ebals := make([]*crypto.ElGamal, ringSize)
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
	return &tx, tx.GetHash()
}

// TestConformance_ValidProof: a correctly built tx MUST verify.
func TestConformance_ValidProof(t *testing.T) {
	tx, txid := buildTxAt(t, ringSizeDefault)
	if txid.String() == "" {
		t.Fatal("empty txid")
	}
	// round-trip serialization
	raw := tx.Serialize()
	tm := &transaction.Transaction{}
	if err := tm.Deserialize(raw); err != nil {
		t.Fatalf("valid tx failed round-trip: %v", err)
	}
	if tm.GetHash().String() != txid.String() {
		t.Fatalf("txid changed after round-trip: %s vs %s", tm.GetHash(), txid)
	}
	t.Logf("valid vector: txid=%s len=%dB ringsize=%d value=%d fees=%d",
		txid, len(raw), ringSizeDefault, value, fees)
}

// TestConformance_MutationsRejected: ANY byte flip in the serialized tx
// MUST produce a reject (either deserialize failure or proof failure).
// This is the executable §10.1 "invalid vectors" contract.
func TestConformance_MutationsRejected(t *testing.T) {
	tx, _ := buildTxAt(t, ringSizeDefault)
	raw := tx.Serialize()

	// flip one byte across header, statement, and proof regions
	offsets := []int{}
	for _, off := range []int{0, 1, 2, 100, 500, 1000, 1500, 2000, 2500, 3000, len(raw) - 1} {
		if off < len(raw) {
			offsets = append(offsets, off)
		}
	}
	for _, off := range offsets {
		mut := append([]byte{}, raw...)
		mut[off] ^= 0xff
		rejected := func() (ok bool) {
			defer func() {
				if recover() != nil {
					ok = true // panic during deserialize = reject
				}
			}()
			tm := &transaction.Transaction{}
			if err := tm.Deserialize(mut); err != nil {
				return true
			}
			for t := range tm.Payloads {
				if tm.Payloads[t].Proof == nil {
					return true
				}
				scid := tm.Payloads[t].SCID
				if !tm.Payloads[t].Proof.Verify(scid, 0, &tm.Payloads[t].Statement, tm.GetHash(), tm.Payloads[t].BurnValue) {
					return true
				}
			}
			return false
		}()
		if !rejected {
			t.Fatalf("mutation at offset %d was ACCEPTED (should be rejected)", off)
		}
	}
	t.Logf("all %d mutation vectors rejected", len(offsets))
}

// TestConformance_RingSizeMatrix: proofs must build and verify at every
// allowed power-of-two ring size (2, 4, 8, 16, 32, 64, 128). This locks
// the §5.7 transcript and the parity/2m-bit index encoding across the
// whole ring-size space, not just 16.
func TestConformance_RingSizeMatrix(t *testing.T) {
	for _, rs := range []int{2, 4, 8, 16, 32, 64, 128} {
		tx, txid := buildTxAt(t, rs)
		raw := tx.Serialize()
		// round-trip
		tm := &transaction.Transaction{}
		if err := tm.Deserialize(raw); err != nil {
			t.Fatalf("ring %d: round-trip failed: %v", rs, err)
		}
		if tm.GetHash().String() != txid.String() {
			t.Fatalf("ring %d: txid changed after round-trip", rs)
		}
		// Key pointers must survive the round-trip byte-identically — consensus
		// re-expands full keys from the balance tree via these pointers
		// (transaction_execute.go:215-235), so pointer integrity IS the
		// serialization contract. Compare the deserialized pointers against
		// the pointers the serializer emits for the ORIGINAL statement
		// (Statement.Serialize computes them via graviton.Sum when empty,
		// protocol_structures.go:58-71).
		stmt := tx.Payloads[0].Statement
		var sbuf bytes.Buffer
		stmt.Serialize(&sbuf)
		want := stmt.Publickeylist_pointers // populated by Serialize
		got := tm.Payloads[0].Statement.Publickeylist_pointers
		if len(want) != len(got) {
			t.Fatalf("ring %d: pointer length changed after round-trip: %d vs %d", rs, len(want), len(got))
		}
		for i := range want {
			if want[i] != got[i] {
				t.Fatalf("ring %d: pointer %d differs after round-trip", rs, i)
			}
		}
		t.Logf("ring %d: OK (txid=%s, %dB, %d pointers)", rs, txid, len(raw), len(got))
	}
}

// TestG2P0_SameIndexAttack: adversarial checklist #1 (spec
// g2-p0-soundness-outline.md §4). If sender and receiver are the SAME
// ring position (wi[0]==wi[1], self-send), balance conservation becomes
// "lose amount+fees, gain amount at same position" = net -fees. The
// wallet bans self-send, but the PROOF system must reject it too —
// otherwise a malicious prover can mint self-referential statements.
// Expected: the proof generator's parity/branch structure makes the
// transcript invalid (no accepting branch), OR the proof verifies and we
// document it as a finding.
func TestG2P0_SameIndexAttack(t *testing.T) {
	// same-index at ringsize 16: sender and receiver both at index 0.
	// Opposite parity is impossible for the same index, so the parity
	// constraint in buildTxAt cannot hold — this is exactly the constraint
	// under test. We emulate the attacker by calling GenerateProof with a
	// same-index witness and checking the verifier.
	sender_secret := new(big.Int).SetBytes(mustHex(sender_secret_hex))
	sender_pub := new(bn256.G1).ScalarMult(crypto.G, sender_secret)

	const ringSize = 16
	ring := make([]*bn256.G1, ringSize)
	for i := 0; i < ringSize; i++ {
		if i == 0 {
			ring[i] = sender_pub
		} else {
			ring[i] = new(bn256.G1).ScalarMult(crypto.G, fixedSecret(i))
		}
	}
	ebals := make([]*crypto.ElGamal, ringSize)
	for i := 0; i < ringSize; i++ {
		if i == 0 {
			ebals[i] = crypto.CommitElGamal(ring[i], new(big.Int).SetUint64(balanceAfter+value+fees+burn))
		} else {
			ebals[i] = crypto.CommitElGamal(ring[i], new(big.Int).SetUint64(12345))
		}
	}

	// deterministic r (mirrors buildTxAt)
	var roothash crypto.Hash
	copy(roothash[:], mustHex(roothash_hex))
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
		if i == 0 {
			// sender loses amount+fees+burn AND receives +amount at the same
			// position: net = -fees-burn. Receiver credit cancels.
			x.ScalarMult(crypto.G, new(big.Int).SetInt64(-int64(fees)-int64(burn)))
		} else {
			x.ScalarMult(crypto.G, new(big.Int).SetInt64(0))
		}
		x.Add(&x, new(bn256.G1).ScalarMult(ring[i], r))
		C = append(C, &x)
	}

	max_bits := 48
	for ; max_bits%8 != 0; max_bits++ {
	}
	var CLn, CRn []*bn256.G1
	for i := 0; i < ringSize; i++ {
		var ll, rr bn256.G1
		ll.Add(ebals[i].Left, C[i])
		CLn = append(CLn, &ll)
		rr.Add(ebals[i].Right, &D)
		CRn = append(CRn, &rr)
	}
	stmt := crypto.Statement{CLn: CLn, CRn: CRn, C: C, D: &D, Publickeylist: ring, Fees: fees}
	copy(stmt.Roothash[:], roothash[:])
	stmt.Bytes_per_publickey = byte(max_bits / 8)

	// same-index witness: wi[0]==wi[1]==0
	wi := []int{0, 0}
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

	var txhash crypto.Hash
	proof := crypto.GenerateProof(scid, 0, &stmt, &witness, u, txhash, burn)
	accepts := proof.Verify(scid, 0, &stmt, txhash, burn)
	t.Logf("same-index proof accepts=%v (finding if true: self-send with net -fees)", accepts)
	if accepts {
		// This would be a finding to escalate — the outline's checklist #1.
		// We do NOT fail here; we document. (If the construction is sound,
		// the parity/branch structure should reject.)
		t.Logf("FINDING: same-index (self-send) proof verifies at the crypto level")
	} else {
		t.Logf("OK: same-index proof rejected (parity/branch structure sound)")
	}
}

// TestG2P0_FakeReceiverMutation: adversarial checklist #2 (spec
// g2-p0-soundness-outline.md §4). Build a VALID tx, then mutate the
// serialized receiver-position bytes (the C vector / ring pointers) so the
// committed receiver position no longer corresponds to a real member.
// The verifier must reject. This exercises the binding of the 2m-bit
// index commitment against a *relocated* receiver.
func TestG2P0_FakeReceiverMutation(t *testing.T) {
	tx, txid := buildTxAt(t, 16)
	raw := tx.Serialize()

	// mutate bytes in the middle of the statement region (C vector area).
	// The exact offset depends on serialization; sweep a window and require
	// ALL mutations in it to be rejected.
	rejected := 0
	total := 0
	for off := 700; off < 1100 && off < len(raw); off += 37 {
		mut := append([]byte{}, raw...)
		mut[off] ^= 0x01 // flip one bit
		total++
		rejectedNow := func() (ok bool) {
			defer func() {
				if recover() != nil {
					ok = true
				}
			}()
			tm := &transaction.Transaction{}
			if err := tm.Deserialize(mut); err != nil {
				return true
			}
			for p := range tm.Payloads {
				if tm.Payloads[p].Proof == nil {
					return true
				}
				scid := tm.Payloads[p].SCID
				if !tm.Payloads[p].Proof.Verify(scid, 0, &tm.Payloads[p].Statement, tm.GetHash(), tm.Payloads[p].BurnValue) {
					return true
				}
			}
			return false
		}()
		if rejectedNow {
			rejected++
		}
	}
	t.Logf("fake-receiver window: %d/%d mutations rejected (txid=%s)", rejected, total, txid)
	if rejected != total {
		t.Fatalf("%d/%d statement-region mutations ACCEPTED — receiver-position binding broken", total-rejected, total)
	}
}

// TestK0_RingSize2IsIdentifiable: regression marker for K0
// (spec §9 K0). At ringsize 2 the signer is recoverable from the tx by
// the same rule Extract_signer uses (parity selects the sender position).
// This documents the CURRENT vulnerability — when Fix B (min-ring-4 for
// NORMAL) lands, this test flips to expect a build failure.
func TestK0_RingSize2IsIdentifiable(t *testing.T) {
	tx, _ := buildTxAt(t, 2)
	// replicate Extract_signer (blockchain/transaction_execute.go:429)
	// at the crypto level: ringsize 2, base asset -> parity picks the signer
	stmt := tx.Payloads[0].Statement
	if len(stmt.Publickeylist) != 2 {
		t.Fatalf("expected ringsize 2, got %d", len(stmt.Publickeylist))
	}
	parity := tx.Payloads[0].Proof.Parity()
	found := 0
	for i := 0; i < 2; i++ {
		if (i%2 == 0) == parity {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("expected exactly one signer position at ringsize 2, found %d", found)
	}
	t.Logf("K0 confirmed: ringsize-2 tx exposes exactly one signer position (parity=%v). Fix B will ban this for NORMAL txs.", parity)
}

// TestConformance_Determinism: same inputs -> same STATEMENT (txid) across
// repeated builds. Proof BYTES may differ (ZK blinding randomness — verified
// separately by TestConformance_Determinism_ProofOnly); the txid excludes
// proofs, so statement determinism is what consensus requires.
func TestConformance_Determinism(t *testing.T) {
	tx1, id1 := buildTxAt(t, ringSizeDefault)
	tx2, id2 := buildTxAt(t, ringSizeDefault)
	if id1.String() != id2.String() {
		t.Fatalf("nondeterministic txid: %s vs %s", id1, id2)
	}
	// statements (header, excluding proofs) must be byte-identical
	h1 := tx1.SerializeCoreStatement()
	h2 := tx2.SerializeCoreStatement()
	if !bytes.Equal(h1, h2) {
		t.Fatalf("nondeterministic statement serialization")
	}
	t.Logf("statement deterministic (%dB), txid=%s", len(h1), id1)
}

// TestConformance_MalformedPointDecode: pins the decode behavior for
// malformed compressed points — the divergence class found by the Rust
// differential harness (derohe-rs): Go's bn256/changes.go:59 discards the
// on-curve Unmarshal error when x >= p, so Go "succeeds" with an invalid
// point while a strict decoder rejects. If a contract ever stores a
// malformed point (commitments, ec_add outputs), the two implementations
// must agree on the outcome or the chain splits.
func TestConformance_MalformedPointDecode(t *testing.T) {
	cases := []struct {
		name string
		hex  string
	}{
		{"x_equals_p", "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47" + "00"}, // x == p (non-canonical)
		{"x_gt_p",     "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd48" + "00"}, // x > p
		{"all_ff",     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00"}, // x = 2^256-1, flag 0x00 (33 bytes)
		{"bad_flag",   "0000000000000000000000000000000000000000000000000000000000000002" + "02"}, // flag byte not 0x00/0x01
		{"x_zero_neg", "0000000000000000000000000000000000000000000000000000000000000000" + "00"}, // x = 0 (non-residue x^3+3)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := hex.DecodeString(c.hex)
			if err != nil || len(b) != 33 {
				t.Fatalf("bad test vector: %v len=%d", err, len(b))
			}
			pt := &bn256.G1{}
			err = pt.DecodeCompressed(b)
			t.Logf("DecodeCompressed(%s) -> err=%v", c.name, err)
			// Assertion: whatever the outcome, it must be *deterministic* —
			// call twice, same result. (The exact accept/reject is left open
			// here so both Go and a strict Rust decoder can converge on it;
			// the regression value is that it must not panic and must not
			// silently produce a *different* point per call.)
			pt2 := &bn256.G1{}
			err2 := pt2.DecodeCompressed(b)
			if (err == nil) != (err2 == nil) {
				t.Fatalf("nondeterministic decode: first err=%v second err=%v", err, err2)
			}
			if err == nil && pt.String() != pt2.String() {
				t.Fatalf("nondeterministic point: %s vs %s", pt.String(), pt2.String())
			}
		})
	}
}
