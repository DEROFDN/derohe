// crypto_budget_test.go — tests for the DVM v9 crypto budget (crypto_budget.go).
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// The budget is a consensus parameter, so the tests pin three things: the
// weights in the intrinsic table, the exact exhaustion boundary, and that the
// meter cannot be refreshed by re-entering the VM (nested/cross-contract calls
// share Shared_State).
package dvm

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/token"
	"math/big"
	"strings"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
)

func cbStrExpr(s string) ast.Expr {
	return &ast.BasicLit{Kind: token.STRING, Value: "\"" + s + "\""}
}

func cbIntExpr(v uint64) ast.Expr {
	return &ast.BasicLit{Kind: token.INT, Value: new(big.Int).SetUint64(v).String()}
}

func cbPointHex() string {
	return hex.EncodeToString(crypto.G.EncodeCompressed())
}

// budget-armed state, exactly as Execute_sc_function arms it
func cbState() *Shared_State {
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	state.EnableCryptoBudget()
	return state
}

// an interpreter that dispatches through Handle_Internal_Function (the
// production consume site) for a single opcode.
func cbCaller(t *testing.T, state *Shared_State, version, opcode string, args ...ast.Expr) func() {
	t.Helper()
	dvm := &DVM_Interpreter{Version: semver.MustParse(version), State: state}
	return func() {
		dvm.Handle_Internal_Function(&ast.CallExpr{Fun: &ast.Ident{Name: opcode}, Args: args}, opcode)
	}
}

// TestCryptoBudgetTableWeights pins the per-opcode weights and proves the cheap
// opcodes stay off the meter.
func TestCryptoBudgetTableWeights(t *testing.T) {
	weighted := map[string]int64{
		"hash_to_point":   CryptoCostHashToPoint,
		"verify_sig":      CryptoCostVerifySig,
		"ec_add":          CryptoCostECAdd,
		"ec_mul":          CryptoCostECMul,
		"pedersen_commit": CryptoCostPedersen,
		"verify_commit":   CryptoCostVerifyCommit,
		"verify_adaptor":  CryptoCostVerifyAdaptor,
	}
	for opcode, want := range weighted {
		entries, ok := func_table[opcode]
		if !ok {
			t.Fatalf("opcode %q missing from the intrinsic table", opcode)
		}
		if got := entries[0].CryptoCost; got != want {
			t.Errorf("%s: CryptoCost = %d, want %d", opcode, got, want)
		}
		if got := entries[0].ComputeCost; got <= 0 {
			t.Errorf("%s: compute gas must stay priced, got %d", opcode, got)
		}
		if entries[0].Range == nil {
			t.Errorf("%s: weighted opcode must be version gated", opcode)
		}
	}

	// everything else must not consume crypto budget
	for opcode, entries := range func_table {
		if _, isWeighted := weighted[opcode]; isWeighted {
			continue
		}
		if entries[0].CryptoCost != 0 {
			t.Errorf("unweighted opcode %s has CryptoCost %d", opcode, entries[0].CryptoCost)
		}
	}
}

// TestCryptoBudgetBoundary asserts the exact opcode count at which ec_mul
// exhausts the budget: floor(100/12) = 8 calls pass, the 9th fails.
func TestCryptoBudgetBoundary(t *testing.T) {
	state := cbState()
	call := cbCaller(t, state, "9.0.0", "ec_mul", cbStrExpr(cbPointHex()), cbIntExpr(2))

	ok_calls := int64(CRYPTO_BUDGET_UNITS / CryptoCostECMul) // 8
	if ok_calls < 1 {
		t.Fatalf("budget %d too small for one ec_mul (%d units)", CRYPTO_BUDGET_UNITS, CryptoCostECMul)
	}
	for i := int64(0); i < ok_calls; i++ {
		call()
	}
	if want := ok_calls * CryptoCostECMul; state.CryptoBudgetUsed != want {
		t.Fatalf("budget used after %d calls = %d, want %d", ok_calls, state.CryptoBudgetUsed, want)
	}

	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatalf("call %d did not exhaust the crypto budget", ok_calls+1)
		}
		if !strings.Contains(fmt.Sprint(recovered), "Insufficient Crypto Budget") {
			t.Fatalf("unexpected panic value: %v", recovered)
		}
	}()
	call()
}

// TestCryptoBudgetCheapOpsDoNotCharge proves hashing/storage loops are governed
// by compute gas alone and cannot trip the crypto meter.
func TestCryptoBudgetCheapOpsDoNotCharge(t *testing.T) {
	state := cbState()
	dvm := &DVM_Interpreter{Version: semver.MustParse("9.0.0"), State: state}
	for i := 0; i < 200; i++ {
		dvm.Handle_Internal_Function(&ast.CallExpr{Fun: &ast.Ident{Name: "sha256"}, Args: []ast.Expr{cbStrExpr("abc")}}, "sha256")
	}
	if state.CryptoBudgetUsed != 0 {
		t.Fatalf("sha256 charged %d crypto units, want 0", state.CryptoBudgetUsed)
	}
}

// TestCryptoBudgetIsCombinationProof: a per-opcode cap would pass this program,
// a weighted budget must reject it. 5 x ec_add (9) + 2 x verify_adaptor (29)
// = 45 + 58 = 103 units > 100, with no single opcode over-used.
func TestCryptoBudgetIsCombinationProof(t *testing.T) {
	state := cbState()
	ec_add := cbCaller(t, state, "10.0.0", "ec_add", cbStrExpr(cbPointHex()), cbStrExpr(cbPointHex()))

	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatalf("mixed-op program of 103 units did not exhaust a %d unit budget", CRYPTO_BUDGET_UNITS)
		}
		if !strings.Contains(fmt.Sprint(recovered), "Insufficient Crypto Budget") {
			t.Fatalf("unexpected panic value: %v", recovered)
		}
		if state.CryptoBudgetUsed <= CRYPTO_BUDGET_UNITS {
			t.Fatalf("budget used %d did not exceed limit %d", state.CryptoBudgetUsed, CRYPTO_BUDGET_UNITS)
		}
	}()

	for i := 0; i < 5; i++ {
		ec_add()
	}
	// remaining budget 100-45 = 55 units allows 1 verify_adaptor (29), the 2nd must fail
	adaptor_args := cbAdaptorArgs(t)
	adaptor := cbCaller(t, state, "10.0.0", "verify_adaptor", adaptor_args...)
	adaptor()
	adaptor()
}

// TestCryptoBudgetPersistsAcrossNestedCalls models a nested/cross-contract call:
// every DVM triggered by the first call shares Shared_State, so re-entering the
// VM must not hand out a fresh budget.
func TestCryptoBudgetPersistsAcrossNestedCalls(t *testing.T) {
	state := cbState()
	call := cbCaller(t, state, "9.0.0", "ec_mul", cbStrExpr(cbPointHex()), cbIntExpr(2))

	first_leg := int64(CRYPTO_BUDGET_UNITS / CryptoCostECMul) // 8, a full leg
	for i := int64(0); i < first_leg; i++ {
		call()
	}
	if state.CryptoBudgetUsed == 0 {
		t.Fatal("first leg consumed nothing")
	}

	defer func() {
		if recover() == nil {
			t.Fatal("second leg refreshed the crypto budget (nested calls must share the meter)")
		}
	}()
	call() // the "nested" leg must see the already-spent budget
}

// TestCryptoBudgetEndToEndProgram drives a real DVM-BASIC program through
// RunSmartContract: 8 EC_MUL calls succeed, 9 are rejected. This proves the
// panic is recovered into an execution error (the call reverts) rather than
// aborting the node.
func TestCryptoBudgetEndToEndProgram(t *testing.T) {
	point := cbPointHex()

	program := func(calls int) string { return cryptoBudgetECMulProgram(calls) }

	run := func(calls int) error {
		sc, _, err := ParseSmartContract(program(calls))
		if err != nil {
			t.Fatalf("parse %d-call program: %v", calls, err)
		}
		state := cbState()
		_, err = RunSmartContract(&sc, "TestRun", state, map[string]interface{}{"p": point})
		return err
	}

	under := int(CRYPTO_BUDGET_UNITS / CryptoCostECMul) // 8
	if err := run(under); err != nil {
		t.Fatalf("%d EC_MUL calls should be within budget, got: %v", under, err)
	}

	err := run(under + 1)
	if err == nil {
		t.Fatalf("%d EC_MUL calls must exceed the crypto budget", under+1)
	}
	if !strings.Contains(err.Error(), "Insufficient Crypto Budget") {
		t.Fatalf("expected a crypto-budget revert, got: %v", err)
	}
}

// TestChainVersionFromHardFork pins the chain hard-fork -> DVM feature mapping.
func TestChainVersionFromHardFork(t *testing.T) {
	cases := []struct {
		hardFork int64
		want     string
	}{
		{0, "8.0.0"}, {1, "8.0.0"}, {2, "8.0.0"}, {3, "8.0.0"},
		{4, "9.0.0"}, {5, "10.0.0"}, {6, "10.0.0"},
	}
	for _, c := range cases {
		if got := ChainVersionFromHardFork(c.hardFork).String(); got != c.want {
			t.Errorf("ChainVersionFromHardFork(%d) = %s, want %s", c.hardFork, got, c.want)
		}
	}
}

func mustPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: expected a panic", name)
		}
	}()
	fn()
}

// TestChainVersionGatesIntrinsics: the chain gate is ANDed with the contract's
// declared version, so a contract that declares v9 cannot use the intrinsics on
// a chain that has not activated v9; cheap opcodes are unaffected.
func TestChainVersionGatesIntrinsics(t *testing.T) {
	state := &Shared_State{Chain_inputs: &Blockchain_Input{}}
	state.EnableCryptoBudget()

	callECMul := func() {
		dvm := &DVM_Interpreter{Version: semver.MustParse("9.0.0"), State: state}
		dvm.Handle_Internal_Function(&ast.CallExpr{Fun: &ast.Ident{Name: "ec_mul"},
			Args: []ast.Expr{cbStrExpr(cbPointHex()), cbIntExpr(2)}}, "ec_mul")
	}

	// pre-v9 chain: the contract declaring 9.0.0 is NOT enough
	state.ChainVersion = ChainVersionFromHardFork(3) // 8.0.0
	mustPanic(t, "ec_mul on a pre-v9 chain", callECMul)

	// v9 chain: allowed
	state.ChainVersion = ChainVersionFromHardFork(4) // 9.0.0
	callECMul()                                      // must not panic

	// cheap opcodes are gated only by the contract version, not the chain
	state.ChainVersion = ChainVersionFromHardFork(3)
	sha := &DVM_Interpreter{Version: semver.MustParse("9.0.0"), State: state}
	sha.Handle_Internal_Function(&ast.CallExpr{Fun: &ast.Ident{Name: "sha256"}, Args: []ast.Expr{cbStrExpr("abc")}}, "sha256") // must not panic
}

// TestChainVersionGatesEndToEnd: a fully in-budget v9 program must fail to run
// on a pre-v9 chain and succeed once the chain activates v9.
func TestChainVersionGatesEndToEnd(t *testing.T) {
	point := cbPointHex()
	under := int(CRYPTO_BUDGET_UNITS / CryptoCostECMul) // 8 EC_MUL calls

	run := func(chainHF int64) error {
		sc, _, err := ParseSmartContract(cryptoBudgetECMulProgram(under))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		state := cbState()
		state.ChainVersion = ChainVersionFromHardFork(chainHF)
		_, err = RunSmartContract(&sc, "TestRun", state, map[string]interface{}{"p": point})
		return err
	}

	if err := run(3); err == nil {
		t.Fatal("v9 program ran on a pre-v9 chain")
	}
	if err := run(4); err != nil {
		t.Fatalf("v9 program should run on a v9 chain, got: %v", err)
	}
}

// cryptoBudgetECMulProgram is a real DVM-BASIC program that declares v9 and
// calls EC_MUL `calls` times. VERSION() is the only writer of dvm.Version, so
// without the chain gate a contract could self-activate the intrinsics.
func cryptoBudgetECMulProgram(calls int) string {
	var b strings.Builder
	b.WriteString("Function TestRun(p String) Uint64\n")
	b.WriteString(" 10 dim r as String\n")
	b.WriteString(" 20 dim v as Uint64\n")
	b.WriteString(" 30 LET v = VERSION(\"9.0.0\")\n")
	line := 40
	for i := 0; i < calls; i++ {
		fmt.Fprintf(&b, " %d LET r = EC_MUL(p, 2)\n", line)
		line += 10
	}
	fmt.Fprintf(&b, " %d RETURN 0\n", line)
	b.WriteString("End Function\n")
	return b.String()
}

// cbAdaptorArgs builds a valid adaptor signature for the combination test.
func cbAdaptorArgs(t *testing.T) []ast.Expr {
	t.Helper()
	pub, msg, sig, _ := buildAdaptorSig(t, []byte("crypto-budget-combination"))
	return []ast.Expr{cbStrExpr(pub), cbStrExpr(msg), cbStrExpr(sig)}
}

// ---------------------------------------------------------------------------
// Benchmarks: the constants in crypto_budget.go are derived from these costs.
// Re-run with `go test -bench BenchmarkCryptoIntrinsic -run '^$'` before
// changing any weight.
// ---------------------------------------------------------------------------
func cbBenchCall(b *testing.B, state *Shared_State, version, opcode string, args ...ast.Expr) {
	b.Helper()
	dvm := &DVM_Interpreter{Version: semver.MustParse(version), State: state}
	call := func() {
		// reset the per-execution meters: a real SC execution starts from zero
		state.Monitor_ops = 0
		state.Monitor_lines_interpreted = 0
		state.CryptoBudgetUsed = 0 // otherwise the crypto budget trips after N ops
		dvm.Handle_Internal_Function(&ast.CallExpr{Fun: &ast.Ident{Name: opcode}, Args: args}, opcode)
	}
	call()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		call()
	}
}

func BenchmarkCryptoIntrinsicHashToPoint(b *testing.B) {
	cbBenchCall(b, cbState(), "9.0.0", "hash_to_point", cbStrExpr("bench"))
}

func BenchmarkCryptoIntrinsicECMul(b *testing.B) {
	cbBenchCall(b, cbState(), "9.0.0", "ec_mul", cbStrExpr(cbPointHex()), cbIntExpr(2))
}

func BenchmarkCryptoIntrinsicECAdd(b *testing.B) {
	cbBenchCall(b, cbState(), "9.0.0", "ec_add", cbStrExpr(cbPointHex()), cbStrExpr(cbPointHex()))
}

func BenchmarkCryptoIntrinsicPedersenCommit(b *testing.B) {
	blind := hex.EncodeToString(new(big.Int).SetUint64(0x0102030405060708).Bytes())
	cbBenchCall(b, cbState(), "9.0.0", "pedersen_commit", cbIntExpr(1234567), cbStrExpr(blind))
}

func BenchmarkCryptoIntrinsicVerifyCommit(b *testing.B) {
	state := cbState()
	blind := hex.EncodeToString(new(big.Int).SetUint64(0x0102030405060708).Bytes())
	dvm := &DVM_Interpreter{Version: semver.MustParse("9.0.0"), State: state}
	_, commit := dvm_pedersen_commit(dvm, &ast.CallExpr{Args: []ast.Expr{cbIntExpr(1234567), cbStrExpr(blind)}})
	cbBenchCall(b, cbState(), "9.0.0", "verify_commit", cbIntExpr(1234567), cbStrExpr(blind), cbStrExpr(commit))
}

func BenchmarkCryptoIntrinsicVerifySig(b *testing.B) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 64)
	rand.Read(msg)
	msg_hex := hex.EncodeToString(msg)
	sig := ed25519.Sign(priv, []byte(msg_hex)) // verify_sig hashes the string bytes
	cbBenchCall(b, cbState(), "9.0.0", "verify_sig", cbStrExpr(hex.EncodeToString(pub)), cbStrExpr(msg_hex), cbStrExpr(hex.EncodeToString(sig)))
}

func BenchmarkCryptoIntrinsicVerifyAdaptor(b *testing.B) {
	// buildAdaptorSig needs *testing.T; build inline for the benchmark
	x := crypto.RandomScalar()
	k := crypto.RandomScalar()
	tweak := crypto.RandomScalar()
	P := new(bn256.G1).ScalarMult(crypto.G, x)
	R := new(bn256.G1).ScalarMult(crypto.G, k)
	T := new(bn256.G1).ScalarMult(crypto.G, tweak)
	msg := []byte("bench-adaptor")
	e := crypto.ReducedHash(append(append(append([]byte{}, R.EncodeCompressed()...), P.EncodeCompressed()...), msg...))
	sp := new(big.Int).Mul(e, x)
	sp.Add(sp, k)
	sp.Sub(sp, tweak)
	sp.Mod(sp, bn256.Order)
	sig := make([]byte, 130)
	copy(sig[64-len(sp.Bytes()):64], sp.Bytes())
	copy(sig[64:97], R.EncodeCompressed())
	copy(sig[97:130], T.EncodeCompressed())

	cbBenchCall(b, cbState(), "10.0.0", "verify_adaptor",
		cbStrExpr(hex.EncodeToString(P.EncodeCompressed())),
		cbStrExpr(hex.EncodeToString(msg)),
		cbStrExpr(hex.EncodeToString(sig)))
}
