// C6 cross-contract calls tests (spec cross-contract-calls.md).
// ⚠️ DRAFT — research tooling, NOT part of DERO release code.
//
// Exercises call_sc through the simulator: install two contracts, call
// across, verify nested success + state, failure rollback, and the
// recursion cap. The DVM must be at >= 10.0.0 (call_sc gate).
package dvm

import (
	"strings"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

const c6CounterCode = `
Function Initialize() Uint64
	5 version("10.0.0")
	10 STORE("count", 0)
	20 RETURN 0
End Function
Function Inc(by Uint64) Uint64
	5 version("10.0.0")
	10 STORE("count", LOAD("count") + by)
	20 RETURN 0
End Function
Function Fail() Uint64
	5 version("10.0.0")
	10 STORE("poison", 1)
	20 RETURN 1
End Function
Function Deposit() Uint64
	5 version("10.0.0")
	10 STORE("got", DEROVALUE())
	20 RETURN 0
End Function
`

const c6CallerCode = `
Function Initialize() Uint64
	5 version("10.0.0")
	10 RETURN 0
End Function
Function CallInc(target String, by Uint64) Uint64
	5 version("10.0.0")
	10 DIM ok AS Uint64
	20 LET ok = call_sc(target, "Inc", "by", by)
	30 IF ok == 0 THEN GOTO 100
	40 RETURN 1
	100 RETURN 0
End Function
Function CallFail(target String) Uint64
	5 version("10.0.0")
	10 DIM ok AS Uint64
	20 LET ok = call_sc(target, "Fail")
	30 IF ok == 0 THEN GOTO 100
	40 STORE("saw_fail", 1)
	50 RETURN 0
	100 RETURN 1
End Function
Function CallSelf() Uint64
	5 version("10.0.0")
	10 DIM ok AS Uint64
	20 LET ok = call_sc(SCID(), "Self", "depth", 0)
	30 RETURN ok
End Function
Function Self(depth Uint64) Uint64
	5 version("10.0.0")
	10 DIM ok AS Uint64
	20 LET ok = call_sc(SCID(), "Self", "depth", depth + 1)
	30 RETURN ok
End Function
Function CallDeposit(target String) Uint64
	5 version("10.0.0")
	10 DIM ok AS Uint64
	20 LET ok = call_sc(target, "Deposit", "value", 100)
	30 RETURN ok
End Function
Function CallDepositTooMuch(target String) Uint64
	5 version("10.0.0")
	10 DIM ok AS Uint64
	20 LET ok = call_sc(target, "Deposit", "value", 99999)
	30 RETURN ok
End Function
`

// c6Install installs a contract in a fresh simulator, returning the scid.
func c6Install(t *testing.T, code string) (*Simulator, crypto.Hash, *rpc.Address) {
	t.Helper()
	s := SimulatorInitialize(nil, 0)
	addr, err := rpc.NewAddress(strings.TrimSpace("deto1qy0ehnqjpr0wxqnknyc66du2fsxyktppkr8m8e6jvplp954klfjz2qqdzcd8p"))
	if err != nil {
		t.Fatal(err)
	}
	var zerohash crypto.Hash
	s.AccountAddBalance(*addr, zerohash, 5000)
	scid, _, _, err := s.SCInstall(code, map[crypto.Hash]uint64{}, rpc.Arguments{}, addr, 0)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	return s, scid, addr
}

// c6InstallOn installs a second contract on an existing simulator.
func c6InstallOn(t *testing.T, s *Simulator, code string, addr *rpc.Address) crypto.Hash {
	t.Helper()
	scid, _, _, err := s.SCInstall(code, map[crypto.Hash]uint64{}, rpc.Arguments{}, addr, 0)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	return scid
}

func c6State(t *testing.T, s *Simulator, scid crypto.Hash, key string) uint64 {
	t.Helper()
	w_sc_data_tree := Wrapped_tree(s.cache, s.ss, scid)
	if v := ReadSCValue(w_sc_data_tree, scid, key); v != nil {
		if uv, ok := v.(uint64); ok {
			return uv
		}
	}
	return 0
}

// c6KeyExists reports whether a state key exists in the tree.
func c6KeyExists(s *Simulator, scid crypto.Hash, key string) bool {
	w_sc_data_tree := Wrapped_tree(s.cache, s.ss, scid)
	return ReadSCValue(w_sc_data_tree, scid, key) != nil
}

// TestC6_NestedSuccess: caller invokes the counter's Inc via call_sc.
func TestC6_NestedSuccess(t *testing.T) {
	s, counterID, addr := c6Install(t, c6CounterCode)
	callerID := c6InstallOn(t, s, c6CallerCode, addr)

	// invoke the caller -> which calls the counter
	_, _, err := s.RunSC(map[crypto.Hash]uint64{}, rpc.Arguments{
		rpc.Argument{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
		rpc.Argument{Name: rpc.SCID, DataType: rpc.DataHash, Value: callerID},
		rpc.Argument{Name: "entrypoint", DataType: rpc.DataString, Value: "CallInc"},
		rpc.Argument{Name: "target", DataType: rpc.DataHash, Value: counterID},
		rpc.Argument{Name: "by", DataType: rpc.DataUint64, Value: uint64(7)},
	}, addr, 0)
	if err != nil {
		t.Fatalf("run caller: %v", err)
	}
	if got := c6State(t, s, counterID, "count"); got != 7 {
		t.Fatalf("counter count = %d, want 7 (nested call applied)", got)
	} else {
		t.Logf("C6 nested success OK: caller -> counter Inc(7), count=%d", got)
	}
}

// TestC6_FailureRollback: a failing callee's writes are rolled back.
func TestC6_FailureRollback(t *testing.T) {
	s, counterID, addr := c6Install(t, c6CounterCode)
	callerID := c6InstallOn(t, s, c6CallerCode, addr)

	_, _, err := s.RunSC(map[crypto.Hash]uint64{}, rpc.Arguments{
		rpc.Argument{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
		rpc.Argument{Name: rpc.SCID, DataType: rpc.DataHash, Value: callerID},
		rpc.Argument{Name: "entrypoint", DataType: rpc.DataString, Value: "CallFail"},
		rpc.Argument{Name: "target", DataType: rpc.DataHash, Value: counterID},
	}, addr, 0)
	if err != nil {
		t.Fatalf("run caller: %v", err)
	}

	// the callee's "poison" write must NOT have been committed
	if c6KeyExists(s, counterID, "poison") {
		t.Fatal("callee's poison write survived a failing nested call — rollback failed")
	}
	t.Log("C6 failure rollback OK: callee writes discarded on failure")
}

// TestC6_RecursionCap: self-call exceeds the depth cap and fails cleanly.
func TestC6_RecursionCap(t *testing.T) {
	s, callerID, addr := c6Install(t, c6CallerCode)
	_ = callerID

	_, _, err := s.RunSC(map[crypto.Hash]uint64{}, rpc.Arguments{
		rpc.Argument{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
		rpc.Argument{Name: rpc.SCID, DataType: rpc.DataHash, Value: callerID},
		rpc.Argument{Name: "entrypoint", DataType: rpc.DataString, Value: "CallSelf"},
	}, addr, 0)
	if err == nil {
		// the recursion cap should eventually make the whole chain fail
		// (each nested call returns 2, but CallSelf returns the ok which is
		// nonzero -> the top-level should error OR return nonzero)
		t.Fatal("expected recursion chain to fail or return nonzero")
	}
	t.Logf("C6 recursion cap OK: %v", err)
}

func TestC6_ValueForward(t *testing.T) {
	s, counterID, addr := c6Install(t, c6CounterCode)
	callerID := c6InstallOn(t, s, c6CallerCode, addr)
	var zerohash crypto.Hash

	_, _, err := s.RunSC(map[crypto.Hash]uint64{zerohash: 250}, rpc.Arguments{
		rpc.Argument{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
		rpc.Argument{Name: rpc.SCID, DataType: rpc.DataHash, Value: callerID},
		rpc.Argument{Name: "entrypoint", DataType: rpc.DataString, Value: "CallDeposit"},
		rpc.Argument{Name: "target", DataType: rpc.DataHash, Value: counterID},
	}, addr, 0)
	if err != nil {
		t.Fatalf("run CallDeposit: %v", err)
	}
	if got := c6State(t, s, counterID, "got"); got != 100 {
		t.Fatalf("callee DEROVALUE stored = %d, want 100", got)
	}

	_, _, err = s.RunSC(map[crypto.Hash]uint64{zerohash: 10}, rpc.Arguments{
		rpc.Argument{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
		rpc.Argument{Name: rpc.SCID, DataType: rpc.DataHash, Value: callerID},
		rpc.Argument{Name: "entrypoint", DataType: rpc.DataString, Value: "CallDepositTooMuch"},
		rpc.Argument{Name: "target", DataType: rpc.DataHash, Value: counterID},
	}, addr, 0)
	if err == nil {
		t.Fatal("expected over-forward to fail the top-level run")
	}
	if got := c6State(t, s, counterID, "got"); got != 100 {
		t.Fatalf("over-forward mutated got=%d", got)
	}
	t.Log("C6 value-forward OK: 100 credited, over-forward rolled back")
}
