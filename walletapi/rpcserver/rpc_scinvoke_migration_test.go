package rpcserver

import (
	"testing"

	"github.com/deroproject/derohe/rpc"
)

func migrationInvokeArgs(destination string) rpc.Arguments {
	return rpc.Arguments{
		{Name: rpc.SCENTRYPOINT, DataType: rpc.DataString, Value: rpc.SeamlessMigrationEntrypoint},
		{Name: "destination", DataType: rpc.DataString, Value: destination},
	}
}

func TestPrepareSeamlessMigrationTransferKeepsDestinationOutOfSCDATA(t *testing.T) {
	const amount = uint64(987654321)
	transfer, safeArgs, ringsize, err := prepareSeamlessMigrationTransfer(migrationInvokeArgs("destination-address"), amount, 0, 0)
	if err != nil {
		t.Fatalf("prepare migration transfer: %v", err)
	}
	if transfer.Destination != "destination-address" || transfer.Amount != amount || transfer.Burn != 0 {
		t.Fatalf("unexpected confidential transfer: %+v", transfer)
	}
	if ringsize != rpc.SeamlessMigrationMinRingSize {
		t.Fatalf("default migration ring size = %d, want %d", ringsize, rpc.SeamlessMigrationMinRingSize)
	}
	if len(safeArgs) != 1 || safeArgs[0].Name != rpc.SCENTRYPOINT || safeArgs[0].Value != rpc.SeamlessMigrationEntrypoint {
		t.Fatalf("unexpected on-chain migration arguments: %+v", safeArgs)
	}
	for _, arg := range safeArgs {
		if arg.Name == "destination" || arg.Name == rpc.SCREFUND {
			t.Fatalf("public recipient/refund argument leaked into SCDATA: %+v", arg)
		}
	}
}

func TestPrepareSeamlessMigrationTransferRejectsUnsafeInputs(t *testing.T) {
	valid := migrationInvokeArgs("destination-address")
	cases := []struct {
		name        string
		args        rpc.Arguments
		amount      uint64
		tokenAmount uint64
		rings       uint64
	}{
		{name: "zero amount", args: valid, amount: 0},
		{name: "token deposit", args: valid, amount: 1, tokenAmount: 1},
		{name: "small ring", args: valid, amount: 1, rings: 4},
		{name: "missing destination", args: rpc.Arguments{{Name: rpc.SCENTRYPOINT, DataType: rpc.DataString, Value: rpc.SeamlessMigrationEntrypoint}}, amount: 1},
		{name: "public refund", args: append(append(rpc.Arguments(nil), valid...), rpc.Argument{Name: rpc.SCREFUND, DataType: rpc.DataString, Value: "refund-address"}), amount: 1},
		{name: "extra public argument", args: append(append(rpc.Arguments(nil), valid...), rpc.Argument{Name: "memo", DataType: rpc.DataString, Value: "leak"}), amount: 1},
		{name: "wrong entrypoint", args: rpc.Arguments{{Name: rpc.SCENTRYPOINT, DataType: rpc.DataString, Value: "Withdraw"}, {Name: "destination", DataType: rpc.DataString, Value: "destination-address"}}, amount: 1},
		{name: "wrong destination type", args: rpc.Arguments{{Name: rpc.SCENTRYPOINT, DataType: rpc.DataString, Value: rpc.SeamlessMigrationEntrypoint}, {Name: "destination", DataType: rpc.DataUint64, Value: uint64(7)}}, amount: 1},
		{name: "duplicate destination", args: append(append(rpc.Arguments(nil), valid...), rpc.Argument{Name: "destination", DataType: rpc.DataString, Value: "other-address"}), amount: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := prepareSeamlessMigrationTransfer(tc.args, tc.amount, tc.tokenAmount, tc.rings); err == nil {
				t.Fatal("unsafe migration request was accepted")
			}
		})
	}
}

func TestPrepareSeamlessMigrationTransferAllowsLargerRing(t *testing.T) {
	_, _, ringsize, err := prepareSeamlessMigrationTransfer(migrationInvokeArgs("destination-address"), 1, 0, 32)
	if err != nil {
		t.Fatalf("larger ring rejected: %v", err)
	}
	if ringsize != 32 {
		t.Fatalf("ring size = %d, want 32", ringsize)
	}
}
