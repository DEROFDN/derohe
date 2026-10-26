package blockchain

import (
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

func validMigrationTestTx() transaction.Transaction {
	return transaction.Transaction{
		Transaction_Prefix: transaction.Transaction_Prefix{
			Version:         1,
			TransactionType: transaction.SC_TX,
			SCDATA: rpc.Arguments{
				{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
				{Name: rpc.SCID, DataType: rpc.DataHash, Value: rpc.SeamlessMigrationSCID()},
				{Name: rpc.SCENTRYPOINT, DataType: rpc.DataString, Value: rpc.SeamlessMigrationEntrypoint},
			},
		},
		Payloads: []transaction.AssetPayload{{
			RPCPayload: make([]byte, 145),
			Statement:  crypto.Statement{RingSize: rpc.SeamlessMigrationMinRingSize},
		}},
	}
}

func cloneMigrationTestTx(tx transaction.Transaction) transaction.Transaction {
	tx.SCDATA = append(rpc.Arguments(nil), tx.SCDATA...)
	tx.Payloads = append([]transaction.AssetPayload(nil), tx.Payloads...)
	return tx
}

func setMigrationTestArg(tx *transaction.Transaction, name string, dtype rpc.DataType, value interface{}) {
	for i := range tx.SCDATA {
		if tx.SCDATA[i].Name == name {
			tx.SCDATA[i].DataType = dtype
			tx.SCDATA[i].Value = value
			return
		}
	}
}

func TestValidateSeamlessMigrationCall(t *testing.T) {
	oldHF4 := globals.Config.MAJOR_HF4_HEIGHT
	globals.Config.MAJOR_HF4_HEIGHT = 5
	t.Cleanup(func() { globals.Config.MAJOR_HF4_HEIGHT = oldHF4 })

	store, err := graviton.NewMemStore()
	if err != nil {
		t.Fatal(err)
	}
	ss, err := store.LoadSnapshot(0)
	if err != nil {
		t.Fatal(err)
	}
	balanceTree, err := ss.GetTree(config.BALANCE_TREE)
	if err != nil {
		t.Fatal(err)
	}

	base := validMigrationTestTx()
	if err := validateSeamlessMigrationCall(base, 5, balanceTree); err != nil {
		t.Fatalf("valid confidential migration call rejected: %v", err)
	}
	strongerRing := cloneMigrationTestTx(base)
	strongerRing.Payloads[0].Statement.RingSize = 32
	if err := validateSeamlessMigrationCall(strongerRing, 5, balanceTree); err != nil {
		t.Fatalf("migration with stronger ring rejected: %v", err)
	}

	cases := []struct {
		name   string
		height uint64
		mutate func(*transaction.Transaction)
	}{
		{name: "pre-activation", height: 4},
		{name: "ring below privacy minimum", height: 5, mutate: func(tx *transaction.Transaction) { tx.Payloads[0].Statement.RingSize = 4 }},
		{name: "public BurnValue amount", height: 5, mutate: func(tx *transaction.Transaction) { tx.Payloads[0].BurnValue = 7 }},
		{name: "non-native asset", height: 5, mutate: func(tx *transaction.Transaction) { tx.Payloads[0].SCID[0] = 1 }},
		{name: "multiple payloads", height: 5, mutate: func(tx *transaction.Transaction) { tx.Payloads = append(tx.Payloads, tx.Payloads[0]) }},
		{name: "no payload", height: 5, mutate: func(tx *transaction.Transaction) { tx.Payloads = nil }},
		{name: "wrong transaction type", height: 5, mutate: func(tx *transaction.Transaction) { tx.TransactionType = transaction.NORMAL }},
		{name: "wrong action", height: 5, mutate: func(tx *transaction.Transaction) {
			setMigrationTestArg(tx, rpc.SCACTION, rpc.DataUint64, uint64(rpc.SC_INSTALL))
		}},
		{name: "wrong entrypoint", height: 5, mutate: func(tx *transaction.Transaction) {
			setMigrationTestArg(tx, rpc.SCENTRYPOINT, rpc.DataString, "Withdraw")
		}},
		{name: "missing entrypoint", height: 5, mutate: func(tx *transaction.Transaction) { tx.SCDATA = tx.SCDATA[:2] }},
		{name: "duplicate entrypoint", height: 5, mutate: func(tx *transaction.Transaction) { tx.SCDATA = append(tx.SCDATA, tx.SCDATA[2]) }},
		{name: "public destination", height: 5, mutate: func(tx *transaction.Transaction) {
			tx.SCDATA = append(tx.SCDATA, rpc.Argument{Name: "destination", DataType: rpc.DataString, Value: "clear-address"})
		}},
		{name: "public refund", height: 5, mutate: func(tx *transaction.Transaction) {
			tx.SCDATA = append(tx.SCDATA, rpc.Argument{Name: rpc.SCREFUND, DataType: rpc.DataString, Value: "clear-refund"})
		}},
		{name: "other public argument", height: 5, mutate: func(tx *transaction.Transaction) {
			tx.SCDATA = append(tx.SCDATA, rpc.Argument{Name: "memo", DataType: rpc.DataString, Value: "not permitted"})
		}},
		{name: "malformed SCID type", height: 5, mutate: func(tx *transaction.Transaction) {
			setMigrationTestArg(tx, rpc.SCID, rpc.DataString, rpc.SeamlessMigrationSCID().String())
		}},
		{name: "duplicate SCID", height: 5, mutate: func(tx *transaction.Transaction) { tx.SCDATA = append(tx.SCDATA, tx.SCDATA[1]) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx := cloneMigrationTestTx(base)
			if tc.mutate != nil {
				tc.mutate(&tx)
			}
			if err := validateSeamlessMigrationCall(tx, tc.height, balanceTree); err == nil {
				t.Fatal("invalid migration transaction was accepted")
			}
		})
	}

	globals.Config.MAJOR_HF4_HEIGHT = -1
	if err := validateSeamlessMigrationCall(base, 5, balanceTree); err == nil {
		t.Fatal("migration transaction accepted with HF4 unscheduled")
	}
	globals.Config.MAJOR_HF4_HEIGHT = 5
	if err := validateSeamlessMigrationCall(base, 5, nil); err == nil {
		t.Fatal("migration transaction accepted without branch balance tree")
	}

	otherSC := cloneMigrationTestTx(base)
	otherSC.SCDATA[1].Value = crypto.Hash{1}
	if err := validateSeamlessMigrationCall(otherSC, 5, balanceTree); err != nil {
		t.Fatalf("non-migration SC transaction was incorrectly restricted: %v", err)
	}
}
