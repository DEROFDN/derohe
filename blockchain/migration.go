package blockchain

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

const seamlessMigrationEntrypoint = rpc.SeamlessMigrationEntrypoint

// hasSeamlessMigrationReference detects the reserved SCID even when a caller
// encodes it using a non-canonical SCDATA type, so malformed attempts are
// rejected rather than falling through to the legacy anonymous-error path.
func hasSeamlessMigrationReference(args rpc.Arguments) bool {
	reserved := rpc.SeamlessMigrationSCID()
	for _, arg := range args {
		if arg.Name != rpc.SCID {
			continue
		}
		switch value := arg.Value.(type) {
		case crypto.Hash:
			if value == reserved {
				return true
			}
		case string:
			if strings.EqualFold(value, reserved.String()) || bytes.Equal([]byte(value), reserved[:]) {
				return true
			}
		case []byte:
			if bytes.Equal(value, reserved[:]) {
				return true
			}
		}
	}
	return false
}

func isSeamlessMigrationCall(tx transaction.Transaction) bool {
	if !hasSeamlessMigrationReference(tx.SCDATA) || !tx.SCDATA.Has(rpc.SCACTION, rpc.DataUint64) {
		return false
	}
	value, ok := tx.SCDATA.Value(rpc.SCACTION, rpc.DataUint64).(uint64)
	return ok && rpc.SC_ACTION(value) == rpc.SC_CALL
}

func singleMigrationStringArg(args rpc.Arguments, name string) (string, error) {
	count := 0
	var value string
	for _, arg := range args {
		if arg.Name != name {
			continue
		}
		count++
		if arg.DataType != rpc.DataString {
			return "", fmt.Errorf("%s must be a string", name)
		}
		var ok bool
		value, ok = arg.Value.(string)
		if !ok || value == "" {
			return "", fmt.Errorf("%s must be a non-empty string", name)
		}
	}
	if count != 1 {
		return "", fmt.Errorf("expected exactly one %s argument", name)
	}
	return value, nil
}

func singleMigrationUint64Arg(args rpc.Arguments, name string) (uint64, error) {
	count := 0
	var value uint64
	for _, arg := range args {
		if arg.Name != name {
			continue
		}
		count++
		if arg.DataType != rpc.DataUint64 {
			return 0, fmt.Errorf("%s must be a uint64", name)
		}
		var ok bool
		value, ok = arg.Value.(uint64)
		if !ok {
			return 0, fmt.Errorf("%s has invalid value type", name)
		}
	}
	if count != 1 {
		return 0, fmt.Errorf("expected exactly one %s argument", name)
	}
	return value, nil
}

func singleMigrationHashArg(args rpc.Arguments, name string) (crypto.Hash, error) {
	count := 0
	var value crypto.Hash
	for _, arg := range args {
		if arg.Name != name {
			continue
		}
		count++
		if arg.DataType != rpc.DataHash {
			return value, fmt.Errorf("%s must be a hash", name)
		}
		var ok bool
		value, ok = arg.Value.(crypto.Hash)
		if !ok {
			return value, fmt.Errorf("%s has invalid value type", name)
		}
	}
	if count != 1 {
		return value, fmt.Errorf("expected exactly one %s argument", name)
	}
	return value, nil
}

func seamlessMigrationActivationHeight() (uint64, bool) {
	height := globals.Config.MAJOR_HF4_HEIGHT
	if height < 0 {
		return 0, false
	}
	return uint64(height), true
}

// validateSeamlessMigrationCall is consensus validation for the reserved HF4
// contract. The native value moves as an ordinary confidential DERO transfer;
// the migration SC receives no BurnValue and no public recipient/refund data.
func validateSeamlessMigrationCall(tx transaction.Transaction, height uint64, balanceTree *graviton.Tree) error {
	if !hasSeamlessMigrationReference(tx.SCDATA) {
		return nil
	}
	if tx.TransactionType != transaction.SC_TX {
		return fmt.Errorf("migration contract may only be called by SC_TX")
	}
	activation, scheduled := seamlessMigrationActivationHeight()
	if !scheduled || height < activation {
		return fmt.Errorf("seamless migration is inactive at height %d", height)
	}

	if len(tx.SCDATA) == 0 {
		return fmt.Errorf("migration call has no SCDATA")
	}
	action, err := singleMigrationUint64Arg(tx.SCDATA, rpc.SCACTION)
	if err != nil || rpc.SC_ACTION(action) != rpc.SC_CALL {
		return fmt.Errorf("migration requires exactly one SC_CALL action")
	}
	scid, err := singleMigrationHashArg(tx.SCDATA, rpc.SCID)
	if err != nil || scid != rpc.SeamlessMigrationSCID() {
		return fmt.Errorf("migration call has invalid SCID")
	}
	entrypoint, err := singleMigrationStringArg(tx.SCDATA, rpc.SCENTRYPOINT)
	if err != nil || entrypoint != seamlessMigrationEntrypoint {
		return fmt.Errorf("migration call must use entrypoint %q", seamlessMigrationEntrypoint)
	}
	if len(tx.SCDATA) != 3 {
		return fmt.Errorf("migration SCDATA must contain only SC_ACTION, SC_ID, and entrypoint")
	}
	for _, arg := range tx.SCDATA {
		if arg.Name != rpc.SCACTION && arg.Name != rpc.SCID && arg.Name != rpc.SCENTRYPOINT {
			return fmt.Errorf("migration SCDATA must not expose recipient or refund data")
		}
	}
	if len(tx.Payloads) != 1 || !tx.Payloads[0].SCID.IsZero() || tx.Payloads[0].BurnValue != 0 {
		return fmt.Errorf("migration requires one native DERO payload with confidential amount (BurnValue must be zero)")
	}
	if tx.Payloads[0].Statement.RingSize < rpc.SeamlessMigrationMinRingSize {
		return fmt.Errorf("migration requires ring size >= %d", rpc.SeamlessMigrationMinRingSize)
	}
	if balanceTree == nil {
		return fmt.Errorf("migration validation requires the branch balance tree")
	}
	return nil
}
