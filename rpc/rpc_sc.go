package rpc

import "github.com/deroproject/derohe/cryptography/crypto"

// definitions related to SC

type SC_ACTION uint64 // sc actions are coded as follow
const (
	SC_CALL SC_ACTION = iota
	SC_INSTALL
)

// SC_CALL must have an arg of type SC_ENTRYPOINT of type String, SCID of type Hash
// SC_INSTALL must have an arg SC of String

// some fields are already defined
const SCACTION = "SC_ACTION" //all SCS must have an ACTION
const SCCODE = "SC_CODE"     // SCCODE must be sent in this ARGUMENT
const SCSIGNER = "SC_SIGNER" // the signer address
const SCSIGNC = "SC_SIGNC"   // the sign C component
const SCSIGNS = "SC_SIGNS"   // the sign S component

const SCID = "SC_ID" // SCID

// SCENTRYPOINT names the called function in an SC_TX.
const SCENTRYPOINT = "entrypoint"

// SCREFUND is retained for RPC compatibility; the confidential migration path rejects it.
const SCREFUND = "refund"

// Seamless migration uses an ordinary confidential transfer, not BurnValue.
// Keep a 16-member ring minimum so both source and receiver ambiguity match
// the wallet's normal default instead of permitting a tiny anonymity set.
const SeamlessMigrationMinRingSize uint64 = 16
const SeamlessMigrationEntrypoint = "Migrate"

// SeamlessMigrationSCID is a reserved hardcoded contract ID (32-byte value 2).
func SeamlessMigrationSCID() (id crypto.Hash) {
	id[31] = 2
	return
}
