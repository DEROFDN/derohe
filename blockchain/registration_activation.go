// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package blockchain

// THIS FILE implements the HF4 "registration activation" cooldown — the
// availability-style gate where a freshly registered wallet is only usable
// (for traceable sends and for mining) after at least
// config.RegistrationActiveAfterBlocks final blocks (50 ≈ 15 minutes) have
// passed since its registration.
//
// The delay is measured in confirmed chain-height progress, not wall-clock
// time, so it stays correct even if BLOCK_TIME changes in a future hard fork.
// This is the seed of the future Proof-of-Availability model: the cost of a
// fresh identity is "living time on-chain", not just a one-shot proof-of-work
// at creation. A mild registration PoW remains (HF4) as the creation cost;
// this gate adds the sustained-availability component on top.
//
// Marker keying / mining identity: DERO identifies a miner by the first 16
// bytes of graviton.Sum(compressed_address), the "KeyHash" carried in
// miniblocks and looked up via balance_tree.GetKeyValueFromHash(keyhash[:16]).
// The registration-age marker is therefore keyed by a derived hash of that
// same 16-byte identity, so it is addressable both when a registration is
// executed (full compressed address in hand) and when a miniblock / work
// request is validated (only the 16-byte KeyHash available).
//
// Legacy wallets: the marker is only written for registrations that land at or
// after the file that activates this rule. Accounts registered before then
// carry no marker and cannot be attributed a registration time, so they are
// treated as legacy and remain usable (gated by the pre-existing checks). Only
// wallets that registered post-activation carry a marker and are subject to
// the cooldown.
//
// Scope / privacy note: DERO spending is ring-signature based. The true sender
// of a transaction is only deterministically recoverable when ringsize == 2
// (see Extract_signer), so the *send* gate only applies to ringsize-2 senders.
// Larger rings are anonymous by protocol design and cannot be attributed.
// Mining, by contrast, exposes a concrete 16-byte identity for every miniblocks,
// so the mining gate applies uniformly.

import (
	"encoding/binary"
	"fmt"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

// registrationActivationPrefix namespaces the in-tree registration-age marker
// so it can never collide with an account balance value. The marker value is
// the final-block height at which the wallet registered.
var registrationActivationPrefix = []byte("regeq1:")

// keyHash16 returns the 16-byte mining identity for an account, i.e. the first
// half of graviton.Sum(compressed_address) — the same bytes that go into a
// miniblock's KeyHash and are looked up by IsAddressHashValid.
func keyHash16(compressedAddr [33]byte) (id [16]byte) {
	full := graviton.Sum(compressedAddr[:])
	copy(id[:], full[:16])
	return
}

// registrationMarkerKey derives the graviton key that stores a wallet's
// registration height, from its 16-byte mining identity.
func registrationMarkerKey(id16 [16]byte) []byte {
	key := make([]byte, 0, len(registrationActivationPrefix)+16)
	key = append(key, registrationActivationPrefix...)
	key = append(key, id16[:]...)
	h := graviton.Sum(key)
	return h[:]
}

// encodeRegistrationHeight packs a registration block height as the marker value.
func encodeRegistrationHeight(height int64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(height))
	return buf[:]
}

// decodeRegistrationHeight unpacks a marker value into a registration height.
func decodeRegistrationHeight(v []byte) (int64, bool) {
	if len(v) != 8 {
		return 0, false
	}
	h := int64(binary.BigEndian.Uint64(v[:8]))
	if h < 0 {
		return 0, false
	}
	return h, true
}

// readRegistrationHeightFromKeyHash reads a wallet's registered block height
// from an already-loaded balance tree, addressed by its 16-byte mining
// identity. Returns ok=false when there is no marker (i.e. a legacy wallet).
func readRegistrationHeightFromKeyHash(balance_tree *graviton.Tree, id16 [16]byte) (int64, bool) {
	if balance_tree == nil {
		return 0, false
	}
	value, err := balance_tree.Get(registrationMarkerKey(id16))
	if err != nil {
		return 0, false
	}
	return decodeRegistrationHeight(value)
}

// writeRegistrationHeightMarker records the block height at which a wallet
// registered into the balance tree. Called while executing a REGISTRATION tx.
func writeRegistrationHeightMarker(balance_tree *graviton.Tree, compressedAddr [33]byte, registrationHeight int64) {
	id16 := keyHash16(compressedAddr)
	balance_tree.Put(registrationMarkerKey(id16), encodeRegistrationHeight(registrationHeight))
}

// registrationActivationActive reports whether the registration-activation
// rule is in force at the given final-block height. It is part of the MAJOR
// HF4 fork, alongside the registration PoW target raise.
func registrationActivationActive(height int64) bool {
	return height >= globals.Config.MAJOR_HF4_HEIGHT
}

// senderUsableAtHeight is the pure consensus rule (no chain I/O) deciding
// whether a wallet whose registration is at registrationHeight is usable at the
// current height. Before HF4 every registered wallet is usable immediately; at
// HF4+ it must wait config.RegistrationActiveAfterBlocks.
func senderUsableAtHeight(registrationHeight, currentHeight int64) bool {
	if !registrationActivationActive(currentHeight) {
		return true
	}
	return transaction.RegistrationActivationTopo(registrationHeight, currentHeight, config.RegistrationActiveAfterBlocks)
}

// balanceTreeAtTip loads the balance tree of the current chain tip. A tip with
// no loaded snapshot yields an error; callers treat that as "unknown" and must
// decide (fail-closed) explicitly.
func (chain *Blockchain) balanceTreeAtTip() (*graviton.Tree, error) {
	topoheight := chain.Load_TOPO_HEIGHT()
	toporecord, err := chain.Store.Topo_store.Read(topoheight)
	if err != nil {
		return nil, err
	}
	ss, err := chain.Store.Balance_store.LoadSnapshot(toporecord.State_Version)
	if err != nil {
		return nil, err
	}
	return ss.GetTree(config.BALANCE_TREE)
}

// usableFromMarkers is the shared decision once the activation rule is active:
// a wallet with a marker must have waited the cooldown; a wallet without a
// marker is legacy (registered pre-activation) and is allowed through.
func (chain *Blockchain) usableFromMarkers(currentHeight int64, lookup func(*graviton.Tree) (int64, bool)) bool {
	if !registrationActivationActive(currentHeight) {
		return true
	}
	balance_tree, err := chain.balanceTreeAtTip()
	if err != nil {
		// Cannot read the tip snapshot. Fail OPEN: this gate is a best-effort
		// anti-spam check, not a funds-conservation check — a transient disk
		// error must not halt every send/miniblock on the network. The marker
		// check itself is still enforced any time the tip is readable.
		return true
	}
	registered, ok := lookup(balance_tree)
	if !ok {
		// No marker: legacy/pre-activation wallet. Allow (nothing to attribute).
		return true
	}
	return senderUsableAtHeight(registered, currentHeight)
}

// IsSenderUsable reports whether a concrete sender (a 33-byte compressed
// public key, e.g. from Extract_signer) may use the network at the current
// height, enforcing the HF4 registration-activation cooldown for post-HF4
// registrations. Legacy wallets (no marker) are allowed through.
func (chain *Blockchain) IsSenderUsable(compressedAddr [33]byte) bool {
	return chain.usableFromMarkers(chain.Get_Height(), func(t *graviton.Tree) (int64, bool) {
		return readRegistrationHeightFromKeyHash(t, keyHash16(compressedAddr))
	})
}

// IsMinerUsable reports whether the miner with the given 16-byte mining
// identity (the KeyHash carried in miniblocks and work requests) may mine at
// the current height, enforcing the HF4 cooldown for post-HF4 registrations.
// Legacy miners (no marker) are allowed through; a present-but-too-young
// marker is rejected.
func (chain *Blockchain) IsMinerUsable(id16 [16]byte) bool {
	return chain.usableFromMarkers(chain.Get_Height(), func(t *graviton.Tree) (int64, bool) {
		return readRegistrationHeightFromKeyHash(t, id16)
	})
}

// IsMinerUsableFromHash is IsMinerUsable for the 32-byte miner hash form used
// throughout the mining code (mbl.KeyHash / address discard into a crypto.Hash
// whose first 16 bytes are the mining identity).
func (chain *Blockchain) IsMinerUsableFromHash(miner_hash crypto.Hash) bool {
	var id16 [16]byte
	copy(id16[:], miner_hash[:16])
	return chain.IsMinerUsable(id16)
}

// senderActiveForTx enforces the HF4 registration-activation cooldown on a
// single transaction whose sender is deterministically known. It is a no-op
// (returns nil) when:
//   - the rule is not yet active at the current height, or
//   - the tx is not a spending tx (registration / coinbase are exempt), or
//   - the sender cannot be recovered (ring size > 2, i.e. anonymous).
//
// When the sender IS known and the wallet registered post-HF4 but too young,
// the tx is rejected with a descriptive error. Legacy wallets (no marker) pass.
func (chain *Blockchain) senderActiveForTx(tx *transaction.Transaction) error {
	currentHeight := chain.Get_Height()
	if !registrationActivationActive(currentHeight) {
		return nil
	}
	if tx.TransactionType != transaction.NORMAL &&
		tx.TransactionType != transaction.BURN_TX &&
		tx.TransactionType != transaction.SC_TX {
		return nil
	}

	signer, err := Extract_signer(tx)
	if err != nil {
		// Anonymous (ring size > 2): the protocol cannot attribute the spend
		// to a single account, so the activation gate cannot apply. This is a
		// privacy property, not a bypass we can close without breaking ring
		// anonymity — leave it un-gated and let the PR doc be explicit.
		return nil
	}

	if chain.IsSenderUsable(signer) {
		return nil
	}

	// Build a descriptive "blocks remaining" message for the failure, giving
	// the wallet operator a concrete ETA instead of a bare rejection.
	remaining := int64(0)
	if registered, ok := chain.registrationTopoHeight(signer); ok {
		remaining = registered + config.RegistrationActiveAfterBlocks - currentHeight
		if remaining < 0 {
			remaining = 0
		}
	}
	return fmt.Errorf("wallet is not yet active — new wallets wait %d blocks (≈%d min) after registration before becoming usable; %d block(s) to go",
		config.RegistrationActiveAfterBlocks, (config.RegistrationActiveAfterBlocks*int64(config.BLOCK_TIME))/60, remaining)
}

// registrationTopoHeight reports the final-block height at which the given
// address registered, from the current chain tip. Used only for error messages.
func (chain *Blockchain) registrationTopoHeight(compressedAddr [33]byte) (int64, bool) {
	balance_tree, err := chain.balanceTreeAtTip()
	if err != nil {
		return 0, false
	}
	return readRegistrationHeightFromKeyHash(balance_tree, keyHash16(compressedAddr))
}
