// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package walletapi

import (
	"encoding/hex"
	"fmt"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

//import "sort"
//import "math/rand"
//import cryptorand "crypto/rand"

//import "encoding/binary"

//import "encoding/json"

//import "github.com/vmihailenco/msgpack"

//import "github.com/deroproject/derohe/crypto/ringct"

import "github.com/deroproject/derohe/globals"

//import "github.com/deroproject/derohe/ddn"

//import "github.com/deroproject/derohe/structures"
//import "github.com/deroproject/derohe/blockchain/inputmaturity"

/*
func (w *Wallet_Memory) Transfer_Simplified(addr string, value uint64, data []byte, scdata rpc.Arguments) (tx *transaction.Transaction, err error) {
	if sender, err := rpc.NewAddress(addr); err == nil {
		burn_value := uint64(0)
		return w.TransferPayload0(*sender, value, burn_value, 0, 0, false, data, scdata, false)
	}
	return
}
*/

// we should reply to an entry

// send amount to specific addresses
func (w *Wallet_Memory) TransferPayload0(transfers []rpc.Transfer, ringsize uint64, transfer_all bool, scdata rpc.Arguments, gasstorage uint64, dry_run bool) (tx *transaction.Transaction, err error) {

	//    var  transfer_details structures.Outgoing_Transfer_Details
	w.transfer_mutex.Lock()
	defer w.transfer_mutex.Unlock()

	//if len(transfers) == 0 {
	//	return nil,  fmt.Error("transfers is nil, cannot send.")
	//}

	ringsize_explicit := ringsize != 0 // caller asked for this ring size by name, see the SC-deposit guard below

	if ringsize == 0 {
		ringsize = uint64(w.account.Ringsize) // use wallet ringsize, if ringsize not provided
	} else { // we need to use supplied ringsize
		if ringsize&(ringsize-1) != 0 {
			err = fmt.Errorf("ringsize should be power of 2. value %d", ringsize)
			return
		}
		if !(ringsize >= config.MIN_RINGSIZE && ringsize <= config.MAX_RINGSIZE) {
			err = fmt.Errorf("ringsize out of range value %d", ringsize)
			return
		}
	}

	//ringsize = 2

	// if wallet is online,take the fees from the network itself
	// otherwise use whatever user has provided
	//if w.GetMode()  {
	fees_per_kb := w.dynamic_fees_per_kb // TODO disabled as protection while lots more testing is going on
	//rlog.Infof("Fees per KB %d\n", fees_per_kb)
	//}

	if fees_per_kb == 0 {
		fees_per_kb = config.FEE_PER_KB
	}

	// user wants to do an SC call, but doesn't want any transfer, so we will transfer 0 to a random account
	if len(scdata) >= 1 && len(transfers) == 0 {
		var zeroscid crypto.Hash
		for _, k := range w.Random_ring_members(zeroscid) {
			if k != w.GetAddress().String() { /// make sure random member is not equal to ourself
				transfers = append(transfers, rpc.Transfer{Destination: k, Amount: 0})
				logger.V(3).Info("Doing 0 transfer to", "random_address", k)
				break
			}
		}
	}

	// SC deposit safety. A burn attached to an SC call can only be given back if the
	// sender can be identified, and blockchain.Extract_signer recovers a sender ONLY
	// from a payload that is zero-SCID AND ringsize 2. At any other ring size a call
	// that does not complete destroys the deposit and there is no refund target, by
	// construction -- the chain cannot fix this after the fact, so refuse to BUILD the
	// shape. This is a wallet-side guard on purpose: refusing it at verification would
	// reject whole blocks produced by un-upgraded miners.
	//
	// Only a DEFAULTED ring size is refused. An explicit ringsize argument is NOT read
	// as consent to lose the deposit -- that number is already overloaded in this
	// ecosystem (TELA reads ring 2 vs ring >2 as updateable vs immutable) and callers
	// pass it positionally, so it cannot carry a second meaning. It is honoured for a
	// narrower reason: refusing it would forbid anonymous paid SC calls outright, and
	// those are legitimate and mostly succeed -- the loss only materialises when the
	// call does not complete, which is undecidable here. So an explicit ring >2 with a
	// deposit is WARNED about, not refused, and only the defaulted path -- where no
	// human chose anything and the wallet default of 16 is silently unrefundable -- is
	// refused outright.
	//
	// The wallet threads ONE ring size through every payload it builds, so "no payload
	// is zero-SCID at ring 2" reduces here to "ringsize != 2"; this is the same
	// condition Extract_signer tests, not a per-payload approximation of it.
	if ringsize != 2 && len(scdata) >= 1 {
		for i := range transfers {
			if transfers[i].Burn == 0 {
				continue
			}
			if !ringsize_explicit {
				// NOTE: deliberately NOT gated on the activation height. At ring >2 the
				// deposit is destroyed on a failed call in BOTH eras, so the refusal is
				// never wrong; only the remedy is era-dependent, which the message says.
				return nil, fmt.Errorf("SC deposit of %d cannot be refunded if the call fails at ringsize %d: only a ringsize-2 payload exposes a signer, so above ringsize 2 the deposit is destroyed whenever the call does not complete, in every era. pass ringsize 2 to become refundable -- at the cost of being identifiable as the sender -- which gives the deposit back today when the contract itself rejects the call, and from height %d onward also when the call never reaches a contract at all (wrong or uninstalled scid, malformed or missing action). note that ringsize 2 also lowers the wallet's AUTO-COMPUTED fee by 60 atomic units versus the default ringsize 16 (transaction_build.go steps the fee at len(ring)/16), and that fee IS the storage-gas budget, so a call that STOREs near the limit may now fail for insufficient storage gas -- pass an explicit fee/gasstorage if the call writes more than a few hundred bytes. or pass ringsize %d explicitly to keep the deposit at risk", transfers[i].Burn, ringsize, globals.Config.BLACKHOLE_HEIGHT, ringsize)
			}
			// globals.Logger, NOT this package's `logger`: walletapi/wallet.go declares
			// logger as logr.Discard() and nothing in the tree ever assigns it, so a
			// warning sent there is discarded in every binary at every verbosity.
			//
			// NO burn value and NO scid in this line, deliberately. globals.InitializeLog
			// tees every record into a zapcore.NewJSONEncoder over `logfile`, which
			// dero-wallet-cli creates as a PLAINTEXT file next to the wallet, while the
			// wallet DB itself is encrypted at rest -- so logging the pair would move an
			// amount<->contract linkage out of the encrypted store and into an
			// unencrypted one, for precisely the caller who asked for anonymity, with no
			// operator switch to turn it off (--flog-level only moves the V threshold).
			// Info, not Error: nothing has failed, the caller asked for this.
			globals.Logger.Info("SC deposit at ringsize >2 is UNREFUNDABLE if the call fails; no signer can be recovered", "ringsize", ringsize)
		}
	}

	if len(transfers) >= 1 {
		has_base := false
		for i := range transfers {
			if transfers[i].SCID.IsZero() {
				has_base = true
			}
		}

		// if we do not have base we can not detect fees. this restriction should be lifted at suitable time
		if !has_base {
			var zeroscid crypto.Hash
			for _, k := range w.Random_ring_members(zeroscid) {
				if k != w.GetAddress().String() { /// make sure random member is not equal to ourself
					transfers = append(transfers, rpc.Transfer{Destination: k, Amount: 0})
					logger.V(3).Info("Doing 0 transfer to", "random_address", k)
					break
				}
			}
		}

	}

	for t := range transfers {
		var data []byte
		if data, err = transfers[t].Payload_RPC.CheckPack(transaction.PAYLOAD0_LIMIT); err != nil {
			return
		}

		if len(data) != transaction.PAYLOAD0_LIMIT {
			err = fmt.Errorf("Expecting exactly %d bytes data  but have  %d bytes", transaction.PAYLOAD0_LIMIT, len(data))
			return
		}
	}

	//fees := (ringsize + 1) * fees_per_kb // start with zero fees
	//	expected_fee := uint64(0)

	if transfer_all {
		err = fmt.Errorf("Transfer all not supported")
		return
		//transfers[0].Amount = w.account.Balance_Mature - fees
	}

	total_amount_required := map[crypto.Hash]uint64{}
	for i := range transfers {
		total_amount_required[transfers[i].SCID] = total_amount_required[transfers[i].SCID] + transfers[i].Amount + transfers[i].Burn
	}

	for i := range transfers {
		var current_balance uint64
		current_balance, _, err = w.GetDecryptedBalanceAtTopoHeight(transfers[i].SCID, -1, w.GetAddress().String())

		if err != nil {
			return
		}
		if total_amount_required[transfers[i].SCID] > current_balance {
			err = fmt.Errorf("Insufficent funds for scid %s Need %s Actual %s", transfers[i].SCID, FormatMoney(total_amount_required[transfers[i].SCID]), FormatMoney(current_balance))
			return
		}
	}

	for t := range transfers {

		if transfers[t].Destination == "" { // user skipped destination
			if transfers[t].SCID.IsZero() {
				err = fmt.Errorf("Main Destination cannot be empty")
				return
			}

			// we will try x times, to get a random ring ring member other than us, if ok, we move ahead
			ring_count := 0
			for i := 0; i < 20; i++ {
				//fmt.Printf("getting random ring member %d\n", i)
				scid := transfers[t].SCID
				if i > 17 { // if we cannot obtain ring member is 17 tries, choose  ring member from zero
					var zeroscid crypto.Hash
					scid = zeroscid
				}
				for _, k := range w.Random_ring_members(scid) {
					if k != w.GetAddress().String() {
						transfers[t].Destination = k
						i = 1000000 // break outer loop also
						ring_count++
						break
					}
				}
			}

		}

		if transfers[t].Destination == "" {
			err = fmt.Errorf("could not obtain random ring member for scid %s", transfers[t].SCID)
			return
		}

		// try to resolve name to address here
		if _, err = rpc.NewAddress(transfers[t].Destination); err != nil {
			if transfers[t].Destination, err = w.NameToAddress(transfers[t].Destination); err != nil {
				err = fmt.Errorf("could not decode name or address err '%s' name '%s'\n", err, transfers[t].Destination)
				return
			}
		}
	}

	//fmt.Printf("transfers %+v\n", transfers)

	var rings [][]*bn256.G1
	var rings_balances [][][]byte //initialize all maps

	var max_bits_array []int

	topoheight := int64(-1)
	var block_hash crypto.Hash

	var zeroscid crypto.Hash

	// noncetopo should be verified for all ring members simultaneously
	// this can lead to tx rejection
	// we currently bypass this since random members are chosen which have not been used in last 5 block
	_, noncetopo, block_hash, self_e, err := w.GetEncryptedBalanceAtTopoHeight(zeroscid, -1, w.GetAddress().String())
	if err != nil {
		err = fmt.Errorf("could not obtain encrypted balance for self err %s\n", err)
		return
	}

	// TODO, we should check nonce for base token and other tokens at the same time
	// right now, we are probably using a bit of luck here
	if daemon_topoheight >= int64(noncetopo)+3 { // if wallet has not been recently used, increase probability  of user's tx being successfully mined
		topoheight = daemon_topoheight - 3
	}

	_, _, block_hash, self_e, _ = w.GetEncryptedBalanceAtTopoHeight(transfers[0].SCID, topoheight, w.GetAddress().String())
	if err != nil {
		fmt.Printf("self unregistered err %s\n", err)
		return
	}

	er, err := w.GetSelfEncryptedBalanceAtTopoHeight(transfers[0].SCID, topoheight)
	if err != nil {
		err = fmt.Errorf("could not obtain encrypted balance for self err %s\n", err)
		return
	}
	height := uint64(er.Height)
	block_hash = er.BlockHash
	topoheight = er.Topoheight
	treehash := er.Merkle_Balance_TreeHash

	treehash_raw, err := hex.DecodeString(treehash)
	if err != nil {
		return
	}
	if len(treehash_raw) != 32 {
		err = fmt.Errorf("roothash is not of 32 bytes, probably daemon corruption '%s'", treehash)
		return
	}

	for t := range transfers {

		var ring []*bn256.G1
		var ring_balances [][]byte

		/*	if transfers[t].SCID.IsZero() {
				ringsize = uint64(ringsize)
			} else {
				ringsize = ringsize // only for easier testing
			}
		*/

		bits_needed := make([]int, ringsize, ringsize)

		bits_needed[0], _, _, self_e, err = w.GetEncryptedBalanceAtTopoHeight(transfers[t].SCID, topoheight, w.GetAddress().String())
		if err != nil {
			fmt.Printf("self unregistered err %s\n", err)
			return
		} else {
			ring_balances = append(ring_balances, self_e.Serialize())
			ring = append(ring, w.account.Keys.Public.G1())
		}

		var addr *rpc.Address
		if addr, err = rpc.NewAddress(transfers[t].Destination); err != nil {
			return
		}

		if addr.IsIntegratedAddress() && addr.Arguments.Validate_Arguments() != nil {
			err = fmt.Errorf("Integrated Address  arguments could not be validated.")
			return
		}

		if addr.IsIntegratedAddress() && len(transfers[t].Payload_RPC) == 0 {
			for _, arg := range addr.Arguments {
				if arg.Name == rpc.RPC_DESTINATION_PORT && addr.Arguments.Has(rpc.RPC_DESTINATION_PORT, rpc.DataUint64) {
					transfers[t].Payload_RPC = append(transfers[t].Payload_RPC, rpc.Argument{Name: rpc.RPC_DESTINATION_PORT, DataType: rpc.DataUint64, Value: addr.Arguments.Value(rpc.RPC_DESTINATION_PORT, rpc.DataUint64).(uint64)})
					continue
				} else {
					fmt.Printf("integrtated address, but don't know how to process\n")
					err = fmt.Errorf("integrated address used, but don't know how to process %+v", addr.Arguments)
				}
			}

			if err != nil {
				return
			}
		}

		var dest_e *crypto.ElGamal
		bits_needed[1], _, _, dest_e, err = w.GetEncryptedBalanceAtTopoHeight(transfers[t].SCID, topoheight, addr.BaseAddress().String())
		if err != nil {
			fmt.Printf(" t %d unregistered1 '%s' %s\n", t, addr, err)
			return
		} else {
			ring_balances = append(ring_balances, dest_e.Serialize())
			ring = append(ring, addr.PublicKey.G1())
		}

		/*if len(w.account.RingMembers) < int(ringsize) {
			err = fmt.Errorf("We do not have enough ring members, expecting alteast %d but have only %d", int(ringsize), len(w.account.RingMembers))
			return
		}*/

		receiver_without_payment_id := addr.BaseAddress()

		//sending to self is not supported
		if w.GetAddress().String() == receiver_without_payment_id.String() {
			err = fmt.Errorf("Sending to self is not supported")
			return
		}

		deduplicator := map[string]bool{}
		deduplicator[receiver_without_payment_id.String()] = true
		deduplicator[w.GetAddress().String()] = true

		for ringsize != 2 {
			probable_members := w.Random_ring_members(transfers[t].SCID)
			if len(probable_members) <= 40 { // we do not have enough ring members for sure, extract ring members from base
				var zeroscid crypto.Hash
				probable_members = w.Random_ring_members(zeroscid)
			}
			for _, k := range probable_members {
				if _, collision := deduplicator[k]; collision {
					continue
				}
				deduplicator[k] = true
				if len(ring_balances) < int(ringsize) && k != receiver_without_payment_id.String() && k != w.GetAddress().String() {
					var addr_member *rpc.Address
					//fmt.Printf("t:%d len %d %s     receiver %s   sender %s\n",t,len(ring_balances),  k, receiver_without_payment_id.String(), w.GetAddress().String())
					var ebal *crypto.ElGamal

					bits_needed[len(ring_balances)], _, _, ebal, err = w.GetEncryptedBalanceAtTopoHeight(transfers[t].SCID, -1, k)
					if err != nil {
						fmt.Printf(" unregistered %s\n", k)
						return
					}
					if addr_member, err = rpc.NewAddress(k); err != nil {
						return
					}

					ring_balances = append(ring_balances, ebal.Serialize())
					ring = append(ring, addr_member.PublicKey.G1())

					if len(ring_balances) == int(ringsize) {
						goto ring_members_collected
					}

				}
			}

		}
	ring_members_collected:

		rings = append(rings, ring)
		rings_balances = append(rings_balances, ring_balances)

		max_bits := 0
		for i := range bits_needed {
			if max_bits < bits_needed[i] {
				max_bits = bits_needed[i]
			}
		}
		max_bits_array = append(max_bits_array, max_bits)
	}
	max_bits := 0
	for i := range max_bits_array {
		if max_bits < max_bits_array[i] {
			max_bits = max_bits_array[i]
		}
	}
	max_bits += 6 // extra 6 bits

	if !dry_run {
		tx = w.BuildTransaction(transfers, rings_balances, rings, block_hash, height, scdata, treehash_raw, max_bits, gasstorage)
	}

	if tx == nil {
		err = fmt.Errorf("somehow the tx could not be built, please retry")
	}

	return
}
