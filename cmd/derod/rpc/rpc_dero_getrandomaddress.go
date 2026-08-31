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

package rpc

import "fmt"
import "bytes"
import "context"
import "encoding/hex"
import "runtime/debug"
import "github.com/deroproject/derohe/config"
import "github.com/deroproject/derohe/globals"
import "github.com/deroproject/derohe/cryptography/crypto"
import "github.com/deroproject/derohe/rpc"

//import "github.com/deroproject/derohe/blockchain"

// only give random members who have not been used in last 5 blocks
func GetRandomAddress(ctx context.Context, p rpc.GetRandomAddress_Params) (result rpc.GetRandomAddress_Result, err error) {
	defer func() { // safety so if anything wrong happens, we return error
		if r := recover(); r != nil {
			err = fmt.Errorf("panic occured. stack trace %s", debug.Stack())
		}
	}()
	topoheight := chain.Load_TOPO_HEIGHT()
	old_topoheight := topoheight

	if old_topoheight > 100 {
		old_topoheight -= 5
	}

	var cursor_list []string

	{

		toporecord, err := chain.Store.Topo_store.Read(topoheight)
		if err != nil {
			panic(err)
		}
		toporecord_old, err := chain.Store.Topo_store.Read(old_topoheight)
		if err != nil {
			panic(err)
		}

		ss, err := chain.Store.Balance_store.LoadSnapshot(toporecord.State_Version)
		if err != nil {
			panic(err)
		}
		ss_old, err := chain.Store.Balance_store.LoadSnapshot(toporecord_old.State_Version)
		if err != nil {
			panic(err)
		}

		treename := config.BALANCE_TREE
		if !p.SCID.IsZero() {
			treename = string(p.SCID[:])
		}

		balance_tree, err := ss.GetTree(treename)
		if err != nil {
			panic(err)
		}
		balance_tree_old, err := ss_old.GetTree(treename)
		if err != nil {
			panic(err)
		}

		account_map := map[string]bool{}

		for i := 0; i < 100; i++ {

			k, v, err := balance_tree.Random()
			if err != nil {
				continue
			}
			v_old, err := balance_tree_old.Get(k)
			if err != nil {
				continue
			}

			if bytes.Compare(v, v_old) != 0 {
				continue
			}

			var acckey crypto.Point
			if err := acckey.DecodeCompressed(k[:]); err != nil {
				continue
			}

			addr := rpc.NewAddressFromKeys(&acckey)
			addr.Mainnet = true
			if globals.Config.Name != config.Mainnet.Name { // anything other than mainnet is testnet at this point in time
				addr.Mainnet = false
			}
			account_map[addr.String()] = true
			if len(account_map) > 140 {
				break
			}
		}

		for k := range account_map {
			cursor_list = append(cursor_list, k)
		}
	}

	/*
	   		c := balance_tree.Cursor()
	   		for k, v, err := c.First(); err == nil; k, v, err = c.Next() {
	               _ = v
	   			//fmt.Printf("key=%x, value=%x err %s\n", k, v, err)

	   			var acckey crypto.Point
	   			if err := acckey.DecodeCompressed(k[:]); err != nil {
	   				panic(err)
	   			}

	   			addr := address.NewAddressFromKeys(&acckey)
	   			if globals.Config.Name != config.Mainnet.Name { // anything other than mainnet is testnet at this point in time
	   				addr.Network = globals.Config.Public_Address_Prefix
	   			}
	   			cursor_list = append(cursor_list, addr.String())
	   			if len(cursor_list) >= 20 {
	   				break
	   			}
	   		}

	   	}
	*/

	result.Address = cursor_list
	result.Status = "OK"

	return result, nil
}

// GetRandomAddressBatch returns a batch of REAL registered accounts with
// their encrypted balances, sampled from the balance tree. The K1/K2 fix:
//   - K1: the 5-block active-account filter is REMOVED — decoys are drawn
//     from the full registered set including recently-active accounts, so
//     "recently touched" is no longer a predictor of sender/receiver.
//     A weak floor (exclude only the CURRENT block's touched set) remains
//     optional and cannot act as a discriminator.
//   - K2: the encrypted balance is returned WITH the candidate, so the
//     wallet never issues per-candidate GetEncryptedBalance calls (which
//     leaked the ring to the daemon in the clear).
//
// The wallet picks the final ring client-side with its own CSPRNG, so the
// daemon's posterior over the true ring after serving a batch of size B
// for a ring of size R is 1/C(B,R) — its information advantage is
// destroyed.
//
// No consensus change — wallet<->daemon protocol only.
func GetRandomAddressBatch(ctx context.Context, p rpc.GetRandomAddressBatch_Params) (result rpc.GetRandomAddressBatch_Result, err error) {
	defer func() { // safety so if anything wrong happens, we return error
		if r := recover(); r != nil {
			err = fmt.Errorf("panic occured. stack trace %s", debug.Stack())
		}
	}()

	// cap the batch size; 512 is more than enough (rings cap at 128)
	count := p.Count
	if count <= 0 || count > 512 {
		count = 512
	}

	topoheight := chain.Load_TOPO_HEIGHT()
	result.TopoHeight = uint64(topoheight)

	toporecord, err := chain.Store.Topo_store.Read(topoheight)
	if err != nil {
		panic(err)
	}

	ss, err := chain.Store.Balance_store.LoadSnapshot(toporecord.State_Version)
	if err != nil {
		panic(err)
	}

	// if the wallet pinned a state version, use it; else the current tip
	var balance_tree interface {
		Random() ([]byte, []byte, error)
		Get(key []byte) ([]byte, error)
	}
	if p.StateVersion != 0 {
		ss_pinned, err := chain.Store.Balance_store.LoadSnapshot(p.StateVersion)
		if err != nil {
			return result, fmt.Errorf("GetRandomAddressBatch: cannot load pinned state version %d: %w", p.StateVersion, err)
		}
		ss = ss_pinned
		result.StateVersion = p.StateVersion
	} else {
		result.StateVersion = toporecord.State_Version
	}

	treename := config.BALANCE_TREE
	if !p.SCID.IsZero() {
		treename = string(p.SCID[:])
	}

	bt, err := ss.GetTree(treename)
	if err != nil {
		panic(err)
	}
	balance_tree = bt

	// weak floor: if requested, exclude accounts touched in the CURRENT
	// block only (topoheight-1), NOT the last 5. Too small a window to
	// build a posterior against.
	var bt_prev interface {
		Get(key []byte) ([]byte, error)
	}
	if p.ExcludeRecentBlock && topoheight > 1 {
		toporecord_prev, err := chain.Store.Topo_store.Read(topoheight - 1)
		if err == nil {
			ss_prev, err := chain.Store.Balance_store.LoadSnapshot(toporecord_prev.State_Version)
			if err == nil {
				if t, err := ss_prev.GetTree(treename); err == nil {
					bt_prev = t
				}
			}
		}
	}

	seen := map[string]bool{}
	result.Candidates = make([]rpc.GetRandomAddressBatch_Candidate, 0, count)

	// sample generously (3x) because some draws collide or fail to decode
	for i := 0; i < count*3 && len(result.Candidates) < count; i++ {
		k, v, err := balance_tree.Random()
		if err != nil {
			continue
		}

		// weak floor: skip only current-block-touched accounts
		if bt_prev != nil {
			v_prev, err := bt_prev.Get(k)
			if err != nil {
				continue
			}
			if bytes.Compare(v, v_prev) != 0 {
				continue
			}
		}

		var acckey crypto.Point
		if err := acckey.DecodeCompressed(k[:]); err != nil {
			continue
		}
		if len(v) == 0 { // no balance record — not a real account (ghost)
			continue
		}

		addr := rpc.NewAddressFromKeys(&acckey)
		addr.Mainnet = true
		if globals.Config.Name != config.Mainnet.Name { // anything other than mainnet is testnet at this point in time
			addr.Mainnet = false
		}
		addrstr := addr.String()
		if seen[addrstr] {
			continue
		}
		seen[addrstr] = true

		result.Candidates = append(result.Candidates, rpc.GetRandomAddressBatch_Candidate{
			Address:          addrstr,
			Registered:       true,
			EncryptedBalance: hex.EncodeToString(v),
		})
	}

	result.Status = "OK"
	return result, nil
}
