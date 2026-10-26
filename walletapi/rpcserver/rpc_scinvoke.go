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

package rpcserver

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

func ScInvoke(ctx context.Context, p rpc.SC_Invoke_Params) (result rpc.Transfer_Result, err error) {
	defer func() { // safety so if anything wrong happens, we return error
		if r := recover(); r != nil {
			err = fmt.Errorf("panic occured. stack trace %s", debug.Stack())
		}
	}()

	w := FromContext(ctx)
	if !w.wallet.GetMode() { // if wallet is in online mode, use the fees, provided by the daemon, else we need to use what is provided by the user
		return result, fmt.Errorf("Wallet is in offline mode")
	}

	// translate rpc to arguments

	//fmt.Printf("incoming transfer params %+v\n", p)

	if p.SC_ID == "" {
		return result, fmt.Errorf("SCID cannot be empty")
	}

	var tp rpc.Transfer_Params
	tp.SC_RPC = p.SC_RPC

	if strings.EqualFold(p.SC_ID, rpc.SeamlessMigrationSCID().String()) {
		transfer, safeArgs, ringsize, prepareErr := prepareSeamlessMigrationTransfer(
			p.SC_RPC, p.SC_DERO_Deposit, p.SC_TOKEN_Deposit, p.Ringsize,
		)
		if prepareErr != nil {
			return result, prepareErr
		}
		tp.Transfers = append(tp.Transfers, transfer)
		tp.SC_RPC = safeArgs
		tp.Ringsize = ringsize
	} else {
		// Preserve the existing public BurnValue behavior for unrelated SC calls.
		if p.SC_DERO_Deposit >= 1 {
			var mainscid crypto.Hash
			random := w.wallet.Random_ring_members(mainscid)
			if len(random) < 3 {
				return result, fmt.Errorf("SCID could not obtain ring members")
			}
			tp.Transfers = append(tp.Transfers, rpc.Transfer{Destination: random[0], Amount: 0, Burn: p.SC_DERO_Deposit})
		}
		if p.SC_TOKEN_Deposit >= 1 {
			scid := crypto.HashHexToHash(p.SC_ID)
			tp.Transfers = append(tp.Transfers, rpc.Transfer{SCID: scid, Amount: 0, Burn: p.SC_TOKEN_Deposit})
		}
		tp.Ringsize = p.Ringsize
	}
	tp.SC_ID = p.SC_ID
	tp.Fees = p.Fees

	//fmt.Printf("transfers %+v\n", tp)

	return Transfer(ctx, tp)
}

// prepareSeamlessMigrationTransfer converts the wallet-side migration amount
// into an ordinary confidential DERO transfer. The recipient is kept out of
// SCDATA; the standard transaction proof hides its value and ring recipient.
func prepareSeamlessMigrationTransfer(args rpc.Arguments, amount, tokenDeposit, ringsize uint64) (rpc.Transfer, rpc.Arguments, uint64, error) {
	if amount == 0 {
		return rpc.Transfer{}, nil, 0, fmt.Errorf("migration requires a positive DERO amount")
	}
	if tokenDeposit != 0 {
		return rpc.Transfer{}, nil, 0, fmt.Errorf("migration accepts native DERO only")
	}

	var destination string
	var haveDestination, haveEntrypoint bool
	safeArgs := make(rpc.Arguments, 0, 1)
	for _, arg := range args {
		switch arg.Name {
		case "destination":
			if haveDestination || arg.DataType != rpc.DataString {
				return rpc.Transfer{}, nil, 0, fmt.Errorf("migration requires exactly one string destination")
			}
			var ok bool
			destination, ok = arg.Value.(string)
			if !ok || destination == "" {
				return rpc.Transfer{}, nil, 0, fmt.Errorf("migration destination must be a non-empty address")
			}
			haveDestination = true
		case rpc.SCENTRYPOINT:
			if haveEntrypoint || arg.DataType != rpc.DataString {
				return rpc.Transfer{}, nil, 0, fmt.Errorf("migration requires exactly one string entrypoint")
			}
			entrypoint, ok := arg.Value.(string)
			if !ok || entrypoint != rpc.SeamlessMigrationEntrypoint {
				return rpc.Transfer{}, nil, 0, fmt.Errorf("migration entrypoint must be %q", rpc.SeamlessMigrationEntrypoint)
			}
			haveEntrypoint = true
			safeArgs = append(safeArgs, arg)
		case rpc.SCREFUND:
			return rpc.Transfer{}, nil, 0, fmt.Errorf("migration has no refund argument; invalid calls are rejected without spending the transfer")
		default:
			return rpc.Transfer{}, nil, 0, fmt.Errorf("migration does not accept public SCDATA argument %q", arg.Name)
		}
	}
	if !haveDestination || !haveEntrypoint {
		return rpc.Transfer{}, nil, 0, fmt.Errorf("migration requires destination and entrypoint arguments")
	}
	if ringsize == 0 {
		ringsize = rpc.SeamlessMigrationMinRingSize
	}
	if ringsize < rpc.SeamlessMigrationMinRingSize {
		return rpc.Transfer{}, nil, 0, fmt.Errorf("migration requires ring size >= %d", rpc.SeamlessMigrationMinRingSize)
	}

	return rpc.Transfer{Destination: destination, Amount: amount}, safeArgs, ringsize, nil
}
