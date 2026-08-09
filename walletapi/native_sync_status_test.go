// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.

package walletapi

import (
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
)

func restoreDaemonHeights(t *testing.T) {
	t.Helper()
	previousHeight, previousTopoHeight := getDaemonHeights()
	t.Cleanup(func() {
		setDaemonHeights(previousHeight, previousTopoHeight)
	})
}

func TestNativeSyncStatusSeparatesSnapshotFromDaemonTip(t *testing.T) {
	restoreDaemonHeights(t)

	var scid crypto.Hash
	wallet := &Wallet_Memory{
		account: &Account{
			Balance_Result: []rpc.GetEncryptedBalance_Result{{
				SCID:       scid,
				Height:     100,
				Topoheight: 125,
			}},
		},
	}

	setDaemonHeights(105, 130)
	status := wallet.Get_Native_Sync_Status()

	if status.WalletHeight != 100 || status.WalletTopoHeight != 125 {
		t.Fatalf("native snapshot changed: got height=%d topoheight=%d", status.WalletHeight, status.WalletTopoHeight)
	}
	if status.DaemonHeight != 105 || status.DaemonTopoHeight != 130 {
		t.Fatalf("daemon tip not reported: got height=%d topoheight=%d", status.DaemonHeight, status.DaemonTopoHeight)
	}
	if status.Synchronized {
		t.Fatal("wallet reported synchronized before reaching daemon tip")
	}
	if wallet.Get_Height() != 100 || wallet.Get_TopoHeight() != 125 {
		t.Fatalf("legacy snapshot getters changed: height=%d topoheight=%d", wallet.Get_Height(), wallet.Get_TopoHeight())
	}

	setDaemonHeights(100, 124)
	status = wallet.Get_Native_Sync_Status()
	if status.Synchronized {
		t.Fatal("wallet reported synchronized with mismatched topoheight")
	}

	setDaemonHeights(100, 125)
	status = wallet.Get_Native_Sync_Status()
	if !status.Synchronized {
		t.Fatal("wallet did not report synchronized after reaching daemon tip")
	}

	setDaemonHeights(99, 125)
	status = wallet.Get_Native_Sync_Status()
	if status.Synchronized {
		t.Fatal("wallet reported synchronized while snapshot was ahead of daemon")
	}
}

func TestNativeSyncStatusOfflineIsNotSynchronized(t *testing.T) {
	restoreDaemonHeights(t)

	var scid crypto.Hash
	wallet := &Wallet_Memory{
		account: &Account{
			Balance_Result: []rpc.GetEncryptedBalance_Result{{SCID: scid, Height: 100}},
		},
	}

	setDaemonHeights(0, 0)
	status := wallet.Get_Native_Sync_Status()
	if status.Synchronized {
		t.Fatal("offline wallet reported synchronized")
	}
}
