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
	previousConnected := isConnected()
	previousGeneration := getConnectionGeneration()
	t.Cleanup(func() {
		setDaemonHeights(previousHeight, previousTopoHeight)
		setConnected(previousConnected)
		daemonStateMu.Lock()
		connectionGeneration = previousGeneration
		daemonStateMu.Unlock()
	})
}

func TestNativeSyncStatusSeparatesSnapshotFromRefreshProgress(t *testing.T) {
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

	setConnected(true)
	setDaemonHeights(105, 130)
	wallet.markNativeSync(105, 130)
	status := wallet.Get_Native_Sync_Status()

	if status.WalletHeight != 100 || status.WalletTopoHeight != 125 {
		t.Fatalf("native snapshot changed: got height=%d topoheight=%d", status.WalletHeight, status.WalletTopoHeight)
	}
	if status.NativeSyncHeight != 105 || status.NativeSyncTopoHeight != 130 {
		t.Fatalf("native refresh progress not reported: got height=%d topoheight=%d", status.NativeSyncHeight, status.NativeSyncTopoHeight)
	}
	if status.DaemonHeight != 105 || status.DaemonTopoHeight != 130 {
		t.Fatalf("daemon tip not reported: got height=%d topoheight=%d", status.DaemonHeight, status.DaemonTopoHeight)
	}
	if !status.Synchronized {
		t.Fatal("wallet did not report synchronized after native refresh completed")
	}
	if wallet.Get_Height() != 100 || wallet.Get_TopoHeight() != 125 {
		t.Fatalf("legacy snapshot getters changed: height=%d topoheight=%d", wallet.Get_Height(), wallet.Get_TopoHeight())
	}

	setDaemonHeights(106, 131)
	status = wallet.Get_Native_Sync_Status()
	if status.Synchronized {
		t.Fatal("wallet reported synchronized before refreshing the new daemon tip")
	}

	wallet.markNativeSync(106, 131)
	status = wallet.Get_Native_Sync_Status()
	if !status.Synchronized {
		t.Fatal("wallet did not report synchronized after refreshing the new daemon tip")
	}

	setDaemonHeights(106, 132)
	wallet.markNativeSync(106, 131)
	status = wallet.Get_Native_Sync_Status()
	if status.Synchronized {
		t.Fatal("wallet reported synchronized with mismatched daemon topoheight")
	}

	setConnected(false)
	setDaemonHeights(0, 0)
	setConnected(true)
	setDaemonHeights(106, 131)
	status = wallet.Get_Native_Sync_Status()
	if status.Synchronized {
		t.Fatal("wallet reported synchronized before a refresh in the new connection session")
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

	setConnected(false)
	setDaemonHeights(0, 0)
	wallet.markNativeSync(0, 0)
	status := wallet.Get_Native_Sync_Status()
	if status.Synchronized {
		t.Fatal("offline wallet reported synchronized")
	}
}
