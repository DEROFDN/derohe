// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

import (
	"io"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/gorilla/websocket"
)

// hungReader models a daemon that accepts the connection and then never answers:
// reads block until the test finishes, so no response ever arrives.
type hungReader struct{ done chan struct{} }

func (h hungReader) Read(p []byte) (int, error) { <-h.done; return 0, io.EOF }

type discardWC struct{}

func (discardWC) Write(p []byte) (int, error) { return len(p), nil }
func (discardWC) Close() error                { return nil }

// Test_CallWithTimeout_HungDaemon pins the per-RPC deadline on the transfer path
// (PR #22 re-review O10).
//
// TransferPayload0WithOptions holds transfer_mutex across every daemon RPC it issues.
// The barren backoff, pass caps, and stall budget bound the SLEEP term of that hold —
// but a daemon that accepts the websocket and never answers used to park the build
// inside a deadline-free CallResult forever, with IsDaemonOnline() still true (it only
// checks WS/RPC non-nil). Post-fix: every RPC the transfer path issues
// (Random_ring_members, GetEncryptedBalanceAtTopoHeight, the decoy probe, and
// NameToAddress — reached pre-assembly, even at ring 2) carries
// walletDaemonCallTimeout, so the first hung call errors the build at the deadline —
// and a deadline error classifies as "could not verify" on the probe path (a transport
// failure, never a silent lenient drop).
func Test_CallWithTimeout_HungDaemon(t *testing.T) {
	done := make(chan struct{})
	defer close(done)

	hung := &Client{RPC: jrpc2.NewClient(channel.RawJSON(hungReader{done}, discardWC{}), nil)}

	// ── the mechanism: a hung call returns at the deadline, not never ──
	var result interface{}
	start := time.Now()
	err := hung.CallWithTimeout(150*time.Millisecond, "DERO.Ping", nil, &result)
	if err == nil {
		t.Fatal("a call the daemon never answers must error at the deadline")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("deadline did not bound the hung call: took %s", elapsed)
	}

	// ── end to end: the transfer-path helpers return under a hung daemon ──
	savedWS, savedRPC, savedTimeout := rpc_client.WS, rpc_client.RPC, walletDaemonCallTimeout
	defer func() { rpc_client.WS, rpc_client.RPC, walletDaemonCallTimeout = savedWS, savedRPC, savedTimeout }()
	rpc_client.WS = &websocket.Conn{} // non-nil: IsDaemonOnline() stays true (O10 premise)
	rpc_client.RPC = hung.RPC
	walletDaemonCallTimeout = 200 * time.Millisecond

	if !IsDaemonOnline() {
		t.Fatal("injection premise broken: IsDaemonOnline must be true with a hung daemon")
	}

	w, werr := Create_Encrypted_Wallet_Random_Memory("")
	if werr != nil {
		t.Fatalf("cannot create in-memory wallet: %s", werr)
	}
	defer w.Close_Encrypted_Wallet()
	w.wallet_online_mode = true // online mode without starting the sync loop

	wdecoy, werr := Create_Encrypted_Wallet_Random_Memory("")
	if werr != nil {
		t.Fatalf("cannot create decoy wallet: %s", werr)
	}
	defer wdecoy.Close_Encrypted_Wallet()

	var zeroscid crypto.Hash

	start = time.Now()
	if _, _, _, _, berr := w.GetEncryptedBalanceAtTopoHeight(zeroscid, -1, w.GetAddress().String()); berr == nil {
		t.Fatal("balance fetch against a hung daemon must error at the deadline")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("balance fetch not bounded by the deadline: took %s", elapsed)
	}

	start = time.Now()
	if members := w.Random_ring_members(zeroscid); len(members) != 0 {
		t.Fatalf("hung daemon cannot yield ring members, got %d", len(members))
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("ring-member fetch not bounded by the deadline: took %s", elapsed)
	}

	// name-destination resolution runs under transfer_mutex BEFORE ring assembly and is
	// reached even at ring 2, so a deadline-free NameToAddress would bypass every
	// ring-assembly bound (PR #22 re-review O11).
	start = time.Now()
	if _, nerr := w.NameToAddress("somename"); nerr == nil {
		t.Fatal("name resolution against a hung daemon must error at the deadline")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("name resolution not bounded by the deadline: took %s", elapsed)
	}

	_ = wdecoy // the decoy-probe classification assertion arrives with review #3's classifier
}
