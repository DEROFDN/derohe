//go:build !wasm
// +build !wasm

package rwc

// Write-deadline pin (PR #22 re-review O14).
//
// A half-open peer (TCP accepted, receive window full, no RST) blocks a websocket
// write for the kernel TCP retransmit timeout (~15+ min on Linux). The wallet
// multiplexes ALL daemon RPCs over one jrpc2 client whose send() holds the
// client-wide mutex ACROSS the socket write and whose context-deadline delivery
// (waitComplete) must take the same mutex — so one blocked deadline-free write
// (e.g. the background test_connectivity Echo) would freeze every concurrent
// call, including transfer-path calls holding transfer_mutex, with their 45s
// call deadlines undeliverable. NewWithWriteTimeout bounds every frame write, so
// the blocked write errors at the deadline and poisons the connection instead.
//
// The test reproduces the exact peer behavior: a websocket server that completes
// the handshake and then never reads. Writes are absorbed by the send/receive
// socket buffers until they fill, then block; the write deadline must convert
// that block into an error within the timeout, and subsequent writes must fail
// fast (poisoned connection → owner reconnects).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func Test_WriteTimeout_UnsticksBlockedWrite(t *testing.T) {
	upgrader := websocket.Upgrader{}
	block := make(chan struct{})
	defer close(block)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(rw, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		<-block // half-open: handshake done, then never read a single frame
	}))
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %s", err)
	}
	defer conn.Close()

	const wtimeout = 500 * time.Millisecond
	rw := NewWithWriteTimeout(conn, wtimeout)

	// Fill the socket buffers until the write blocks. Kernel auto-tuning tops out
	// far below the 256MB ceiling, so the loop always hits the blocked state.
	payload := make([]byte, 1<<20)
	start := time.Now()
	var werr error
	for i := 0; i < 256; i++ {
		if _, werr = rw.Write(payload); werr != nil {
			break
		}
	}
	elapsed := time.Since(start)
	if werr == nil {
		t.Fatal("writes against a peer that stopped reading never failed — write deadline not armed")
	}
	// Bound: buffered writes are memcpy-fast; the blocked one errors within its
	// deadline. Generous multiple for CI scheduling noise — the point is minutes
	// (TCP retransmit) vs sub-second (deadline).
	if elapsed > 30*time.Second {
		t.Fatalf("blocked write took %s to fail; want ~%s (deadline not effective)", elapsed, wtimeout)
	}
	t.Logf("blocked write failed after %s: %s", elapsed, werr)

	// Deadline expiry poisons the connection: the next write must fail fast, so a
	// broken transport is never silently reused (the wallet reconnects instead).
	if _, err := rw.Write([]byte("x")); err == nil {
		t.Fatal("connection usable after write-deadline expiry; expected poisoned connection")
	}
}
