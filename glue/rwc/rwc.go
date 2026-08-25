//go:build !wasm
// +build !wasm

package rwc

import (
	"io"
	"time"

	"github.com/gorilla/websocket"
)

type ReadWriteCloser struct {
	WS *websocket.Conn
	r  io.Reader
	w  io.WriteCloser

	// wtimeout, when non-zero, arms a fresh write deadline on the underlying
	// websocket before every frame write/flush. A write blocked on a half-open
	// peer (accepted TCP, receive window full, no RST) then errors at the
	// deadline instead of stalling for the kernel TCP retransmit timeout
	// (~15+ min on Linux) — and a jrpc2 client multiplexed over this channel
	// serializes ALL sends and its context-deadline delivery on one mutex, so
	// one such stalled write would otherwise freeze every concurrent call.
	// Zero preserves the historical deadline-free behavior (daemon/explorer
	// server paths use New and are unchanged).
	wtimeout time.Duration
}

func New(conn *websocket.Conn) *ReadWriteCloser {
	return &ReadWriteCloser{WS: conn}
}

// NewWithWriteTimeout is New with a per-write deadline (see wtimeout). On expiry
// gorilla/websocket fails the write and poisons the connection: subsequent writes
// fail fast, the reader errors, and the owner is expected to reconnect.
func NewWithWriteTimeout(conn *websocket.Conn, d time.Duration) *ReadWriteCloser {
	return &ReadWriteCloser{WS: conn, wtimeout: d}
}

func (rwc *ReadWriteCloser) Read(p []byte) (n int, err error) {
	if rwc.r == nil {
		_, rwc.r, err = rwc.WS.NextReader()
		if err != nil {
			return 0, err
		}
	}
	for n = 0; n < len(p); {
		var m int
		m, err = rwc.r.Read(p[n:])
		n += m
		if err == io.EOF {
			rwc.r = nil
		}
		if err != nil {
			break
		}
	}
	return
}

func (rwc *ReadWriteCloser) Write(p []byte) (n int, err error) {
	if rwc.wtimeout > 0 {
		rwc.WS.SetWriteDeadline(time.Now().Add(rwc.wtimeout))
	}
	if rwc.w == nil {
		rwc.w, err = rwc.WS.NextWriter(websocket.TextMessage)
		if err != nil {
			return 0, err
		}
	}
	for n = 0; n < len(p); {
		var m int
		m, err = rwc.w.Write(p)
		n += m
		if err != nil {
			break
		}
	}
	if err != nil || n == len(p) {
		err = rwc.Close()
	}
	return
}

func (rwc *ReadWriteCloser) Close() (err error) {
	if rwc.w != nil {
		if rwc.wtimeout > 0 {
			// Close flushes the frame — a socket write — so it needs its own
			// deadline when called outside Write (e.g. by the channel layer).
			rwc.WS.SetWriteDeadline(time.Now().Add(rwc.wtimeout))
		}
		err = rwc.w.Close()
		rwc.w = nil
	}
	return err
}
