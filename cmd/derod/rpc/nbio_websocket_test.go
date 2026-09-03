package rpc

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	gws "github.com/gorilla/websocket"
	ltls "github.com/lesismal/llib/std/crypto/tls"
	"github.com/lesismal/nbio/nbhttp"
	"github.com/lesismal/nbio/nbhttp/websocket"
)

// TestNbioWebsocketRoundTrip validates that the bumped nbio (v1.6.11) websocket
// server still upgrades HTTP connections, delivers messages, and fires the
// connection-close callback. This exercises the exact library the getwork
// mining server relies on (websocket_getwork_server.go), which the simulator
// integration suite does not cover.
func TestNbioWebsocketRoundTrip(t *testing.T) {
	// Reserve an ephemeral port.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	// Self-signed cert (same generator the production getwork server uses,
	// backed by llib's crypto/tls which nbio v1.6.11 requires).
	tlsCert := generate_random_tls_cert()
	tlsConfig := &ltls.Config{Certificates: []ltls.Certificate{tlsCert}}

	upgrader := websocket.NewUpgrader()
	var closed int32
	upgrader.OnMessage(func(c *websocket.Conn, messageType websocket.MessageType, data []byte) {
		// Echo the payload back to the client.
		_ = c.WriteMessage(messageType, data)
	})
	upgrader.OnClose(func(c *websocket.Conn, err error) {
		atomic.AddInt32(&closed, 1)
	})

	mux := &http.ServeMux{}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := upgrader.Upgrade(w, r, nil); err != nil {
			t.Errorf("upgrade failed: %v", err)
		}
	})

	svr := nbhttp.NewServer(nbhttp.Config{
		Name:      "TEST",
		Network:   "tcp",
		AddrsTLS:  []string{addr},
		TLSConfig: tlsConfig,
		Handler:   mux,
		NPoller:   1,
	})
	if err := svr.Start(); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	defer svr.Stop()

	// Allow the listener to come up.
	time.Sleep(200 * time.Millisecond)

	dialer := gws.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	c, _, err := dialer.Dial("wss://"+addr+"/", nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer c.Close()

	// Send a frame and expect it echoed back.
	msg := []byte("hello-nbio-v1.6.11")
	if err := c.WriteMessage(gws.TextMessage, msg); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	mt, got, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if mt != gws.TextMessage {
		t.Fatalf("message type = %d, want TextMessage", mt)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}

	// Closing the client must trigger the server-side OnClose callback.
	c.Close()
	time.Sleep(200 * time.Millisecond)
	if atomic.LoadInt32(&closed) == 0 {
		t.Fatalf("expected OnClose to fire after client disconnect")
	}
}
