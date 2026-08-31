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

// this file needs  serious improvements but have extremely limited time
/* this file handles communication with the daemon
 * this includes receiving output information
 *
 * *
 */
//import "io"
//import "os"
import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/deroproject/derohe/glue/rwc"
)

// there should be no global variables, so multiple wallets can run at the same time with different assset

var netClient *http.Client

type Client struct {
	WS  *websocket.Conn
	RPC *jrpc2.Client
	mu  sync.RWMutex
	// lifecycleMu prevents Connect/invalidation from closing an RPC client
	// while a call is still using it.
	lifecycleMu sync.RWMutex
}

var rpc_client = &Client{}

// this is as simple as it gets
// single threaded communication to get the daemon status and height
// this will tell whether the wallet can connection successfully to  daemon or not
func Connect(endpoint string) error {
	return connectWithContext(context.Background(), endpoint)
}

func connectWithContext(ctx context.Context, endpoint string) (err error) {

	activeEndpoint := getDaemonEndpointActive()
	if endpoint == "" {
		activeEndpoint = get_daemon_address()
	} else {
		setDaemonEndpointActive(endpoint)
		activeEndpoint = endpoint
	}

	logger.V(1).Info("Daemon endpoint ", "address", activeEndpoint)

	// TODO enable socks support here
	var netTransport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second, // 5 second timeout
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	netClient = &http.Client{
		Timeout:   time.Second * 10,
		Transport: netTransport,
	}

	daemonURI := daemonWebsocketURL(activeEndpoint)
	fmt.Printf("will use endpoint %s\n", daemonURI)

	newWS, _, err := websocket.Dial(ctx, daemonURI, nil)
	if err != nil {
		setConnected(false)
		return err
	}
	inputOutput := rwc.NewNhooyr(newWS)
	newRPC := jrpc2.NewClient(channel.RawJSON(inputOutput, inputOutput), &jrpc2.ClientOptions{OnNotify: Notify_broadcaster})

	rpc_client.lifecycleMu.Lock()
	rpc_client.mu.Lock()
	oldWS, oldRPC := rpc_client.WS, rpc_client.RPC
	rpc_client.WS, rpc_client.RPC = newWS, newRPC
	rpc_client.mu.Unlock()

	if oldWS != nil {
		_ = oldWS.Close(websocket.StatusNormalClosure, "")
	}
	if oldRPC != nil {
		_ = oldRPC.Close()
	}
	rpc_client.lifecycleMu.Unlock()

	// notify user of any state change
	// if daemon connection breaks or comes live again
	setConnected(true)
	if err = test_connectivity(); err != nil {
		invalidateRPCClient(rpc_client, newRPC)
		return err
	}
	return nil
}

func invalidateRPCClient(cli *Client, expected *jrpc2.Client) {
	if cli == nil {
		return
	}

	cli.lifecycleMu.Lock()
	defer cli.lifecycleMu.Unlock()

	cli.mu.Lock()
	if expected != nil && cli.RPC != expected {
		cli.mu.Unlock()
		return
	}
	rpc := cli.RPC
	ws := cli.WS
	cli.RPC = nil
	cli.WS = nil
	cli.mu.Unlock()

	if ws != nil {
		_ = ws.Close(websocket.StatusNormalClosure, "")
	}
	if rpc != nil {
		_ = rpc.Close()
	}
	if cli == rpc_client {
		setConnected(false)
		setDaemonHeights(0, 0)
	}
}
