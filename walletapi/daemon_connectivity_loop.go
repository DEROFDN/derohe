// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; LOSS OF
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.

package walletapi

import (
	"context"
	"sync"
	"time"
)

var timeout = 5 * time.Second

type connectivityLoop struct {
	stop   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func newConnectivityLoop() *connectivityLoop {
	ctx, cancel := context.WithCancel(context.Background())
	return &connectivityLoop{
		stop:   make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}
}

func (loop *connectivityLoop) stopLoop() {
	if loop == nil {
		return
	}
	loop.once.Do(func() {
		loop.cancel()
		close(loop.stop)
	})
}

// Connectivity is a reference-counted handle to the process-wide daemon
// connectivity loop. The daemon client itself is process-wide, so starting
// multiple polling goroutines would race by replacing one another's client.
type Connectivity struct {
	manager *connectivityManager
	once    sync.Once
}

type connectivityManager struct {
	mu       sync.Mutex
	loop     *connectivityLoop
	refs     int
	stopping bool
	stopped  chan struct{}
}

var sharedConnectivity connectivityManager

// Start_Connectivity acquires a lifecycle reference to the shared connectivity
// loop. Each returned handle must eventually be stopped by its owner.
func Start_Connectivity() *Connectivity {
	for {
		sharedConnectivity.mu.Lock()
		if !sharedConnectivity.stopping {
			if sharedConnectivity.loop == nil {
				sharedConnectivity.loop = newConnectivityLoop()
				go runConnectivityLoop(sharedConnectivity.loop)
			}
			sharedConnectivity.refs++
			sharedConnectivity.mu.Unlock()
			return &Connectivity{manager: &sharedConnectivity}
		}
		stopped := sharedConnectivity.stopped
		sharedConnectivity.mu.Unlock()
		<-stopped
	}
}

// Stop releases this handle's reference. The shared loop is stopped only after
// the final handle is released, so one wallet cannot disconnect another.
func (c *Connectivity) Stop() {
	if c == nil || c.manager == nil {
		return
	}
	c.once.Do(func() {
		manager := c.manager
		// Acquire the connection gate before marking the manager stopping. A
		// Connect already in progress is allowed to finish; once this gate is
		// acquired, later Connect calls observe stopping and cannot install a
		// client during final teardown.
		connectionMu.Lock()
		manager.mu.Lock()
		if manager.refs > 0 {
			manager.refs--
		}
		loop := manager.loop
		lastReference := manager.refs == 0
		if !lastReference {
			manager.mu.Unlock()
			connectionMu.Unlock()
			return
		}
		manager.stopping = true
		manager.stopped = make(chan struct{})
		stopped := manager.stopped
		manager.mu.Unlock()
		connectionMu.Unlock()

		// Stop the loop after admission is closed. A loop connection attempt
		// that races this point observes stopping and returns promptly.
		if loop != nil {
			loop.stopLoop()
			<-loop.done
		}
		// The RPC client is process-wide. Serialize final teardown with direct
		// Connect calls, then clear the client so the next owner dials a fresh
		// daemon connection instead of treating a closed websocket as online.
		connectionMu.Lock()
		invalidateRPCClient(rpc_client, nil)
		connectionMu.Unlock()

		manager.mu.Lock()
		manager.loop = nil
		manager.stopping = false
		manager.stopped = nil
		close(stopped)
		manager.mu.Unlock()
	})
}

type legacyConnectivity struct {
	handle *Connectivity
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once
}

var (
	legacyConnectivityMu sync.Mutex
	legacyLoops          = map[*legacyConnectivity]struct{}{}
)

// Stop_Connectivity is retained for source compatibility. It releases all
// handles acquired through Keep_Connectivity, without affecting independently
// owned Start_Connectivity handles.
// Deprecated: use Start_Connectivity and (*Connectivity).Stop.
func Stop_Connectivity() {
	legacyConnectivityMu.Lock()
	loops := make([]*legacyConnectivity, 0, len(legacyLoops))
	for loop := range legacyLoops {
		loops = append(loops, loop)
		loop.once.Do(func() { close(loop.stop) })
	}
	legacyConnectivityMu.Unlock()

	for _, loop := range loops {
		<-loop.done
	}
}

// Keep_Connectivity preserves the historical blocking API while sharing the
// singleton loop with Start_Connectivity.
// Deprecated: use Start_Connectivity when the loop lifetime is caller-owned.
func Keep_Connectivity() {
	loop := &legacyConnectivity{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	legacyConnectivityMu.Lock()
	legacyLoops[loop] = struct{}{}
	legacyConnectivityMu.Unlock()

	loop.handle = Start_Connectivity()
	<-loop.stop
	loop.handle.Stop()
	legacyConnectivityMu.Lock()
	delete(legacyLoops, loop)
	legacyConnectivityMu.Unlock()
	close(loop.done)
}

func runConnectivityLoop(loop *connectivityLoop) {
	defer close(loop.done)

	ctx := loop.ctx
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-loop.stop:
			return
		case <-timer.C:
			if !isConnected() {
				// Keep startup/reconnect responsive while the daemon's HTTP
				// listener is coming up; do not make callers wait a full poll
				// interval after a transient dial failure.
				connectWithContext(ctx, "")
				timer.Reset(100 * time.Millisecond)
			} else {
				if IsDaemonOnline() {
					var result string
					if err := rpc_client.CallWithContext(ctx, "DERO.Ping", nil, &result); err != nil {
						// Only transport/deadline failures require reconnecting. A
						// JSON-RPC application error does not mean the websocket is unusable.
						if isRPCTransportFailure(err) {
							invalidateRPCClient(rpc_client, nil)
						}
					}
				}
				timer.Reset(timeout)
			}
		}
	}
}
