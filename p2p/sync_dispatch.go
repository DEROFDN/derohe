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

package p2p

import (
	"sync"
	"sync/atomic"
)

// run_fanout_dispatch assigns work-stealing units to a fixed pool of
// workers. Assignment is Pruned-aware, per work unit (not a blanket
// per-peer exclusion like trigger_sync's own check) - a peer is eligible
// for a unit only if it hasn't pruned that specific topoheight away yet.
// A unit no connected peer can serve is reported back rather than
// silently misassigned. Pruned is read via atomic.LoadInt64 since it's
// touched by concurrent worker goroutines here and nothing enforces safe
// concurrent access at its (unmodified) write site in rpc_handshake.go.

// block_work is one unit of work in the shared queue - a single missing
// block, addressed by topoheight. One-block-per-unit matches the dev's
// benchmarking report (batch vs chunk landed on chunk/per-block).
type block_work struct {
	topoheight int64
}

// dispatch_result is what a worker reports after handling one unit. Fetch
// is deliberately absent - this prototype only decides WHICH connection
// would serve each unit, it does not perform the fetch.
type dispatch_result struct {
	topoheight    int64
	worker_id     int
	assigned_addr string // connection.Addr.String(), log-only
}

// run_fanout_dispatch pulls block_work off a shared queue using a fixed
// pool of workers (work-stealing: whichever worker finishes first pulls the
// next unit, so a slow connection can't stall units assigned to others).
// connections should already be filtered to currently-lagging peers by the
// caller, same as trigger_sync's existing islagging check - Pruned
// eligibility is handled here, per unit, since it depends on which
// specific topoheight is being assigned, not just which peers are lagging.
//
// Returns dispatched results plus the topoheights of any units no
// connected peer could serve (Pruned past every candidate) - reported
// rather than silently assigned to a peer that can't actually answer.
func run_fanout_dispatch(work []block_work, connections []*Connection, worker_count int) (results []dispatch_result, unfulfilled []int64) {
	if worker_count < 1 {
		worker_count = 1
	}
	if len(connections) == 0 || len(work) == 0 {
		return nil, nil
	}

	work_ch := make(chan block_work, len(work))
	for _, w := range work {
		work_ch <- w
	}
	close(work_ch)

	type outcome struct {
		result                 dispatch_result
		fulfilled              bool
		unfulfilled_topoheight int64
	}
	outcomes_ch := make(chan outcome, len(work))
	var wg sync.WaitGroup

	for wk := 0; wk < worker_count; wk++ {
		wg.Add(1)
		go func(worker_id int) {
			defer wg.Done()
			for w := range work_ch {
				var eligible []*Connection
				for _, c := range connections {
					if atomic.LoadInt64(&c.Pruned) < w.topoheight {
						eligible = append(eligible, c)
					}
				}
				if len(eligible) == 0 {
					outcomes_ch <- outcome{fulfilled: false, unfulfilled_topoheight: w.topoheight}
					continue
				}
				// round-robin by (topoheight, worker_id) among ELIGIBLE peers only -
				// a placeholder policy beyond eligibility; real connection-health-aware
				// assignment among eligible peers is future work.
				conn := eligible[(int(w.topoheight)+worker_id)%len(eligible)]
				outcomes_ch <- outcome{fulfilled: true, result: dispatch_result{
					topoheight:    w.topoheight,
					worker_id:     worker_id,
					assigned_addr: conn.Addr.String(),
				}}
			}
		}(wk)
	}

	wg.Wait()
	close(outcomes_ch)

	results = make([]dispatch_result, 0, len(work))
	for o := range outcomes_ch {
		if o.fulfilled {
			results = append(results, o.result)
		} else {
			unfulfilled = append(unfulfilled, o.unfulfilled_topoheight)
		}
	}
	return results, unfulfilled
}

// pick_alternate_connection handles the case where a unit's originally-
// assigned connection fails the actual fetch (network hiccup, peer briefly
// busy) even though it was Pruned-eligible at assignment time. It finds a
// different eligible connection for a retry, excluding addresses already
// tried for this unit - returns nil if none remain (caller then reports a
// genuine, final failure rather than retrying forever).
func pick_alternate_connection(connections []*Connection, topoheight int64, already_tried map[string]bool) *Connection {
	for _, c := range connections {
		if already_tried[c.Addr.String()] {
			continue
		}
		if atomic.LoadInt64(&c.Pruned) < topoheight {
			return c
		}
	}
	return nil
}
