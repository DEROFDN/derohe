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
	"net"
	"testing"
)

// Synthetic connections only - no real network, no RPC, no chain state.
// Proves the work-stealing wiring compiles and distributes work across
// multiple connections.
func Test_Fanout_Dispatch(t *testing.T) {
	connections := []*Connection{
		{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 20201}},
		{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 20202}},
		{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 20203}},
	}

	var work []block_work
	for h := int64(1001); h <= int64(1200); h++ {
		work = append(work, block_work{topoheight: h})
	}

	results, unfulfilled := run_fanout_dispatch(work, connections, 10)

	if len(unfulfilled) != 0 {
		t.Fatalf("expected 0 unfulfilled (all mock peers have Pruned=0), got %d", len(unfulfilled))
	}
	if len(results) != len(work) {
		t.Fatalf("expected %d results, got %d - work-stealing dropped units", len(work), len(results))
	}

	seen := map[int64]bool{}
	per_conn := map[string]int{}
	for _, r := range results {
		if seen[r.topoheight] {
			t.Fatalf("topoheight %d dispatched more than once", r.topoheight)
		}
		seen[r.topoheight] = true
		per_conn[r.assigned_addr]++
	}

	if len(per_conn) != len(connections) {
		t.Fatalf("expected work spread across all %d connections, only %d received any", len(connections), len(per_conn))
	}

	t.Logf("distribution across %d connections: %+v", len(connections), per_conn)
}

// zero connections must not panic or hang - log-only path degrades to nil.
func Test_Fanout_Dispatch_No_Connections(t *testing.T) {
	work := []block_work{{topoheight: 1}}
	results, unfulfilled := run_fanout_dispatch(work, nil, 10)
	if results != nil {
		t.Fatalf("expected nil results with no connections, got %d", len(results))
	}
	if unfulfilled != nil {
		t.Fatalf("expected nil unfulfilled with no connections, got %d", len(unfulfilled))
	}
}

// Real peer addresses and Pruned values observed from a live node
// (2026-08-25 derod.log): 194.77.71.65 and 38.180.60.233, both real
// mainnet peers that were blanket-excluded by trigger_sync's coarse
// check. A work sample straddling their two real Pruned watermarks
// proves the per-unit filter recovers eligibility where the blanket
// check couldn't.
func Test_Fanout_Dispatch_Real_Pruned_Watermarks(t *testing.T) {
	const pruned_a = 7410274 // real: 194.77.71.65
	const pruned_b = 7471050 // real: 38.180.60.233

	addr_a, _ := net.ResolveTCPAddr("tcp", "194.77.71.65:18089")
	addr_b, _ := net.ResolveTCPAddr("tcp", "38.180.60.233:11011")
	conn_a := &Connection{Addr: addr_a, Pruned: pruned_a}
	conn_b := &Connection{Addr: addr_b, Pruned: pruned_b}
	connections := []*Connection{conn_a, conn_b}

	var work []block_work
	// below both: neither eligible -> must land in unfulfilled
	work = append(work, block_work{topoheight: pruned_a - 100})
	// in [pruned_a, pruned_b): only conn_a eligible
	work = append(work, block_work{topoheight: pruned_a + 100})
	// at/above pruned_b: both eligible
	work = append(work, block_work{topoheight: pruned_b + 100})

	results, unfulfilled := run_fanout_dispatch(work, connections, 4)

	if len(unfulfilled) != 1 || unfulfilled[0] != pruned_a-100 {
		t.Fatalf("expected exactly the sub-pruned_a unit unfulfilled, got %v", unfulfilled)
	}

	for _, r := range results {
		switch r.topoheight {
		case pruned_a + 100:
			if r.assigned_addr != conn_a.Addr.String() {
				t.Fatalf("topoheight %d (between real watermarks) must only go to conn_a (Pruned=%d), got %s", r.topoheight, pruned_a, r.assigned_addr)
			}
		}
		// hard invariant: never assigned to a peer whose real Pruned >= this unit's topoheight
		for _, c := range connections {
			if c.Addr.String() == r.assigned_addr && c.Pruned >= r.topoheight {
				t.Fatalf("invariant violated: unit %d assigned to peer with Pruned=%d", r.topoheight, c.Pruned)
			}
		}
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 fulfilled results (the two units above pruned_a), got %d", len(results))
	}
}

// A unit that literally no connected peer can serve must be reported in
// unfulfilled, never silently misassigned.
func Test_Fanout_Dispatch_Unfulfillable_Unit(t *testing.T) {
	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:20201")
	connections := []*Connection{{Addr: addr, Pruned: 5_000_000}}
	work := []block_work{{topoheight: 1_000_000}} // below the only peer's Pruned watermark

	results, unfulfilled := run_fanout_dispatch(work, connections, 4)

	if len(results) != 0 {
		t.Fatalf("expected 0 fulfilled results, got %d: %+v", len(results), results)
	}
	if len(unfulfilled) != 1 || unfulfilled[0] != 1_000_000 {
		t.Fatalf("expected exactly [1000000] unfulfilled, got %v", unfulfilled)
	}
}

// Simulates one connection failing for a specific unit (by marking it
// already_tried) while another eligible connection exists -
// pick_alternate_connection must recover by returning the other one,
// never the failed one, and must return nil once every eligible
// connection has actually been exhausted.
func Test_Pick_Alternate_Connection_Recovers_From_One_Failure(t *testing.T) {
	addr_a, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:20201")
	addr_b, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:20202")
	conn_a := &Connection{Addr: addr_a, Pruned: 0}
	conn_b := &Connection{Addr: addr_b, Pruned: 0}
	connections := []*Connection{conn_a, conn_b}

	const topoheight = 1000

	// conn_a was tried and failed - retry must land on conn_b, not conn_a.
	already_tried := map[string]bool{conn_a.Addr.String(): true}
	alt := pick_alternate_connection(connections, topoheight, already_tried)
	if alt == nil || alt.Addr.String() != conn_b.Addr.String() {
		t.Fatalf("expected retry to land on conn_b, got %+v", alt)
	}

	// now both have been tried - nothing left, must return nil, not conn_a again.
	already_tried[conn_b.Addr.String()] = true
	exhausted := pick_alternate_connection(connections, topoheight, already_tried)
	if exhausted != nil {
		t.Fatalf("expected nil once every eligible connection is exhausted, got %+v", exhausted)
	}
}
