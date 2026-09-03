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

// fanout_sync is the permanent, default catch-up path for trigger_sync()
// when chain.Sync is true (fast-sync/bootstrap_chain is a separate
// mechanism, untouched). It combines Pruned-aware dispatch
// (run_fanout_dispatch), retry against a different peer
// (pick_alternate_connection), and an ascending-order commit into
// chain.Add_Complete_Block guarded against panics (a real, pre-existing
// SC-execution panic was found live during development - normal sync is
// shielded by cron.Recover, this path needs its own recover since it's a
// direct call).
//
// Called from trigger_sync() as the PRIMARY path; returns false when its
// own preconditions aren't met (fewer than 2 eligible peers, the Chain()
// call fails, or no missing blocks are found), in which case the caller
// falls back to the existing, unchanged single-connection sync_chain().

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/metrics"
)

const fanout_sync_batch_size = 32 // double the value proven safe in real trials against live peers
const fanout_sync_max_attempts = 3
const fanout_sync_max_consecutive_failures = 3

func fanout_build_chain_request() (request Chain_Request_Struct) {
	start_point := chain.Load_TOPO_HEIGHT()
	for i := int64(0); i < start_point && len(request.Block_list) < 20; i++ {
		tr, err := chain.Store.Topo_store.Read(start_point - i)
		if err != nil || tr.IsClean() {
			break
		}
		request.Block_list = append(request.Block_list, tr.BLOCK_ID)
		request.TopoHeights = append(request.TopoHeights, start_point-i)
	}
	request.Block_list = append(request.Block_list, globals.Config.Genesis_Block_Hash)
	request.TopoHeights = append(request.TopoHeights, 0)
	fill_common(&request.Common)
	return
}

// fanout_eligible_lagging filters candidates to those currently ahead of
// our height - the same whole-peer relationship trigger_sync's own
// islagging check uses, computed once here rather than reused from the
// caller's possibly-stale view.
func fanout_eligible_lagging(candidates []*Connection) (lagging []*Connection, addr_to_conn map[string]*Connection, our_height int64) {
	our_height = chain.Get_Height()
	addr_to_conn = map[string]*Connection{}
	for _, c := range candidates {
		if atomic.LoadUint32(&c.State) == HANDSHAKE_PENDING {
			continue
		}
		if c.Height > our_height {
			lagging = append(lagging, c)
			addr_to_conn[c.Addr.String()] = c
		}
	}
	return
}

func fanout_select_chain_request_peer(candidates []*Connection) *Connection {
	our_top := chain.Load_Block_Topological_order(chain.Get_Top_ID())
	for _, c := range candidates {
		if atomic.LoadInt64(&c.Pruned) <= our_top {
			return c
		}
	}
	return nil
}

func fanout_get_object(connection *Connection, blid [32]byte) (cbl Complete_Block, ok bool, err error) {
	var orequest ObjectList
	var oresponse Objects
	orequest.Block_list = append(orequest.Block_list, blid)
	fill_common(&orequest.Common)
	if err = connection.Client.Call("Peer.GetObject", orequest, &oresponse); err != nil {
		return cbl, false, err
	}
	if len(oresponse.CBlocks) < 1 {
		return cbl, false, fmt.Errorf("empty response for %x", blid)
	}
	return oresponse.CBlocks[0], true, nil
}

// fanout_sync fans a catch-up batch across all currently-lagging, Pruned-
// eligible connections concurrently. Returns true if it committed at least
// one block (real forward progress, even on a partial batch), false if it
// couldn't get started at all - the caller should fall back to sync_chain()
// in that case.
func fanout_sync(candidates []*Connection) bool {
	lagging, addr_to_conn, our_height := fanout_eligible_lagging(candidates)
	if len(lagging) < 2 {
		return false
	}

	chain_peer := fanout_select_chain_request_peer(lagging)
	if chain_peer == nil {
		return false
	}

	request := fanout_build_chain_request()
	var response Chain_Response_Struct
	if err := chain_peer.Client.Call("Peer.Chain", request, &response); err != nil {
		chain_peer.logger.V(2).Info("fanout_sync: Chain call failed", "err", err)
		return false
	}
	if response.Start_topoheight < our_height-1000 {
		chain_peer.logger.V(1).Info("fanout_sync: Chain response far below our height, skipping", "start_topoheight", response.Start_topoheight, "our_height", our_height)
		return false
	}

	type pending struct {
		topoheight int64
		blid       [32]byte
	}
	var to_fetch []pending
	for i := range response.Block_list {
		topo := response.Start_topoheight + int64(i)
		our_topo_order := chain.Load_Block_Topological_order(response.Block_list[i])
		if our_topo_order != topo || our_topo_order == -1 {
			to_fetch = append(to_fetch, pending{topoheight: topo, blid: response.Block_list[i]})
			if len(to_fetch) >= fanout_sync_batch_size {
				break
			}
		}
	}
	if len(to_fetch) == 0 {
		return false
	}

	blid_by_topo := map[int64][32]byte{}
	var work []block_work
	for _, p := range to_fetch {
		blid_by_topo[p.topoheight] = p.blid
		work = append(work, block_work{topoheight: p.topoheight})
	}

	// Scale concurrency to real peer availability instead of a fixed pool -
	// a fixed worker_count=4 left most of a tick's real, currently-eligible
	// peers completely unused (real runs observed 31-32 eligible peers per
	// tick against a batch of 32). Capping at len(work) means we never spin
	// up more workers than there are units - excess workers would just idle
	// under run_fanout_dispatch's work-stealing model. This also spreads
	// load thinner per individual peer (each peer asked for ~1 block/tick
	// instead of ~8), not thicker.
	worker_count := len(lagging)
	if worker_count > len(work) {
		worker_count = len(work)
	}
	dispatch_results, _ := run_fanout_dispatch(work, lagging, worker_count)

	distinct_peers := map[string]bool{}
	for _, r := range dispatch_results {
		distinct_peers[r.assigned_addr] = true
	}

	var consecutive_failures int32
	circuit_tripped := int32(0)

	fetched := map[int64]Complete_Block{}
	var fetched_mu sync.Mutex
	var wg sync.WaitGroup
	for _, r := range dispatch_results {
		wg.Add(1)
		go func(r dispatch_result) {
			defer wg.Done()
			if atomic.LoadInt32(&circuit_tripped) != 0 {
				return
			}
			blid := blid_by_topo[r.topoheight]
			already_tried := map[string]bool{}
			conn := addr_to_conn[r.assigned_addr]
			var cbl Complete_Block
			var ok bool
			for attempt := 0; attempt < fanout_sync_max_attempts && conn != nil; attempt++ {
				already_tried[conn.Addr.String()] = true
				var err error
				cbl, ok, err = fanout_get_object(conn, blid)
				if ok {
					break
				}
				conn.logger.V(2).Info("fanout_sync: fetch attempt failed", "topoheight", r.topoheight, "attempt", attempt+1, "err", err)
				conn = pick_alternate_connection(lagging, r.topoheight, already_tried)
			}
			if !ok {
				if atomic.AddInt32(&consecutive_failures, 1) >= fanout_sync_max_consecutive_failures {
					atomic.StoreInt32(&circuit_tripped, 1)
				}
				return
			}
			atomic.StoreInt32(&consecutive_failures, 0)
			fetched_mu.Lock()
			fetched[r.topoheight] = cbl
			fetched_mu.Unlock()
		}(r)
	}
	wg.Wait()

	if len(fetched) == 0 {
		return false
	}

	var ordered_topos []int64
	for topo := range fetched {
		ordered_topos = append(ordered_topos, topo)
	}
	sort.Slice(ordered_topos, func(i, j int) bool { return ordered_topos[i] < ordered_topos[j] })

	committed := 0
	for _, topo := range ordered_topos {
		cblock := fetched[topo]
		cbl, _ := ConvertCBlock_To_CompleteBlock(cblock)
		accepted := false
		func() {
			// A real, pre-existing SC-execution panic was found live during
			// development (graviton "leaf not found: collision"). Normal
			// sync is shielded by cron.Recover; this direct call is not, so
			// an unrecovered panic here would crash the whole daemon
			// instead of just failing one block.
			defer func() {
				if r := recover(); r != nil {
					logger.V(0).Error(nil, "fanout_sync: recovered panic during Add_Complete_Block", "topoheight", topo, "r", r)
				}
			}()
			var err error
			err, accepted = chain.Add_Complete_Block(&cbl)
			if !accepted {
				logger.V(2).Info("fanout_sync: block rejected", "topoheight", topo, "err", err)
			}
		}()
		if accepted {
			committed++
		} else {
			break // parent-ordering: no point continuing past a rejection or panic
		}
	}

	if committed > 0 {
		metrics.Set.GetOrCreateCounter("blockchain_fanout_sync_total").Inc()
		metrics.Set.GetOrCreateHistogram("blockchain_fanout_sync_blocks_committed").Update(float64(committed))
		logger.V(1).Info("fanout_sync: committed blocks", "committed", committed, "attempted", len(to_fetch), "distinct_peers_used", len(distinct_peers), "eligible_peers", len(lagging), "new_height", chain.Get_Height())
	}

	return committed > 0
}
