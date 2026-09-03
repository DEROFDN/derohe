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

/* this file implements the peer manager, keeping a list of peers which can be tried for connection etc
 *
 */
import "os"
import "fmt"

import "errors"
import "sync"
import "time"
import "sort"
import "path/filepath"
import "encoding/json"

//import "encoding/binary"
//import "container/list"

//import log "github.com/sirupsen/logrus"

import "github.com/deroproject/derohe/globals"

//import "github.com/deroproject/derosuite/crypto"

// This structure is used to do book keeping for the peer list and keeps other DATA related to peer
// all peers are servers, means they have exposed a port for connections
// all peers are identified by their endpoint tcp address
// all clients are identified by ther peer id ( however ip-address is used to control amount )
// the following daemon commands interact with the list
// peer_list := print the peer list
// ban address  time  // ban this address for spcific time
// unban address
// enableban address  // by default all addresses are bannable
// disableban address  // this address will never be banned
type Peer struct {
	Address string `json:"address"` // pairs in the ip:port or dns:port, basically  endpoint
	ID      uint64 `json:"peerid"`  // peer id
	Miner   bool   `json:"miner"`   // miner
	//NeverBlacklist    bool    // this address will never be blacklisted
	LastConnected   uint64 `json:"lastconnected"`   // epoch time when it was connected , 0 if never connected
	FailCount       uint64 `json:"failcount"`       // how many times have we failed  (tcp errors)
	ConnectAfter    uint64 `json:"connectafter"`    // we should connect when the following timestamp passes
	BlacklistBefore uint64 `json:"blacklistbefore"` // peer blacklisted till epoch , priority nodes are never blacklisted, 0 if not blacklist
	GoodCount       uint64 `json:"goodcount"`       // how many times peer has been shared with us
	SuccessCount    uint64 `json:"successcount"`    // successful handshakes, in or out (for scoring); effectively 0 or 1 — peer map evicts on disconnect
	LastLatency     int64  `json:"lastlatency"`     // nanoseconds, from rtt_micro
	LastTopoHeight  int64  `json:"lasttopoheight"`  // peer's topo height at measurement
	LastMeasured    uint64 `json:"lastmeasured"`    // epoch seconds when latency captured
	Version         int    `json:"version"`         // version 1 is original C daemon peer, version 2 is golang p2p version
	Whitelist       bool   `json:"whitelist"`
	sync.Mutex
}

var peer_map = map[string]*Peer{}
var peer_mutex sync.Mutex

// loads peers list from disk
func load_peer_list() {
	defer clean_up()
	peer_mutex.Lock()
	defer peer_mutex.Unlock()

	peer_file := filepath.Join(globals.GetDataDirectory(), "peers.json")
	if _, err := os.Stat(peer_file); errors.Is(err, os.ErrNotExist) {
		return // since file doesn't exist , we cannot load it
	}
	file, err := os.Open(peer_file)
	if err != nil {
		logger.Error(err, "opening peer file")
	} else {
		defer file.Close()
		decoder := json.NewDecoder(file)
		err = decoder.Decode(&peer_map)
		if err != nil {
			logger.Error(err, "Error unmarshalling peer data")
		} else { // successfully unmarshalled data
			logger.V(1).Info("Successfully loaded peers from file", "peer_count", (len(peer_map)))
		}
	}

}

// save peer list to disk
func save_peer_list() {

	clean_up()
	peer_mutex.Lock()
	defer peer_mutex.Unlock()

	peer_file := filepath.Join(globals.GetDataDirectory(), "peers.json")
	file, err := os.Create(peer_file)
	if err != nil {
		logger.Error(err, "saving peer file")
	} else {
		defer file.Close()
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "\t")
		err = encoder.Encode(&peer_map)
		if err != nil {
			logger.Error(err, "Error marshalling peer data")
		} else { // successfully unmarshalled data
			logger.V(1).Info("Successfully saved peers to file", "peer_count", (len(peer_map)))
		}
	}
}

// clean up by discarding entries which are too much into future
func clean_up() {
	peer_mutex.Lock()
	defer peer_mutex.Unlock()
	for k, v := range peer_map {
		if IsAddressConnected(ParseIPNoError(v.Address)) {
			continue
		}
		if v.FailCount >= 8 { // roughly 8 tries before we discard the peer
			delete(peer_map, k)
		}
		if v.LastConnected == 0 { // if never connected, purge the peer
			delete(peer_map, k)
		}

		if uint64(time.Now().UTC().Unix()) > (v.LastConnected + 3600) { // purge all peers which were not connected in
			delete(peer_map, k)
		}
	}
}

// check whether an IP is in the map already
func IsPeerInList(address string) bool {
	peer_mutex.Lock()
	defer peer_mutex.Unlock()

	if _, ok := peer_map[ParseIPNoError(address)]; ok {
		return true
	}
	return false
}
func GetPeerInList(address string) *Peer {
	peer_mutex.Lock()
	defer peer_mutex.Unlock()

	if v, ok := peer_map[ParseIPNoError(address)]; ok {
		return v
	}
	return nil
}

// add connection to  map
func Peer_Add(p *Peer) {
	clean_up()
	peer_mutex.Lock()
	defer peer_mutex.Unlock()

	if p.ID == GetPeerID() { // if peer is self do not connect
		// logger.Infof("Peer is ourselves, discard")
		return

	}

	if v, ok := peer_map[ParseIPNoError(p.Address)]; ok {
		v.Lock()
		// logger.Infof("Peer already in list adding good count")
		v.GoodCount++
		v.Unlock()
	} else {
		// logger.Infof("Peer adding to list")
		peer_map[ParseIPNoError(p.Address)] = p
	}
}

// a peer marked as fail, will only be connected  based on exponential back-off based on powers of 2
func Peer_SetFail(address string) {
	p := GetPeerInList(ParseIPNoError(address))
	if p == nil {
		return
	}
	peer_mutex.Lock()
	defer peer_mutex.Unlock()
	p.FailCount++ //  increase fail count, and mark for delayed connect
	p.ConnectAfter = uint64(time.Now().UTC().Unix()) + 1<<(p.FailCount-1)
}

// set peer as successfully connected
// we will only distribute peers which have been successfully connected by us
func Peer_SetSuccess(address string) {
	//logger.Infof("Setting peer as success")
	p := GetPeerInList(ParseIPNoError(address))
	if p == nil {
		return
	}
	peer_mutex.Lock()
	defer peer_mutex.Unlock()
	p.FailCount = 0 //  fail count is zero again
	p.ConnectAfter = 0
	p.Whitelist = true
	p.LastConnected = uint64(time.Now().UTC().Unix()) // set time when last connected
	p.SuccessCount++

	// logger.Infof("Setting peer as white listed")
}

// captures live latency/topoheight from the ping path, not from handshake
// call after c.update(&response.Common) in ping_loop when Latency > 0
func Peer_UpdateLatency(address string, latencyNs int64, topoHeight int64) {
	peer_mutex.Lock()
	defer peer_mutex.Unlock()
	p, ok := peer_map[ParseIPNoError(address)]
	if !ok || p == nil {
		return
	}
	p.LastLatency = latencyNs
	p.LastTopoHeight = topoHeight
	p.LastMeasured = uint64(time.Now().UTC().Unix())
}

// computes a score for a peer: success/fail history + latency bonus
// SuccessCount is effectively 0 or 1 (peer map evicts on disconnect), so it contributes
// linearly at weight 1, not a large multiplier. The latency bonus drives selection.
// latency bonus decays to zero after 24 hours
func peerScore(p *Peer, now uint64) float64 {
	score := float64(p.SuccessCount) - float64(p.FailCount*50)

	if p.LastMeasured > 0 && p.LastLatency > 0 {
		age := now - p.LastMeasured
		if age < 24*3600 {
			latencyMs := float64(p.LastLatency) / 1e6 // ns → ms
			score += 10000.0 / (latencyMs + 1.0)      // +1 avoids div-by-zero
		}
	}
	return score
}

/*
 //TODO do we need a functionality so some peers are never banned
func Peer_DisableBan(address string) (err error){
    p := GetPeerInList(address)
    if p == nil {
     return fmt.Errorf("Peer \"%s\" not found in list")
    }
    p.Lock()
    defer p.Unlock()
    p.NeverBlacklist = true
}

func Peer_EnableBan(address string) (err error){
    p := GetPeerInList(address)
    if p == nil {
     return fmt.Errorf("Peer \"%s\" not found in list")
    }
    p.Lock()
    defer p.Unlock()
    p.NeverBlacklist = false
}
*/

// add connection to  map
func Peer_Delete(p *Peer) {
	peer_mutex.Lock()
	defer peer_mutex.Unlock()
	delete(peer_map, ParseIPNoError(p.Address))
}

func printLatency(p *Peer) string {
	if p.LastLatency <= 0 {
		return "-"
	}
	ms := float64(p.LastLatency) / 1e6
	return fmt.Sprintf("%.1fms", ms)
}

// prints all the connection info to screen
func PeerList_Print() {
	peer_mutex.Lock()
	defer peer_mutex.Unlock()
	fmt.Printf("Peer List\n")
	fmt.Printf("%-22s %-6s %4s %5s %4s %8s %8s\n", "Remote Addr", "Active", "Good", "Fail", "Succ", "Lat(ms)", "Age")

	var list []*Peer
	greycount := 0
	for _, v := range peer_map {
		if v.Whitelist {
			list = append(list, v)
		} else {
			greycount++
		}
	}

	sort.Slice(list, func(i, j int) bool { return list[i].Address < list[j].Address })

	for i := range list {
		connected := ""
		if IsAddressConnected(ParseIPNoError(list[i].Address)) {
			connected = "ACTIVE"
		}
		ageStr := "-"
		if list[i].LastMeasured > 0 {
			age := time.Now().UTC().Unix() - int64(list[i].LastMeasured)
			switch {
			case age < 0:
				ageStr = "now"
			case age < 60:
				ageStr = fmt.Sprintf("%ds ago", age)
			case age < 3600:
				ageStr = fmt.Sprintf("%dm ago", age/60)
			case age < 86400:
				ageStr = fmt.Sprintf("%dh ago", age/3600)
			default:
				ageStr = fmt.Sprintf("%dd ago", age/86400)
			}
		}
		fmt.Printf("%-22s %-6s %4d %5d %4d %8s %8s\n",
			list[i].Address, connected,
			list[i].GoodCount, list[i].FailCount,
			list[i].SuccessCount,
			printLatency(list[i]),
			ageStr)
	}

	fmt.Printf("\nWhitelist size %d\n", len(peer_map)-greycount)
	fmt.Printf("Greylist size %d\n", greycount)

}

// this function return peer count which are in our list
func Peer_Counts() (Count uint64) {
	peer_mutex.Lock()
	defer peer_mutex.Unlock()
	return uint64(len(peer_map))
}

// this function finds a possible peer to connect to keeping blacklist and already existing connections into picture
// it must not be already connected using outgoing connection
// we do allow loops such as both  incoming/outgoing simultaneously
// this will return atmost 1 address, empty address if peer list is empty
func find_peer_to_connect(version int) *Peer {
	defer clean_up()
	peer_mutex.Lock()
	defer peer_mutex.Unlock()

	now := uint64(time.Now().UTC().Unix())

	// Pass 1: weighted random among eligible whitelist peers (reservoir sampling)
	var best *Peer
	var totalWeight float64
	for _, v := range peer_map {
		if now > v.BlacklistBefore &&
			now > v.ConnectAfter &&
			!IsAddressConnected(ParseIPNoError(v.Address)) &&
			v.Whitelist &&
			!IsAddressInBanList(ParseIPNoError(v.Address)) {

			w := peerScore(v, now)
			if w < 0.1 {
				w = 0.1 // minimum weight 0.1 preserves FailCount ordering for negatives (1 fail > 10 fails)
			}
			totalWeight += w
			if globals.Global_Random.Float64()*totalWeight < w {
				best = v
			}
		}
	}
	if best != nil {
		best.ConnectAfter = now + 10 // minimum 10 secs gap
		return best
	}

	// Pass 2: uniform random among eligible greylist peers (no latency data)
	var greyBest *Peer
	var greyCount float64
	for _, v := range peer_map {
		if now > v.BlacklistBefore &&
			now > v.ConnectAfter &&
			!IsAddressConnected(ParseIPNoError(v.Address)) &&
			!v.Whitelist &&
			!IsAddressInBanList(ParseIPNoError(v.Address)) {

			greyCount++
			if globals.Global_Random.Float64()*greyCount < 1 {
				greyBest = v
			}
		}
	}
	if greyBest != nil {
		greyBest.ConnectAfter = now + 10 // minimum 10 secs gap
		return greyBest
	}

	return nil // if no peer found, return nil
}

// return white listed peer list
// for use in handshake
func get_peer_list() (peers []Peer_Info) {
	peer_mutex.Lock()
	defer peer_mutex.Unlock()

	for _, v := range peer_map { // trim the white list
		if v.Whitelist && !IsAddressConnected(ParseIPNoError(v.Address)) {
			delete(peer_map, ParseIPNoError(v.Address))
		}
	}

	for _, v := range peer_map {
		if v.Whitelist {
			peers = append(peers, Peer_Info{Addr: v.Address})
		}
	}
	return
}

func get_peer_list_specific(addr string) (peers []Peer_Info) {
	plist := get_peer_list()
	sort.SliceStable(plist, func(i, j int) bool { return plist[i].Addr < plist[j].Addr })

	if len(plist) <= 31 {
		peers = plist
	} else {
		index := sort.Search(len(plist), func(i int) bool { return plist[i].Addr < addr })
		for i := range plist {
			peers = append(peers, plist[(i+index)%len(plist)])
			if len(peers) >= 31 {
				break
			}
		}
	}
	return peers
}
