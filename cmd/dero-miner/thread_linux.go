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

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

var processor int32

// coreOrder maps a 0-based thread slot to a logical CPU so that slots
// [0, physicalCores) land one per distinct physical core before any core's
// SMT sibling is used, and slots beyond that fill each core's sibling(s) in
// the same round-robin order -- instead of assuming siblings are adjacent or
// evenly/oddly split by CPU number, which does not hold on every platform.
// This AMD box pairs siblings as core0={0,8}, core1={1,9}, ..., not the
// interleaved core0={0,1}, core1={2,3}, ... layout some code assumes; get the
// pairing wrong and threads silently stack two-deep on a handful of cores
// while others sit idle, then a jump in thread count wakes several idle
// cores to full boost at once instead of one at a time.
var (
	coreOrderOnce sync.Once
	coreOrder     []int
)

func buildCoreOrder() []int {
	count := runtime.GOMAXPROCS(0)
	identity := func() []int {
		order := make([]int, count)
		for i := range order {
			order[i] = i
		}
		return order
	}

	var coreIDs []int
	siblingsOf := map[int][]int{}
	for cpu := 0; cpu < count; cpu++ {
		id, err := readCoreID(cpu)
		if err != nil {
			// topology unreadable (container, restricted /sys, etc): fall
			// back to identity order rather than guessing a pairing that
			// might be wrong.
			return identity()
		}
		if _, seen := siblingsOf[id]; !seen {
			coreIDs = append(coreIDs, id)
		}
		siblingsOf[id] = append(siblingsOf[id], cpu)
	}

	order := make([]int, 0, count)
	for _, id := range coreIDs { // first pass: one thread per physical core
		order = append(order, siblingsOf[id][0])
	}
	for pass := 1; len(order) < count; pass++ { // later passes: siblings, round-robin
		for _, id := range coreIDs {
			if pass < len(siblingsOf[id]) {
				order = append(order, siblingsOf[id][pass])
			}
		}
	}
	return order
}

func readCoreID(cpu int) (int, error) {
	b, err := os.ReadFile(filepath.Join("/sys/devices/system/cpu", "cpu"+strconv.Itoa(cpu), "topology", "core_id"))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

// sets thread affinity to avoid cache collision and thread migration
func threadaffinity() {
	coreOrderOnce.Do(func() { coreOrder = buildCoreOrder() })

	slot := int(atomic.AddInt32(&processor, 1)) - 1 // 0-based
	if slot < 0 || slot >= len(coreOrder) {          // more threads than CPUs, leave unpinned
		return
	}

	var cpuset unix.CPUSet
	cpuset.Zero()
	cpuset.Set(coreOrder[slot])

	unix.SchedSetaffinity(0, &cpuset)
}
