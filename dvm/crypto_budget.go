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

package dvm

import (
	"github.com/blang/semver/v4"
)

// Crypto budget (DVM v9 intrinsics): a deterministic, cost-weighted cap on the
// expensive elliptic-curve and signature intrinsics.
//
// Why a second meter is needed. Compute gas prices opcodes as if they were all
// cheap hashes: a 64-byte sha256 costs 25,000 gas (~0.1 us of real work) while
// the EC intrinsics cost 15,000-250,000 gas for 83-285 us of work. Measured on
// a Ryzen 9 5900X through the real in-VM entry points that is 235,849 gas/us for
// sha256 against 211-5,082 gas/us for the EC ops. Under the flat 10,000,000
// compute cap (see sc.go) a program can therefore buy ~30-47 ms of CPU with the
// EC intrinsics where the previous worst case was ~42 us. No single gas price
// can express both, because pricing ec_mul to match sha256's gas/us would need
// ~15,000,000 gas, more than the entire compute cap. So the expensive class gets
// its own weighted budget, and compute gas keeps pricing everything else.
//
// Weights are ceil(measured_us / CRYPTO_COST_UNIT_US), measured through the real
// in-VM entry points (dvm_hash_to_point ... dvm_verify_adaptor). Rounding up
// means CRYPTO_BUDGET_UNITS bounds worst-case CPU for ANY opcode mix:
//
//	opcode            measured     weight
//	hash_to_point      25.9 us          3
//	verify_sig         49.7 us          5
//	ec_add             83.3 us          9
//	ec_mul            112.5 us         12
//	pedersen_commit   159.3 us         16
//	verify_commit     197.6 us         20
//	verify_adaptor    285.1 us         29
//
// Re-measure before changing a weight: these are consensus parameters.

const (
	// CRYPTO_COST_UNIT_US is the real-cost granularity one budget unit stands for.
	CRYPTO_COST_UNIT_US = 10

	// CRYPTO_BUDGET_UNITS caps total crypto work per SC execution.
	// 100 units ~ 1 ms of worst-case CPU, versus ~42 us for a gas-only
	// sha256 program, and versus ~30-47 ms with no cap at all.
	CRYPTO_BUDGET_UNITS = 100
)

// Per-opcode weights, in CRYPTO_COST_UNIT_US units.
const (
	CryptoCostHashToPoint   = 3
	CryptoCostVerifySig     = 5
	CryptoCostECAdd         = 9
	CryptoCostECMul         = 12
	CryptoCostPedersen      = 16
	CryptoCostVerifyCommit  = 20
	CryptoCostVerifyAdaptor = 29
)

// EnableCryptoBudget arms the crypto budget. It is called once per SC execution.
// The meter lives on Shared_State, which every DVM triggered by the first call
// shares, so nested and cross-contract calls cannot refresh the budget by
// re-entering the VM.
func (state *Shared_State) EnableCryptoBudget() {
	if state != nil {
		state.CryptoBudgetLimit = CRYPTO_BUDGET_UNITS
		state.CryptoBudgetCheck = true
	}
}

// ChainVersionFromHardFork maps a chain hard-fork version to the DVM feature
// version it activates. This is the gate that stops the v9/v10 crypto intrinsics
// from being self-activated by a contract: a contract can declare any version it
// likes via VERSION(), but an intrinsic is only callable if BOTH the declared
// version and the chain version satisfy its Range.
//
// Versions 1-3 (current mainnet) activate nothing at v9: the intrinsics stay
// off until a real hard fork raises the mapping. Assigning the feature to hard
// fork 4 (v9) and 5 (v10) is the proposed activation; adjust the numbers to
// whatever fork actually ships the intrinsics, but never remove the ceiling.
func ChainVersionFromHardFork(hardForkVersion int64) semver.Version {
	switch {
	case hardForkVersion >= 5:
		return semver.MustParse("10.0.0")
	case hardForkVersion == 4:
		return semver.MustParse("9.0.0")
	default: // 0-3: no crypto intrinsics activated
		return semver.MustParse("8.0.0")
	}
}

// ConsumeCryptoBudget charges the expensive-op meter and fails the execution when
// the budget is exhausted. Like the gas meters it panics, which RunSmartContract
// recovers into an execution error, so an over-budget call reverts the SC call
// instead of aborting the node.
func (state *Shared_State) ConsumeCryptoBudget(cost int64) {
	if state == nil || cost <= 0 {
		return
	}
	state.CryptoBudgetUsed += cost
	if state.CryptoBudgetCheck && state.CryptoBudgetUsed > state.CryptoBudgetLimit {
		panic("Insufficient Crypto Budget")
	}
}
