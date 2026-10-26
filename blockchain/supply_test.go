// Copyright 2017-2022 DERO Project. All rights reserved.
// Use of this source code in any form is governed by the RESEARCH license.
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

package blockchain

import (
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/forensicsupply"
	"github.com/deroproject/derohe/globals"
)

func Test_Supply(t *testing.T) {
	supplyAtZero := CalcBlockReward(0)
	totalSupply := uint64(0)
	for i := uint64(0); i < 14; i++ {
		supply := CalcBlockReward(i * RewardReductionInterval)
		totalSupply += supply * RewardReductionInterval
		t.Logf("Supply at height %9d   %s Emission after %d years (%s)", i*RewardReductionInterval, globals.FormatMoney(supply), 4+i*4, globals.FormatMoney(totalSupply))
		if supply != supplyAtZero>>i {
			t.Errorf("supply not halvening as needed ")
			return
		}
	}
}

func TestSpendableSupplyForNetworkGatesAndNetsForensicFloor(t *testing.T) {
	const hf3Height int64 = 100
	tests := []struct {
		name      string
		network   string
		simulator bool
		height    uint64
		hf3Height int64
		wantFloor bool
	}{
		{name: "mainnet before HF3", network: "mainnet", height: uint64(hf3Height - 1), hf3Height: hf3Height},
		{name: "mainnet at HF3", network: "mainnet", height: uint64(hf3Height), hf3Height: hf3Height, wantFloor: true},
		{name: "mainnet after HF3", network: "mainnet", height: uint64(hf3Height + 1), hf3Height: hf3Height, wantFloor: true},
		{name: "testnet", network: "testnet", height: uint64(hf3Height + 1), hf3Height: hf3Height},
		{name: "simulator retaining mainnet config", network: "mainnet", simulator: true, height: uint64(hf3Height + 1), hf3Height: hf3Height},
		{name: "mainnet with missing HF3 height", network: "mainnet", height: uint64(hf3Height + 1)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := CalcSupply(test.height)
			if test.wantFloor {
				want += forensicsupply.NetCreatedFloorAtomicUnits
			}
			got := SpendableSupplyForNetwork(test.height, test.network, test.simulator, test.hf3Height)
			if got != want {
				t.Fatalf("SpendableSupplyForNetwork() = %d, want %d", got, want)
			}
		})
	}
}

func TestLegacySpendableSupplyUsesMainnetHF3Gate(t *testing.T) {
	hf3Height := uint64(config.Mainnet.MAJOR_HF3_HEIGHT)
	if got, want := SpendableSupply(hf3Height-1), CalcSupply(hf3Height-1); got != want {
		t.Fatalf("pre-HF3 SpendableSupply() = %d, want schedule-only %d", got, want)
	}
	if got, want := SpendableSupply(hf3Height), CalcSupply(hf3Height)+forensicsupply.NetCreatedFloorAtomicUnits; got != want {
		t.Fatalf("HF3 SpendableSupply() = %d, want %d", got, want)
	}
}

func TestDocumentedForensicReferenceSupplyValues(t *testing.T) {
	const referenceHeight uint64 = 7_545_119
	const scheduleSupplyAtomic uint64 = 1_675_659_548_850
	const spendableSupplyAtomic uint64 = 3_564_311_278_850

	if got := CalcSupply(referenceHeight); got != scheduleSupplyAtomic {
		t.Fatalf("schedule supply at reference height = %d, want %d", got, scheduleSupplyAtomic)
	}
	if got := SpendableSupplyForNetwork(referenceHeight, "mainnet", false, 7_504_640); got != spendableSupplyAtomic {
		t.Fatalf("post-HF3 spendable supply at reference height = %d, want %d", got, spendableSupplyAtomic)
	}
	if got := CalcSupply(referenceHeight) / forensicsupply.AtomicUnitsPerDERO; got != 16_756_595 {
		t.Fatalf("GetInfo total_supply at reference height = %d DERO, want 16756595", got)
	}
	if got := SpendableSupplyForNetwork(referenceHeight, "mainnet", false, 7_504_640) / forensicsupply.AtomicUnitsPerDERO; got != 35_643_112 {
		t.Fatalf("GetInfo spendable_supply at reference height = %d DERO, want 35643112", got)
	}
}
