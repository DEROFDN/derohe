package blockchain

import (
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
)

func TestHF4ActiveAtHeightBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		height     uint64
		activation int64
		want       bool
	}{
		{name: "testnet genesis activation", height: 0, activation: 0, want: true},
		{name: "before activation", height: 99, activation: 100, want: false},
		{name: "at activation", height: 100, activation: 100, want: true},
		{name: "after activation", height: 101, activation: 100, want: true},
		{name: "unscheduled", height: 100, activation: config.HeightUnscheduled, want: false},
		{name: "unscheduled at maximum height", height: ^uint64(0), activation: config.HeightUnscheduled, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := hf4ActiveAtHeight(test.height, test.activation); got != test.want {
				t.Fatalf("hf4ActiveAtHeight(%d, %d) = %t, want %t", test.height, test.activation, got, test.want)
			}
		})
	}
}

func TestRegistrationPoWHF4Boundary(t *testing.T) {
	newHash := func(first, second, third byte) crypto.Hash {
		var hash crypto.Hash
		hash[0], hash[1], hash[2] = first, second, third
		return hash
	}

	tests := []struct {
		name       string
		hash       crypto.Hash
		height     uint64
		activation int64
		simulator  bool
		want       bool
	}{
		{name: "legacy zero first byte", hash: newHash(0, 1, 1), height: 99, activation: 100, want: true},
		{name: "legacy zero second byte", hash: newHash(1, 0, 1), height: 99, activation: 100, want: true},
		{name: "legacy rejects both nonzero", hash: newHash(1, 1, 0), height: 99, activation: 100, want: false},
		{name: "HF4 rejects nonzero third byte", hash: newHash(0, 0, 1), height: 100, activation: 100, want: false},
		{name: "HF4 requires first three zero bytes", hash: newHash(0, 0, 0), height: 100, activation: 100, want: true},
		{name: "HF4 remains active after boundary", hash: newHash(0, 1, 1), height: 101, activation: 100, want: false},
		{name: "unscheduled retains legacy behavior", hash: newHash(0, 1, 1), height: 100, activation: config.HeightUnscheduled, want: true},
		{name: "simulator bypass", hash: newHash(1, 1, 1), height: 100, activation: 100, simulator: true, want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := registrationPoWValid(test.hash, test.height, test.activation, test.simulator)
			if got != test.want {
				t.Fatalf("registrationPoWValid(%x, %d, %d, %t) = %t, want %t", test.hash[:3], test.height, test.activation, test.simulator, got, test.want)
			}
		})
	}
}

func TestMainnetHF4ScheduleIsFailClosed(t *testing.T) {
	previous := current_hard_forks
	previousConfig := globals.Config
	globals.Config = config.Mainnet
	t.Cleanup(func() {
		current_hard_forks = previous
		globals.Config = previousConfig
	})

	chain := &Blockchain{}
	approvedTestHeight := config.Mainnet.MAJOR_HF3_HEIGHT + 100
	current_hard_forks = mainnetHardForkScheduleForHeight(approvedTestHeight)
	if got := chain.Get_Current_Version_at_Height(approvedTestHeight - 1); got != 3 {
		t.Fatalf("mainnet version before configured HF4 = %d, want 3", got)
	}
	if got := chain.Get_Current_Version_at_Height(approvedTestHeight); got != 4 {
		t.Fatalf("mainnet version at configured HF4 = %d, want 4", got)
	}

	current_hard_forks = mainnetHardForkSchedule()
	height := globals.Config.MAJOR_HF4_HEIGHT
	if height < 0 {
		if got := chain.Get_Current_Version_at_Height(int64(1<<63 - 1)); got != 3 {
			t.Fatalf("unscheduled mainnet HF4 returned version %d at maximum height; want 3", got)
		}
	} else {
		if got := chain.Get_Current_Version_at_Height(height - 1); got != 3 {
			t.Fatalf("mainnet version before HF4 = %d, want 3", got)
		}
		if got := chain.Get_Current_Version_at_Height(height); got != 4 {
			t.Fatalf("mainnet version at HF4 = %d, want 4", got)
		}
	}

	current_hard_forks = testnet_hard_forks
	if got := chain.Get_Current_Version_at_Height(0); got != 4 {
		t.Fatalf("testnet version at genesis = %d, want 4", got)
	}
}

func TestNetworkSchedulesUseActiveHF4Height(t *testing.T) {
	previousConfig := globals.Config
	t.Cleanup(func() { globals.Config = previousConfig })

	tests := []struct {
		name     string
		network  config.CHAIN_CONFIG
		schedule func() []Hard_fork
	}{
		{name: "mainnet", network: config.Mainnet, schedule: mainnetHardForkSchedule},
		{name: "testnet", network: config.Testnet, schedule: testnetHardForkSchedule},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			globals.Config = test.network
			globals.Config.MAJOR_HF4_HEIGHT = 17

			var found int
			for _, fork := range test.schedule() {
				if fork.Version == 4 {
					found++
					if fork.Height != 17 {
						t.Fatalf("HF4 height = %d, want active config height 17", fork.Height)
					}
				}
			}
			if found != 1 {
				t.Fatalf("schedule contains %d HF4 entries, want exactly 1", found)
			}

			globals.Config.MAJOR_HF4_HEIGHT = config.HeightUnscheduled
			for _, fork := range test.schedule() {
				if fork.Version == 4 {
					t.Fatalf("unscheduled active config still includes HF4 at height %d", fork.Height)
				}
			}
		})
	}
}
