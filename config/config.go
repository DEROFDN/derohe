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

package config

import (
	"github.com/deroproject/derohe/cryptography/crypto"
	uuid "github.com/satori/go.uuid"
)

//import "github.com/caarlos0/env/v6"

// all global configuration variables are picked from here

// though testing has complete successfully with 3 secs block time, however
// consider homeusers/developing countries we will be targetting  9 secs
// later hardforks can make it lower by 1 sec, say every 6 months or so, until the system reaches 3 secs
// by that time, networking,space requirements  and  processing requiremtn will probably outgrow homeusers
// since most mining nodes will be running in datacenter, 3 secs  blocks c
// this is in millisecs
const BLOCK_TIME = uint64(18)
const BLOCK_TIME_MILLISECS = BLOCK_TIME * 1000
const MINIBLOCK_HIGHDIFF = 9

// note we are keeping the tree name small for disk savings, since they will be stored n times (atleast or archival nodes)
// this is used by graviton
const BALANCE_TREE = "B" // keeps main balance
const SC_META = "M"      // keeps all SCs balance, their state, their OWNER, their data tree top hash is stored here
// one are open SCs, which provide i/o privacy
// one are private SCs which are truly private, in which no one has visibility of io or functionality

// this limits the contract size or amount of data it can store per interaction
const MAX_STORAGE_GAS_ATOMIC_UNITS = 20000

// Minimum FEE calculation constants are here
const FEE_PER_KB = uint64(20) // .00020 dero per kb

// we can easily improve TPS by changing few parameters in this file
// the resources compute/network may not be easy for the developing countries
// we need to trade of TPS  as per community
const STARGATE_HE_MAX_BLOCK_SIZE = uint64((10 * 1024 * 1024) + (256 * 1024)) // max block size limit

const STARGATE_HE_MAX_TX_SIZE = 300 * 1024 // max size

const MIN_RINGSIZE = 2   //  >= 2 ,   ringsize will be accepted
const MAX_RINGSIZE = 128 // <= 128,  ringsize will be accepted

const PREMINE uint64 = 1228125400000 // this is total supply of old chain ( considering both chain will be running together for some time)

type SettingsStruct struct {
	MAINNET_BOOTSTRAP_DIFFICULTY uint64 `env:"MAINNET_BOOTSTRAP_DIFFICULTY" envDefault:"10000000"` // mainnet bootstrap is 10 MH/s
	MAINNET_MINIMUM_DIFFICULTY   uint64 `env:"MAINNET_MINIMUM_DIFFICULTY" envDefault:"100000"`     // mainnet minimum is 100 KH/s

	TESTNET_BOOTSTRAP_DIFFICULTY uint64 `env:"TESTNET_BOOTSTRAP_DIFFICULTY" envDefault:"10000"`
	TESTNET_MINIMUM_DIFFICULTY   uint64 `env:"TESTNET_MINIMUM_DIFFICULTY" envDefault:"10000"`
}

var Settings SettingsStruct

//var _ = env.Parse(&Settings)

// this single parameter controls lots of various parameters
// within the consensus, it should never go below 7
// if changed responsibly, we can have one second  or lower blocks (ignoring chain bloat/size issues)
// gives immense scalability,
const STABLE_LIMIT = int64(8)

// we can have number of chains running for testing reasons
type CHAIN_CONFIG struct {
	Name       string
	Network_ID uuid.UUID // network ID

	GETWORK_Default_Port    int // used for miner getwork as effeciently as poosible
	P2P_Default_Port        int
	RPC_Default_Port        int
	Wallet_RPC_Default_Port int

	HF1_HEIGHT       int64 // first HF applied here
	HF2_HEIGHT       int64 // second HF applie here
	MAJOR_HF2_HEIGHT int64 // MAJOR HF2 applies here, changes pow
	MAJOR_HF3_HEIGHT int64 // MAJOR HF3 applied here, changes/adds consensus rules
	BLACKHOLE_HEIGHT int64 // SC deposit refund rule applies here. gates a STATE transition only: no tx or block is ever REJECTED by this rule directly. that is not the same as harmless where it is retro-active -- a diverged balance tree changes Load_Merkle_Hash, and a later tx whose Statement.Roothash was built against the canonical tree then fails the roothash check in verify_Transaction_NonCoinbase_internal, which fails the block that carries it. on a chain that already has history that is a permanent sync wedge, not merely a diverged tree. on mainnet this is not a calendar assertion: the value is tied RELATIVELY to MAJOR_HF3_HEIGHT in init(), so it cannot independently go stale -- move the fork height and this moves with it, and it can never activate before the block-version bump that ships it. the residual (HF3 itself shipping after its own height has passed) is the base patch's rollout constraint, inherited not added. see init() below for the testnet position, where MAJOR_HF3_HEIGHT is 0 and the tie WOULD be retro-active. a separate knob so it can be moved without touching the block-version schedule; on mainnet it is TIED to MAJOR_HF3_HEIGHT in init() below

	Dev_Address        string // to which address the integrator rewatd will go, if user doesn't specify integrator address'
	Genesis_Tx         string
	Genesis_Block_Hash crypto.Hash
}

var Mainnet = CHAIN_CONFIG{Name: "mainnet",
	Network_ID:              uuid.FromBytesOrNil([]byte{0x59, 0xd7, 0xf7, 0xe9, 0xdd, 0x48, 0xd5, 0xfd, 0x13, 0x0a, 0xf6, 0xe0, 0x9a, 0x44, 0x41, 0x0}),
	GETWORK_Default_Port:    10100,
	RPC_Default_Port:        10102,
	Wallet_RPC_Default_Port: 10103,
	Dev_Address:             "dero1qykyta6ntpd27nl0yq4xtzaf4ls6p5e9pqu0k2x4x3pqq5xavjsdxqgny8270",
	HF1_HEIGHT:              21480,
	HF2_HEIGHT:              29000,
	MAJOR_HF2_HEIGHT:        481600,
	MAJOR_HF3_HEIGHT:        7504640,
	// BLACKHOLE_HEIGHT is NOT set here on purpose, see init() below

	Genesis_Tx: "" +
		"01" + // version
		"00" + // Source is DERO network
		"00" + // Dest is DERO network
		"00" + // PREMINE_FLAG
		"c0d7e98fdf23" + // PREMINE_VALUE
		"2c45f753585aaf4fef202a658ba9afe1a0d3250838fb28d534420050dd64a0d301", // miners public key

}

var Testnet = CHAIN_CONFIG{Name: "testnet", // testnet will always have last 3 bytes 0
	Network_ID:              uuid.FromBytesOrNil([]byte{0x59, 0xd7, 0xf7, 0xe9, 0xdd, 0x48, 0xd5, 0xfd, 0x13, 0x0a, 0xf6, 0xe0, 0x87, 0x00, 0x00, 0x00}),
	GETWORK_Default_Port:    10100,
	RPC_Default_Port:        40402,
	Wallet_RPC_Default_Port: 40403,

	Dev_Address:      "deto1qy0ehnqjpr0wxqnknyc66du2fsxyktppkr8m8e6jvplp954klfjz2qqdzcd8p",
	HF1_HEIGHT:       0, // on testnet apply at genesis
	HF2_HEIGHT:       0, // on testnet apply at genesis
	MAJOR_HF2_HEIGHT: 4, // on testnet apply at 4
	MAJOR_HF3_HEIGHT: 0, // on testnet apply at genesis
	// BLACKHOLE_HEIGHT is NOT set here on purpose, see init() below

	Genesis_Tx: "" +
		"01" + // version
		"00" + // Source is DERO network
		"00" + // Dest is DERO network
		"00" + // PREMINE_FLAG
		"c0d7e98fdf23" + // PREMINE_VALUE
		"1f9bcc1208dee302769931ad378a4c0c4b2c21b0cfb3e752607e12d2b6fa642500", // miners public key
}

func init() {
	// the refund rule activates on exactly the block which bumps the block version,
	// on every network. a composite literal cannot reference a sibling field, so the
	// tie is made here rather than by duplicating the number and hoping the two
	// literals are edited together; the field exists so that this rule can be moved
	// independently later without touching the block-version schedule.
	//
	// NOTE, and it must be in the release note: the version bump does NOT make an
	// un-upgraded node reject these blocks. blockchain/hardfork_core.go already
	// carries the version-3 entry, and Check_Block_Version only compares the block's
	// version to the one the node itself computes at that height, so a node running
	// the un-patched code computes 3 too, accepts the block, and applies the old burn
	// semantics. there is no state-root commitment in the block header (block.Proof
	// is declared but never written or checked), so the divergence surfaces only
	// later and indirectly, when a tx built against the diverged tree fails the
	// Roothash check in transaction_verify. every node MUST be upgraded before the
	// activation height; this is the same exposure any height-gated state rule
	// carries, HF3's own changes included.
	//
	// TESTNET is deliberately NOT tied to MAJOR_HF3_HEIGHT. MAJOR_HF3_HEIGHT
	// is 0 there, so the refund rule is retro-active to testnet genesis and a patched
	// node replaying testnet history diverges at the first historical ring-2 SC tx
	// which fails in one of the newly-routed ways (uninstalled scid, unknown action,
	// SC_INSTALL without code, SCDATA carrying no action). by the roothash mechanism
	// described on the field above, that is a permanent divergence for a replaying
	// node, not a cosmetic one. this is the SAME class the baseline already carries
	// on testnet -- f7a56db's sc_change_cache de-duplication in blockchain.go is
	// gated on MAJOR_HF3_HEIGHT, which is 0 on testnet, so it too is retro-active
	// to testnet genesis (on mainnet it is properly gated) -- so this is an
	// increment to an existing exposure rather than a new one, and neither
	// trigger's historical incidence has been counted on a live testnet.
	// so testnet gets a height ABOVE any plausible current testnet head instead of 0:
	// a rule that can wedge a resync must never be retro-active on a chain that has
	// history. the number below is a placeholder to be tightened at release against
	// the live testnet head; leaving it un-tightened costs nothing, because the rule
	// is exercised on the simulator, which is unaffected either way --
	// blockchain.Blockchain_Start overrides BLACKHOLE_HEIGHT to 0 for --simulator and
	// a simulator chain starts at genesis with no history to diverge from.
	Mainnet.BLACKHOLE_HEIGHT = Mainnet.MAJOR_HF3_HEIGHT
	Testnet.BLACKHOLE_HEIGHT = 100000000
}

// mainnet has a remote daemon node, which can be used be default, if user provides a  --remote flag
const REMOTE_DAEMON = "node.derofoundation.org:11012" // "89.38.99.117" // "https://rwallet.dero.live"
