// SC Blackhole reproduction test.
//
// Demonstrates, on a live simulator chain, that DERO attached (as BurnValue) to
// a smart-contract call is debited from the sender and lost across TWO distinct
// loss families -- and crucially that the loss is NOT cleanly ring-gated: ring 2
// can lose funds too.
//
//   Family A (ring > 2): a rejecting call to a REAL contract burns the deposit
//     because Extract_signer cannot recover the sender at ring > 2, so the
//     refund is routed to a null account that panics.
//   Family B (ANY ring, incl. 2): a call to an UNINSTALLED SCID early-returns
//     before the refund path, so the deposit is burned even at ring 2. This is
//     the family that matches losses reported on mainnet (all ring 2). The
//     mechanism behind those specific mainnet transactions is NOT reproduced --
//     this test demonstrates the shape, not the cause of any particular loss.
//
// The one ring-2 shape that is safe -- a correctly-targeted rejecting call to a
// real contract -- is included as a control; it refunds. It does NOT prove ring
// 2 is safe in general.
//
// This file is now a TWO-MODE regression harness, not just a reproduction. The
// "prefork" subtest pins the unpatched baseline (criterion A); the "postfork"
// subtest pins the fix (criterion C). Every LOST/refunded label printed below is
// derived from the measured loss, never hardcoded.
//
// Observed result, PRE-FORK (== unpatched Release 142 / f7a56db baseline):
//   FAMILY A  RING 8 (real SC, rejects):    sender loss=100226  (deposit=100000)  <- LOST
//   CONTROL   RING 2 (real SC, rejects):    sender loss=226     (deposit=100000)  <- refunded
//   FAMILY B  RING 2 (uninstalled SCID):    sender loss=100226  (deposit=100000)  <- LOST
//
// Observed result, POST-FORK (patched):
//   FAMILY A  RING 8 (real SC, rejects):    sender loss=100226  (deposit=100000)  <- LOST (residual, by design)
//   CONTROL   RING 2 (real SC, rejects):    sender loss=226     (deposit=100000)  <- refunded
//   FAMILY B  RING 2 (uninstalled SCID):    sender loss=226     (deposit=100000)  <- refunded  <== THE FIX
//
// The consensus layer deliberately does NOT refuse the unrefundable ring>2 shape:
// this verifier also runs at block-add, so a refusal there rejects whole blocks
// produced by un-upgraded miners. The ring>2 loss is prevented one layer up, in
// walletapi.TransferPayload0, and that guard is asserted in BOTH modes by the
// WALLET GUARD block below.
//
// How to run: drop this file into cmd/simulator/ of a Release 142 checkout, then
// from the repo root:
//   GOFLAGS=-mod=vendor go test ./cmd/simulator/ -run Test_Blackhole_SC_Deposit_Loss -v -count=1 -timeout 400s
// The -mod=vendor flag is required: the Release142 tag ships a vendor/ dir with
// no modules.txt, so a modern Go toolchain otherwise tries (and fails) to fetch
// DERO's custom-forked deps from the network. See BlackholeTest/README.md.
//
// This file is a self-contained reproduction artifact; see the investigation
// docs (BLACKHOLE_TECHNICAL_REPORT.md, BLACKHOLE_REPRODUCTION_GUIDE.md) for the
// full root-cause walkthrough. It is read-only with respect to daemon code: it
// changes no behavior, it only observes it -- the only value it sets is
// globals.Config.BLACKHOLE_HEIGHT, and only to select the mode.
//
// "Both families fixed" is NOT the target and must not be made one: ring > 2 has
// no recoverable sender, so Family A's deposit stays burned post-fork and that is
// asserted, not tolerated. See the NOTE at the end of run_blackhole.

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deroproject/derohe/blockchain"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/dvm"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/derohe/walletapi"
)

// The minimal reject-on-call stub. Initialize() succeeds so the install
// commits; Swap() always RETURNs non-zero, which the DVM treats as a knowing
// discard -- the correct way for a swap contract to reject. The contract is
// NOT buggy; the daemon's refund path is.
const blackhole_reject_stub = `Function Initialize() Uint64
10 RETURN 0
End Function

Function Swap() Uint64
10 RETURN 1
End Function`

// The accepting counterpart of the reject stub. Deposit() takes the daemon's
// overridden `value` parameter -- exactly the number dvm/sc.go builds from
// incoming_value -- and RETURNs 0, so the call SUCCEEDS and the deposit is
// committed to the contract's own native balance. Used to observe what a live
// contract sees when a call carries more than one payload for the same SCID.
const blackhole_accept_stub = `Function Initialize() Uint64
10 RETURN 0
End Function

Function Deposit(value Uint64) Uint64
10 STORE("seen", value)
20 RETURN 0
End Function`

// read_sc_dero_balance returns the SC's native (zero-SCID) DERO balance from the
// committed state at the current topo height, mirroring exactly what the
// DERO.GetSC daemon handler does (rpc_dero_getsc.go). Returns (balance, found).
func read_sc_dero_balance(chain *blockchain.Blockchain, scid crypto.Hash) (uint64, bool) {
	topoheight := chain.Load_TOPO_HEIGHT()
	toporecord, err := chain.Store.Topo_store.Read(topoheight)
	if err != nil {
		return 0, false
	}
	ss, err := chain.Store.Balance_store.LoadSnapshot(toporecord.State_Version)
	if err != nil {
		return 0, false
	}
	sc_data_tree, err := ss.GetTree(string(scid[:]))
	if err != nil {
		return 0, false
	}
	var zerohash crypto.Hash
	balance_bytes, err := sc_data_tree.Get(zerohash[:])
	if err != nil || len(balance_bytes) != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(balance_bytes), true
}

// sc_is_installed reports whether the SCID's code is present in committed state.
func sc_is_installed(chain *blockchain.Blockchain, scid crypto.Hash) bool {
	topoheight := chain.Load_TOPO_HEIGHT()
	toporecord, err := chain.Store.Topo_store.Read(topoheight)
	if err != nil {
		return false
	}
	ss, err := chain.Store.Balance_store.LoadSnapshot(toporecord.State_Version)
	if err != nil {
		return false
	}
	sc_data_tree, err := ss.GetTree(string(scid[:]))
	if err != nil {
		return false
	}
	_, err = sc_data_tree.Get(dvm.SC_Code_Key(scid))
	return err == nil
}

// sc_tree_hash returns the graviton merkle hash of the SCID's own data tree in
// committed state, and whether that tree has any content at all. This is the
// instrument criterion (A) actually needs: a wallet balance delta cannot see an
// extra tree materialization or a write into a third party's SC tree, but the
// tree hash can, and every one of those bytes feeds the block's balance root.
func sc_tree_hash(chain *blockchain.Blockchain, scid crypto.Hash) (h [32]byte, ok bool) {
	topoheight := chain.Load_TOPO_HEIGHT()
	toporecord, err := chain.Store.Topo_store.Read(topoheight)
	if err != nil {
		return h, false
	}
	ss, err := chain.Store.Balance_store.LoadSnapshot(toporecord.State_Version)
	if err != nil {
		return h, false
	}
	tree, err := ss.GetTree(string(scid[:]))
	if err != nil {
		return h, false
	}
	h, err = tree.Hash()
	return h, err == nil
}

// state_merkle returns the committed balance-tree root at the current topo
// height -- the same value Check_Block_Version does NOT check and the same value
// a diverging node would differ on. Logged per probe so two runs (or a patched
// vs unpatched build driven with the same seeds) can be diffed by eye.
func state_merkle(chain *blockchain.Blockchain) (h crypto.Hash, ok bool) {
	topoheight := chain.Load_TOPO_HEIGHT()
	toporecord, err := chain.Store.Topo_store.Read(topoheight)
	if err != nil {
		return h, false
	}
	h, err = chain.Load_Merkle_Hash(toporecord.State_Version)
	return h, err == nil
}

// carrier_prefork_loss records PROBE7's pre-fork loss so the post-fork subtest can
// assert the zero-burn action-less shape is unchanged by the fix rather than merely
// cheap. Package-level because prefork and postfork are separate subtests. Zero
// means the pre-fork subtest did not run (e.g. `-run .../postfork`), in which case
// the cross-era check is skipped rather than failing on a phantom baseline.
var carrier_prefork_loss uint64

// zeroburn_prefork_loss is the same baseline for PROBE8, the ring-2 zero-burn case
// that isolates blackhole_refund's `total == 0` bail (see PROBE8).
var zeroburn_prefork_loss uint64

// Both sides of the gate run by default, in one process, from a plain
// `go test ./cmd/simulator/ -run Test_Blackhole_SC_Deposit_Loss`. The pre-fork
// subtest is the criterion-A guard (unpatched behaviour must be reproduced
// exactly); the post-fork subtest is the criterion-C guard (the fix works).
// Neither is reachable only via an env var -- a reviewer who runs nothing but
// the file gets both.
func Test_Blackhole_SC_Deposit_Loss(t *testing.T) {
	t.Run("prefork", func(t *testing.T) { run_blackhole(t, false) })
	// the daemon RPC listener from the first chain needs a moment to release the
	// port before the second chain binds it
	time.Sleep(5 * time.Second)
	t.Run("postfork", func(t *testing.T) { run_blackhole(t, true) })
}

// walletapi.Keep_Connectivity() never returns and selects on a PACKAGE-LEVEL
// timer, so starting a second one in the second subtest gives two goroutines
// racing over one channel and one shared rpc_client -- which is what made the
// post-fork subtest abort in setup roughly one run in three. One goroutine for
// the whole process, and every wait below is a poll with a deadline rather than
// a fixed sleep.
var keep_connectivity_once sync.Once

// verdict derives the LOST/refunded label from the MEASURED loss instead of
// hardcoding it. the labels used to be string literals written for the pre-fix
// baseline, so the post-fork run -- the one that proves the fix works -- printed
// "<- LOST" next to a fees-only loss.
func verdict(loss, deposit uint64) string {
	if loss >= deposit {
		return "LOST"
	}
	return "refunded"
}

// wait_for_daemon blocks until the wallet package considers the daemon online.
func wait_for_daemon(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if walletapi.IsDaemonOnline() {
			return
		}
		walletapi.Connect("") // reconnect the shared client to this subtest's chain
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("daemon did not come online at %s", rpcport_test)
}

func run_blackhole(t *testing.T, postfork bool) {
	time.Sleep(time.Millisecond)

	// pin the shipped wiring itself, which no other test in the tree executes:
	// the SAFETY PROPERTY is asserted here, not the implementation. mainnet must
	// activate at or after the block-version bump that ships the rule (activating
	// before it would apply a state rule under the old consensus version), and must
	// never be 0. it is TIED to MAJOR_HF3_HEIGHT in config.init() today, but moving
	// mainnet to an independent FUTURE height is a legal hardening and must not turn
	// this suite red -- so the assertion is >=, not ==.
	if config.Mainnet.BLACKHOLE_HEIGHT < config.Mainnet.MAJOR_HF3_HEIGHT || config.Mainnet.BLACKHOLE_HEIGHT == 0 {
		t.Fatalf("config.init() wiring broken: Mainnet.BLACKHOLE_HEIGHT=%d must be >0 and >= MAJOR_HF3_HEIGHT=%d",
			config.Mainnet.BLACKHOLE_HEIGHT, config.Mainnet.MAJOR_HF3_HEIGHT)
	}
	// testnet must NOT be retro-active. MAJOR_HF3_HEIGHT is 0 there, and this rule
	// changes state on old blocks, which changes Load_Merkle_Hash, which fails the
	// Roothash check on a later tx, which fails the block carrying it -- a permanent
	// resync wedge on a chain that already has history. re-tying testnet to
	// MAJOR_HF3_HEIGHT, or setting it to 0, must go red here.
	if config.Testnet.BLACKHOLE_HEIGHT <= 0 {
		t.Fatalf("config.init() wiring broken: Testnet.BLACKHOLE_HEIGHT=%d must be a future height, never retro-active",
			config.Testnet.BLACKHOLE_HEIGHT)
	}

	// POST-fork is NOT set by this test: Blockchain_Start's params["--simulator"]
	// branch forces the gate to 0 for every simulator chain, so the post-fork
	// subtest exercises the shipped override rather than a harness assignment
	// (asserted after the chain is up, below). PRE-fork pushes the gate above any
	// height this sim chain can reach, applied AFTER the chain starts for the same
	// reason -- the gate is read per-tx at execution time.
	t.Logf("mode=%s", map[bool]string{true: "POST-FORK", false: "PRE-FORK"}[postfork])
	walletapi.Initialize_LookupTable(1, 1<<17)

	wsrc_db := filepath.Join(os.TempDir(), "dero_blackhole_wsrc.db")
	wgen_db := filepath.Join(os.TempDir(), "dero_blackhole_wgen.db")
	os.Remove(wsrc_db)
	os.Remove(wgen_db)

	// wsrc -- the victim: registered, will send the rejecting deposit call.
	wsrc, err := walletapi.Create_Encrypted_Wallet_From_Recovery_Words(wsrc_db, "QWER",
		"sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly seasons randomly")
	if err != nil {
		t.Fatalf("cannot create src wallet: %s", err)
	}
	// wgen -- owns the genesis premine and mines blocks. NOT registered via a
	// regtx; it is known to the chain through the genesis tx itself. (Same role
	// as wgenesis in Test_Creation_TX, same recovery seed.)
	wgen, err := walletapi.Create_Encrypted_Wallet_From_Recovery_Words(wgen_db, "QWER",
		"perfil lujo faja puma favor pedir detalle doble carbón neón paella cuarto ánimo cuento conga correr dental moneda león donar entero logro realidad acceso doble")
	if err != nil {
		t.Fatalf("cannot create genesis wallet: %s", err)
	}

	// genesis wiring: the premine Value lands directly on wsrc (the victim), so
	// it has a spendable balance with no inter-wallet funding transfer needed.
	// wgen only mines blocks; it is never a transfer endpoint.
	genesis_tx := transaction.Transaction{Transaction_Prefix: transaction.Transaction_Prefix{Version: 1, Value: 2012345}}
	copy(genesis_tx.MinerAddress[:], wsrc.GetAddress().PublicKey.EncodeCompressed())
	config.Testnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	config.Mainnet.Genesis_Tx = fmt.Sprintf("%x", genesis_tx.Serialize())
	genesis_block := blockchain.Generate_Genesis_Block()
	config.Testnet.Genesis_Block_Hash = genesis_block.GetHash()
	config.Mainnet.Genesis_Block_Hash = genesis_block.GetHash()

	// poison the gate with a sentinel so that "it is 0 after chain start" can only
	// mean Blockchain_Start's params["--simulator"] branch actually assigned it.
	// the sentinel keeps the assertion below honest whatever the shipped testnet
	// value is (it was vacuous when testnet shipped 0) -- verified by
	// mutation: deleting the override left it green. the sentinel must go on
	// config.Testnet, not globals.Config, because simulator_chain_start calls
	// globals.Initialize() which re-copies the network struct.
	shipped_testnet_blackhole := config.Testnet.BLACKHOLE_HEIGHT
	config.Testnet.BLACKHOLE_HEIGHT = 999999999

	chain, rpcserver, _ := simulator_chain_start()
	defer simulator_chain_stop(chain, rpcserver)

	// this is the ONLY coverage of the simulator override in the tree; without it a
	// wrong predicate (the O20 defect: globals.IsSimulator() reads a CLI flag no
	// in-process chain sets) leaves every embedded simulator permanently pre-fork
	// while the whole suite still passes green.
	if globals.Config.BLACKHOLE_HEIGHT != 0 {
		t.Fatalf("simulator override did not fire: BLACKHOLE_HEIGHT=%d (sentinel survived Blockchain_Start)",
			globals.Config.BLACKHOLE_HEIGHT)
	}
	config.Testnet.BLACKHOLE_HEIGHT = shipped_testnet_blackhole // un-poison for the next subtest

	if !postfork {
		globals.Config.BLACKHOLE_HEIGHT = 1000000 // above any height this sim chain reaches
	}
	t.Logf("BLACKHOLE_HEIGHT=%d", globals.Config.BLACKHOLE_HEIGHT)

	globals.Arguments["--daemon-address"] = rpcport_test
	keep_connectivity_once.Do(func() { go walletapi.Keep_Connectivity() })
	wait_for_daemon(t)

	wgen.SetDaemonAddress(rpcport)
	wsrc.SetDaemonAddress(rpcport)
	wgen.SetOnlineMode()
	wsrc.SetOnlineMode()
	defer os.Remove(wsrc_db)
	defer os.Remove(wgen_db)

	// Mining recipient. We start by mining with wsrc (the premine holder, always
	// a valid miner) so wgen's registration can land; after that we mine with
	// wgen so that coinbase rewards do NOT pollute wsrc's balance -- keeping the
	// victim's balance delta a clean measure of the deposit mechanics alone.
	miner := wsrc
	mineN := func(n int) {
		for i := 0; i < n; i++ {
			simulator_chain_mineblock(chain, miner.GetAddress(), t)
			time.Sleep(50 * time.Millisecond)
		}
	}

	// Register wgen plus several throwaway accounts so the daemon's
	// DERO.GetRandomAddress has a populated pool to draw ring members from.
	// With too few registered accounts the wallet's ring padding can produce a
	// degenerate (RingSize 0) statement that fails verification.
	if err := chain.Add_TX_To_Pool(wgen.GetRegistrationTX()); err != nil {
		t.Fatalf("cannot add gen regtx: %s", err)
	}
	for i := 0; i < 8; i++ {
		filler, ferr := walletapi.Create_Encrypted_Wallet_Random_Memory("QWER")
		if ferr != nil {
			t.Fatalf("cannot create filler wallet %d: %s", i, ferr)
		}
		if err := chain.Add_TX_To_Pool(filler.GetRegistrationTX()); err != nil {
			t.Fatalf("cannot register filler wallet %d: %s", i, err)
		}
	}
	mineN(6)
	miner = wgen // from here on, wgen mines so wsrc's balance is undisturbed

	// poll instead of sleeping a fixed 2s: the wallets learn they are registered
	// only from a successful daemon round trip, and the second subtest reconnects
	// a shared, package-level rpc client. keep mining while we wait so a
	// registration still sitting in the pool gets a block to land in.
	registered := false
	for i := 0; i < 40 && !registered; i++ {
		_ = wgen.Sync_Wallet_Memory_With_Daemon()
		_ = wsrc.Sync_Wallet_Memory_With_Daemon()
		registered = wsrc.IsRegistered() && wgen.IsRegistered()
		if !registered {
			if i%4 == 3 {
				mineN(1)
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	if !registered {
		t.Fatalf("wallets not registered after polling (wsrc=%v wgen=%v)", wsrc.IsRegistered(), wgen.IsRegistered())
	}
	srcbal, _ := wsrc.Get_Balance()
	t.Logf("wsrc spendable balance (premine): %d", srcbal)

	// ---- install the stubs (no deposit; install always succeeds) ----
	var zeroscid crypto.Hash
	install_sc := func(label string, code string) crypto.Hash {
		install_args := rpc.Arguments{
			{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_INSTALL)},
			{Name: rpc.SCCODE, DataType: rpc.DataString, Value: code},
		}
		wsrc.SetRingSize(2)
		if err = wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
			t.Fatalf("%s: src sync before install: %s", label, err)
		}
		// Provide an explicit ring-member destination (Amount 0) rather than relying
		// on the wallet's empty-transfer padding, which did not materialize a ring.
		rm := wsrc.Random_ring_members(zeroscid)
		if len(rm) < 1 {
			t.Fatalf("%s: no ring members available for install", label)
		}
		install_tx, ierr := wsrc.TransferPayload0(
			[]rpc.Transfer{{Destination: rm[0], Amount: 0}},
			2, false, install_args, 0, false)
		if ierr != nil {
			t.Fatalf("%s: cannot build install tx: %s", label, ierr)
		}
		installed := install_tx.GetHash() // SCID == install tx hash
		// Submit a serialize/deserialize round-trip of the tx, exactly as
		// Test_Creation_TX does -- the daemon expects the wire form (with expanded
		// publickeylist pointers), not the freshly-built in-memory tx.
		var install_dtx transaction.Transaction
		if derr := install_dtx.Deserialize(install_tx.Serialize()); derr != nil {
			t.Fatalf("%s: install tx deserialize: %s", label, derr)
		}
		if perr := chain.Add_TX_To_Pool(&install_dtx); perr != nil {
			t.Fatalf("%s: cannot add install tx: %s", label, perr)
		}
		mineN(4) // install + confirmation margin before the deposit call is built
		time.Sleep(500 * time.Millisecond)
		if !sc_is_installed(chain, installed) {
			t.Fatalf("%s: SC %s did not install", label, installed)
		}
		return installed
	}

	scid := install_sc("reject stub", blackhole_reject_stub)
	accept_scid := install_sc("accept stub", blackhole_accept_stub)
	base_bal, _ := read_sc_dero_balance(chain, scid)
	t.Logf("SC installed scid=%s baseline native balance=%d", scid, base_bal)

	// helper: send a Swap() call with `deposit` DERO attached at the given ring
	// size to `target_scid`, mine, and return the installed-SC's native-balance
	// delta and the sender's total balance loss. When target_scid == the real
	// stub, the contract runs and rejects (RETURN non-zero); when it is an SCID
	// that was never installed, the daemon early-returns before the contract
	// runs (the Family B path), but either way we read the real stub's balance
	// to confirm it is never credited.
	// refused reports that the daemon would not admit the tx at all. post-fork an SC
	// call carrying a burn above ringsize 2 is refused at verification, so the deposit
	// is never debited -- the loss is prevented rather than refunded. pre-fork the same
	// call is admitted and the deposit is destroyed.
	fire_call := func(ring uint64, deposit uint64, target_scid crypto.Hash) (sc_delta uint64, sender_loss uint64, refused bool) {
		if err = wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
			t.Fatalf("src sync before call: %s", err)
		}
		sc_before, _ := read_sc_dero_balance(chain, scid)
		sender_before, _ := wsrc.Get_Balance()

		var mainscid crypto.Hash
		random := wsrc.Random_ring_members(mainscid)
		if len(random) < 3 {
			t.Fatalf("could not obtain ring members for deposit")
		}
		call_args := rpc.Arguments{
			{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
			{Name: rpc.SCID, DataType: rpc.DataHash, Value: target_scid},
			{Name: "entrypoint", DataType: rpc.DataString, Value: "Swap"},
		}
		transfers := []rpc.Transfer{{Destination: random[0], Amount: 0, Burn: deposit}}

		wsrc.SetRingSize(int(ring))
		call_tx, err := wsrc.TransferPayload0(transfers, ring, false, call_args, 0, false)
		if err != nil {
			// the wallet-side SC-deposit guard is the ONLY legitimate build refusal.
			// it must not fire here: fire_call always passes an EXPLICIT ring size, and
			// an explicit ring size is an accepted opt-in. if it ever does fire, the
			// guard has stopped honouring the explicit choice.
			if strings.Contains(err.Error(), "cannot be refunded if the call fails") {
				t.Logf("ring=%d REFUSED by the wallet guard at build time: %s", ring, err)
				return 0, 0, true
			}
			t.Fatalf("ring=%d cannot build call: %s", ring, err)
		}
		// submit the wire round-trip (see install note above)
		var call_dtx transaction.Transaction
		if derr := call_dtx.Deserialize(call_tx.Serialize()); derr != nil {
			t.Fatalf("ring=%d call tx deserialize: %s", ring, derr)
		}
		t.Logf("ring=%d deposit=%d target=%s  wire ringsize=%d txid=%s", ring, deposit,
			target_scid, call_dtx.Payloads[0].Statement.RingSize, call_dtx.GetHash())

		// there is NO consensus-side refusal of an unrefundable deposit -- refusing at
		// verification would reject whole blocks. Any pool error here is a harness
		// fault and must never be read as the fix working.
		if err := chain.Add_TX_To_Pool(&call_dtx); err != nil {
			t.Fatalf("ring=%d cannot add call to pool: %s", ring, err)
		}
		mineN(4) // settle the call + confirmation margin before the next build
		time.Sleep(500 * time.Millisecond)

		if err = wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
			t.Fatalf("src sync after call: %s", err)
		}
		sc_after, _ := read_sc_dero_balance(chain, scid)
		sender_after, _ := wsrc.Get_Balance()
		return sc_after - sc_before, sender_before - sender_after, false
	}

	const deposit = uint64(100000) // 0.001 DERO, atomic

	// An SCID that was never installed -- the Family B trigger. Any 32-byte hash
	// with no meta entry in the executing state works; we use a fixed nonzero
	// pattern distinct from the real stub's scid.
	var uninstalled_scid crypto.Hash
	for i := range uninstalled_scid {
		uninstalled_scid[i] = 0xAB
	}

	// criterion (A)/(D) instrument: the reject stub's own data tree and the
	// never-installed SCID's tree must come out of every probe below untouched.
	// A wallet balance delta cannot see a stray tree materialization or a write
	// into a third party's contract; these hashes can, and they are exactly the
	// bytes the balance root is built from.
	stub_tree_before, stub_tree_present := sc_tree_hash(chain, scid)
	unin_tree_before, unin_tree_present := sc_tree_hash(chain, uninstalled_scid)
	if m, ok := state_merkle(chain); ok {
		t.Logf("state merkle before probes: %x (stub tree present=%v hash=%x | uninstalled tree present=%v hash=%x)",
			m, stub_tree_present, stub_tree_before, unin_tree_present, unin_tree_before)
	}

	// ---- PROBE 1 (O1 trigger A): ring 8 + uninstalled SCID ----
	// under the WITHDRAWN ErrorDeposit design this reached ErrorDeposit with an scid
	// that has no SC_Meta_Key, poisoned sc_change_cache, and panicked the block
	// commit loop -> chain halt. That design is dead; this probe is what keeps it
	// dead. mineN t.Fatal's if a block cannot be added.
	p1delta, p1loss, p1refused := fire_call(8, deposit, uninstalled_scid)
	t.Logf("PROBE1 RING 8 + UNINSTALLED SCID: SC delta=%d sender loss=%d refused=%v (chain survived)", p1delta, p1loss, p1refused)

	// ---- PROBE 2 (O1 trigger B): anonymous SC_INSTALL that fails to parse ----
	{
		bad_args := rpc.Arguments{
			{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_INSTALL)},
			{Name: rpc.SCCODE, DataType: rpc.DataString, Value: "this is not a valid dvm contract"},
		}
		_ = wsrc.Sync_Wallet_Memory_With_Daemon()
		rmb := wsrc.Random_ring_members(zeroscid)
		if len(rmb) < 1 {
			t.Fatalf("no ring members for probe2")
		}
		wsrc.SetRingSize(8)
		bad_tx, berr := wsrc.TransferPayload0([]rpc.Transfer{{Destination: rmb[0], Amount: 0}}, 8, false, bad_args, 0, false)
		if berr != nil {
			t.Fatalf("probe2 build: %s", berr)
		}
		var bad_dtx transaction.Transaction
		if derr := bad_dtx.Deserialize(bad_tx.Serialize()); derr != nil {
			t.Fatalf("probe2 deserialize: %s", derr)
		}
		if err := chain.Add_TX_To_Pool(&bad_dtx); err != nil {
			t.Fatalf("probe2 pool: %s", err)
		}
		mineN(4)
		time.Sleep(500 * time.Millisecond)
		t.Logf("PROBE2 failed anonymous SC_INSTALL survived mining (chain height %d)", chain.Get_Height())
	}

	// generic submit helper: build the tx from arbitrary transfers + SCDATA at the
	// given ring size, mine it, return the sender's total balance loss.
	fire_raw := func(label string, ring uint64, args rpc.Arguments, transfers []rpc.Transfer) uint64 {
		if err = wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
			t.Fatalf("%s sync before: %s", label, err)
		}
		before, _ := wsrc.Get_Balance()
		wsrc.SetRingSize(int(ring))
		tx, berr := wsrc.TransferPayload0(transfers, ring, false, args, 0, false)
		if berr != nil {
			t.Fatalf("%s build: %s", label, berr)
		}
		var dtx transaction.Transaction
		if derr := dtx.Deserialize(tx.Serialize()); derr != nil {
			t.Fatalf("%s deserialize: %s", label, derr)
		}
		t.Logf("%s txid=%s payloads=%d", label, dtx.GetHash(), len(dtx.Payloads))
		if perr := chain.Add_TX_To_Pool(&dtx); perr != nil {
			t.Fatalf("%s pool: %s", label, perr)
		}
		mineN(4)
		time.Sleep(500 * time.Millisecond)
		if err = wsrc.Sync_Wallet_Memory_With_Daemon(); err != nil {
			t.Fatalf("%s sync after: %s", label, err)
		}
		after, _ := wsrc.Get_Balance()
		return before - after
	}

	// ---- PROBE 3 (O10): ring-2 SC_INSTALL with SCACTION but NO SCCODE ----
	// pre-fork this leaves err nil with a nil w_sc_data_tree, so
	// SanityCheckExternalTransfers nil-derefs; the recover swallows it and the
	// function returns SUCCESS while the burn is destroyed. This is a FOURTH loss
	// family in the same switch, and the only exit which reports err == nil.
	rm3 := wsrc.Random_ring_members(zeroscid)
	if len(rm3) < 2 {
		t.Fatalf("no ring members for probe3")
	}
	p3loss := fire_raw("PROBE3 ring2 SC_INSTALL no-SCCODE",
		2,
		rpc.Arguments{{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_INSTALL)}},
		[]rpc.Transfer{{Destination: rm3[0], Amount: 0, Burn: deposit}})
	t.Logf("PROBE3 (no SCCODE, ring 2): sender loss=%d (deposit=%d)", p3loss, deposit)

	// ---- PROBE 4 (O11): two zero-SCID payloads, burn on the FIRST ----
	// incoming_value was built by assignment, so the last payload for a SCID won
	// and the earlier burn was invisible to both the contract and the refund --
	// a routine multi-destination SC call, not an exotic hand-built tx.
	rm4 := wsrc.Random_ring_members(zeroscid)
	if len(rm4) < 2 {
		t.Fatalf("no ring members for probe4")
	}
	p4loss := fire_raw("PROBE4 ring2 two-payload burn-not-last",
		2,
		rpc.Arguments{
			{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
			{Name: rpc.SCID, DataType: rpc.DataHash, Value: uninstalled_scid},
			{Name: "entrypoint", DataType: rpc.DataString, Value: "Swap"},
		},
		[]rpc.Transfer{
			{Destination: rm4[0], Amount: 0, Burn: deposit},
			{Destination: rm4[1], Amount: 0},
		})
	t.Logf("PROBE4 (burn on non-last payload, ring 2): sender loss=%d (deposit=%d)", p4loss, deposit)
	// PROBE4 targets an UNINSTALLED scid, so pre-fork it early-returns before the
	// refund block: its pre-fork assertion pins the Family B loss, NOT the
	// `=` vs `+=` behaviour. PROBE5 below is the probe that pins that.

	// ---- PROBE 5 (O14): same two-payload shape against a contract that RUNS ----
	// This is the success path, which `+=` also changes: dvm/sc.go credits
	// incoming_value to the contract's stored asset balance and passes it as the
	// entrypoint's `value` parameter. Pre-fork the contract sees the LAST
	// payload's burn (zero here) and the real burn is destroyed even though the
	// call succeeded -- a fifth loss shape. Post-fork it sees the true total.
	accept_before, _ := read_sc_dero_balance(chain, accept_scid)
	rm5 := wsrc.Random_ring_members(zeroscid)
	if len(rm5) < 2 {
		t.Fatalf("no ring members for probe5")
	}
	p5loss := fire_raw("PROBE5 ring2 two-payload burn-not-last, ACCEPTING sc",
		2,
		rpc.Arguments{
			{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
			{Name: rpc.SCID, DataType: rpc.DataHash, Value: accept_scid},
			{Name: "entrypoint", DataType: rpc.DataString, Value: "Deposit"},
		},
		[]rpc.Transfer{
			{Destination: rm5[0], Amount: 0, Burn: deposit},
			{Destination: rm5[1], Amount: 0},
		})
	accept_after, _ := read_sc_dero_balance(chain, accept_scid)
	p5delta := accept_after - accept_before
	t.Logf("PROBE5 (accepting SC, burn on non-last payload, ring 2): SC credited=%d sender loss=%d (deposit=%d)",
		p5delta, p5loss, deposit)

	// ---- PROBE 6 (O17): SC_TX whose SCDATA carries NO SC_ACTION ----
	// walletapi/rpcserver/rpc_transfer.go injects SC_ACTION only when SC_Code or
	// SC_ID is set, while walletapi/transaction_build.go makes the tx an SC_TX from
	// any non-empty sc_rpc. A `transfer` that passes entrypoint+params with the scid
	// omitted (or SC_ACTION sent with the wrong datatype) therefore reaches
	// process_transaction_sc with no action, and pre-fork exits ABOVE the switch
	// with err == nil while the burn is destroyed. Same class as Family B.
	rm6 := wsrc.Random_ring_members(zeroscid)
	if len(rm6) < 2 {
		t.Fatalf("no ring members for probe6")
	}
	p6loss := fire_raw("PROBE6 ring2 SC_TX with no SCACTION",
		2,
		rpc.Arguments{{Name: "entrypoint", DataType: rpc.DataString, Value: "Swap"}},
		[]rpc.Transfer{{Destination: rm6[0], Amount: 0, Burn: deposit}})
	t.Logf("PROBE6 (no SCACTION, ring 2): sender loss=%d (deposit=%d)", p6loss, deposit)

	// ---- PROBE 7: the CARRIER shape -- zero burn, no SC_ACTION -- must stay INERT ----
	// PROBE6 above fires this exit WITH a deposit. The Transmission messenger rides
	// the very same exit deliberately and with NO deposit: an action-less SCDATA
	// body at ring >2 (wiring/builder.go INV-1, enforced structurally -- the carrier
	// params struct has no burn-injectable field -- plus a drift-assert). That is a
	// live mainnet workload sitting on a line this patch now gates, so post-fork it
	// runs new code on every message.
	//
	// At the carrier's own ring size it is inert for TWO independent reasons --
	// blackhole_refund bails on `total == 0`, and Extract_signer would fail at any
	// ring >2 regardless -- so this probe pins the shipped messenger shape but does
	// NOT isolate either guard. PROBE8 below strips the second one away.
	// Asserted in both eras and compared ACROSS them: "cheap" is not the claim,
	// "unchanged" is.
	rm7 := wsrc.Random_ring_members(zeroscid)
	if len(rm7) < 2 {
		t.Fatalf("no ring members for probe7")
	}
	p7loss := fire_raw("PROBE7 ring8 zero-burn action-less SCDATA (carrier shape)",
		8,
		rpc.Arguments{
			{Name: "B", DataType: rpc.DataString, Value: "deadbeef"},
			{Name: "v", DataType: rpc.DataUint64, Value: uint64(1)},
		},
		[]rpc.Transfer{{Destination: rm7[0], Amount: 1, Burn: 0}})
	t.Logf("PROBE7 (carrier: zero burn, no SCACTION, ring 8): sender loss=%d (fees + the 1 sent; deposit=%d)", p7loss, deposit)

	// ---- PROBE 8: zero burn at ring 2 -- the action-less exit with a REAL signer ----
	// Same shape as PROBE7 but at ring 2, where Extract_signer succeeds, so this is
	// the deepest a zero-burn tx can get into blackhole_refund: only `total == 0`
	// sits between it and ErrorRevertHF3.
	//
	// MEASURED, do not re-assert otherwise: deleting that bail does NOT move this
	// probe. ErrorRevertHF3 with an all-zero incoming_value credits nothing, so a
	// balance-delta instrument cannot see the difference (this is residual O16 --
	// criterion (A) is measured on wallet balances, not state roots). The bail is a
	// defensive early-return, not a load-bearing correctness guard, and no probe in
	// this file can prove otherwise without a state-root instrument.
	//
	// What these two probes DO pin, which nothing else here did: an action-less
	// zero-burn tx destroys no value and costs exactly the same on both sides of
	// the gate. That is the property the Transmission carrier depends on.
	rm8 := wsrc.Random_ring_members(zeroscid)
	if len(rm8) < 2 {
		t.Fatalf("no ring members for probe8")
	}
	p8loss := fire_raw("PROBE8 ring2 zero-burn action-less SCDATA",
		2,
		rpc.Arguments{
			{Name: "B", DataType: rpc.DataString, Value: "deadbeef"},
			{Name: "v", DataType: rpc.DataUint64, Value: uint64(1)},
		},
		[]rpc.Transfer{{Destination: rm8[0], Amount: 1, Burn: 0}})
	t.Logf("PROBE8 (zero burn, no SCACTION, ring 2): sender loss=%d (fees + the 1 sent; deposit=%d)", p8loss, deposit)

	// ---- Family A, ring 8: null-signer blackhole (rejecting call, real SC) ----
	delta8, loss8, refused8 := fire_call(8, deposit, scid)
	if refused8 {
		t.Logf("FAMILY A  RING 8 (real SC, rejects): REFUSED at verification, deposit never debited (loss=%d)", loss8)
	} else {
		t.Logf("FAMILY A  RING 8 (real SC, rejects): SC delta=%d  sender loss=%d  (deposit=%d)  <- %s", delta8, loss8, deposit, verdict(loss8, deposit))
	}

	// ---- Ring-2 control for Family A: rejecting call to the REAL SC refunds ----
	// At ring 2 with a correctly-targeted contract, Extract_signer succeeds and
	// the refund branch credits the sender, so only fees are lost. This is the
	// ONE ring-2 shape that is safe -- it is a control for Family A, NOT proof
	// that ring 2 is safe in general (see Family B below).
	delta2, loss2, refused2 := fire_call(2, deposit, scid)
	if refused2 {
		t.Fatalf("ring-2 control was refused at verification; the rule must only refuse deposits above ringsize 2")
	}
	t.Logf("CONTROL   RING 2 (real SC, rejects): SC delta=%d  sender loss=%d  (deposit=%d)  <- %s", delta2, loss2, deposit, verdict(loss2, deposit))

	// ---- Family B, ring 2: deposit to an UNINSTALLED SCID is burned ----
	// This is the loss the DERO team observed on mainnet: a ring-2 SC_CALL with
	// DERO attached to a SCID that has no meta entry in the executing state
	// (wrong / typo'd / stale / unconfirmed SCID). The daemon early-returns at
	// transaction_execute.go:366-369 -- AFTER the deposit is debited and BEFORE
	// the refund path -- so the deposit is destroyed even at ring 2.
	deltaB, lossB, refusedB := fire_call(2, deposit, uninstalled_scid)
	if refusedB {
		t.Fatalf("Family B ring-2 was refused at verification; the rule must only refuse deposits above ringsize 2")
	}
	t.Logf("FAMILY B  RING 2 (uninstalled SCID): SC delta=%d  sender loss=%d  (deposit=%d)  <- %s", deltaB, lossB, deposit, verdict(lossB, deposit))

	// ---- WALLET GUARD (where the ring>2 loss is actually prevented) ----
	// The consensus layer cannot refuse an unrefundable deposit without rejecting
	// whole blocks, so the refusal lives in walletapi.TransferPayload0 instead. Four
	// cases, run in BOTH modes because the guard is height-independent:
	//   1. DEFAULTED ring size (>2, the stock wallet's shape) + burn + scdata -> REFUSED
	//   2. same shape with the ring size passed EXPLICITLY          -> BUILT (opt-in)
	//   3. defaulted ring size, SC call with NO burn                -> BUILT (anonymous
	//      zero-value calls, e.g. voting, must keep working)
	//   4. defaulted ring size, burn but NO scdata                  -> BUILT (not an SC
	//      deposit; nothing reaches process_transaction_sc)
	// dry_run is NOT used: TransferPayload0 returns "could not be built" for every
	// dry run, which would make the must-still-build cases pass for a false reason.
	// The txs built here are never added to the pool, so they cost nothing.
	{
		guard_args := rpc.Arguments{
			{Name: rpc.SCACTION, DataType: rpc.DataUint64, Value: uint64(rpc.SC_CALL)},
			{Name: rpc.SCID, DataType: rpc.DataHash, Value: scid},
			{Name: "entrypoint", DataType: rpc.DataString, Value: "Swap"},
		}
		var zeroscid crypto.Hash
		grm := wsrc.Random_ring_members(zeroscid)
		if len(grm) < 3 {
			t.Fatalf("wallet guard: could not obtain ring members")
		}
		burning := []rpc.Transfer{{Destination: grm[0], Amount: 0, Burn: deposit}}
		plain := []rpc.Transfer{{Destination: grm[0], Amount: 0}}

		// ring 8, not the stock default 16: the guard fires on any defaulted ring != 2
		// and this simulator chain does not have enough registered accounts to BUILD a
		// ring-16 tx, which would make the must-still-build cases below fail for an
		// unrelated reason.
		wsrc.SetRingSize(8)
		if _, err := wsrc.TransferPayload0(burning, 0, false, guard_args, 0, false); err == nil {
			t.Errorf("WALLET GUARD case 1: a defaulted-ringsize SC deposit was BUILT; the unrefundable shape must be refused at build time")
		} else if !strings.Contains(err.Error(), "cannot be refunded if the call fails") {
			t.Errorf("WALLET GUARD case 1: refused for the wrong reason: %s", err)
		} else {
			t.Logf("WALLET GUARD case 1 (defaulted ring 8 + deposit): REFUSED -- %s", err)
		}

		// cases 2-4 assert the ACTUAL ring size on the built tx, not merely that a tx
		// came back. The obvious "don't refuse me, just build it at ring 2" follow-up
		// is a one-line change at the guard and would silently deanonymise every paid
		// SC call in the network while leaving err==nil; only reading
		// Statement.RingSize can tell a refusal from a silent downgrade.
		// Statement.RingSize is populated on DESERIALIZE, not at build, so read the
		// wire form -- that is also exactly what the chain and Extract_signer see.
		ring_of := func(tx *transaction.Transaction) uint64 {
			if tx == nil {
				return 0
			}
			var dtx transaction.Transaction
			if derr := dtx.Deserialize(tx.Serialize()); derr != nil {
				t.Fatalf("wallet guard: built tx does not deserialize: %s", derr)
			}
			if len(dtx.Payloads) == 0 {
				return 0
			}
			return dtx.Payloads[0].Statement.RingSize
		}
		if gtx, err := wsrc.TransferPayload0(burning, 8, false, guard_args, 0, false); err != nil {
			t.Errorf("WALLET GUARD case 2: an EXPLICIT ring-8 deposit must still build (anonymous paid calls stay possible), got: %s", err)
		} else if r := ring_of(gtx); r != 8 {
			t.Errorf("WALLET GUARD case 2: explicit ring 8 was SILENTLY REWRITTEN to ring %d; the guard must refuse, never downgrade", r)
		}
		if gtx, err := wsrc.TransferPayload0(plain, 0, false, guard_args, 0, false); err != nil {
			t.Errorf("WALLET GUARD case 3: a zero-burn anonymous SC call must still build, got: %s", err)
		} else if r := ring_of(gtx); r != 8 {
			t.Errorf("WALLET GUARD case 3: a zero-burn anonymous SC call was built at ring %d, expected the wallet default 8; anonymity must not be silently reduced", r)
		}
		if gtx, err := wsrc.TransferPayload0(burning, 0, false, nil, 0, false); err != nil {
			t.Errorf("WALLET GUARD case 4: a burn with no SCDATA is not an SC deposit and must still build, got: %s", err)
		} else if r := ring_of(gtx); r != 8 {
			t.Errorf("WALLET GUARD case 4: a non-SC burn was built at ring %d, expected the wallet default 8; the guard must not touch it", r)
		}
		wsrc.SetRingSize(2)
	}

	// ---- assertions ----

	// 1. The real stub is never credited in any case (its staged state is
	//    discarded on the non-zero RETURN; the uninstalled call never runs it).
	if delta8 != 0 {
		t.Errorf("Family A ring-8: expected real-SC balance unchanged, got delta=%d", delta8)
	}
	if delta2 != 0 {
		t.Errorf("ring-2 control: expected real-SC balance unchanged, got delta=%d", delta2)
	}
	if deltaB != 0 {
		t.Errorf("Family B ring-2: expected real-SC balance unchanged, got delta=%d", deltaB)
	}

	// 2. Family A: PRE-FORK the ring-8 sender loses the whole deposit while the ring-2
	//    control against the same real SC refunds it, and the difference isolates the
	//    null-signer (ring>2) loss. POST-FORK the ring-8 call is refused at
	//    verification instead, so there is no loss to measure -- the deposit is never
	//    debited. Only the refused/not-refused branch differs; the ring-2 control is
	//    identical in both modes.
	if !refused8 {
		if loss8 < deposit {
			t.Errorf("Family A ring-8: sender loss %d < deposit %d; the deposit should be fully lost", loss8, deposit)
		}
		if loss8 <= loss2 {
			t.Errorf("expected ring-8 loss (%d) to exceed ring-2-control loss (%d) by ~the deposit (%d)", loss8, loss2, deposit)
		}
	}
	if loss2 >= deposit {
		t.Errorf("ring-2 control: sender loss %d >= deposit %d; the deposit should have been refunded (fees only)", loss2, deposit)
	}

	// 3. Family B: a ring-2 deposit to an uninstalled SCID is destroyed -- the
	//    sender loss includes the full deposit, NOT just fees. This is the
	//    mainnet-observed ring-2 loss, and it proves ring 2 is NOT safe in
	//    general; only the correctly-targeted case (the control above) refunds.
	//    Post-fork it must be REFUNDED instead -- that is the whole point of the fix.
	if globals.Config.BLACKHOLE_HEIGHT == 0 { // post-fork
		if lossB >= deposit {
			t.Errorf("POST-FORK Family B ring-2: sender loss %d >= deposit %d; the deposit should have been refunded", lossB, deposit)
		}
		// ACCEPTED RESIDUAL, asserted so it can never silently change: a ring>2 sender
		// is not recoverable, so a failed call still destroys the deposit even
		// post-fork. The chain cannot refund what it cannot address. This is pinned as
		// a POSITIVE measurement (the deposit IS still lost) rather than as a refusal,
		// because the consensus layer deliberately does not refuse it -- see the
		// wallet-guard assertions below, which are where the loss is actually
		// prevented for anyone on a patched build.
		if p1refused || refused8 {
			t.Errorf("POST-FORK: a ring-8 deposit was refused at consensus (p1=%v familyA=%v); there must be NO verify-side refusal, it would reject whole blocks", p1refused, refused8)
		}
		if p1loss < deposit {
			t.Errorf("POST-FORK ring-8 uninstalled: loss %d < deposit %d; the ring>2 residual is expected to remain a full loss, a change here needs a design review", p1loss, deposit)
		}
		if loss8 < deposit {
			t.Errorf("POST-FORK Family A ring-8: loss %d < deposit %d; the ring>2 residual is expected to remain a full loss, a change here needs a design review", loss8, deposit)
		}
		// O10: the no-SCCODE install must no longer nil-deref and burn.
		if p3loss >= deposit {
			t.Errorf("POST-FORK PROBE3 no-SCCODE install: loss %d >= deposit %d; the deposit should have been refunded", p3loss, deposit)
		}
		// O11: the burn on a non-last payload must be refunded too.
		if p4loss >= deposit {
			t.Errorf("POST-FORK PROBE4 burn-not-last: loss %d >= deposit %d; the earlier payload's burn was dropped", p4loss, deposit)
		}
		// O14: on the SUCCESS path the running contract must be credited the true
		// total of the call's burns, and the sender must lose only fees.
		if p5delta != deposit {
			t.Errorf("POST-FORK PROBE5 accepting SC: credited %d, expected the full deposit %d", p5delta, deposit)
		}
		// the sender's loss legitimately still includes the deposit here -- the
		// call SUCCEEDED, so the money was delivered rather than refunded. The
		// discriminator is p5delta above: pre-fork the same loss buys the
		// contract nothing.
		if p5loss < deposit {
			t.Errorf("POST-FORK PROBE5 accepting SC: sender loss %d < deposit %d; the deposit was delivered, so it must be spent", p5loss, deposit)
		}
		// O17: the no-SCACTION exit above the switch must refund too.
		if p6loss >= deposit {
			t.Errorf("POST-FORK PROBE6 no-SCACTION: loss %d >= deposit %d; the deposit should have been refunded", p6loss, deposit)
		}
		// The carrier shape must be INERT, not merely cheap. A zero-burn tx can
		// lose nothing, so any deposit-scale loss means the gate did something it
		// must not, and any change from the pre-fork figure means the fix reached a
		// path a live messenger workload depends on.
		if p7loss >= deposit {
			t.Errorf("POST-FORK PROBE7 carrier: loss %d >= deposit %d; a zero-burn action-less SCDATA tx must only pay fees", p7loss, deposit)
		}
		if carrier_prefork_loss != 0 && p7loss != carrier_prefork_loss {
			t.Errorf("POST-FORK PROBE7 carrier: loss %d != pre-fork loss %d; the gate must be invisible to a zero-burn action-less tx", p7loss, carrier_prefork_loss)
		}
		// PROBE8: same claim at ring 2, where the signer IS recoverable and the tx
		// therefore reaches the deepest point a zero-burn tx can reach.
		if p8loss >= deposit {
			t.Errorf("POST-FORK PROBE8 zero-burn ring 2: loss %d >= deposit %d; a zero-burn tx must only pay fees", p8loss, deposit)
		}
		if zeroburn_prefork_loss != 0 && p8loss != zeroburn_prefork_loss {
			t.Errorf("POST-FORK PROBE8 zero-burn ring 2: loss %d != pre-fork loss %d; the gate must not change the cost of a tx that burned nothing", p8loss, zeroburn_prefork_loss)
		}
	} else { // pre-fork: must reproduce the baseline byte for byte
		// the deposit-above-ring-2 refusal is gated too: pre-fork the ring-8 calls
		// must still be ADMITTED and must still destroy the deposit. a refusal here
		// would mean the verification rule leaked below the activation height.
		if p1refused || refused8 {
			t.Errorf("PRE-FORK: a ring-8 deposit was refused at verification (p1=%v familyA=%v); the rule must not apply below the activation height", p1refused, refused8)
		}
		if p1loss < deposit {
			t.Errorf("PRE-FORK ring-8 uninstalled: loss %d < deposit %d; pre-fork behaviour must be unchanged", p1loss, deposit)
		}
		if loss8 < deposit {
			t.Errorf("PRE-FORK Family A ring-8: loss %d < deposit %d; pre-fork behaviour must be unchanged", loss8, deposit)
		}
		if lossB < deposit {
			t.Errorf("PRE-FORK Family B ring-2: sender loss %d < deposit %d; pre-fork behaviour must be unchanged", lossB, deposit)
		}
		if p3loss < deposit {
			t.Errorf("PRE-FORK PROBE3 no-SCCODE install: loss %d < deposit %d; pre-fork behaviour must be unchanged", p3loss, deposit)
		}
		if p4loss < deposit {
			t.Errorf("PRE-FORK PROBE4 burn-not-last: loss %d < deposit %d; pre-fork behaviour must be unchanged", p4loss, deposit)
		}
		// O14 pre-fork: the accepting contract must still see only the LAST
		// payload's burn (zero) and the sender must still lose the deposit.
		if p5delta != 0 {
			t.Errorf("PRE-FORK PROBE5 accepting SC: credited %d, unpatched behaviour credits 0 (last payload's burn)", p5delta)
		}
		if p5loss < deposit {
			t.Errorf("PRE-FORK PROBE5 accepting SC: loss %d < deposit %d; pre-fork behaviour must be unchanged", p5loss, deposit)
		}
		if p6loss < deposit {
			t.Errorf("PRE-FORK PROBE6 no-SCACTION: loss %d < deposit %d; pre-fork behaviour must be unchanged", p6loss, deposit)
		}
		// PROBE7 is the one probe that must look IDENTICAL on both sides of the
		// gate, so the pre-fork figure is the baseline the post-fork run compares
		// against rather than an assertion of its own. It still cannot exceed the
		// deposit -- there is no burn to lose.
		if p7loss >= deposit {
			t.Errorf("PRE-FORK PROBE7 carrier: loss %d >= deposit %d; a zero-burn tx has no deposit to lose in any era", p7loss, deposit)
		}
		carrier_prefork_loss = p7loss
		if p8loss >= deposit {
			t.Errorf("PRE-FORK PROBE8 zero-burn ring 2: loss %d >= deposit %d; a zero-burn tx has no deposit to lose in any era", p8loss, deposit)
		}
		zeroburn_prefork_loss = p8loss
	}

	// 4. criterion (A)/(D): no probe above may materialize the never-installed
	//    SCID's tree or write into the reject stub's tree, in EITHER mode. These
	//    are the state-root-visible effects a balance delta is blind to.
	stub_tree_after, stub_present_after := sc_tree_hash(chain, scid)
	unin_tree_after, unin_present_after := sc_tree_hash(chain, uninstalled_scid)
	if m, ok := state_merkle(chain); ok {
		t.Logf("state merkle after probes: %x", m)
	}
	if stub_present_after != stub_tree_present || stub_tree_after != stub_tree_before {
		t.Errorf("reject stub's data tree changed across the probes (present %v->%v, hash %x->%x); no probe targets it for a write",
			stub_tree_present, stub_present_after, stub_tree_before, stub_tree_after)
	}
	if unin_present_after != unin_tree_present || unin_tree_after != unin_tree_before {
		t.Errorf("never-installed SCID's tree changed across the probes (present %v->%v, hash %x->%x); the refund must never materialize it",
			unin_tree_present, unin_present_after, unin_tree_before, unin_tree_after)
	}

	if postfork {
		t.Logf("POST-FORK CONFIRMED: ring-2 to an UNINSTALLED SCID is REFUNDED (Family B, "+
			"the mainnet-observed family) -- sender lost %d in fees against a %d deposit; "+
			"the ring-2 control still refunds (lost %d). RESIDUAL, asserted above and NOT fixed: "+
			"ring-8 to a real SC still destroys the deposit (lost %d), because the sender is "+
			"anonymous by construction at ring > 2.",
			lossB, deposit, loss2, loss8)
	} else {
		t.Logf("PRE-FORK CONFIRMED (unpatched baseline reproduced): ring-8 to a real SC destroys "+
			"the %d deposit (Family A, null signer); ring-2 to an UNINSTALLED SCID also destroys "+
			"it (Family B, early return) -- sender lost %d; only the ring-2 call to a "+
			"correctly-targeted real SC refunds (lost %d in fees). Ring 2 is NOT safe in general; "+
			"the loss is in-block, no reorg.",
			deposit, lossB, loss2)
	}

	// NOTE for future maintainers: do NOT "fix" the ring-8 residual by routing the
	// orphaned burn to dvm.ErrorDeposit. That was the originally committed design and
	// it was WITHDRAWN: crediting an SCID with no SC_Meta_Key poisons sc_change_cache
	// and panics the block-commit loop (chain-halt DoS), and at ring > 2 the
	// beneficiary is chosen by the tx author, not the sender. Assertion #1 (delta8 ==
	// 0) is load-bearing -- it is what stops that from being reintroduced silently.
}
