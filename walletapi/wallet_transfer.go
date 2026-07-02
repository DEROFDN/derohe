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

package walletapi

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

//import "sort"
//import "math/rand"
//import cryptorand "crypto/rand"

//import "encoding/binary"

//import "encoding/json"

//import "github.com/vmihailenco/msgpack"

//import "github.com/deroproject/derohe/crypto/ringct"

//import "github.com/deroproject/derohe/globals"

//import "github.com/deroproject/derohe/ddn"

//import "github.com/deroproject/derohe/structures"
//import "github.com/deroproject/derohe/blockchain/inputmaturity"

/*
func (w *Wallet_Memory) Transfer_Simplified(addr string, value uint64, data []byte, scdata rpc.Arguments) (tx *transaction.Transaction, err error) {
	if sender, err := rpc.NewAddress(addr); err == nil {
		burn_value := uint64(0)
		return w.TransferPayload0(*sender, value, burn_value, 0, 0, false, data, scdata, false)
	}
	return
}
*/

// we should reply to an entry

// send amount to specific addresses
// TransferPayload0 is preserved with its exact signature as a shim over
// TransferPayload0WithOptions, so all existing callers keep compiling and get
// today's behavior (honest attribution, random ring selection).
func (w *Wallet_Memory) TransferPayload0(transfers []rpc.Transfer, ringsize uint64, transfer_all bool, scdata rpc.Arguments, gasstorage uint64, dry_run bool) (tx *transaction.Transaction, err error) {
	return w.TransferPayload0WithOptions(transfers, ringsize, transfer_all, scdata, gasstorage, dry_run, TransferOptions{})
}

// curatedRingCandidates returns an ordered list of candidate ring members:
// validated preferred decoys first, then the daemon's random members. With a nil
// RingPreference it returns exactly Random_ring_members(scid) — today's behavior.
//
// A preferred decoy is validated to be parseable, not the wallet's own address, not a
// duplicate, and registered on the BASE (zero-SCID) balance tree. The base tree is the
// PRIMARY tree the consensus verifier checks for a zero-SCID transfer's ring members, and
// the FALLBACK tree it consults for a non-zero-SCID transfer's members not found in the SC
// tree (transaction_verify.go). Probing the base tree (rather than the transfer's SCID tree)
// therefore prevents a curated decoy that passes the wallet but rejects at consensus after
// the user has signed. NOTE: for a zero-SCID transfer this probe is redundant with the
// unconditional per-candidate re-probe in the ring-assembly loop; it is the SOLE wallet-side
// defense only on the non-zero-SCID path. In Strict mode a bad decoy is a hard error;
// otherwise it is skipped and random members fill the slot.
//
// recipientAddr is the transfer's recipient address string (any HRP/network/integrated
// encoding); its pubkey seeds the distinctness set so an alt-encoding of the recipient is
// rejected as a duplicate. Empty means "no recipient seed".
//
// curated reports how many validated preferred decoys lead alist, so the caller can
// measure candidate scarcity on the random tail alone. The count is measured from the
// validated list, not derived from len(PreferredDecoys): in non-Strict mode a decoy is
// dropped when it is unparseable, the wallet's own address, a duplicate, or judged
// unregistered by the daemon — EVERY drop, whatever the reason, is recorded in drops and
// logged (a lenient build whose curation shrank must never look identical to one whose
// curation fully applied; review #3 / re-review O7). A probe that FAILS — as opposed to
// returning an unregistered verdict — errors in both modes; it never silently shrinks
// the curation (review #3).
//
// verdicts, if non-nil, memoizes registration verdicts (key: canonical base address,
// value: registered) across calls within ONE transfer build, so a pass costs O(1) probes
// after the first instead of O(len(PreferredDecoys)) — the assembly loop may run up to
// maxTotalRingPassesFactor×ringsize passes, and registration probes are sequential
// RPCs issued under
// transfer_mutex. Memoizing is sound within a build: registration is permanent, and an
// unregistered verdict going stale for the few seconds of one build only means the decoy
// is picked up on the NEXT send. Pass nil to force fresh probes.
//
// drops, if non-nil, accumulates lenient drops across calls within one build (key: the
// supplied decoy string, value: the reason) — the caller derives its pre-signing
// "reduced curation" summary from it, and it doubles as the once-per-build log
// deduplicator (the assembly loop re-validates decoys every pass; only the first drop
// of each decoy is logged). With drops == nil every drop is logged on every call.
// Strict mode never records a drop: it hard-errors on the first bad decoy instead.
//
// slots is the ring's decoy capacity (ringsize-2: the sender and the recipient hold the
// other two positions). Validation stops accepting decoys once slots are filled: the
// assembly loop places the curated head in order and stops at a full ring, so a decoy
// past the capacity would be validated (one RPC) and then silently never placed — a
// curation shortfall with no signal (re-review O9). Overflow is a hard error in Strict
// mode (also pre-checked by TransferPayload0WithOptions against the supplied count) and
// a recorded, logged drop in lenient mode.
func (w *Wallet_Memory) curatedRingCandidates(scid crypto.Hash, recipientAddr string, pref *RingPreference, slots int, verdicts map[string]bool, drops map[string]string) (alist []string, curated int, err error) {
	if pref == nil {
		return w.Random_ring_members(scid), 0, nil
	}

	var zeroscid crypto.Hash
	// A ring member is identified by its public key, not its address string. The seen-set
	// is therefore keyed on the raw 33-byte compressed pubkey, NOT a stringified address.
	// Address strings vary along several axes that all encode the SAME pubkey — network HRP
	// (dero/deto), the deroproof HRP (rpc/address.go MarshalText overrides the network HRP
	// whenever Proof is set), and the integrated "i" HRP/Arguments — so a string key lets an
	// alt-encoding of the sender, recipient, or an already-curated decoy slip every check and
	// land the same pubkey in the ring twice, which the wallet accepts but consensus rejects
	// (transaction_verify.go) AFTER the user has signed. A pubkey key collapses every such
	// axis (including any future HRP axis) into one identity.
	pkKey := func(a *rpc.Address) string { return hex.EncodeToString(a.PublicKey.EncodeCompressed()) }
	selfAddr := w.GetAddress()
	self := pkKey(&selfAddr)
	// seed with sender AND recipient pubkeys: both are already in the ring, so an alt-encoding
	// of either is a duplicate that must not be curated as a decoy.
	seen := map[string]bool{self: true}
	if recipientAddr != "" {
		if ra, e := rpc.NewAddress(recipientAddr); e == nil {
			seen[pkKey(ra)] = true
		}
	}

	// recordDecoyDrop is the single funnel for LENIENT drops: every rejected decoy is
	// logged and (when the caller keeps a drops record) accumulated for the pre-signing
	// summary, whatever the rejection reason — wallet-side validation (parse/self/dup)
	// and the daemon's unregistered verdict alike. A drop that only some reasons report
	// recreates the silent-degradation bug for the unreported reasons (re-review O7).
	recordDecoyDrop := func(d, reason string) {
		if drops != nil {
			if _, already := drops[d]; already {
				return // logged on first sight; the loop re-validates every pass
			}
			drops[d] = reason
		}
		logger.V(1).Info("preferred decoy dropped", "decoy", d, "reason", reason)
	}

	for _, d := range pref.PreferredDecoys {
		if len(alist) >= slots { // every decoy slot is spoken for: anything further cannot ride
			if pref.Strict { // defense in depth: the caller pre-checks the supplied count
				return nil, 0, fmt.Errorf("too many preferred decoys: only %d decoy slots at this ring size", slots)
			}
			recordDecoyDrop(d, fmt.Sprintf("no decoy slot left (this ring holds %d decoys)", slots))
			continue
		}
		addr, e := rpc.NewAddress(d)
		if e != nil { // must be a parseable address
			if pref.Strict {
				return nil, 0, fmt.Errorf("preferred decoy is not a valid address: %s", d)
			}
			recordDecoyDrop(d, "not a parseable address")
			continue
		}
		key := pkKey(addr) // pubkey is the network-/proof-/integrated-agnostic identity
		if key == self {   // curating your own address collapses your anonymity set
			if pref.Strict {
				return nil, 0, fmt.Errorf("preferred decoy cannot be your own address")
			}
			recordDecoyDrop(d, "own address")
			continue
		}
		if seen[key] { // distinctness (consensus rejects duplicate ring members)
			if pref.Strict {
				return nil, 0, fmt.Errorf("duplicate preferred decoy: %s", d)
			}
			recordDecoyDrop(d, "duplicate of the sender, recipient, or another decoy")
			continue
		}
		// The ring carries a normal BASE address (Arguments cleared, Proof cleared, network
		// pinned to this wallet's) — a deroproof or integrated encoding is not a usable ring
		// entry. The seen-set is keyed on the pubkey above, so this stringification only has
		// to produce a resolvable address; its HRP axes no longer affect distinctness.
		canon := addr.BaseAddress()
		canon.Proof = false
		canon.Mainnet = w.GetNetwork()
		base := canon.String()
		// registration: probe the BASE balance tree, the tree consensus checks against.
		// The probe error is CLASSIFIED: only the daemon's explicit unregistered verdict is
		// a judgment on the decoy (Strict: hard error; lenient: skip). Any other failure —
		// offline, transport, daemon fault — is an unknown verdict and errors in BOTH modes:
		// treating it as "invalid decoy" would let a transient blip silently strip every
		// curated decoy and ship a fully random ring the user believes is curated.
		if reg, cached := verdicts[base]; cached {
			if !reg {
				if pref.Strict {
					return nil, 0, fmt.Errorf("preferred decoy is not registered: %s", d)
				}
				// recorded again because drops is keyed on the SUPPLIED string: the same
				// unregistered pubkey under a second encoding shares the verdict memo but
				// is a distinct supplied decoy the summary must count.
				recordDecoyDrop(d, "daemon reports it unregistered")
				continue
			}
		} else if _, _, _, _, e := w.GetEncryptedBalanceAtTopoHeight(zeroscid, -1, base); e != nil {
			if !isUnregisteredError(e) {
				return nil, 0, fmt.Errorf("could not verify preferred decoy %s: %s — retry the send", d, e)
			}
			if verdicts != nil {
				verdicts[base] = false
			}
			if pref.Strict {
				return nil, 0, fmt.Errorf("preferred decoy is not registered: %s", d)
			}
			// The unregistered verdict comes solely from the daemon — the wallet has no
			// independent view of the tree — so a lenient drop must never be silent: a
			// daemon falsely vetoing curated decoys would otherwise strip curation with
			// zero signal. Recorded per decoy (logged once per build via drops) and
			// summarized at default verbosity by the caller.
			recordDecoyDrop(d, "daemon reports it unregistered")
			continue
		} else if verdicts != nil {
			verdicts[base] = true
		}
		seen[key] = true
		alist = append(alist, base) // ring carries the canonical base form
	}

	curated = len(alist) // count captured before the random tail is appended
	return append(alist, w.Random_ring_members(scid)...), curated, nil
}

// Ring-assembly termination bounds (review #1). A pass over the candidate list that adds
// no new distinct candidate to the deduplicator is "barren": the daemon's sample was fully
// saturated. Without bounds a candidate pool smaller than the ring spins forever holding
// transfer_mutex: the per-member balance probe cannot error on a non-zero SCID
// (unregistered accounts get synthesized zero balances with err=nil), success needs a full
// ring, and the candidate stream stops yielding new members.
//
// Two recovery layers run BEFORE the exhaustion error:
//
//  1. Stall rescue: after ringStallRescueAfter consecutive barren passes the loop
//     permanently switches to base-tree candidates for the remaining slots — the same
//     fill the <=40 scarcity fast-path uses, just triggered by observed starvation
//     instead of a size heuristic. This covers the band the heuristic cannot see: a
//     token tree with more than 40 members but fewer than ringsize (the daemon's
//     5-block recent-activity filter can also push a larger tree into this band).
//  2. Barren backoff: consecutive barren passes sleep with exponential backoff (250ms
//     doubling to a 4s cap). The sleeps that can actually occur before the cap fires
//     (barren 1..maxBarrenRingPasses-1) total ~112s — longer than the daemon's
//     recent-activity filter window (5 blocks × 18s = 90s,
//     rpc_dero_getrandomaddress.go / config.BLOCK_TIME), so a BASE pool transiently
//     thinned by the filter can roll past it before exhaustion is declared. The
//     schedule sum is pinned against the filter window by Test_BarrenBackoff_Spans_Filter.
//
// The pool is declared exhausted only after maxBarrenRingPasses CONSECUTIVE barren passes
// with the rescue already armed, or maxTotalRingPassesFactor × ringsize total passes
// (bounding adversarial trickle progress: the deduplicator is monotone, so even a daemon
// feeding one fresh member per pass terminates).
//
// Pass counts alone do not bound WALL CLOCK: barren_passes resets on any deduplicator
// growth, so a daemon trickling one fresh member per ~31 passes could re-arm the full
// backoff window once per trickle inside the total-pass cap (~32 windows at ring 128).
// maxRingBuildStallBudget therefore caps the CUMULATIVE backoff sleep PER TRANSFER,
// regardless of trickle pattern. It is scoped per transfer, not per build: barren/rescue
// state resets per transfer, so each transfer owns a full consecutive-barren window
// (~112s) and the honest filter-recovery path is never cut short — even when an earlier
// transfer in the array already consumed its own window (a shared budget would convert
// the second recovery into a false "stall budget exhausted" error). The resulting
// mutex-held sleep bound is len(transfers) × the budget, and len(transfers) is itself
// capped wallet-side at MaxTransfersPerBuild BEFORE any mutex-held RPC or sleep. That
// cap is what makes the multiplier a constant: the consensus tx-size limit
// (STARGATE_HE_MAX_TX_SIZE = 300KB) is enforced only at verification/broadcast — AFTER
// the whole assembly loop has run — so it bounds what can broadcast, never how long
// assembly holds the mutex. The wallet cap is a necessary condition of that limit
// (every payload serializes to more than STARGATE_HE_MAX_TX_SIZE/MaxTransfersPerBuild
// bytes even at the ring-2 minimum — statement ring keys + CT proof; pinned on a real
// built transaction by Test_Ring2PayloadFloor_JustifiesTransferCap), so it can never
// reject an array that could have broadcast. Exceeding the
// budget means the daemon is starving assembly and the build errors. The remaining
// hold term is RPC latency — bounded in COUNT by the pass caps and in TIME by the
// per-call deadline on every daemon RPC the transfer path issues
// (walletDaemonCallTimeout, daemon_communication.go): a daemon that accepts the
// connection but never answers no longer parks the build inside a deadline-free
// CallResult holding transfer_mutex forever; the first hung call errors the build at
// the deadline. RPC_COUNT_BOUND covers the whole body, not just ring assembly:
// per BUILD, ≤2 fee/SC-call random-member fetches (each may append one 0-amount
// transfer, so the loops below run over an EFFECTIVE transfer count ≤ len(transfers)+1
// — the appends are mutually exclusive: the SC-call append creates the base transfer
// the fee append checks for); per EFFECTIVE transfer, 1 balance probe, ≤20
// empty-destination resolver fetches, ≤1 NameToAddress resolution, then the
// pass-capped assembly RPCs (≤8×ringsize member fetches + ≤maxPreferredDecoys
// memoized probes + ringsize member-balance fetches). The full worst-case hold is
// therefore (min(len(transfers), MaxTransfersPerBuild)+1) × (150s sleep +
// RPC_COUNT_BOUND × per-RPC time bound) — an absolute constant, astronomical only
// against a daemon stalling EVERY reply just under the deadline (visible, and strictly
// narrower than the unbounded pre-fix hold), and ~one deadline for the common
// hung-daemon case. The per-RPC time bound covers the transmit side too: every
// websocket WRITE on the wallet's daemon client carries a write deadline
// (rwc.NewWithWriteTimeout in Connect; walletDaemonWriteTimeout). The call-context
// deadline alone cannot bound a blocked write — the vendored jrpc2 client serializes
// send() and deadline delivery on one client-wide mutex, so one write blocked on a
// half-open peer (including the deadline-free background test_connectivity Echo/GetInfo)
// would otherwise freeze every concurrent call's transmit AND its timeout delivery for
// the kernel TCP retransmit timeout (~15+ min), not 45s. With the write deadline the
// blocked write errors and poisons the connection, so one transfer-path RPC is bounded
// by (concurrent writer's write deadline) + (own write deadline) + (response deadline)
// ≤ 3 × 45s.
const maxBarrenRingPasses = 32
const maxTotalRingPassesFactor = 8
const ringStallRescueAfter = 2
const maxRingBuildStallBudget = 150 * time.Second

// MaxTransfersPerBuild caps the transfer array accepted by a single build, checked
// before any mutex-held RPC or sleep (see the bounds comment above: it is what turns
// the per-transfer hold bound into an absolute one). 256 is a NECESSARY condition of
// the consensus 300KB tx-size limit: a single payload — statement ring keys, per-member
// commitments and the CT proof — serializes to well over 300*1024/256 = 1200 bytes even
// at ring 2 (Test_Ring2PayloadFloor_JustifiesTransferCap pins this on a real built tx),
// so any array longer than 256 could never have broadcast anyway and the cap rejects no
// previously-usable input. Exported: it is part of the build API contract.
const MaxTransfersPerBuild = 256

// maxPreferredDecoys bounds request size: preferred decoys are validated with sequential
// registration RPCs under transfer_mutex, so the list length is a cost dimension the
// caller controls. 256 = 2× the maximum legal ringsize — far above any usable curation
// (decoy slots max out at ringsize-2 = 126) while cutting off degenerate inputs. Exceeding
// it is request validation, not decoy quality, so it errors in BOTH modes.
const maxPreferredDecoys = 256

// barrenRingSleep is the backoff before retrying after the barren-th consecutive
// fruitless pass: 250ms, 500ms, 1s, 2s, then 4s flat (see the bounds comment above).
func barrenRingSleep(barren int) time.Duration {
	d := 250 * time.Millisecond
	for i := 1; i < barren && d < 4*time.Second; i++ {
		d *= 2
	}
	if d > 4*time.Second {
		d = 4 * time.Second
	}
	return d
}

// TransferPayload0WithOptions is the additive variant carrying opt-in transfer
// privacy knobs (sender-attribution mode, decoy curation). A zero-value
// TransferOptions reproduces TransferPayload0 exactly.
func (w *Wallet_Memory) TransferPayload0WithOptions(transfers []rpc.Transfer, ringsize uint64, transfer_all bool, scdata rpc.Arguments, gasstorage uint64, dry_run bool, opts TransferOptions) (tx *transaction.Transaction, err error) {

	//    var  transfer_details structures.Outgoing_Transfer_Details
	w.transfer_mutex.Lock()
	defer w.transfer_mutex.Unlock()

	//if len(transfers) == 0 {
	//	return nil,  fmt.Error("transfers is nil, cannot send.")
	//}

	// request-size validation before ANY daemon RPC or sleep: assembly cost — and the
	// transfer_mutex hold — scales linearly in the transfer count, and the consensus
	// 300KB tx-size limit only fires at broadcast, after that cost is already paid.
	// See MaxTransfersPerBuild.
	if len(transfers) > MaxTransfersPerBuild {
		err = fmt.Errorf("too many transfers in one build: %d (maximum %d; a transaction this large could not broadcast under the %d-byte consensus limit) — split the batch", len(transfers), MaxTransfersPerBuild, config.STARGATE_HE_MAX_TX_SIZE)
		return
	}

	if ringsize == 0 {
		ringsize = uint64(w.account.Ringsize) // use wallet ringsize, if ringsize not provided
	} else { // we need to use supplied ringsize
		if ringsize&(ringsize-1) != 0 {
			err = fmt.Errorf("ringsize should be power of 2. value %d", ringsize)
			return
		}
		if !(ringsize >= config.MIN_RINGSIZE && ringsize <= config.MAX_RINGSIZE) {
			err = fmt.Errorf("ringsize out of range value %d", ringsize)
			return
		}
	}

	// fail closed on anonymous attribution at ring 2: there are no decoy slots
	// (witness_index[2:] is empty), so the build would silently fall through to honest
	// attribution and broadcast a verifiably-attributed transfer while the caller believes
	// it is anonymized. ringsize is now the effective value (supplied or wallet default).
	if opts.Attribution == AttributionAnonymous && ringsize < 3 {
		err = fmt.Errorf("anonymous attribution requires ring size >= 4; ring size %d has no decoy slots", ringsize)
		return
	}

	// request-size validation, both modes: see maxPreferredDecoys.
	if opts.Ring != nil && len(opts.Ring.PreferredDecoys) > maxPreferredDecoys {
		err = fmt.Errorf("too many preferred decoys: %d (maximum %d; a ring holds at most %d decoys)", len(opts.Ring.PreferredDecoys), maxPreferredDecoys, config.MAX_RINGSIZE-2)
		return
	}

	// per-build registration-verdict memo for curated decoys (see curatedRingCandidates):
	// caps validation cost at one probe per distinct decoy per build. decoy_drops is the
	// per-build record of EVERY lenient drop with its reason — wallet-side rejections
	// (unparseable/self/duplicate/no free slot) and daemon unregistered verdicts alike —
	// feeding the pre-signing summary log after ring assembly (re-review O7). decoy_slots
	// is the ring's decoy capacity: sender and recipient hold the other two positions.
	var decoy_verdicts map[string]bool
	var decoy_drops map[string]string
	decoy_slots := int(ringsize) - 2
	if opts.Ring != nil && len(opts.Ring.PreferredDecoys) > 0 {
		decoy_verdicts = map[string]bool{}
		decoy_drops = map[string]string{}
	}

	// fail closed on Strict decoy curation at ring 2: the assembly loop ("for ringsize != 2")
	// never runs, so curatedRingCandidates — the only decoy validator — is never invoked and
	// Strict's hard-error contract would be silently void (garbage decoys build and broadcast
	// at ring 2 while the identical input at ring 4 hard-errors). Lenient curation stays
	// permitted: its documented contract is silent drop, which a ring with no decoy slots
	// satisfies — every decoy is recorded dropped so the pre-signing reduced-curation
	// summary fires at default verbosity (re-review O9 closed the log-only gap).
	if opts.Ring != nil && len(opts.Ring.PreferredDecoys) > 0 && ringsize < 3 {
		if opts.Ring.Strict {
			err = fmt.Errorf("strict decoy curation requires ring size >= 4; ring size %d has no decoy slots", ringsize)
			return
		}
		for _, d := range opts.Ring.PreferredDecoys {
			if _, already := decoy_drops[d]; !already {
				decoy_drops[d] = "no decoy slot left (ring size 2 holds no decoys)"
				logger.V(1).Info("preferred decoy dropped", "decoy", d, "reason", "ring size 2 holds no decoys")
			}
		}
	}

	// fail closed on Strict over-supply at ANY ring size: a ring places at most
	// decoy_slots curated decoys; the surplus would be validated and then silently
	// never placed — the caller asked for a curation the ring cannot physically honor
	// (re-review O9). Checked on the SUPPLIED count, which for a Strict list that can
	// build at all equals the validated count (duplicates/garbage already hard-error).
	// Lenient over-supply proceeds: the surplus is dropped with a per-decoy record and
	// the pre-signing reduced-curation summary.
	if opts.Ring != nil && opts.Ring.Strict && ringsize >= 3 && len(opts.Ring.PreferredDecoys) > decoy_slots {
		err = fmt.Errorf("too many preferred decoys for ring size %d: %d supplied but only %d decoy slots (sender and recipient hold the other two) — raise the ring size or trim the list", ringsize, len(opts.Ring.PreferredDecoys), decoy_slots)
		return
	}

	//ringsize = 2

	// if wallet is online,take the fees from the network itself
	// otherwise use whatever user has provided
	//if w.GetMode()  {
	fees_per_kb := w.dynamic_fees_per_kb // TODO disabled as protection while lots more testing is going on
	//rlog.Infof("Fees per KB %d\n", fees_per_kb)
	//}

	if fees_per_kb == 0 {
		fees_per_kb = config.FEE_PER_KB
	}

	// user wants to do an SC call, but doesn't want any transfer, so we will transfer 0 to a random account
	if len(scdata) >= 1 && len(transfers) == 0 {
		var zeroscid crypto.Hash
		for _, k := range w.Random_ring_members(zeroscid) {
			if k != w.GetAddress().String() { /// make sure random member is not equal to ourself
				transfers = append(transfers, rpc.Transfer{Destination: k, Amount: 0})
				logger.V(3).Info("Doing 0 transfer to", "random_address", k)
				break
			}
		}
	}

	if len(transfers) >= 1 {
		has_base := false
		for i := range transfers {
			if transfers[i].SCID.IsZero() {
				has_base = true
			}
		}

		// if we do not have base we can not detect fees. this restriction should be lifted at suitable time
		if !has_base {
			var zeroscid crypto.Hash
			for _, k := range w.Random_ring_members(zeroscid) {
				if k != w.GetAddress().String() { /// make sure random member is not equal to ourself
					transfers = append(transfers, rpc.Transfer{Destination: k, Amount: 0})
					logger.V(3).Info("Doing 0 transfer to", "random_address", k)
					break
				}
			}
		}

	}

	for t := range transfers {
		var data []byte
		if data, err = transfers[t].Payload_RPC.CheckPack(transaction.PAYLOAD0_LIMIT); err != nil {
			return
		}

		if len(data) != transaction.PAYLOAD0_LIMIT {
			err = fmt.Errorf("Expecting exactly %d bytes data  but have  %d bytes", transaction.PAYLOAD0_LIMIT, len(data))
			return
		}
	}

	//fees := (ringsize + 1) * fees_per_kb // start with zero fees
	//	expected_fee := uint64(0)

	if transfer_all {
		err = fmt.Errorf("Transfer all not supported")
		return
		//transfers[0].Amount = w.account.Balance_Mature - fees
	}

	total_amount_required := map[crypto.Hash]uint64{}
	for i := range transfers {
		total_amount_required[transfers[i].SCID] = total_amount_required[transfers[i].SCID] + transfers[i].Amount + transfers[i].Burn
	}

	for i := range transfers {
		var current_balance uint64
		current_balance, _, err = w.GetDecryptedBalanceAtTopoHeight(transfers[i].SCID, -1, w.GetAddress().String())

		if err != nil {
			return
		}
		if total_amount_required[transfers[i].SCID] > current_balance {
			err = fmt.Errorf("Insufficent funds for scid %s Need %s Actual %s", transfers[i].SCID, FormatMoney(total_amount_required[transfers[i].SCID]), FormatMoney(current_balance))
			return
		}
	}

	for t := range transfers {

		if transfers[t].Destination == "" { // user skipped destination
			if transfers[t].SCID.IsZero() {
				err = fmt.Errorf("Main Destination cannot be empty")
				return
			}

			// we will try x times, to get a random ring ring member other than us, if ok, we move ahead
			ring_count := 0
			for i := 0; i < 20; i++ {
				//fmt.Printf("getting random ring member %d\n", i)
				scid := transfers[t].SCID
				if i > 17 { // if we cannot obtain ring member is 17 tries, choose  ring member from zero
					var zeroscid crypto.Hash
					scid = zeroscid
				}
				for _, k := range w.Random_ring_members(scid) {
					if k != w.GetAddress().String() {
						transfers[t].Destination = k
						i = 1000000 // break outer loop also
						ring_count++
						break
					}
				}
			}

		}

		if transfers[t].Destination == "" {
			err = fmt.Errorf("could not obtain random ring member for scid %s", transfers[t].SCID)
			return
		}

		// try to resolve name to address here
		if _, err = rpc.NewAddress(transfers[t].Destination); err != nil {
			if transfers[t].Destination, err = w.NameToAddress(transfers[t].Destination); err != nil {
				err = fmt.Errorf("could not decode name or address err '%s' name '%s'\n", err, transfers[t].Destination)
				return
			}
		}
	}

	//fmt.Printf("transfers %+v\n", transfers)

	var rings [][]*bn256.G1
	var rings_balances [][][]byte //initialize all maps

	var max_bits_array []int

	topoheight := int64(-1)
	var block_hash crypto.Hash

	var zeroscid crypto.Hash

	// noncetopo should be verified for all ring members simultaneously
	// this can lead to tx rejection
	// we currently bypass this since random members are chosen which have not been used in last 5 block
	_, noncetopo, block_hash, self_e, err := w.GetEncryptedBalanceAtTopoHeight(zeroscid, -1, w.GetAddress().String())
	if err != nil {
		err = fmt.Errorf("could not obtain encrypted balance for self err %s\n", err)
		return
	}

	// TODO, we should check nonce for base token and other tokens at the same time
	// right now, we are probably using a bit of luck here
	if daemon_topoheight >= int64(noncetopo)+3 { // if wallet has not been recently used, increase probability  of user's tx being successfully mined
		topoheight = daemon_topoheight - 3
	}

	_, _, block_hash, self_e, _ = w.GetEncryptedBalanceAtTopoHeight(transfers[0].SCID, topoheight, w.GetAddress().String())
	if err != nil {
		fmt.Printf("self unregistered err %s\n", err)
		return
	}

	er, err := w.GetSelfEncryptedBalanceAtTopoHeight(transfers[0].SCID, topoheight)
	if err != nil {
		err = fmt.Errorf("could not obtain encrypted balance for self err %s\n", err)
		return
	}
	height := uint64(er.Height)
	block_hash = er.BlockHash
	topoheight = er.Topoheight
	treehash := er.Merkle_Balance_TreeHash

	treehash_raw, err := hex.DecodeString(treehash)
	if err != nil {
		return
	}
	if len(treehash_raw) != 32 {
		err = fmt.Errorf("roothash is not of 32 bytes, probably daemon corruption '%s'", treehash)
		return
	}

	for t := range transfers {

		var ring []*bn256.G1
		var ring_balances [][]byte

		/*	if transfers[t].SCID.IsZero() {
				ringsize = uint64(ringsize)
			} else {
				ringsize = ringsize // only for easier testing
			}
		*/

		bits_needed := make([]int, ringsize, ringsize)

		bits_needed[0], _, _, self_e, err = w.GetEncryptedBalanceAtTopoHeight(transfers[t].SCID, topoheight, w.GetAddress().String())
		if err != nil {
			fmt.Printf("self unregistered err %s\n", err)
			return
		} else {
			ring_balances = append(ring_balances, self_e.Serialize())
			ring = append(ring, w.account.Keys.Public.G1())
		}

		var addr *rpc.Address
		if addr, err = rpc.NewAddress(transfers[t].Destination); err != nil {
			return
		}

		if addr.IsIntegratedAddress() && addr.Arguments.Validate_Arguments() != nil {
			err = fmt.Errorf("Integrated Address  arguments could not be validated.")
			return
		}

		if addr.IsIntegratedAddress() && len(transfers[t].Payload_RPC) == 0 {
			for _, arg := range addr.Arguments {
				if arg.Name == rpc.RPC_DESTINATION_PORT && addr.Arguments.Has(rpc.RPC_DESTINATION_PORT, rpc.DataUint64) {
					transfers[t].Payload_RPC = append(transfers[t].Payload_RPC, rpc.Argument{Name: rpc.RPC_DESTINATION_PORT, DataType: rpc.DataUint64, Value: addr.Arguments.Value(rpc.RPC_DESTINATION_PORT, rpc.DataUint64).(uint64)})
					continue
				} else {
					fmt.Printf("integrtated address, but don't know how to process\n")
					err = fmt.Errorf("integrated address used, but don't know how to process %+v", addr.Arguments)
				}
			}

			return
		}

		var dest_e *crypto.ElGamal
		bits_needed[1], _, _, dest_e, err = w.GetEncryptedBalanceAtTopoHeight(transfers[t].SCID, topoheight, addr.BaseAddress().String())
		if err != nil {
			fmt.Printf(" t %d unregistered1 '%s' %s\n", t, addr, err)
			return
		} else {
			ring_balances = append(ring_balances, dest_e.Serialize())
			ring = append(ring, addr.PublicKey.G1())
		}

		/*if len(w.account.RingMembers) < int(ringsize) {
			err = fmt.Errorf("We do not have enough ring members, expecting alteast %d but have only %d", int(ringsize), len(w.account.RingMembers))
			return
		}*/

		receiver_without_payment_id := addr.BaseAddress()
		// curatedRingCandidates now keys distinctness on the recipient's raw pubkey (it parses
		// the address string we hand it), so the recipient seed no longer has to be network-pinned
		// to stay in lockstep with the decoy keys. Leaving it on the recipient's native network
		// keeps the caller-side deduplicator below consistent with the recipient ring member added
		// above (also native-network), so a duplicate is caught on the same string form.

		//sending to self is not supported
		if w.GetAddress().String() == receiver_without_payment_id.String() {
			err = fmt.Errorf("Sending to self is not supported")
			return
		}

		deduplicator := map[string]bool{}
		deduplicator[receiver_without_payment_id.String()] = true
		deduplicator[w.GetAddress().String()] = true

		// Termination guarantee: deduplicator growth is monotone and bounded by the finite
		// candidate universe (curated decoys + tree leaves), so requiring growth at least
		// once every maxBarrenRingPasses passes bounds the loop; the absolute cap bounds
		// even adversarial trickle progress. See the consts' comment (review #1).
		barren_passes := 0
		total_passes := 0
		base_rescue := false // armed on stall or the <=40 fast path; sticky for the rest of this transfer
		// per-TRANSFER stall budget, matching the per-transfer barren/rescue state above:
		// caps this transfer's cumulative barren-backoff sleep under transfer_mutex while
		// guaranteeing each transfer a full filter-recovery window (see the bounds comment
		// on maxRingBuildStallBudget).
		ring_stall_budget := maxRingBuildStallBudget
		for ringsize != 2 {
			// curated preferred decoys (if any) go first; random members top up. With no
			// RingPreference this returns exactly Random_ring_members(scid). base_rescue is
			// sticky: once assembly has switched to base-tree fill, a per-pass SCID fetch
			// would be discarded unread, so rescue passes fetch the base tree ONLY — one
			// random-member RPC per pass, not two. Curated decoys still lead the base list
			// (curatedRingCandidates prepends them regardless of tree).
			var probable_members []string
			if !base_rescue {
				members, curated, cerr := w.curatedRingCandidates(transfers[t].SCID, receiver_without_payment_id.String(), opts.Ring, decoy_slots, decoy_verdicts, decoy_drops)
				if cerr != nil {
					err = cerr
					return
				}
				probable_members = members
				// Scarcity is measured on the RANDOM TAIL alone — upstream's own measure (its
				// list had no curated head). Counting curated decoys here lets them mask a
				// scarce tree, the base-tree rescue never fires, and the loop starves (review #1).
				// The <=40 size check is only the fast path: base_rescue also arms on OBSERVED
				// starvation (consecutive barren passes) to catch trees the heuristic
				// cannot — more than 40 members but fewer than the ring needs.
				if len(probable_members)-curated <= 40 { // we do not have enough ring members for sure, extract ring members from base
					base_rescue = true
				}
			}
			if base_rescue {
				var zeroscid crypto.Hash
				base_members, _, berr := w.curatedRingCandidates(zeroscid, receiver_without_payment_id.String(), opts.Ring, decoy_slots, decoy_verdicts, decoy_drops)
				if berr != nil {
					err = berr
					return
				}
				probable_members = base_members
			}
			seen_before := len(deduplicator)
			for _, k := range probable_members {
				if _, collision := deduplicator[k]; collision {
					continue
				}
				deduplicator[k] = true
				if len(ring_balances) < int(ringsize) && k != receiver_without_payment_id.String() && k != w.GetAddress().String() {
					var addr_member *rpc.Address
					//fmt.Printf("t:%d len %d %s     receiver %s   sender %s\n",t,len(ring_balances),  k, receiver_without_payment_id.String(), w.GetAddress().String())
					var ebal *crypto.ElGamal

					bits_needed[len(ring_balances)], _, _, ebal, err = w.GetEncryptedBalanceAtTopoHeight(transfers[t].SCID, -1, k)
					if err != nil {
						fmt.Printf(" unregistered %s\n", k)
						return
					}
					if addr_member, err = rpc.NewAddress(k); err != nil {
						return
					}

					ring_balances = append(ring_balances, ebal.Serialize())
					ring = append(ring, addr_member.PublicKey.G1())

					if len(ring_balances) == int(ringsize) {
						goto ring_members_collected
					}

				}
			}

			total_passes++
			if len(deduplicator) > seen_before {
				barren_passes = 0
			} else {
				barren_passes++
				if !base_rescue && barren_passes >= ringStallRescueAfter {
					// The SCID tree stopped yielding new members with the ring unfilled:
					// switch to base-tree fill (the same fill the <=40 fast path uses)
					// and give the base pool its own full barren budget.
					base_rescue = true
					barren_passes = 0
				}
			}
			if barren_passes >= maxBarrenRingPasses || total_passes >= maxTotalRingPassesFactor*int(ringsize) {
				if len(probable_members) == 0 {
					// Random_ring_members swallows RPC failures into an empty list — an
					// empty final fetch means a degraded daemon, not a small pool.
					err = fmt.Errorf("cannot assemble ring for scid %s: daemon returned no ring candidates after %d attempts — check the daemon connection", transfers[t].SCID, total_passes)
				} else {
					err = fmt.Errorf("cannot assemble ring for scid %s: candidate pool exhausted after %d passes without progress (have %d of %d members, %d distinct candidates seen) — retry later or lower the ringsize", transfers[t].SCID, barren_passes, len(ring_balances), ringsize, len(deduplicator)-2)
				}
				return
			}
			if barren_passes > 0 {
				// exponential backoff so the full barren window outlasts the daemon's
				// 5-block recent-activity filter (see the bounds comment on the consts).
				// Every sleep draws on this transfer's stall budget: barren_passes resets on
				// any progress, so without the budget a trickling daemon could re-arm the
				// backoff window repeatedly and hold transfer_mutex for the product of the
				// windows instead of one.
				d := barrenRingSleep(barren_passes)
				if d > ring_stall_budget {
					err = fmt.Errorf("cannot assemble ring for scid %s: stall budget exhausted after %d passes (have %d of %d members, %d distinct candidates seen) — the daemon is starving ring assembly; retry later or lower the ringsize", transfers[t].SCID, total_passes, len(ring_balances), ringsize, len(deduplicator)-2)
					return
				}
				ring_stall_budget -= d
				time.Sleep(d)
			}
		}
	ring_members_collected:

		rings = append(rings, ring)
		rings_balances = append(rings_balances, ring_balances)

		max_bits := 0
		for i := range bits_needed {
			if max_bits < bits_needed[i] {
				max_bits = bits_needed[i]
			}
		}
		max_bits_array = append(max_bits_array, max_bits)
	}

	// Lenient curation signal (Strict never reaches here with a drop — it errors): if ANY
	// curated decoy was dropped — unparseable, self, duplicate, or daemon-judged
	// unregistered — say so at default verbosity BEFORE the transaction is signed. A build
	// whose curation was reduced must never look identical to one whose curation fully
	// applied, whatever the drop reason: an all-dropped lenient list otherwise signs a
	// fully random ring the caller believes curated (re-review O7).
	if len(decoy_drops) > 0 {
		reasons := map[string]int{}
		for _, r := range decoy_drops {
			reasons[r]++
		}
		logger.Info("some preferred decoys were dropped — ring built with reduced curation", "dropped", len(decoy_drops), "supplied", len(opts.Ring.PreferredDecoys), "reasons", fmt.Sprintf("%v", reasons))
	}

	max_bits := 0
	for i := range max_bits_array {
		if max_bits < max_bits_array[i] {
			max_bits = max_bits_array[i]
		}
	}
	max_bits += 6 // extra 6 bits

	if !dry_run {
		tx = w.buildTransaction(transfers, rings_balances, rings, block_hash, height, scdata, treehash_raw, max_bits, gasstorage, opts)
	}

	if tx == nil {
		err = fmt.Errorf("somehow the tx could not be built, please retry")
	}

	return
}
