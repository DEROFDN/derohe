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
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/chzyer/readline"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/derohe/walletapi"
)

// session-scoped sticky default for "Anonymize sender?". NOT persisted across
// wallet close/reopen (would require an engine Account field, which is forbidden).
// Seeded by --anonymous at startup; toggled by "set anonymous on/off".
var anonymize_default bool

// session-scoped preferred decoys seeded by --decoys; used as prompt defaults.
var decoys_default []string

// buildTransferOptions constructs opts honoring the no-op contract: when anonymize
// is false AND members is empty, it returns a LITERAL zero value, so Ring stays nil
// (the engine fast path) and Attribution stays AttributionHonest. opts.Ring is
// assigned ONLY when len(members) > 0 — a non-nil empty Ring pointer would change
// the engine code path and break byte-identity with today's behavior.
func buildTransferOptions(anonymize bool, members []string) walletapi.TransferOptions {
	opts := walletapi.TransferOptions{}
	if anonymize {
		opts.Attribution = walletapi.AttributionAnonymous
	}
	if len(members) > 0 {
		opts.Ring = &walletapi.RingPreference{PreferredDecoys: members, Strict: false}
	}
	return opts
}

// anonymizeEffectiveAtRingsize reports whether AttributionAnonymous can actually
// take effect at the given effective ringsize. Anonymous attribution needs a decoy
// slot beyond [0]=sender and [1]=receiver; the ring is a power of 2, so ringsize 2
// has none and 4 is the first that does. This mirrors the cli-head engine gate
// (transaction_build.go: `len(witness_index) > 2`) AND the rebase-target hard guard
// (wallet_transfer.go: `ringsize < 3` => error). It is the single source of truth the
// CLI uses to decide what it PROMISES the user, so the promise can never outrun the tx.
//
// O10 (latent assumption — re-verify post-rebase): this reads the REQUESTED ringsize
// (wallet.GetRingSize()), not the as-built witness count. The coherence "report never
// outruns the tx" depends on the engine FAILING the build if it cannot fill the ring to
// the requested size — and it does today: the ring-assembly loop (wallet_transfer.go:
// 402-448) has NO exhaustion exit; it either reaches the full ring (goto :442) or errors
// at GetEncryptedBalanceAtTopoHeight/NewAddress (:429-434) on an unregistered/insufficient
// member, an error the CLI surfaces ("Error while building Transaction") and aborts on.
// So a silently-shrunk ring under an ANONYMOUS label cannot ship. If a future engine
// change ever allowed a silently-smaller ring (e.g. best-effort fill), THIS would become
// a real false-anonymity and the truth-source here must switch to the built witness count.
func anonymizeEffectiveAtRingsize(ringsize int) bool {
	return ringsize >= 4
}

// resolveAnonymizeOrDowngrade enforces the prompt's promise against the engine reality.
// When the user asked to anonymize but the effective ringsize has no decoy slot, the
// engine would ship an HONEST (verifiably-attributed) transfer (cli-head) or hard-error
// (post-rebase). Either way the user's belief "I am hidden" is false. So the CLI
// fails closed: it DOWNGRADES anonymize to false here and tells the user plainly, so
// what is built, broadcast, and reported all agree (criterion 1). Returns the effective
// anonymize flag the rest of the flow must use.
func resolveAnonymizeOrDowngrade(anonymize bool) bool {
	if anonymize && !anonymizeEffectiveAtRingsize(wallet.GetRingSize()) {
		logger.Info(color_yellow +
			"Anonymize CANCELLED: ringsize " + fmt.Sprintf("%d", wallet.GetRingSize()) +
			" has no decoy slot (needs 4 or higher). This transfer will ship HONEST — " +
			"your sender address IS visible to the receiver. Run 'set ringsize 16' and " +
			"resend if you want to be anonymized." + color_normal)
		return false
	}
	return anonymize
}

// canonBase reduces an address string to its canonical base (pubkey) form for
// distinctness comparison, matching the engine's curatedRingCandidates. Unparseable
// or empty input yields "" (which never matches a real seeded key).
func canonBase(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	a, err := globals.ParseValidateAddress(raw)
	if err != nil {
		return ""
	}
	return a.BaseAddress().String()
}

// collectDecoys prompts for base-address decoys one per line until a blank line.
// Each entry is validated at prompt time: parseable, not your own address, not an
// integrated address, no duplicates. Bad entries are reported and skipped (the loop
// simply does not advance). Returns the accepted base-address strings. The engine
// re-validates registration/base-tree at send time (Strict:false skips the rest),
// so this is fast immediate feedback, not the security boundary.
// decoyCollector holds the validation + dedup state for curated decoys. It is the
// pure, readline-free core so the security-relevant logic (canonicalization, the
// sender/recipient/duplicate rejection of O5) is unit-testable without a terminal.
type decoyCollector struct {
	self    string // canonical base of the sender
	seen    map[string]bool
	members []string
}

// newDecoyCollector seeds the seen-set with the sender AND recipient canonical bases:
// both are already real members of the ring, so curating either (under ANY encoding)
// as a "decoy" creates a duplicate pubkey that consensus rejects after signing. This
// is the ONLY prompt-time guard for the recipient case on cli-head (the engine
// recipient-seed lives in the rebase target only), so it must hold here (O5).
func newDecoyCollector(recipient string) *decoyCollector {
	self := canonBase(wallet.GetAddress().String())
	seen := map[string]bool{}
	if self != "" {
		seen[self] = true
	}
	if rb := canonBase(recipient); rb != "" {
		seen[rb] = true
	}
	return &decoyCollector{self: self, seen: seen}
}

// add validates one raw entry and appends its canonical base form on success. Bad
// entries are reported and skipped. Distinctness is by PUBKEY (BaseAddress), not the
// raw network-tagged string, matching the engine fix (curatedRingCandidates): a
// raw-string seen-map misses an alt-encoding of the sender, recipient, or an already
// curated decoy.
func (c *decoyCollector) add(raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	a, err := globals.ParseValidateAddress(raw)
	if err != nil {
		logger.Error(err, "Not a valid address; skipping decoy", "decoy", raw)
		return
	}
	if a.IsIntegratedAddress() {
		logger.Error(fmt.Errorf("integrated address"), "Decoy must be a base address (no payment id); skipping", "decoy", raw)
		return
	}
	base := a.BaseAddress().String() // canonical pubkey identity
	if base == c.self {
		logger.Error(fmt.Errorf("own address"), "A decoy cannot be your own address; skipping")
		return
	}
	if c.seen[base] {
		// covers exact dupes, the recipient (incl. an alt-encoding of it), and the
		// sender under any encoding — all are already in the ring.
		logger.Error(fmt.Errorf("duplicate ring member"), "Decoy is already in the ring (recipient/sender/duplicate); skipping", "decoy", raw)
		return
	}
	c.seen[base] = true
	c.members = append(c.members, base) // carry the canonical base form, as the engine does
}

// collectDecoys prompts for base-address decoys one per line until a blank line.
// Each entry is validated at prompt time via decoyCollector: parseable, not your own
// address, not the transfer recipient, not an integrated address, no duplicates. Bad
// entries are reported and skipped. Returns the accepted canonical base-address
// strings. The engine re-validates registration/base-tree at send time (Strict:false
// skips the rest), so this is fast immediate feedback, not the sole security boundary.
func collectDecoys(l *readline.Instance, defaults []string, recipient string) []string {
	c := newDecoyCollector(recipient)

	for _, d := range defaults { // pre-seed from --decoys
		c.add(d)
	}

	for {
		v, err := ReadString(l, "decoy address (blank to finish)", "")
		if err != nil {
			break
		}
		if strings.TrimSpace(v) == "" {
			break
		}
		c.add(v)
	}
	return c.members
}

// promptAnonymizeAndDecoys runs the full interactive flow: anonymize y/N (default
// seeded from anonymize_default), ring-size warn, then decoy collection (only when
// anonymize is yes). Returns the built opts plus the chosen flags for the summary.
func promptAnonymizeAndDecoys(l *readline.Instance, recipient string) (opts walletapi.TransferOptions, anonymize bool, members []string) {
	if anonymize_default {
		anonymize = ConfirmYesNoDefaultYes(l, "Anonymize sender? (decoys hide you from the receiver) (Y/n) ")
	} else {
		anonymize = ConfirmYesNoDefaultNo(l, "Anonymize sender? (decoys hide you from the receiver) (y/N) ")
	}
	// Enforce the promise against engine reality BEFORE collecting decoys or building
	// opts: if the ringsize cannot host anonymity, downgrade to honest now so every
	// downstream artifact (built opts, review line, post-send report) tells the truth.
	anonymize = resolveAnonymizeOrDowngrade(anonymize)
	if anonymize {
		members = collectDecoys(l, decoys_default, recipient)
	}
	return buildTransferOptions(anonymize, members), anonymize, members
}

// curatedDecoysInTx counts how many of the user's curated decoy base-addresses
// ACTUALLY landed in the ring that DELIVERS the transfer to `recipient`, rather than
// echoing the prompt-time request count. The engine (curatedRingCandidates) runs under
// Strict:false, so a curated decoy that is unparseable / unregistered /
// deregistered-since-prompt is SILENTLY skipped and a random member fills the slot —
// len(members) would then over-report curation. The authoritative record of what
// finalized is the freshly built tx's Statement.Publickeylist (the serialized wire form
// keeps only index pointers, so this must read the in-memory built tx, exactly as the
// curated-ring finalization test does).
//
// O9: a token transfer (non-zero SCID) auto-injects a SECOND base (zero-SCID) 0-value
// payload to a RANDOM member (wallet_transfer.go:172-191); each payload builds its OWN
// ring with INDEPENDENT random fill. The slot that hides the sender from the RECIPIENT is
// in the RECIPIENT's payload ring only. Flattening BOTH rings would count a curated decoy
// that landed only in the throwaway base ring as "landed", over-reporting cover the
// delivered transfer never got. So we count membership ONLY in the payload whose ring
// contains the recipient's own pubkey — the delivering payload. The throwaway base ring
// goes to a random member, never the recipient, so this scopes cleanly for both menus
// (plain DERO = single zero-SCID payload that holds the recipient; token = the token-SCID
// payload). If the recipient cannot be resolved/located (defensive), we fall back to the
// union of all rings (the prior, possibly-over-counting behavior) rather than report 0.
// O(ring) per payload; tiny.
func curatedDecoysInTx(tx *transaction.Transaction, members []string, recipient string) int {
	if tx == nil || len(members) == 0 {
		return 0
	}
	// resolve the recipient's compressed pubkey so we can find the delivering payload.
	var recipientKey string
	if a, err := rpc.NewAddress(recipient); err == nil {
		recipientKey = hex.EncodeToString(a.PublicKey.EncodeCompressed())
	}
	// build the set of ring keys present in the DELIVERING payload's ring (the one whose
	// ring contains the recipient). Fall back to the union if we cannot identify it.
	ringKeys := map[string]bool{}
	addPayload := func(payload transaction.AssetPayload) {
		for _, p := range payload.Statement.Publickeylist {
			if p == nil {
				continue
			}
			ringKeys[hex.EncodeToString((*crypto.Point)(p).EncodeCompressed())] = true
		}
	}
	if recipientKey != "" {
		for _, payload := range tx.Payloads {
			for _, p := range payload.Statement.Publickeylist {
				if p == nil {
					continue
				}
				if hex.EncodeToString((*crypto.Point)(p).EncodeCompressed()) == recipientKey {
					addPayload(payload)
					break // this payload delivers to the recipient; scope to it
				}
			}
		}
	}
	if len(ringKeys) == 0 { // recipient not resolvable/located: defensive union fallback
		for _, payload := range tx.Payloads {
			addPayload(payload)
		}
	}
	// count distinct requested members whose pubkey is in the ring. members are already
	// canonical, distinct base addresses (decoyCollector dedups by pubkey), so each maps
	// to one key; a key counted once even if (defensively) it appeared twice.
	counted := map[string]bool{}
	n := 0
	for _, m := range members {
		a, err := rpc.NewAddress(m)
		if err != nil {
			continue
		}
		k := hex.EncodeToString(a.PublicKey.EncodeCompressed())
		if ringKeys[k] && !counted[k] {
			counted[k] = true
			n++
		}
	}
	return n
}

// reportAttribution prints the truthful attribution + decoy count to the CONSOLE ONLY
// (l.Stderr()), bypassing logger.Info which tees to the on-disk wallet log. This gives
// the user a clear pre-send and post-send statement of how the tx is actually attributed
// (O2) WITHOUT writing an anonymize-intent/decoy forensic artifact to disk (O3).
//
// `decoys` is the count to display and its `label` (e.g. "requested" pre-send, "landed
// in ring" post-send) so the post-send line reflects what the engine ACTUALLY placed —
// curated decoys are dropped silently under Strict:false, so an echoed prompt-time count
// would over-report curation (O8).
func reportAttribution(l *readline.Instance, opts walletapi.TransferOptions, decoys int, label string) {
	fmt.Fprintf(l.Stderr(), "%sAttribution: %s  (curated decoys %s: %d)%s\n",
		color_extra_white, attributionResultLine(opts), label, decoys, color_normal)
}

// attributionResultLine renders the TRUTH about how a built/sent transfer is attributed,
// derived from the same effective ringsize the engine uses — not the user's requested
// flag. Used both in the pre-send review and the post-send confirmation so the user can
// always tell after the fact whether they were actually anonymized (criterion 1).
func attributionResultLine(opts walletapi.TransferOptions) string {
	if opts.Attribution == walletapi.AttributionAnonymous &&
		anonymizeEffectiveAtRingsize(wallet.GetRingSize()) {
		return "ANONYMOUS (sender hidden in the decoy ring)"
	}
	return "HONEST (your sender address is visible to the receiver)"
}
