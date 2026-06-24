package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/derohe/walletapi"
)

// TestBuildTransferOptionsNoOp locks the backward-compat contract: with anonymize
// off and no decoys, buildTransferOptions MUST return the literal zero value so the
// engine reproduces today's behavior byte-for-byte (honest attribution, nil Ring →
// random ring selection). A regression here would silently change every default send.
func TestBuildTransferOptionsNoOp(t *testing.T) {
	opts := buildTransferOptions(false, nil)

	if opts != (walletapi.TransferOptions{}) {
		t.Fatalf("expected zero-value TransferOptions, got %+v", opts)
	}
	if opts.Ring != nil {
		t.Fatalf("expected nil Ring for no-op, got %+v", opts.Ring)
	}
	if opts.Attribution != walletapi.AttributionHonest {
		t.Fatalf("expected AttributionHonest for no-op, got %v", opts.Attribution)
	}

	// an empty (non-nil) members slice must also stay a no-op (Ring must stay nil).
	if got := buildTransferOptions(false, []string{}); got.Ring != nil {
		t.Fatalf("empty members must not produce a non-nil Ring, got %+v", got.Ring)
	}
}

// TestBuildTransferOptionsAnonymous verifies the opt-in paths flip exactly the
// expected fields and nothing else.
func TestBuildTransferOptionsAnonymous(t *testing.T) {
	opts := buildTransferOptions(true, nil)
	if opts.Attribution != walletapi.AttributionAnonymous {
		t.Fatalf("expected AttributionAnonymous, got %v", opts.Attribution)
	}
	if opts.Ring != nil {
		t.Fatalf("expected nil Ring with no decoys, got %+v", opts.Ring)
	}

	members := []string{"dero1qyabc"}
	opts = buildTransferOptions(false, members)
	if opts.Attribution != walletapi.AttributionHonest {
		t.Fatalf("decoys alone must not change attribution, got %v", opts.Attribution)
	}
	if opts.Ring == nil || len(opts.Ring.PreferredDecoys) != 1 {
		t.Fatalf("expected Ring with 1 preferred decoy, got %+v", opts.Ring)
	}
	if opts.Ring.Strict {
		t.Fatalf("Strict must default to false (forgiving skip + random-fill)")
	}
}

// TestAnonymizeEffectiveAtRingsize pins the single source of truth the CLI uses to
// decide what it PROMISES. It MUST agree with the engine: anonymity needs a decoy slot
// beyond [0]=sender, [1]=receiver, and the ring is a power of 2, so 2 has none and 4 is
// the first that does. (Teeth for O1/O2: change >= 4 to >= 2 here and this fails.)
func TestAnonymizeEffectiveAtRingsize(t *testing.T) {
	cases := map[int]bool{1: false, 2: false, 3: false, 4: true, 8: true, 16: true}
	for rs, want := range cases {
		if got := anonymizeEffectiveAtRingsize(rs); got != want {
			t.Fatalf("anonymizeEffectiveAtRingsize(%d) = %v, want %v", rs, got, want)
		}
	}
}

// newTestWallet creates a disk wallet in a temp dir and installs it as the package
// global so the wallet-dependent helpers (GetAddress, GetRingSize, SetRingSize) work.
func newTestWallet(t *testing.T) (cleanup func()) {
	t.Helper()
	// Create_Encrypted_Wallet mints testnet (deto1...) addresses by default; pin the
	// global network to testnet so globals.ParseValidateAddress accepts them (it rejects
	// cross-network addresses). Without this, every decoy fails to parse.
	prev := globals.Config
	globals.Config = config.Testnet
	t.Cleanup(func() { globals.Config = prev })

	dir := t.TempDir()
	path := filepath.Join(dir, "anon_test.db")
	w, err := walletapi.Create_Encrypted_Wallet(path, "x", crypto.RandomScalarBNRed())
	if err != nil {
		t.Fatalf("create wallet: %s", err)
	}
	wallet = w
	return func() {
		w.Close_Encrypted_Wallet()
		wallet = nil
		os.Remove(path)
	}
}

// TestResolveAnonymizeOrDowngrade is the O1 teeth: when the user asks to anonymize but
// the ringsize cannot host anonymity, the CLI MUST downgrade the flag to false so the
// built opts, the review line, and the post-send report all agree with the engine
// (which ships HONEST at ring<4). A false return here is the false-anonymity bug.
func TestResolveAnonymizeOrDowngrade(t *testing.T) {
	defer newTestWallet(t)()

	// ring 2: anonymize must be CANCELLED (downgraded to honest).
	wallet.SetRingSize(2)
	if resolveAnonymizeOrDowngrade(true) {
		t.Fatalf("ring 2: anonymize must downgrade to false (engine ships honest); got true")
	}
	// ring 4: anonymize survives.
	wallet.SetRingSize(4)
	if !resolveAnonymizeOrDowngrade(true) {
		t.Fatalf("ring 4: anonymize must survive; got false")
	}
	// honest request is never upgraded.
	if resolveAnonymizeOrDowngrade(false) {
		t.Fatalf("honest request must stay honest at any ringsize")
	}
}

// TestAttributionResultLine is the O2 teeth: the report derives the truth from the
// effective ringsize, NOT the requested flag. At ring<4 an AttributionAnonymous opts
// MUST report HONEST, so the user can tell after the fact.
func TestAttributionResultLine(t *testing.T) {
	defer newTestWallet(t)()
	anonOpts := walletapi.TransferOptions{Attribution: walletapi.AttributionAnonymous}

	wallet.SetRingSize(2)
	if got := attributionResultLine(anonOpts); got == "" || got[0] != 'H' {
		t.Fatalf("ring 2 anonymous opts must report HONEST, got %q", got)
	}
	wallet.SetRingSize(8)
	if got := attributionResultLine(anonOpts); got == "" || got[0] != 'A' {
		t.Fatalf("ring 8 anonymous opts must report ANONYMOUS, got %q", got)
	}
	// honest opts always report honest.
	if got := attributionResultLine(walletapi.TransferOptions{}); got[0] != 'H' {
		t.Fatalf("honest opts must report HONEST, got %q", got)
	}
}

// TestCollectDecoysRejectsRecipientAndSelf is the O5 teeth: collectDecoys must reject
// (a) the sender's own address, (b) the transfer recipient, and (c) an INTEGRATED
// alt-encoding of the recipient's pubkey — all are already real members of the ring,
// so curating them as decoys produces a duplicate pubkey that consensus rejects after
// signing. The check canonicalizes to BaseAddress so the alt-encoding cannot slip
// through a raw-string seen-map (the class of hole the #22 engine fix closes).
func TestCollectDecoysRejectsRecipientAndSelf(t *testing.T) {
	defer newTestWallet(t)()
	wallet.SetRingSize(16)

	self := wallet.GetAddress().String()

	// build a second, distinct wallet to act as the recipient.
	dir := t.TempDir()
	rw, err := walletapi.Create_Encrypted_Wallet(filepath.Join(dir, "rcpt.db"), "x", crypto.RandomScalarBNRed())
	if err != nil {
		t.Fatalf("create recipient wallet: %s", err)
	}
	defer rw.Close_Encrypted_Wallet()
	recipientBase := rw.GetAddress().String()

	// an INTEGRATED encoding of the recipient: same pubkey, different string.
	recipientIntegrated := rw.GetRandomIAddress8()
	if !recipientIntegrated.IsIntegratedAddress() {
		t.Fatalf("expected an integrated recipient encoding")
	}
	if recipientIntegrated.String() == recipientBase {
		t.Fatalf("integrated form must differ from base string (else the test proves nothing)")
	}

	// a clean, distinct decoy that MUST be accepted.
	dir2 := t.TempDir()
	dw, err := walletapi.Create_Encrypted_Wallet(filepath.Join(dir2, "decoy.db"), "x", crypto.RandomScalarBNRed())
	if err != nil {
		t.Fatalf("create decoy wallet: %s", err)
	}
	defer dw.Close_Encrypted_Wallet()
	goodDecoy := dw.GetAddress().String()

	// feed: self, recipient(base), recipient(integrated alt-encoding), a dupe of the
	// good decoy, and the good decoy. Only ONE (the good decoy) may survive. We drive
	// the readline-free core (decoyCollector) directly — the same code path the
	// interactive collectDecoys uses for every entry.
	c := newDecoyCollector(recipientBase)
	for _, d := range []string{
		self,
		recipientBase,
		recipientIntegrated.String(),
		goodDecoy,
		goodDecoy, // raw duplicate
	} {
		c.add(d)
	}
	members := c.members

	if len(members) != 1 {
		t.Fatalf("expected exactly 1 surviving decoy (the clean one), got %d: %v", len(members), members)
	}
	// the survivor must be the canonical base of the good decoy.
	wantBase := canonBase(goodDecoy)
	if members[0] != wantBase {
		t.Fatalf("survivor must be the canonical good decoy %q, got %q", wantBase, members[0])
	}
	// explicitly: neither recipient encoding nor self may have survived.
	for _, m := range members {
		if m == canonBase(recipientBase) {
			t.Fatalf("recipient leaked into decoys: %q", m)
		}
		if m == canonBase(self) {
			t.Fatalf("self leaked into decoys: %q", m)
		}
	}
}

// pubkeyG1 returns the bn256.G1 ring point for a base address string.
func pubkeyG1(t *testing.T, addr string) *bn256.G1 {
	t.Helper()
	a, err := rpc.NewAddress(addr)
	if err != nil {
		t.Fatalf("parse address %q: %s", addr, err)
	}
	return (*bn256.G1)(a.PublicKey)
}

// TestCuratedDecoysInTx is the O8 teeth: the post-send report must count curated decoys
// that ACTUALLY landed in the built ring, not echo the prompt-time request. The engine
// runs Strict:false, so an unregistered/dropped decoy is silently replaced by a random
// member; len(members) would over-report. We build a synthetic tx whose ring contains
// only SOME of the requested members and assert the count reflects the ring, not the ask.
func TestCuratedDecoysInTx(t *testing.T) {
	defer newTestWallet(t)()

	// mint four distinct registered-shaped wallets to use as curated members.
	mk := func(name string) string {
		dir := t.TempDir()
		w, err := walletapi.Create_Encrypted_Wallet(filepath.Join(dir, name+".db"), "x", crypto.RandomScalarBNRed())
		if err != nil {
			t.Fatalf("create %s: %s", name, err)
		}
		t.Cleanup(func() { w.Close_Encrypted_Wallet() })
		return w.GetAddress().String()
	}
	recipient := mk("recipient")
	landed1, landed2 := mk("landed1"), mk("landed2")
	dropped := mk("dropped") // requested but NOT placed in the ring (engine dropped it)
	unrelated := mk("unrelated")

	// build a tx whose (single, recipient-delivering) ring holds: sender, the recipient,
	// an unrelated random fill, and the two landed curated members — but NOT `dropped`.
	// This is exactly the Strict:false outcome where one curated decoy was unregistered
	// and a random member took its slot.
	ring := []*bn256.G1{
		pubkeyG1(t, wallet.GetAddress().String()),
		pubkeyG1(t, recipient),
		pubkeyG1(t, unrelated),
		pubkeyG1(t, landed1),
		pubkeyG1(t, landed2),
	}
	tx := &transaction.Transaction{}
	tx.Payloads = append(tx.Payloads, transaction.AssetPayload{
		Statement: crypto.Statement{Publickeylist: ring},
	})

	// requested = 3 curated (landed1, landed2, dropped); only 2 actually landed.
	requested := []string{landed1, landed2, dropped}
	got := curatedDecoysInTx(tx, requested, recipient)
	if got != 2 {
		t.Fatalf("curatedDecoysInTx must count ONLY decoys present in the built ring (2), got %d — the report would over-state curation", got)
	}

	// nil tx and empty members are both zero (no panic).
	if curatedDecoysInTx(nil, requested, recipient) != 0 {
		t.Fatalf("nil tx must count 0")
	}
	if curatedDecoysInTx(tx, nil, recipient) != 0 {
		t.Fatalf("empty members must count 0")
	}

	// a member duplicated in the request must not be double-counted off one ring slot.
	if n := curatedDecoysInTx(tx, []string{landed1, landed1}, recipient); n != 1 {
		t.Fatalf("a requested member duplicated must count once (1), got %d", n)
	}
}

// TestCuratedDecoysInTx_TokenTransferTwoRings is the O9 teeth: a token transfer builds
// TWO payloads each with its OWN ring — the token-SCID payload that DELIVERS to the
// recipient, and an auto-injected zero-SCID 0-value payload to a RANDOM member. A curated
// decoy that landed ONLY in the throwaway base ring (e.g. displaced from the token ring by
// independent random fill) provides ZERO cover for the delivered transfer, so it must NOT
// be counted. curatedDecoysInTx must scope to the recipient-delivering payload's ring.
func TestCuratedDecoysInTx_TokenTransferTwoRings(t *testing.T) {
	defer newTestWallet(t)()

	mk := func(name string) string {
		dir := t.TempDir()
		w, err := walletapi.Create_Encrypted_Wallet(filepath.Join(dir, name+".db"), "x", crypto.RandomScalarBNRed())
		if err != nil {
			t.Fatalf("create %s: %s", name, err)
		}
		t.Cleanup(func() { w.Close_Encrypted_Wallet() })
		return w.GetAddress().String()
	}
	self := wallet.GetAddress().String()
	recipient := mk("recipient")
	inTokenRing := mk("inTokenRing")   // curated decoy that landed in the DELIVERING ring
	onlyInBaseRing := mk("onlyInBase") // curated decoy that landed ONLY in the throwaway ring
	baseRandom := mk("baseRandom")     // the random member the base payload was sent to

	// payload 0: the token-SCID payload that DELIVERS to the recipient. Holds the curated
	// decoy `inTokenRing` but NOT `onlyInBaseRing`.
	tokenRing := []*bn256.G1{
		pubkeyG1(t, self),
		pubkeyG1(t, recipient),
		pubkeyG1(t, inTokenRing),
	}
	// payload 1: the auto-injected zero-SCID 0-value base payload to a RANDOM member.
	// Holds `onlyInBaseRing` (a curated decoy that happened to land here) but NOT the
	// recipient. Counting this ring would over-report cover the delivered transfer lacks.
	baseRing := []*bn256.G1{
		pubkeyG1(t, self),
		pubkeyG1(t, baseRandom),
		pubkeyG1(t, onlyInBaseRing),
	}
	tx := &transaction.Transaction{}
	tx.Payloads = append(tx.Payloads,
		transaction.AssetPayload{Statement: crypto.Statement{Publickeylist: tokenRing}},
		transaction.AssetPayload{Statement: crypto.Statement{Publickeylist: baseRing}},
	)

	// the user curated BOTH decoys; only ONE (inTokenRing) actually covers the delivery.
	requested := []string{inTokenRing, onlyInBaseRing}
	got := curatedDecoysInTx(tx, requested, recipient)
	if got != 1 {
		t.Fatalf("O9: must count ONLY the curated decoy in the recipient-delivering ring (1), got %d — a base-ring-only decoy was over-reported as cover", got)
	}

	// defensive fallback: an unresolvable recipient must NOT report 0 (it unions the rings,
	// the prior behavior) — better to over-count than to silently report no cover.
	if n := curatedDecoysInTx(tx, requested, "not-an-address"); n != 2 {
		t.Fatalf("unresolvable recipient must fall back to the union (2), got %d", n)
	}
}

// TestCanonBase confirms an integrated address and its base reduce to the SAME
// canonical key (the property the dedup relies on), and junk yields "".
func TestCanonBase(t *testing.T) {
	defer newTestWallet(t)()
	base := wallet.GetAddress().String()
	integrated := wallet.GetRandomIAddress8().String()

	if canonBase(base) != canonBase(integrated) {
		t.Fatalf("base and integrated of the same key must canonicalize equal:\n base=%q\n int =%q", canonBase(base), canonBase(integrated))
	}
	if canonBase("not-an-address") != "" {
		t.Fatalf("unparseable input must canonicalize to empty string")
	}
	if canonBase("   ") != "" {
		t.Fatalf("blank input must canonicalize to empty string")
	}
}
