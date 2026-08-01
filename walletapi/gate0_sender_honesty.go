package walletapi

// GATE 0 — receiver-side sender-index resolution.
//
// The sender index byte (payload[0]) that arrives on an incoming transaction is SELF-DECLARED,
// attacker-chosen, and UNAUTHENTICATED. Two distinct hazards live here:
//
//  1. BOUNDS (remotely-triggerable crash): Publickeylist has exactly RingSize entries
//     (valid indices 0..RingSize-1). The original guard used "<=", which admits an index equal
//     to RingSize, indexing one PAST the slice and panicking the receiver. A peer can set the
//     byte to exactly RingSize to crash any receiver. The strict "<" below is the fix.
//
//  2. HONESTY (sender attribution is only a CLAIM at ring > 2): at ring size 2 the counterparty
//     is necessarily the sender, so resolved attribution is trustworthy. At ring size > 2 the
//     sender chose the attribution byte and it is unverified. The returned verified flag is
//     FAIL-CLOSED: it is true ONLY at ring size 2, false otherwise.
//
// resolveSenderGate0 is the SINGLE source of truth for both hazards. Both decode sites in
// daemon_communication.go and the GATE 0 tests call THIS function — there is no hand-copied
// mirror that can silently drift from the real site, and the bound exists in exactly one place.
//
//	senderIdxByte    : the self-declared, attacker-chosen payload[0] byte (UNAUTHENTICATED)
//	ringSize         : tx ring size; Publickeylist has exactly this many entries (idx 0..ringSize-1)
//	counterpartySlot : true when the receiver's own scan position (j==0 at the call site) makes the
//	                   other slot the sender at ring size 2
//
// Returns:
//
//	idx      : index into Publickeylist (only meaningful when resolved is true)
//	resolved : true iff idx is strictly in-bounds (idx < ringSize); never indexes one past
//	verified : true ONLY at ring size 2 (protocol-pinned). Fail-closed: false otherwise.
func resolveSenderGate0(senderIdxByte byte, ringSize uint, counterpartySlot bool) (idx uint, resolved, verified bool) {
	idx = uint(senderIdxByte)
	if ringSize == 2 {
		idx = 0
		if counterpartySlot {
			idx = 1
		}
		verified = true // ring size 2: the counterparty is unambiguously the sender
	}
	// ring > 2: verified stays false (fail-closed); idx is the attacker's claimed byte
	if idx < ringSize { // strict "<": idx == ringSize would index one past Publickeylist and panic
		resolved = true
	}
	return idx, resolved, verified
}

// outgoingSenderVerifiedGate0 is the single tested source of truth for the verification verdict on
// an OUTGOING (self-sent) entry. On an outgoing tx the wallet itself built the transaction and
// entry.Sender is set to the wallet's OWN address (w.account.Keys.Public.G1()), so the attribution
// is authenticated by construction — the most trustworthy attribution possible. It is therefore
// always verified, regardless of ring size. Both outgoing decode sites in daemon_communication.go
// call THIS function rather than hard-coding the constant, so the producer-side verdict lives in
// exactly one tested place and a regression to the fail-open default (false) is caught by the test.
func outgoingSenderVerifiedGate0() bool {
	return true
}
