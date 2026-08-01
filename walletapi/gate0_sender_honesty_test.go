package walletapi

// GATE 0 — receiver-side sender-honesty + the latent out-of-bounds crash fix.
//
// These tests pin the two guarantees the carrier/rotation work depends on, at the two
// sender-index decode sites in daemon_communication.go (ENCRYPTED_DEFAULT_PAYLOAD_CBOR and
// ENCRYPTED_DEFAULT_PAYLOAD_CBOR_V2):
//
//  1. NO OUT-OF-BOUNDS PANIC. Publickeylist has exactly RingSize entries (indices
//     0..RingSize-1). The original guard `sender_idx <= RingSize` admits sender_idx == RingSize,
//     which indexes one past the slice and panics the receiver. A peer can set the self-declared
//     payload[0] byte to exactly RingSize, so this is a remotely-triggerable receiver crash.
//     The fix is the strict bound `sender_idx < RingSize`.
//
//  2. SENDER VERIFIED ONLY AT RING 2 (fail-closed). At ring 2 the counterparty is unambiguous,
//     so the resolved Sender is trustworthy (SenderVerified == true). At ring > 2 the sender
//     index is attacker-chosen and unauthenticated, so Sender is only a claim and SenderVerified
//     must be false. Zero-value false == not verified, so a forgotten flag defaults to untrusted.
//
// UNLIKE the prior generation of this test, there is NO hand-copied mirror of the guard here:
// these tests call resolveSenderGate0 in gate0_sender_honesty.go, which is the EXACT function the
// two real decode sites call. The bound and the honesty classification live in exactly one tested
// place, so the test cannot stay green while the real guard regresses — there is nothing to drift.

import "testing"

func TestGate0_NoOOBOnMalformedPayload0(t *testing.T) {
	// The exact attack: a peer sets payload[0] == RingSize at ring > 2. Under the old `<=` guard
	// this indexed Publickeylist[RingSize] (one past the slice) and panicked. The strict bound
	// must reject it without resolving a sender and without panicking.
	for _, ringSize := range []uint{4, 8, 16, 64, 128} {
		if _, resolved, _ := resolveSenderGate0(byte(ringSize), ringSize, false); resolved {
			t.Fatalf("ringSize=%d: sender_idx==RingSize must NOT resolve (it is out of bounds); "+
				"the guard regressed to `<=` and would panic on the real Publickeylist", ringSize)
		}
		// one past also: RingSize+1 must likewise be rejected
		if _, resolved, _ := resolveSenderGate0(byte(ringSize+1), ringSize, false); resolved {
			t.Fatalf("ringSize=%d: sender_idx>RingSize must NOT resolve", ringSize)
		}
		// the last valid index RingSize-1 MUST still resolve (we didn't over-tighten)
		if _, resolved, _ := resolveSenderGate0(byte(ringSize-1), ringSize, false); !resolved {
			t.Fatalf("ringSize=%d: sender_idx==RingSize-1 is the last valid index and must resolve", ringSize)
		}
	}
}

func TestGate0_VerifiedOnlyAtRing2(t *testing.T) {
	cases := []struct {
		name         string
		ringSize     uint
		wantVerified bool
	}{
		{"ring2_verified", 2, true},
		{"ring4_unverified", 4, false},
		{"ring16_unverified", 16, false},
		{"ring64_unverified", 64, false},
		{"ring128_unverified", 128, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, verified := resolveSenderGate0(0x00, c.ringSize, false); verified != c.wantVerified {
				t.Fatalf("ringSize=%d: SenderVerified=%v, want %v (fail-closed: only ring 2 is verified)",
					c.ringSize, verified, c.wantVerified)
			}
		})
	}
}

func TestGate0_Ring2ResolvesCounterpartySlot(t *testing.T) {
	// At ring 2 the resolved index is the OTHER slot relative to the receiver's own scan position:
	// j==0 (counterpartySlot true) -> idx 1, otherwise idx 0. This is protocol-pinned and verified.
	if idx, resolved, verified := resolveSenderGate0(0xFF, 2, true); !resolved || idx != 1 || !verified {
		t.Fatalf("ring2 counterparty slot: got idx=%d resolved=%v verified=%v, want idx=1 resolved=true verified=true", idx, resolved, verified)
	}
	if idx, resolved, verified := resolveSenderGate0(0xFF, 2, false); !resolved || idx != 0 || !verified {
		t.Fatalf("ring2 own slot: got idx=%d resolved=%v verified=%v, want idx=0 resolved=true verified=true", idx, resolved, verified)
	}
}

func TestGate0_OutgoingSelfSendIsVerified(t *testing.T) {
	// Producer-side teeth for the MEDIUM-defect fix. An OUTGOING (self-sent) entry carries the
	// wallet's OWN address as Sender, authenticated by construction. Both outgoing decode sites in
	// daemon_communication.go set entry.SenderVerified = outgoingSenderVerifiedGate0() — the EXACT
	// function this test calls (single source of truth, no mirror to drift). The verdict must be
	// true so the wallet's own send is never mislabelled "(unverified)" by Entry.String(). A
	// regression to the fail-open default (false) is caught here and goes RED.
	if !outgoingSenderVerifiedGate0() {
		t.Fatalf("outgoing self-send must be verified (the wallet built the tx; its own address is " +
			"authenticated by construction) — defaulting to false mislabels it (unverified)")
	}
}

func TestGate0_NeverPanicsAcrossAllBytes(t *testing.T) {
	// Exhaustive: no payload[0] value, at any plausible ring size, may panic, and no resolved
	// index may ever be out of bounds (which is what would panic the real Publickeylist access).
	for _, ringSize := range []uint{2, 4, 8, 16, 64, 128} {
		for b := 0; b < 256; b++ {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("ringSize=%d byte=%d: panicked: %v", ringSize, b, r)
					}
				}()
				idx, resolved, _ := resolveSenderGate0(byte(b), ringSize, b%2 == 0)
				if resolved && idx >= ringSize {
					t.Fatalf("ringSize=%d byte=%d: resolved with out-of-bounds idx %d (would panic Publickeylist)", ringSize, b, idx)
				}
			}()
		}
	}
}
