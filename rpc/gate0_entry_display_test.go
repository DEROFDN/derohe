package rpc

// GATE 0 — consumer teeth for the fail-closed SenderVerified flag.
//
// Entry.String() is the human-facing CLI consumer of attribution. It MUST NOT present an
// unverified sender (ring size > 2, where the attribution byte is attacker-chosen) as a trusted
// address, and MUST show a protocol-pinned ring-2 (or outgoing self-send) sender plainly. This
// pins the consumer sense so a flip of the SenderVerified polarity is caught.
//
// The shipped renderer follows the truth table documented on rpc.Entry.SenderVerified: a verified
// entry prints "Sender: <addr>", while an unverified one is WITHHELD and prints
// "Sender: unknown (unverifiable, ring size N)". These teeth assert against that shipped render.

import (
	"strings"
	"testing"
)

func TestGate0_EntryStringLabelsUnverifiedSender(t *testing.T) {
	const sender = "deroXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXsender"

	// ring > 2: SenderVerified false -> attribution is withheld, never shown as a trusted address.
	unverified := Entry{PayloadType: 0, Sender: sender, SenderVerified: false, RingSize: 16}
	out := unverified.String()
	if !strings.Contains(out, "unknown (unverifiable, ring size 16)") {
		t.Fatalf("unverified sender not marked unverifiable; got:\n%s", out)
	}
	if strings.Contains(out, sender) {
		t.Fatalf("unverified sender address must be withheld, not rendered; got:\n%s", out)
	}

	// ring 2: SenderVerified true -> must be shown plainly and NOT marked unverifiable.
	verified := Entry{PayloadType: 0, Sender: sender, SenderVerified: true, RingSize: 2}
	vout := verified.String()
	if strings.Contains(vout, "unverifiable") {
		t.Fatalf("verified ring-2 sender wrongly marked unverifiable; got:\n%s", vout)
	}
	if !strings.Contains(vout, "Sender: "+sender+"\n") {
		t.Fatalf("verified sender not shown plainly; got:\n%s", vout)
	}
}

// TestGate0_OutgoingSelfSendNotUnverified pins the MEDIUM-defect fix: an OUTGOING (self-sent)
// entry carries the wallet's OWN address as Sender, authenticated by construction. The two
// outgoing decode sites in daemon_communication.go set SenderVerified=true, so Entry.String()
// MUST show it plainly and MUST NOT withhold it as unverifiable. A regression that drops the
// outgoing SenderVerified=true assignment (defaulting it to false) would withhold the wallet's
// own send — this test goes RED on that.
func TestGate0_OutgoingSelfSendNotUnverified(t *testing.T) {
	const self = "deroSELFXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXself"

	// Mirrors the outgoing site after the fix: Incoming=false, Sender=own addr, SenderVerified=true.
	out := Entry{PayloadType: 0, Incoming: false, Sender: self, SenderVerified: true, RingSize: 16}.String()
	if strings.Contains(out, "unverifiable") {
		t.Fatalf("outgoing self-send wrongly withheld as unverifiable; the wallet's own authenticated "+
			"address must never be marked untrusted; got:\n%s", out)
	}
	if !strings.Contains(out, "Sender: "+self+"\n") {
		t.Fatalf("outgoing self-send sender not shown plainly; got:\n%s", out)
	}
}
