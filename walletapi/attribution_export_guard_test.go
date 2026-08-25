package walletapi

import (
	"os"
	"regexp"
	"testing"
)

// Test_AttributionExportGuard_UnverifiedSlotByteScrubbed locks the export-boundary
// scrub for an unverified sender attribution (ring > 2).
//
// When a received transfer's attribution is unverified, payload[0] is a sender-chosen,
// unauthenticated slot index. It must NOT survive into any exported Entry field: the raw
// byte re-derives the claimed sender via the public Publickeylist even after entry.Sender
// is blanked, because entry.Data carries the whole payload and Publickeylist is public.
//
// This guard pairs with Test_AttributionGuard_HonestWritesReceiverIndex (the send-side
// guardrail). It is a source-level guard (greps the two receive-as-receiver decode sites)
// so it needs no wallet/daemon harness; the behavioral end-to-end proof lives in the
// simulator harness. Its job is to make a future refactor that drops the scrub fail loud.
func Test_AttributionExportGuard_UnverifiedSlotByteScrubbed(t *testing.T) {
	src, err := os.ReadFile("daemon_communication.go")
	if err != nil {
		t.Fatalf("cannot read daemon_communication.go: %v", err)
	}

	// The scrub must blank entry.Sender when the attribution is unverified.
	blankSender := regexp.MustCompile(`if\s+!entry\.SenderVerified\s*\{[\s\S]*?entry\.Sender\s*=\s*""`)
	if n := len(blankSender.FindAll(src, -1)); n < 2 {
		t.Fatalf("EXPORT SCRUB MISSING: expected entry.Sender blanked under `if !entry.SenderVerified` at "+
			"both receive sites (CBOR + CBOR_V2); found %d. An unverified attribution must not export a "+
			"claimed sender string.", n)
	}

	// The scrub must zero the leading slot byte in the payload copy that feeds entry.Data,
	// so the byte cannot re-derive the sender via Publickeylist. Matches both the CBOR site
	// (`tx.Payloads[t].RPCPayload[1:]`) and the CBOR_V2 site (the local `payload[1:]`).
	zeroByte := regexp.MustCompile(`append\(\[\]byte\{0x00\},\s*[\w.\[\]]+\[1:\]\.\.\.\)`)
	if n := len(zeroByte.FindAll(src, -1)); n < 2 {
		t.Fatalf("EXPORT SCRUB MISSING: expected the attribution slot byte zeroed (`append([]byte{0x00}, "+
			"...[1:]...)`) in the exported payload at both receive sites; found %d. Without this, "+
			"entry.Data[0] still re-derives the claimed sender through the public Publickeylist.", n)
	}

	// At the two receive-as-receiver sites, entry.Data must be fed from the sanitized
	// `exported_payload`, never the raw payload. (The two SELF-side decode sites — where the
	// wallet decodes a tx IT sent — legitimately keep the raw payload and are not gated by
	// SenderVerified; they are out of scope and intentionally not matched here.)
	sanitizedExport := regexp.MustCompile(`entry\.Data\s*=\s*append\(entry\.Data,\s*exported_payload`)
	if n := len(sanitizedExport.FindAll(src, -1)); n < 2 {
		t.Fatalf("EXPORT SCRUB BYPASSED: expected entry.Data fed from the sanitized `exported_payload` at "+
			"both receive sites; found %d. Feeding the raw payload would export an unverified slot byte "+
			"that re-derives the claimed sender via the public Publickeylist.", n)
	}
}
