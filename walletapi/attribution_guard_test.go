package walletapi

import (
	"os"
	"regexp"
	"testing"
)

// Test_AttributionGuard_HonestWritesReceiverIndex locks the sender-attribution
// guardrail: honest mode MUST write witness_index[1] (the receiver's own slot),
// never witness_index[0] (the real sender slot).
//
// Writing witness_index[0] would make the receiver-decryptable attribution byte
// reveal the true sender on every transfer, de-anonymizing senders chain-wide. A
// previous change to witness_index[0] was reverted before release for exactly this
// reason; this test makes that regression fail loud rather than ship silently.
//
// It is a source-level guard (greps the build site) so it needs no wallet/daemon
// harness and cannot be defeated by an unrelated refactor of the surrounding code.
func Test_AttributionGuard_HonestWritesReceiverIndex(t *testing.T) {
	src, err := os.ReadFile("transaction_build.go")
	if err != nil {
		t.Fatalf("cannot read transaction_build.go: %v", err)
	}

	// The honest default assignment for the attribution byte index.
	honest := regexp.MustCompile(`attrIndex\s*:=\s*witness_index\[1\]`)
	if !honest.Match(src) {
		t.Fatal("GUARDRAIL VIOLATED: honest attribution must be `attrIndex := witness_index[1]` " +
			"(receiver slot). If you changed it to witness_index[0], you would reveal the real " +
			"sender to every receiver. Do not change the honest byte.")
	}

	// Defense in depth: the honest assignment must not be the sender slot.
	forbidden := regexp.MustCompile(`attrIndex\s*:=\s*witness_index\[0\]`)
	if forbidden.Match(src) {
		t.Fatal("GUARDRAIL VIOLATED: honest attribution is set to witness_index[0] (the real " +
			"sender slot). This de-anonymizes the sender on every transfer. Revert to witness_index[1].")
	}
}
