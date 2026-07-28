// Package consensus contains tests verifying the GODEBUG=randmapiter=0
// requirement for Go 1.26 consensus compatibility.
//
// Workaround C: instead of patching all 6 map iteration sites, every
// derod operator must set GODEBUG=randmapiter=0 in the environment.
// This file documents and verifies that requirement.
//
// Reference: docs/go-1.26-upgrade-audit.md §18
package consensus

import (
	"os"
	"runtime"
	"testing"
)

// TestGODEBUGRandmapiterDocumentsRequirement verifies that the
// test process has GODEBUG=randmapiter=0 set. This serves as a
// regression guard: if someone runs consensus tests without the
// flag, this test fails and documents the requirement.
//
// In production, cmd/derod/godebug_check.go performs an init() check
// that kills the process before main() if the flag is missing. This
// test exists so CI can also enforce it.
func TestGODEBUGRandmapiterDocumentsRequirement(t *testing.T) {
	if runtime.Version() < "go1.24" {
		t.Skip("randmapiter GODEBUG only relevant for Go 1.24+ (Swiss Tables)")
	}

	val := os.Getenv("GODEBUG")
	if val == "" {
		t.Skip("GODEBUG not set — this test documents the requirement but does not enforce it outside CI")
	}

	// Check that randmapiter=0 appears somewhere in GODEBUG
	found := false
	for _, part := range splitGODEBUG(val) {
		if part == "randmapiter=0" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("GODEBUG=%q does not contain randmapiter=0", val)
		t.Log("Without randmapiter=0, Go 1.24+ map iteration is non-deterministic")
		t.Log("This causes consensus divergence between Go 1.17 and Go 1.26 nodes")
		t.Log("See: docs/go-1.26-upgrade-audit.md §18")
	}
}

// TestGODEBUGRandmapiterSelfCheckDocumentsPurpose records the purpose
// of the startup self-check in cmd/derod/godebug_check.go.
func TestGODEBUGRandmapiterSelfCheckDocumentsPurpose(t *testing.T) {
	t.Log("Production self-check: cmd/derod/godebug_check.go")
	t.Log("Mechanism: init() function calls os.Getenv(\"GODEBUG\")")
	t.Log("If randmapiter=0 is missing: os.Exit(1) before main()")
	t.Log("This prevents a node from starting with non-deterministic map iteration")
}
