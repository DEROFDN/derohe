package walletapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The sync loop must refresh every tracked SCID, not just the zero-SCID
// balance. In-process consumers read EntriesNative directly and expect token
// balances to stay live without pulling them through an API call; a loop that
// syncs only the zero SCID leaves them silently stale rather than erroring.
//
// This is a source guard, not a behavioural test: it asserts sync_loop still
// enumerates trackedSCIDs() and syncs each one. It cannot prove the sync
// itself works — only that the enumeration has not been dropped again.
func Test_SyncLoop_Refreshes_Tracked_SCIDs(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "daemon_communication.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon_communication.go: %v", err)
	}

	var loop *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "sync_loop" && fn.Recv != nil {
			loop = fn
			break
		}
	}
	if loop == nil {
		t.Fatal("sync_loop not found in daemon_communication.go")
	}

	var callsTrackedSCIDs, syncsALoopVariable bool
	ast.Inspect(loop, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "trackedSCIDs":
			callsTrackedSCIDs = true
		case "Sync_Wallet_Memory_With_Daemon_internal":
			// The argument must be a plain identifier that is NOT the
			// zero-value hash declared in the loop, i.e. a range variable.
			if len(call.Args) == 1 {
				if ident, ok := call.Args[0].(*ast.Ident); ok && ident.Name != "zerohash" {
					syncsALoopVariable = true
				}
			}
		}
		return true
	})

	if !callsTrackedSCIDs {
		t.Error("sync_loop no longer calls trackedSCIDs(): tracked token balances will go stale")
	}
	if !syncsALoopVariable {
		t.Error("sync_loop only syncs the zero SCID: tracked token balances will go stale")
	}
}
