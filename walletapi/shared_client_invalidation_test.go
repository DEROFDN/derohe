package walletapi

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
)

// The daemon client is process-wide. Invalidating it disconnects every wallet
// in the process, so a caller cancelling its own context must not be treated as
// evidence that the transport died.
func Test_ShouldInvalidateAfterCall(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	expired, cancelExpired := context.WithDeadline(context.Background(), deadlineInThePast())
	defer cancelExpired()

	cases := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"no error", context.Background(), nil, false},
		{"caller cancelled", cancelled, context.Canceled, false},
		{"caller deadline exceeded", expired, context.DeadlineExceeded, false},
		{"caller cancelled, transport error surfaced", cancelled, errors.New("use of closed network connection"), false},
		{"application error", context.Background(), &jrpc2.Error{Code: jrpc2.Code(-32602), Message: "invalid params"}, false},
		{"transport failure, caller still live", context.Background(), errors.New("use of closed network connection"), true},
		{"call budget expired, caller still live", context.Background(), context.DeadlineExceeded, true},
		{"nil caller context, transport failure", nil, errors.New("broken pipe"), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldInvalidateAfterCall(tc.ctx, tc.err); got != tc.want {
				t.Errorf("shouldInvalidateAfterCall(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// A dial that succeeds followed by a failed probe means the daemon is offline,
// not that the client should be torn down. Callers that log the error and carry
// on relied on the client staying installed before the connectivity rewrite.
//
// This is a source guard, not a behavioural test: it asserts the probe-failure
// branch marks the daemon offline instead of invalidating the shared client.
func Test_ProbeFailure_Does_Not_Discard_Client(t *testing.T) {
	for _, file := range []string{"daemon_connectivity.go", "daemon_connectivity_wasm.go"} {
		t.Run(file, func(t *testing.T) {
			fset := token.NewFileSet()
			parsed, err := parser.ParseFile(fset, file, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", file, err)
			}

			var connect *ast.FuncDecl
			for _, decl := range parsed.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if ok && fn.Recv == nil && (fn.Name.Name == "connectWithContext" || fn.Name.Name == "Connect") && len(fn.Body.List) > 3 {
					connect = fn
				}
			}
			if connect == nil {
				t.Fatalf("connect function not found in %s", file)
			}

			probe := findProbeFailureBranch(connect)
			if probe == nil {
				t.Fatalf("probe-failure branch not found in %s", file)
			}

			var invalidates bool
			ast.Inspect(probe, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "invalidateRPCClient" {
					invalidates = true
				}
				return true
			})

			if invalidates {
				t.Errorf("%s discards the shared RPC client when only the probe failed; "+
					"callers that continue past the error lose a usable client", file)
			}
		})
	}
}

// findProbeFailureBranch returns the body of the `if err = test_connectivity...`
// guard, which runs only when the dial already succeeded.
func findProbeFailureBranch(fn *ast.FuncDecl) *ast.BlockStmt {
	var found *ast.BlockStmt
	ast.Inspect(fn, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Init == nil {
			return true
		}
		assign, ok := ifStmt.Init.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if ident.Name == "test_connectivity" || ident.Name == "test_connectivity_with_context" {
			found = ifStmt.Body
		}
		return true
	})
	return found
}

func deadlineInThePast() time.Time {
	return time.Now().Add(-time.Second)
}
