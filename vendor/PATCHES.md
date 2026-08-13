# Local patches carried in vendor/

This tree contains dependencies that have been **modified locally**. Their contents match no
released version and no commit in the upstream repository.

`vendor/` here has no `vendor/modules.txt` and the repo has no `go.sum`, so Go does not verify
vendored contents against any declared version. That means **`go mod vendor` will silently
revert every patch listed below** — the build will still succeed and no warning will be printed.

Read this file before regenerating `vendor/`.

Each entry records the upstream revision the vendored copy is based on, so a patch can be
re-applied or dropped deliberately rather than by accident.

---

## golang.org/x/net — 5 second dial timeout

**Base revision:** `v0.0.0-20171212005608-d866cfc389ce` (2017-12-12)
All files match that revision except `proxy/direct.go`.

**File:** `vendor/golang.org/x/net/proxy/direct.go`

```go
func (direct) Dial(network, addr string) (net.Conn, error) {
	//return net.Dial(network, addr)
        return net.DialTimeout(network, addr, 5 * time.Second)
}
```

Upstream calls `net.Dial` with no timeout. The patch bounds the dial at 5 seconds and adds the
`time` import.

**Consumer:** `globals/globals.go` (imports `golang.org/x/net/proxy`).

**If reverted:** proxy dials become unbounded.

---

## github.com/deroproject/graviton — KeyCountEstimate bound and return value

**Base revision:** `v0.0.0-20220130070622-2c248a53b2e1` (repository tip)
`extra.go` and `README.md` differ from it and from every other commit in the repo.

**File:** `vendor/github.com/deroproject/graviton/extra.go`, `Tree.KeyCountEstimate()`

```go
		depth_array = append(depth_array, len(c.node_path))
		if len(depth_array) >= 20 {
			break
		}
	}
	if len(depth_array) <= 19 {
		return int64(len(depth_array))
	}
```

Upstream has no early `break` (it walks the whole tree) and returns `int64(count)` when
`len(depth_array) <= 4`.

**Consumers — note this value crosses the p2p boundary:**

- `p2p/rpc_changeset.go:93`  — `response.KeyCount = current_balance_tree.KeyCountEstimate()`
- `p2p/rpc_changeset.go:104` — `response.SCKeyCount = current_sc_tree.KeyCountEstimate()`
- `p2p/rpc_treesection.go:42` — `response.KeyCount = topo_balance_tree.KeyCountEstimate()`

The function's own comment says *"very crude but only used for use display"*. That comment is
inaccurate: the value is sent to peers during chain sync.

**If reverted:** the early `break` is lost (full tree walk on every call) and the value returned
for small trees changes.

Note: this directory also contains a nested `vendor/gopkg.in/yaml.v2` subtree, which
`go mod vendor` never produces — it was copied by some other means.

---

## github.com/chzyer/readline — KickReader and ReadCloser

**Base revision:** `v1.5.1`. Only `operation.go` and `std.go` differ.

**File:** `vendor/github.com/chzyer/readline/operation.go`

Adds a `kickerchan chan struct{}` field, initialises it in `NewOperation`, adds a
`case <-o.kickerchan: return nil, nil` arm to the read select, and adds an exported
`KickReader()` method, commented *"Allow another thread to take the priority of reading"*.

**File:** `vendor/github.com/chzyer/readline/std.go`

Changes `FillableStdin.stdin` and the `NewFillableStdin` parameter from `io.Reader` to
`io.ReadCloser`, and adds `s.stdin.Close()` in `Close()`.

**If reverted:** `KickReader()` disappears (compile error at any call site) and stdin is no
longer closed.

---

## Not a patch, but easy to mistake for one

Many other vendored dependencies also match no released *tag* — they were vendored from
untagged commits. Those are not modified; they are simply mid-release snapshots. Example:
`github.com/lesismal/nbio` matches `v1.2.14-0.20220301150822-22a5357345f3` exactly.

A resolved revision map for the full tree is available in the audit that produced this file.
