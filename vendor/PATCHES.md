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

Upstream at that same revision **already has** the `>= 20` early break — that part is not a
local change. The entire local delta is two lines, the small-tree return:

```
upstream:  if len(depth_array) <= 4  { return int64(count) }
vendored:  if len(depth_array) <= 19 { return int64(len(depth_array)) }
```

Note `count` is a named return that is never assigned, so upstream returns **0** for trees with
≤4 keys. The local change reports the real sampled count instead, for trees up to 19 keys.

**Consumers — note this value crosses the p2p boundary:**

- `p2p/rpc_changeset.go:93`  — `response.KeyCount = current_balance_tree.KeyCountEstimate()`
- `p2p/rpc_changeset.go:104` — `response.SCKeyCount = current_sc_tree.KeyCountEstimate()`
- `p2p/rpc_treesection.go:42` — `response.KeyCount = topo_balance_tree.KeyCountEstimate()`

The function's own comment says *"very crude but only used for use display"*. That comment is
inaccurate. There are no display consumers in this tree. The value is serialized to peers as a
CBOR wire field (`p2p/wire_structs.go:111`, `cbor:"KEYCOUNT"`) and the receiving node computes
with it during fastsync:

- `p2p/chain_bootstrap.go:100-105` — `chunks_estm := response.KeyCount / chunksize`, then
  doubles `chunks` and increments `path_length` until it covers the estimate. This sets how many
  `Peer.TreeSection` requests the peer issues and the bit-depth it asks for.
- `p2p/chain_bootstrap.go:166-171,183,186` — same for `SCKeyCount`.
- `p2p/chain_bootstrap.go:224` — `} else if sc_response.KeyCount < 4096 {` selects the
  whole-tree path instead of chunked retrieval.

The handlers are registered unconditionally (`p2p/controller.go:662,671`), so every node with
p2p enabled emits this value; only the consumer side is behind fastsync.

This is not consensus-critical — the value never reaches block validation, hashing, or the
balance tree, and the consumer floors at 2 chunks and rounds to powers of two, so a moderately
wrong estimate costs round-trips rather than correctness. It is still not cosmetic, and should
not be changed on the assumption that it is.

**If reverted:** trees with ≤4 keys report `KeyCount` 0 instead of their real count, and trees
with 5–19 keys report `exp2(avg_depth)` instead of the exact count. No fastsync consumer branches
differently at those magnitudes (both still yield `chunks=2` and take the `< 4096` path), so the
practical effect is nil — but the reported number does change.

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
