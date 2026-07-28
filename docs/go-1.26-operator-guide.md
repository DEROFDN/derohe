# Go 1.26 Operator Guide — Workaround C

## Quick Start (30 seconds)

Every `derod` process **must** have `GODEBUG=randmapiter=0` set. Without this, nodes running Go 1.26+ will produce different map iteration order and diverge from nodes running Go 1.17, causing a hard fork at the next block.

### Verify Before Upgrade

```bash
# Check what Go version your current derod was built with
derod --version

# Check if your service file already sets GODEBUG
cat /etc/systemd/system/derod.service | grep GODEBUG
```

### Set the Flag (Pick Your Platform)

#### systemd (Debian/Ubuntu/Most Servers)

Edit your service unit:

```bash
sudo systemctl edit derod.service
```

Add to the `[Service]` section:

```ini
Environment="GODEBUG=randmapiter=0"
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl restart derod
```

Verify it took effect:

```bash
cat /proc/$(pgrep derod)/environ | tr '\0' '\n' | grep GODEBUG
# Expected output: GODEBUG=randmapiter=0
```

#### Docker

Add to your `docker run` command:

```bash
docker run -e GODEBUG=randmapiter=0 -v /data:/data derohe
```

Or in `docker-compose.yml`:

```yaml
services:
  derod:
    image: derohe
    environment:
      - GODEBUG=randmapiter=0
    volumes:
      - /data:/data
```

#### Shell / Manual Start

```bash
export GODEBUG=randmapiter=0
derod --help  # or your normal start command
```

#### init.d / Custom Script

Add the export before the derod binary is invoked:

```bash
#!/bin/sh
export GODEBUG=randmapiter=0
exec /usr/local/bin/derod --data-dir /data
```

## How to Verify a Running Node

```bash
# Find derod PID
pgrep derod

# Check the process environment
cat /proc/<PID>/environ | tr '\0' '\n' | grep GODEBUG
```

**Must output:**
```
GODEBUG=randmapiter=0
```

If the line is missing or shows anything other than `randmapiter=0`, that node is at risk of consensus divergence. **Stop it immediately** and restart with the flag.

## If a Node Is Missing the Flag

1. **Alert** the team — this node may have diverged its state root from peers.
2. **Stop** the node immediately.
3. **Set** the flag (see platform-specific instructions above).
4. **Restart** the node.
5. **Check** the node re-syncs from stable height. If the node was running for a long time without the flag, it may need a full resync from a known-good peer.

## What `GODEBUG=randmapiter=0` Does

Since Go 1.0, maps have been iterated in a deliberately randomized order (to prevent programs from depending on iteration order). `randmapiter=0` disables the randomization, returning to Go 1.0-era deterministic map behavior.

This means:
- The **same** keys will always be visited in the **same** order, on every machine, every time.
- Nodes running Go 1.17 (which happens to iterate in a consistent order per binary) and Go 1.26 (with `randmapiter=0`) will produce identical iteration sequences.
- This **only** affects map iteration — no other behavior is changed.

## Cross-Version Consensus

The Go team guarantees `randmapiter=0` support through at least Go 1.30. This makes it safe for a heterogeneous network where some nodes are built with Go 1.17 and others with Go 1.26.

**Important:** When upgrading, perform a **rolling upgrade** — don't restart all nodes simultaneously. Ensure every node has the flag before the upgrade completes.

## Long-Term Risk

The `randmapiter` GODEBUG knob may be deprecated or removed in a future Go release. When that happens, the code patches from `docs/go-1.26-fix-patches/` (patches 1–6) must be applied to all consensus-critical map iteration sites to achieve deterministic behavior without the flag.

The patches are already documented and ready in `docs/go-1.26-fix-patches/`. When the flag is removed:
1. Apply patches 1–6 to the source
2. Remove `GODEBUG=randmapiter=0` from all service units
3. Rebuild and deploy

## Platform-Specific Notes

### Raspberry Pi / ARM

Some ARM builds may not support GODEBUG. Test with:

```bash
GODEBUG=randmapiter=0 derod --help
```

If the binary fails to start, you must apply the code patches instead.

### FreeBSD

The `randmapiter` GODEBUG knob is supported on FreeBSD. Use the same env var approach:

```bash
env GODEBUG=randmapiter=0 derod --data-dir /data
```

## Checklist

- [ ] Every `derod` service unit has `GODEBUG=randmapiter=0`
- [ ] Every Docker compose file includes `GODEBUG=randmapiter=0`
- [ ] Verified running node with `/proc/<pid>/environ`
- [ ] Node re-synced from stable height after restart
- [ ] Rolling upgrade performed (not simultaneous)
- [ ] Documented in ops runbook

## Troubleshooting

### "my node won't start after upgrade"

Check if `GODEBUG=randmapiter=0` is set. The derod binary may now require it.

### "node diverged from peers after upgrade"

This node was started without the flag. Stop it, set the flag, and re-sync from a known-good peer at a recent stable height.

### "I already applied the code patches"

If you applied the source code patches from `docs/go-1.26-fix-patches/` (patches 1–6), you do **not** need the `GODEBUG` flag for those sites. You still need patch 7 (gob replacement) regardless.
