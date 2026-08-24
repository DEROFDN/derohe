# feat(consensus): registration-activation cooldown — a wallet becomes usable N blocks after registration (availability prototype, part of HF4)

## Summary

Adds the second half of the wallet anti-spam design and the seed of a future
**Proof-of-Availability** model: a freshly registered wallet is not usable
until it has waited **50 final blocks (≈ 15 min)** on-chain after its
registration. The delay is measured in confirmed chain-height progress, not
wall-clock time, so it stays correct even if block time changes in a later
fork.

**This ships as part of the single HF4 fork**, together with the registration
PoW target bump (24 → 28 bits, from #76). Both rules activate at
`MAJOR_HF4_HEIGHT`. Together they form the hybrid: **a mild creation PoW plus
a sustained, availability-style cooldown.**

> **Supersedes the discussion in #76 (closed).** #76's PoW discussion is what
> motivated this; both rules are now one fork. See the #76 thread for the
> original PoW/cooldown rationale from the devs.

## The hybrid and the PoA rationale

Devs have floated moving toward a proof-of-availability consensus, and asked
how that could be exercised at the wallet-registration level first. The idea:

- **Creation cost:** the registration PoW target bump (24 → 28 bits) makes
  mass registration non-trivial.
- **Sustained cost (this PR):** a fresh wallet must "live" on-chain for 50
  blocks before it can mine or spend traceably. This is the availability
  toggle: cost is measured in lived participation, not compute, which is what
  a PoA regime would later generalise.

A cooldown alone is cheap for honest users (no burning cycles on weak
hardware) and, unlike a bare wall-clock timer, is robust because it counts
confirmed blocks.

## What changed

- **config:** the cooldown activates at the existing `MAJOR_HF4_HEIGHT`
  (mainnet/testnet placeholders — see REQUIRED BEFORE MERGE) and
  `RegistrationActiveAfterBlocks = 50`.
- **transaction:** `RegistrationActivationTopo(regTopo, nowTopo, afterBlocks)`
  — the pure rule + unit tests.
- **blockchain:** a per-account **registration-height marker** is written into
  the balance tree (additive, keyed by the account's 16-byte mining identity)
  when a registration tx is executed.
- **Enforcement (all HF4-gated):**
  - **Sends:** ring-size-2 spends (sender recoverable via `Extract_signer`)
    are rejected from the mempool and from block inclusion while the wallet is
    too young.
  - **Mining:** GETWORK admission, work-template creation, miniblock
    insertion, and block acceptance all reject a miner still in the cooldown.

## Scope / privacy note (important)

DERO spending is **ring-signature** based. The true sender is only
deterministically recoverable at **ringsize == 2**. Therefore:

- The **send gate only applies to ringsize-2 senders.** Ring > 2 spends are
  anonymous by protocol design and cannot be attributed to one account — the
  gate cannot enforce without breaking ring anonymity. This is a known,
  accepted property, not a bypass we can close silently.
- The **mining gate applies uniformly**, because a miner exposes a concrete
  16-byte identity in every miniblock.

Post-HF4 registrations carry a marker and are gated; **legacy wallets
registered before HF4 carry no marker and are treated as already-active**
(they cannot be attributed a registration time and must not be locked out).

## REQUIRED BEFORE MERGE

`MAJOR_HF4_HEIGHT` is a placeholder (far in the future). The rule stays
dormant until it's set to a real height. Shipping with the placeholder is
unsafe — set the real mainnet/testnet activation heights first.

## Verification

- `go build ./...` clean.
- `go test ./transaction/ ./config/` pass.
- `go vet` clean of new warnings (remaining warnings are pre-existing dead
  code).
- TODO (before merge): private testnet / simulator run with
  `MAJOR_HF4_HEIGHT` low to confirm: (1) a fresh registration mines/spends
  only after N blocks, (2) a legacy (no-marker) account keeps working, (3) no
  regression to block validation speed (marker reads are per-admission tip
  tree lookups — consider an LRU like `IsAddressHashValid` if profiling shows
  a need).

## Related

- #76 (closed) — registration PoW target bump (24 → 28 bits), the
  creation-cost half of this design and the discussion that motivated it.
  Retained for history; both rules land together in HF4.
