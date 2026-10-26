# HF4 activation runbook

_Status: implementation-branch runbook. **Mainnet HF4 activation is unscheduled.** This document does not propose an activation height and is not a consensus proposal._

## Scope

The HF4 implementation on this branch contains three changes:

1. **v4 transaction-body commitment.** HF4 blocks bind the ordered serialized transaction bodies to `Block.Proof`. This changes v4 block IDs. See [HF4 consensus and reporting integration](hf4-consensus.md).
2. **Seamless migration path.** The reserved migration SCID becomes a stateless `Migrate` marker. Native DERO moves through a standard confidential transfer with `BurnValue=0` and ring size at least 16. See [Seamless migration](seamless-migration.md).
3. **HF3-gated forensic supply reporting.** `DERO.GetInfo` may include `created_supply_floor` and a `spendable_supply` adjustment on real mainnet at or after HF3. This is reporting only. It does not change consensus, issuance, or balances.

Not included in this branch: the proof-carrying supply checkpoint, corrected full-history accounting, claim/nullifier state, or the repair transition. Those remain design work.

## Roles

| Role | Responsibility |
|---|---|
| Release manager | Tag the commit, publish binaries and checksums, set the activation height, coordinate notices |
| Node operators | Upgrade `derod` before the activation height, monitor peers, blocks, and RPC |
| Miners / pools | Upgrade mining software before the activation height; publish a minimum version |
| Wallet operators | Upgrade wallet services; confirm migration calls use ring size at least 16 and `BurnValue=0` |
| Explorer operators | Upgrade the explorer; verify supply fields and block IDs after activation |
| Exchanges / integrators | Upgrade deposit/withdrawal nodes and confirm block-ID handling |

## Pre-activation gates

- [ ] Code review complete; branch merged to the release line
- [ ] CI green: build, vet, consensus/migration/supply/simulator tests, race tests
- [ ] Reproducible build hash published for the release commit
- [ ] Testnet rehearsal complete and recorded
- [ ] Activation height agreed and published
- [ ] Signed binaries and checksums published at least the agreed notice period before the height
- [ ] Wallet, explorer, exchange, and mining notices sent
- [ ] Abort criteria and communication channel agreed

Do not publish an activation height until every gate above is closed.

## Testnet rehearsal

Run at least three independently operated nodes from the release commit.

The two-node loopback rehearsal in [hf4-testnet-rehearsal.md](hf4-testnet-rehearsal.md) covers the v4 block path, the body commitment, the migration install, and the supply gate. It does not replace the multi-operator WAN rehearsal required here.

1. Build the release binary from the release commit:

   ```sh
   CGO_ENABLED=0 go build -trimpath -buildvcs=false -o derod ./cmd/derod
   sha256sum derod
   ```

2. Start the nodes with `--testnet`. Confirm the configured HF4 height in `config.Testnet.MAJOR_HF4_HEIGHT` and that all nodes agree on genesis.
3. Mine across the activation height. Confirm that v4 block IDs include the transaction-body commitment and that all nodes accept the same chain.
4. Submit a valid migration call: one native DERO payload, `BurnValue=0`, ring size 16, reserved SCID, `entrypoint="Migrate"`, destination a registered account. Confirm the destination is credited and no clear destination, amount, or refund appears in `SCDATA`.
5. Submit invalid calls and confirm rejection without any balance change:
   - ring size 15
   - `BurnValue != 0`
   - extra or destination `SCDATA`
   - unregistered destination
   - token deposit
6. Force a reorg across the activation boundary. Confirm acceptance and rejection behavior does not change.
7. Query `DERO.GetInfo` on testnet. Confirm `total_supply` and `spendable_supply` are present and that `created_supply_floor` is absent on testnet and simulator.
8. Stop the nodes and restart from the pre-HF4 binary at the boundary. Confirm the old binary does not silently accept post-HF4 v4 blocks; record the failure mode.

Record the commit hash, binary hashes, node versions, activation height, block IDs at the boundary, migration transaction IDs, and RPC output.

## Mainnet activation

1. Publish the activation height `H`, the release commit, binary checksums, and the upgrade deadline.
2. Node operators upgrade before `H` and verify the running version and commit.
3. Miners and pools upgrade before `H`. A pre-HF4 miner will not produce valid post-HF4 v4 blocks.
4. Wallets, explorers, and exchanges upgrade before `H`. Block-ID handling and supply display change.
5. At `H`, monitor:
   - block height and topological height
   - peer count and chain tips
   - block IDs and block acceptance
   - mempool growth and transaction acceptance
   - `DERO.GetInfo` supply fields
   - explorer block, transaction, and header pages
6. After HF3 on mainnet, verify:
   - `total_supply` remains the schedule calculation
   - `spendable_supply` includes the pinned net created-supply floor
   - `created_supply_floor` is present with `burn_attribution="unproven"`
   - the explorer renders the forensic record with the "not outstanding or circulating supply" caveat

### Verification commands

Use the node's configured RPC address and port:

```sh
curl -s http://127.0.0.1:<rpc-port>/json_rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"1","method":"DERO.GetInfo","params":{}}'
```

Check `height`, `topoheight`, `total_supply`, `spendable_supply`, and `created_supply_floor` in the response. Check the explorer header for the same values.

## Abort and rollback

HF4 is a consensus hard fork. There is no safe "downgrade after activation" path: a pre-HF4 node and a post-HF4 node disagree on v4 block IDs. Abort only **before** the activation height by keeping the height unscheduled or by publishing a new height and a new release.

If a defect is found after activation, the options are a coordinated chain rollback with all operators or a follow-up fork. Both require an explicit operator decision and a new release. Do not run mixed versions and expect normal operation.

## Residual risks

- The transaction-body commitment is a breaking v4 block-ID change. Mixed-version operation is unsafe.
- The migration path is a first cut. It does not add one-time recipient keys, a pool, or a general confidential DVM interface. The SCID and timing remain linkable to the transaction.
- The forensic supply record is reporting only. It is not a balance census, not circulating supply, and not proof that exploit coins are outstanding. Burn attribution is unproven.
- The proof-carrying supply checkpoint and the corrected accounting path are not implemented in this branch.
- No activation height is set by this document.
