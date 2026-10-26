# Seamless migration: confidential transfer path

## Design

The migration SCID is retained as a visible routing/intent marker, but native DERO no longer enters the DVM as `BurnValue`. The wallet routes `SC_DERO_Deposit` into an ordinary native-asset `TransferPayload0` transfer to the caller-selected destination. The standard DERO proof carries the encrypted balance changes; the recipient is placed at a randomized position among the transfer ring. Migration calls require a ring size of at least 16, matching the wallet's normal default.

The contract is a stateless `Migrate()` marker. It neither reads `DEROVALUE()` nor emits `SEND_DERO_TO_ADDRESS`; it cannot hold, forward, mint, refund, or otherwise account for the transferred value. The base-layer transaction owns value movement and rollback.

## On-chain visibility and privacy boundary

- Hidden from chain observers: transfer amount and which ring member is the source/recipient, subject to the existing DERO confidential-transfer construction and the ring's anonymity set.
- Visible: transaction timing, transaction type, the reserved SCID, the `Migrate` entrypoint, ring size/members, public fees, and transaction-size metadata. The migration itself remains identifiable.
- The wallet RPC process sees the amount and destination supplied by the caller. The on-chain privacy properties do not protect against a remote or compromised wallet service.
- No clear destination, refund address, amount, or opaque value handle is placed in migration `SCDATA`. There is no DVM refund path: an invalid transaction/call is rejected, not partially executed and refunded.
- The destination must be a registered account that the standard transfer builder can resolve. This first cut does not add one-time recipient/refund keys, a pool, or a general confidential DVM interface.

The design does not claim unlinkability beyond the existing ring transfer. The SCID and timing remain linkable to the same transaction, as accepted for the first phase.

## Wallet call

Call `SCInvoke` with the reserved SCID, a positive `SC_DERO_Deposit`, `SC_TOKEN_Deposit=0`, and `SC_RPC` containing exactly:

```go
rpc.Arguments{
    {Name: "destination", DataType: rpc.DataString, Value: destination},
    {Name: rpc.SCENTRYPOINT, DataType: rpc.DataString, Value: rpc.SeamlessMigrationEntrypoint},
}
```

The wallet extracts `destination` locally, strips it from `SCDATA`, and submits the amount as `rpc.Transfer{Destination: destination, Amount: SC_DERO_Deposit}` with `Burn=0`. The ordinary transfer handler appends the visible `SC_ACTION=SC_CALL` and reserved `SC_ID`. A zero ringsize resolves to the migration minimum of 16; a supplied ringsize below 16 and all token deposits are rejected. Do not supply `SC_ACTION`, `SC_ID`, `SCREFUND`, or other public arguments yourself.

## Consensus constraints

Before base-layer processing, consensus validates migration calls against the active HF4 height and requires exactly one each of `SC_ACTION=SC_CALL`, the reserved `SC_ID`, and `entrypoint="Migrate"`; no other `SCDATA` fields are accepted. The transaction must contain exactly one native DERO payload, `BurnValue=0`, and ring size >=16. Calls that violate the shape are rejected before state changes. If marker execution or the DVM no-external-transfer invariant fails, block processing rejects the transaction; it does not synthesize a clear-value refund.

The marker contract is installed deterministically at the configured activation height. This change does not set a mainnet activation height or perform a deployment. The v4 transaction-body commitment and reporting-only forensic supply integration are documented in [HF4 consensus and reporting integration](hf4-consensus.md).

## Verification

The migration validator, wallet routing, DVM, and simulator fork/reorg tests passed in the current worktree. The integration test passed 10 consecutive runs; full-repository tests were not run. Coverage includes:

- validator tests: correct shape, activation boundary, minimum ring, `BurnValue=0`, native-only payload, and rejection of extra/destination/refund `SCDATA`;
- wallet routing tests: destination and amount become a normal transfer, only the entrypoint survives in caller SCDATA, minimum ring is enforced, and token deposits are refused;
- DVM tests: stateless marker changes neither balances nor contract balance and cannot emit external transfers;
- simulator test: successful standard confidential transfer across activation/reorg, `BurnValue=0`, ring >=16, no clear recipient/refund in SCDATA, and rejection without balance changes for malformed calls or unregistered recipients.
