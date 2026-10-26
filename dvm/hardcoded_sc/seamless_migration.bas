// Stateless migration marker. Native value is an ordinary confidential
// DERO transfer committed by the base-layer transaction proof. The contract
// never receives, reads, escrows, or forwards an amount.
Function Migrate() Uint64
10 RETURN 0
End Function
