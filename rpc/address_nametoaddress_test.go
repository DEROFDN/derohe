package rpc

import "testing"

// Twelve mainnet nameservice entries carry an empty stored value (ICEBERG,
// cracker, e=mc², ...). NameToAddress discarded the address constructor's
// error (addr, _ := NewAddressFromCompressedKeys(...)), so an empty value
// produced a nil *Address that was then dereferenced, panicking the handler.
//
// The fix guards on a nil address and returns. This test pins the two
// properties the fix relies on: an empty compressed key yields a nil
// *Address (so the handler bails instead of dereferencing nil), while the
// 33 all-zero bytes stored by legitimate zero-owned names yield a non-nil
// *Address (so those names still resolve exactly as before — no regression).
func TestNameToAddress_CompressedKeyValidation(t *testing.T) {
	if addr, _ := NewAddressFromCompressedKeys([]byte("")); addr != nil {
		t.Fatalf("empty compressed key must yield a nil address; the NameToAddress nil guard relies on it")
	}

	if addr, _ := NewAddressFromCompressedKeys(make([]byte, 33)); addr == nil {
		t.Fatalf("33 zero bytes must yield a non-nil address so zero-owned names still resolve")
	}
}
