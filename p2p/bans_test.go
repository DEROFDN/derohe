// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package p2p

import "testing"

// withNonBanList swaps nonbanlist for the duration of a test.
func withNonBanList(t *testing.T, entries []string) {
	t.Helper()
	old := nonbanlist
	nonbanlist = entries
	t.Cleanup(func() { nonbanlist = old })
}

func TestPinnedPeerIsNotReportedAsBanned(t *testing.T) {
	// a pin given WITHOUT a port, e.g. --add-priority-node=127.0.0.1
	withNonBanList(t, []string{"127.0.0.1"})

	if IsAddressInBanList("127.0.0.1") {
		t.Error("a pinned peer given without a port is reported as banned; " +
			"every caller reads that as 'refuse this address', which is the opposite of pinning it")
	}
}

func TestPortedPinAndSeedsStayBannable(t *testing.T) {
	// pins given WITH a port, and every compiled-in seed, are stored the same way
	withNonBanList(t, []string{"127.0.0.1:11011", "testnet.derofoundation.co:40401"})

	if IsAddressInBanList("127.0.0.1") {
		t.Fatal("a ported pin exempted a bare-IP lookup; it should not, callers only ever pass a bare IP")
	}

	if err := Ban_Address("127.0.0.1", 600); err != nil {
		t.Fatalf("could not ban a ported pin's resolved IP: %s", err)
	}
	if !IsAddressInBanList("127.0.0.1") {
		t.Error("a ported pin (or a compiled-in seed) could not be banned; " +
			"this exemption must never cover the documented ip:port form")
	}
	UnBan_Address("127.0.0.1")
}

func TestPinnedPeerMatchesByCanonicalIP(t *testing.T) {
	// an IPv6 loopback pin can be written several equivalent ways; nonbanlist
	// keeps whatever the operator typed, so the comparison must canonicalize.
	// Checked through Ban_Address, not a bare IsAddressInBanList read: an
	// unrecognised exemption and a plain "not banned yet" both read as false,
	// so only actually attempting the ban can tell them apart.
	withNonBanList(t, []string{"0:0:0:0:0:0:0:1"})

	if err := Ban_Address("::1", 600); err == nil {
		UnBan_Address("::1")
		t.Error("a pin written as a non-canonical IP form was banned instead of refused; " +
			"isNonBannable must compare parsed addresses, not raw strings")
	}
}

func TestBanAddressRefusesAPinnedPeer(t *testing.T) {
	withNonBanList(t, []string{"127.0.0.1"})

	if err := Ban_Address("127.0.0.1", 600); err == nil {
		t.Fatal("Ban_Address accepted a ban on a pinned peer with no error")
	}

	if IsAddressInBanList("127.0.0.1") {
		t.Error("a refused ban still ended up recorded as banned")
	}

	// the refusal must not have written anything for UnBan_Address to lie about later
	if err := UnBan_Address("127.0.0.1"); err == nil {
		t.Error("UnBan_Address succeeded for an address that was never actually banned")
	}
}

func TestOrdinaryBansAreUnaffected(t *testing.T) {
	withNonBanList(t, []string{"127.0.0.1"})

	if err := Ban_Address("203.0.113.7", 600); err != nil {
		t.Fatalf("an unrelated address could not be banned: %s", err)
	}
	if !IsAddressInBanList("203.0.113.7") {
		t.Error("a genuinely banned address is no longer reported as banned")
	}
	if IsAddressInBanList("203.0.113.8") {
		t.Error("an unrelated address is reported as banned")
	}
	UnBan_Address("203.0.113.7")
}
