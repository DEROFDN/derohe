// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package rpc

import (
	"strings"
	"testing"
)

// Test_Entry_String_SenderTruthTable pins Entry.String()'s Sender line to the
// renderer truth table documented on SenderVerified (PR #21 review finding #6):
// a scrubbed attribution must read as a deliberate refusal — never a bare
// "Sender: " line that looks like a decode bug — and stay distinct from an
// actual decode failure.
func Test_Entry_String_SenderTruthTable(t *testing.T) {
	cases := []struct {
		name   string
		e      Entry
		want   string
		forbid string
	}{
		{
			name: "verified sender is shown",
			e:    Entry{Incoming: true, PayloadType: 0, Sender: "deto1qyexampleaddress", SenderVerified: true, RingSize: 2},
			want: "Sender: deto1qyexampleaddress\n",
		},
		{
			name:   "scrubbed ring>2 renders unverifiable with ring size",
			e:      Entry{Incoming: true, PayloadType: 0, Sender: "", SenderVerified: false, RingSize: 4},
			want:   "Sender: unknown (unverifiable, ring size 4)\n",
			forbid: "Sender: \n",
		},
		{
			name:   "decode failure renders distinctly from a scrub",
			e:      Entry{Incoming: true, PayloadType: 0, Sender: "", SenderVerified: false, RingSize: 4, PayloadError: "short payload"},
			want:   "Sender: unknown (payload decode failed)\n",
			forbid: "unverifiable",
		},
	}

	for _, c := range cases {
		out := c.e.String()
		if !strings.Contains(out, c.want) {
			t.Fatalf("%s: rendered output missing %q:\n%s", c.name, c.want, out)
		}
		if c.forbid != "" && strings.Contains(out, c.forbid) {
			t.Fatalf("%s: rendered output must not contain %q:\n%s", c.name, c.forbid, out)
		}
	}
}
