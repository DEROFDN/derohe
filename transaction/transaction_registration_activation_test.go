package transaction

import "testing"

// TestRegistrationActivationTopo guards the registration usability cooldown
// rule (the HF4 availability-style gate). A wallet registered at a given topo
// height only becomes active once at least `afterBlocks` final blocks have
// passed. It must reject when the window is not over yet and reject insane
// inputs (future registration, non-positive window, same block).
func TestRegistrationActivationTopo(t *testing.T) {
	cases := []struct {
		name     string
		reg, now int64
		after    int64
		want     bool
	}{
		{name: "not yet active (49 < 50)", reg: 1000, now: 1049, after: 50, want: false},
		{name: "just active (1000 + 50)", reg: 1000, now: 1050, after: 50, want: true},
		{name: "long active", reg: 1000, now: 2000, after: 50, want: true},
		{name: "same block", reg: 1000, now: 1000, after: 50, want: false},
		{name: "registration in the future (reorg/clock skew)", reg: 1100, now: 1000, after: 50, want: false},
		{name: "negative nowTopo", reg: 0, now: -1, after: 50, want: false},
		{name: "negative registrationTopo", reg: -5, now: 100, after: 50, want: false},
		{name: "zero window (disabled)", reg: 1000, now: 1000, after: 0, want: false},
		{name: "zero window, far apart", reg: 1000, now: 5000, after: 0, want: false},
		{name: "one block window", reg: 1000, now: 1001, after: 1, want: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RegistrationActivationTopo(c.reg, c.now, c.after); got != c.want {
				t.Fatalf("RegistrationActivationTopo(reg=%d, now=%d, after=%d) = %v, want %v",
					c.reg, c.now, c.after, got, c.want)
			}
		})
	}
}
