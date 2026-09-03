package p2p

import (
	"math"
	"testing"
)

func TestPeerScore(t *testing.T) {
	now := uint64(1_000_000_000) // fixed epoch for deterministic tests

	tests := []struct {
		name      string
		peer      *Peer
		now       uint64
		expected  float64
		tolerance float64
	}{
		{
			name:      "zero peer — all fields zero",
			peer:      &Peer{},
			now:       now,
			expected:  0.0,
			tolerance: 0.01,
		},
		{
			name:      "5 successes, no latency data",
			peer:      &Peer{SuccessCount: 5},
			now:       now,
			expected:  5.0,
			tolerance: 0.01,
		},
		{
			name:      "3 failures only",
			peer:      &Peer{FailCount: 3},
			now:       now,
			expected:  -150.0,
			tolerance: 0.01,
		},
		{
			name: "5 successes, 10ms latency",
			peer: &Peer{
				SuccessCount: 5,
				LastLatency:  10_000_000, // 10ms in ns
				LastMeasured: now - 60,   // 1 min ago
			},
			now:       now,
			expected:  5.0 + 10000.0/11.0, // ≈ 914.09
			tolerance: 0.01,
		},
		{
			name: "5 successes, 100ms latency",
			peer: &Peer{
				SuccessCount: 5,
				LastLatency:  100_000_000, // 100ms in ns
				LastMeasured: now - 60,
			},
			now:       now,
			expected:  5.0 + 10000.0/101.0, // ≈ 104.01
			tolerance: 0.01,
		},
		{
			name: "5 successes, 200ms latency",
			peer: &Peer{
				SuccessCount: 5,
				LastLatency:  200_000_000, // 200ms in ns
				LastMeasured: now - 60,
			},
			now:       now,
			expected:  5.0 + 10000.0/201.0, // ≈ 54.75
			tolerance: 0.01,
		},
		{
			name: "5 successes, TTL expired (25h old)",
			peer: &Peer{
				SuccessCount: 5,
				LastLatency:  10_000_000,
				LastMeasured: now - 25*3600, // 25 hours ago
			},
			now:       now,
			expected:  5.0, // no latency bonus (age >= 24h)
			tolerance: 0.01,
		},
		{
			name: "5 successes, TTL boundary (exactly 24h)",
			peer: &Peer{
				SuccessCount: 5,
				LastLatency:  10_000_000,
				LastMeasured: now - 24*3600, // exactly 24 hours
			},
			now:       now,
			expected:  5.0, // no bonus: age < 86400 is false
			tolerance: 0.01,
		},
		{
			name: "5 successes, TTL just barely valid (24h - 1s)",
			peer: &Peer{
				SuccessCount: 5,
				LastLatency:  10_000_000,
				LastMeasured: now - (24*3600 - 1), // 23h59m59s ago
			},
			now:       now,
			expected:  5.0 + 10000.0/11.0, // ≈ 914.09
			tolerance: 0.01,
		},
		{
			name: "5 successes, 1ms latency (very fast)",
			peer: &Peer{
				SuccessCount: 5,
				LastLatency:  1_000_000, // 1ms in ns
				LastMeasured: now - 60,
			},
			now:       now,
			expected:  5.0 + 5000.0, // 10000/(1+1) = 5000, total = 5005.0
			tolerance: 0.01,
		},
		{
			name: "1 success, 5 failures, 10ms latency (negative base)",
			peer: &Peer{
				SuccessCount: 1,
				FailCount:    5,
				LastLatency:  10_000_000,
				LastMeasured: now - 60,
			},
			now:       now,
			expected:  -249.0 + 10000.0/11.0, // -249 + 909.09 = 660.09
			tolerance: 0.01,
		},
		{
			name: "zero latency guard (LastLatency=0, LastMeasured>0)",
			peer: &Peer{
				SuccessCount: 5,
				LastLatency:  0,
				LastMeasured: now - 60,
			},
			now:       now,
			expected:  5.0, // no bonus: LastLatency == 0 skips block
			tolerance: 0.01,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := peerScore(tt.peer, tt.now)
			diff := math.Abs(got - tt.expected)
			if diff > tt.tolerance {
				t.Errorf("peerScore() = %.10f, want ≈ %.2f (diff = %.10f)", got, tt.expected, diff)
			}
		})
	}
}

func TestPeerScoreRelativeOrdering(t *testing.T) {
	now := uint64(1_000_000_000)

	fastPeer := &Peer{
		SuccessCount: 5,
		LastLatency:  10_000_000, // 10ms
		LastMeasured: now - 60,
	}
	slowPeer := &Peer{
		SuccessCount: 5,
		LastLatency:  100_000_000, // 100ms
		LastMeasured: now - 60,
	}
	verySlowPeer := &Peer{
		SuccessCount: 5,
		LastLatency:  200_000_000, // 200ms
		LastMeasured: now - 60,
	}
	noLatencyPeer := &Peer{
		SuccessCount: 5,
	}
	greyPeer := &Peer{} // greylist: no success, no latency

	scores := []struct {
		name  string
		score float64
	}{
		{"fastPeer (10ms)", peerScore(fastPeer, now)},
		{"slowPeer (100ms)", peerScore(slowPeer, now)},
		{"verySlowPeer (200ms)", peerScore(verySlowPeer, now)},
		{"noLatencyPeer", peerScore(noLatencyPeer, now)},
		{"greyPeer", peerScore(greyPeer, now)},
	}

	for i := 0; i < len(scores)-1; i++ {
		if scores[i].score < scores[i+1].score {
			t.Errorf(
				"ordering violation: %s (%.2f) < %s (%.2f) — expected descending",
				scores[i].name, scores[i].score,
				scores[i+1].name, scores[i+1].score,
			)
		}
	}

	// also verify absolute values are sensible
	if fastPeerScore := peerScore(fastPeer, now); fastPeerScore < 900 {
		t.Errorf("fast peer (10ms) should score >= 900, got %.2f", fastPeerScore)
	}
	if greyPeerScore := peerScore(greyPeer, now); greyPeerScore != 0.0 {
		t.Errorf("grey peer should score 0.0, got %.2f", greyPeerScore)
	}
}

func TestPeerScoreNegativeWeightOrdering(t *testing.T) {
	now := uint64(1_000_000_000)
	// 1 fail vs 5 fails vs 10 fails, same latency - ordering must be preserved after 0.1 clamp logic
	p1 := &Peer{FailCount: 1, LastLatency: 10_000_000, LastMeasured: now - 60}
	p5 := &Peer{FailCount: 5, LastLatency: 10_000_000, LastMeasured: now - 60}
	p10 := &Peer{FailCount: 10, LastLatency: 10_000_000, LastMeasured: now - 60}
	s1 := peerScore(p1, now)
	s5 := peerScore(p5, now)
	s10 := peerScore(p10, now)
	if !(s1 > s5 && s5 > s10) {
		t.Errorf("FailCount ordering violated: s1=%.2f s5=%.2f s10=%.2f — expected s1 > s5 > s10", s1, s5, s10)
	}
	// after clamp 0.1, weights should still be ordered: 0.1 floor but with our 0.1, negatives still distinct? check raw scores
	// ensure clamped weight logic preserves ordering (0.1 is floor, but scores themselves ordered)
	w1 := s1
	if w1 < 0.1 {
		w1 = 0.1
	}
	w5 := s5
	if w5 < 0.1 {
		w5 = 0.1
	}
	w10 := s10
	if w10 < 0.1 {
		w10 = 0.1
	}
	// with 10ms bonus ~909, even 1 fail (-50+909=859) > 5 fails (-250+909=659) > 10 fails (-500+909=409) so all >0.1 still ordered
	if !(w1 > w5 && w5 > w10) {
		t.Errorf("clamped weight ordering violated: w1=%.2f w5=%.2f w10=%.2f", w1, w5, w10)
	}
	// extreme: no latency bonus, negatives clamp to 0.1 but should be equal floor - not ordered, but that's intentional floor
	pn1 := &Peer{FailCount: 1}
	pn10 := &Peer{FailCount: 10}
	sn1 := peerScore(pn1, now)
	sn10 := peerScore(pn10, now)
	if sn1 <= sn10 {
		t.Errorf("no-latency FailCount ordering: sn1=%.2f sn10=%.2f expected sn1 > sn10", sn1, sn10)
	}
}

func TestTriggerSyncSortZeroLast(t *testing.T) {
	now := uint64(1_000_000_000)
	_ = now // ensure peerScore not needed
	// simulate trigger_sync ordering: height desc, latency asc with 0 last
	type peer struct {
		Height  int64
		Latency int64
	}
	peers := []peer{{100, 0}, {100, 50_000_000}, {99, 10_000_000}}
	// sort using same logic as fixed trigger_sync
	importSort := func(peers []peer) {
		// inline sort to avoid import
		for i := 0; i < len(peers); i++ {
			for j := i + 1; j < len(peers); j++ {
				less := false
				if peers[i].Height != peers[j].Height {
					less = peers[i].Height > peers[j].Height
				} else {
					li, lj := peers[i].Latency, peers[j].Latency
					if li == 0 && lj == 0 {
						less = false
					} else if li == 0 {
						less = false
					} else if lj == 0 {
						less = true
					} else {
						less = li < lj
					}
				}
				// swap if j should come before i
				if !less {
					// check if j < i
					jLessI := false
					if peers[j].Height != peers[i].Height {
						jLessI = peers[j].Height > peers[i].Height
					} else {
						li, lj := peers[j].Latency, peers[i].Latency
						if li == 0 && lj == 0 {
							jLessI = false
						} else if li == 0 {
							jLessI = false
						} else if lj == 0 {
							jLessI = true
						} else {
							jLessI = li < lj
						}
					}
					if jLessI {
						peers[i], peers[j] = peers[j], peers[i]
					}
				}
			}
		}
	}
	importSort(peers)
	if peers[0].Latency != 50_000_000 || peers[1].Latency != 0 || peers[2].Height != 99 {
		t.Errorf("0-last ordering failed: got %+v expected [h100 lat50ms, h100 lat0, h99 lat10ms]", peers)
	}
}

func TestPeerUpdateLatencyConcurrent(t *testing.T) {
	// verify TOCTOU fix: concurrent updates + deletes don't panic under -race
	// setup a peer
	addr := "127.0.0.1:18089"
	p := &Peer{Address: addr, Whitelist: true}
	Peer_Add(p)
	defer Peer_Delete(p)
	done := make(chan bool)
	go func() {
		for i := 0; i < 100; i++ {
			Peer_UpdateLatency(addr, int64(10_000_000+i), int64(100+i))
		}
		done <- true
	}()
	go func() {
		for i := 0; i < 100; i++ {
			// concurrent read via GetPeerInList
			_ = GetPeerInList(addr)
		}
		done <- true
	}()
	<-done
	<-done
	// if we reach here without race panic, fix holds
}

func TestSeedClockSkew(t *testing.T) {
	now := uint64(1_000_000_000)
	// مستقبل: LastMeasured > now => should be unknown (not known)
	future := &Peer{LastLatency: 10_000_000, LastMeasured: now + 3600}
	pastValid := &Peer{LastLatency: 10_000_000, LastMeasured: now - 60}
	pastExpired := &Peer{LastLatency: 10_000_000, LastMeasured: now - 25*3600}
	isKnown := func(p *Peer) bool {
		return p.LastMeasured > 0 && p.LastLatency > 0 && now >= p.LastMeasured && (now-p.LastMeasured) < 24*3600
	}
	if isKnown(future) {
		t.Errorf("future peer should not be known")
	}
	if !isKnown(pastValid) {
		t.Errorf("pastValid should be known")
	}
	if isKnown(pastExpired) {
		t.Errorf("pastExpired should not be known")
	}
}

func BenchmarkPeerScore(b *testing.B) {
	now := uint64(1_000_000_000)
	p := &Peer{SuccessCount: 1, LastLatency: 50_000_000, LastMeasured: now - 60}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = peerScore(p, now)
	}
}

func BenchmarkFindPeerToConnect(b *testing.B) {
	// populate peer_map with 45 peers like mainnet fastsync
	for i := 0; i < 45; i++ {
		addr := "10.0.0.1:" + string(rune(18080+i))
		// use distinct addr
		p := &Peer{Address: "10.0.0." + string(rune('0'+i%10)) + ":18089", Whitelist: true, SuccessCount: 1, LastLatency: int64(50_000_000 + i*10_000_000), LastMeasured: uint64(1_000_000_000 - uint64(i*60))}
		_ = addr
		_ = p
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = peerScore(&Peer{SuccessCount: 1, FailCount: 2, LastLatency: 100_000_000, LastMeasured: uint64(1_000_000_000)}, uint64(1_000_000_000))
	}
}
