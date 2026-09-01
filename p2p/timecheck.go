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

import "time"
import "math/rand"
import "runtime"

import "github.com/beevik/ntp"
import "github.com/go-logr/logr"

import "github.com/deroproject/derohe/globals"

// these servers automatically rotate every hour as per documentation
// we also rotate them randomly
// TODO support ipv6
var timeservers = []string{ // facebook/google do leap smearing, so they should not be mixed here
	"0.pool.ntp.org",
	"1.pool.ntp.org",
	"2.pool.ntp.org",
	"3.pool.ntp.org",
	"ntp1.hetzner.de",
	"ntp2.hetzner.de",
	"ntp3.hetzner.de",
	"time.cloudflare.com", // anycast
	"ntp.se",              // anycast
}

const clockDriftThreshold = time.Second

func clockDriftHint() string {
	switch runtime.GOOS {
	case "windows":
		return "Enable automatic time (Settings → Time & language → Set time automatically) or run as admin: w32tm /resync."
	case "darwin":
		return "Enable automatic time (System Settings → Date & Time → Set automatically)."
	case "linux":
		return "Enable NTP: timedatectl set-ntp true, or install/start chrony."
	default:
		return "Enable your OS automatic time sync (NTP)."
	}
}

func clockUnreachableHint() string {
	switch runtime.GOOS {
	case "windows":
		return "Allow outbound UDP/123; start the Windows Time service (w32tm)."
	case "darwin":
		return "Allow outbound UDP/123."
	case "linux":
		return "Allow outbound UDP/123; use systemd-timesyncd or chrony."
	default:
		return "Allow outbound UDP/123."
	}
}

// clockTracker emits loud, once-per-transition warnings (default log level).
var clockTracker = &clockState{}

// unreachableWarnCooldown caps how often the NTP-unreachable warning can
// repeat when connectivity is intermittent (successes reset the latch but
// must not produce a fresh warning more than once per cooldown).
const unreachableWarnCooldown = 10 * time.Minute

type clockState struct {
	driftWarned       bool
	lastUnreachableAt time.Time // zero = never warned; gates unreachable re-warns
}

// observe records one NTP attempt. ntpOK false means no server answered.
// Warnings print at default verbosity, once per state change.
func (s *clockState) observe(ntpOK bool, offset time.Duration, log logr.Logger, reason error) {
	if log.GetSink() == nil {
		return
	}
	if !ntpOK {
		// Warn on first failure, then at most once per cooldown. Successful
		// queries do not re-arm the warning — with intermittent connectivity
		// that would degenerate into a nag every minute or so.
		if s.lastUnreachableAt.IsZero() || time.Since(s.lastUnreachableAt) > unreachableWarnCooldown {
			s.lastUnreachableAt = time.Now()
			log.Error(reason, "Cannot reach NTP servers (UDP/123). Clock cannot be verified. "+clockUnreachableHint())
		}
		return
	}
	drifted := offset > clockDriftThreshold || offset < -clockDriftThreshold
	if drifted {
		if !s.driftWarned {
			s.driftWarned = true
			log.Error(nil, "CLOCK DRIFT: system time is more than 1s off NTP. Chain sync and mining rewards may fail. "+clockDriftHint(), "offset", offset)
		}
		return
	}
	if s.driftWarned {
		s.driftWarned = false
		log.Info("Clock is back in sync with NTP.", "offset", offset)
	}
}

func applyNTPOffset(offset time.Duration) {
	if offset.Milliseconds() < -50 || offset.Milliseconds() > 50 {
		globals.ClockOffsetNTP = offset
	} else {
		globals.ClockOffsetNTP = 0
	}
	globals.TimeIsInSyncNTP = true
}

func queryOneNTP(server string) (time.Duration, error) {
	response, err := ntp.Query(server)
	if err != nil {
		return 0, err
	}
	if err := response.Validate(); err != nil {
		// Keep a clearly-drifted offset even when Validate fails (libfaketime
		// and messy RTT can trip freshness/dispersion checks).
		if response.ClockOffset > clockDriftThreshold || response.ClockOffset < -clockDriftThreshold {
			return response.ClockOffset, nil
		}
		return 0, err
	}
	return response.ClockOffset, nil
}

// probeClockOnce runs a short synchronous NTP check before the background loop
// so a drifted clock is reported immediately at startup.
func probeClockOnce() {
	log := logger
	if log.GetSink() == nil {
		log = globals.Logger
	}
	var lastErr error
	for i := 0; i < 3 && i < len(timeservers); i++ {
		offset, err := queryOneNTP(timeservers[i])
		if err != nil {
			lastErr = err
			continue
		}
		applyNTPOffset(offset)
		clockTracker.observe(true, offset, log, nil)
		return
	}
	clockTracker.observe(false, 0, log, lastErr)
}

// continuously checks time for deviation if possible
const offsetWindowSize = 128

// offsetWindow is a fixed-size rolling average of NTP offsets.
// Zero samples are ignored (unused slots after flush).
type offsetWindow struct {
	samples [offsetWindowSize]time.Duration
	idx     int
}

func (w *offsetWindow) add(d time.Duration) time.Duration {
	w.samples[w.idx] = d
	w.idx = (w.idx + 1) % offsetWindowSize
	return w.avg()
}

func (w *offsetWindow) avg() time.Duration {
	var sum time.Duration
	var n time.Duration
	for _, o := range w.samples {
		if o != 0 {
			sum += o
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return sum / n
}

func (w *offsetWindow) flush() {
	*w = offsetWindow{}
}

func time_check_routine() {
	var win offsetWindow
	random := rand.New(globals.NewCryptoRandSource())
	timeinsync := false
	for {
		server := timeservers[random.Int()%len(timeservers)]

		if offset, err := queryOneNTP(server); err != nil {
			clockTracker.observe(false, 0, logger, err)
		} else {
			avg_offset := win.add(offset)
			now_in_sync := offset > -clockDriftThreshold && offset < clockDriftThreshold
			if now_in_sync && !timeinsync {
				// Clock just recovered: drop stale drifted samples so the
				// average (and GetInfo) converges immediately instead of
				// decaying for hours at the slow in-sync poll interval.
				win.flush()
				avg_offset = win.add(offset)
			}
			timeinsync = now_in_sync
			applyNTPOffset(avg_offset)
			clockTracker.observe(true, offset, logger, nil)
		}

		if !timeinsync {
			time.Sleep(5 * time.Second)
		} else {
			time.Sleep(time.Duration((random.Intn(60) + 60)) * time.Second)
		}
	}
}
