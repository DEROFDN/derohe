package p2p

import "bytes"
import "errors"
import "runtime"
import "strings"
import "testing"
import "time"

import "github.com/go-logr/logr"
import "github.com/go-logr/zapr"
import "go.uber.org/zap"
import "go.uber.org/zap/zapcore"

func testLogger() (logr.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	enc := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	core := zapcore.NewCore(enc, zapcore.AddSync(buf), zapcore.InfoLevel)
	return zapr.NewLogger(zap.New(core)), buf
}

func TestClockState_WarnsOnceOnDrift(t *testing.T) {
	log, buf := testLogger()
	s := &clockState{}
	s.observe(true, 5*time.Second, log, nil)
	s.observe(true, 6*time.Second, log, nil)
	out := buf.String()
	if strings.Count(out, "CLOCK DRIFT") != 1 {
		t.Fatalf("expected exactly one CLOCK DRIFT warning, got:\n%s", out)
	}
}

func TestClockState_RecoveryOnce(t *testing.T) {
	log, buf := testLogger()
	s := &clockState{}
	s.observe(true, 5*time.Second, log, nil)
	s.observe(true, 10*time.Millisecond, log, nil)
	s.observe(true, 20*time.Millisecond, log, nil)
	out := buf.String()
	if strings.Count(out, "CLOCK DRIFT") != 1 {
		t.Fatalf("expected one CLOCK DRIFT, got:\n%s", out)
	}
	if strings.Count(out, "back in sync") != 1 {
		t.Fatalf("expected one recovery message, got:\n%s", out)
	}
}

func TestClockState_UnreachableOnce(t *testing.T) {
	log, buf := testLogger()
	s := &clockState{}
	s.observe(false, 0, log, nil)
	s.observe(false, 0, log, nil)
	out := buf.String()
	if strings.Count(out, "Cannot reach NTP") != 1 {
		t.Fatalf("expected one unreachable warning, got:\n%s", out)
	}
}

func TestClockState_SuccessDoesNotReArm(t *testing.T) {
	log, buf := testLogger()
	s := &clockState{}
	s.observe(false, 0, log, errors.New("timeout a"))
	s.observe(true, 5*time.Millisecond, log, nil) // resets nothing
	s.observe(false, 0, log, errors.New("timeout b"))
	out := buf.String()
	if strings.Count(out, "Cannot reach NTP") != 1 {
		t.Fatalf("success must not re-arm unreachable warning inside cooldown, got:\n%s", out)
	}
}

func TestClockHints_NonEmpty(t *testing.T) {
	if clockDriftHint() == "" || clockUnreachableHint() == "" {
		t.Fatal("OS clock hints must be non-empty")
	}
	// This builder is linux; keep the linux wording pinned so a GOOS switch
	// regression is obvious in CI.
	if runtime.GOOS == "linux" {
		if !strings.Contains(clockDriftHint(), "timedatectl") {
			t.Fatalf("linux drift hint: %s", clockDriftHint())
		}
		if !strings.Contains(clockUnreachableHint(), "chrony") {
			t.Fatalf("linux unreachable hint: %s", clockUnreachableHint())
		}
	}
}

func TestClockState_UnreachableCooldown(t *testing.T) {
	log, buf := testLogger()
	s := &clockState{}
	errA := errors.New("timeout a")
	errB := errors.New("timeout b")

	s.observe(false, 0, log, errA)
	if got := strings.Count(buf.String(), "Cannot reach NTP"); got != 1 {
		t.Fatalf("first failure should warn once, got %d:\n%s", got, buf.String())
	}

	// 6 minutes later — inside cooldown: silent even after an interleaved
	// success (which resets the latch but not the cooldown clock).
	s.lastUnreachableAt = time.Now().Add(-6 * time.Minute)
	s.observe(true, 5*time.Millisecond, log, nil)
	s.observe(false, 0, log, errB)
	if got := strings.Count(buf.String(), "Cannot reach NTP"); got != 1 {
		t.Fatalf("re-warn inside 10m cooldown, got %d:\n%s", got, buf.String())
	}

	// 11 minutes since last warning — cooldown expired: warn again.
	s.lastUnreachableAt = time.Now().Add(-11 * time.Minute)
	s.observe(false, 0, log, errB)
	if got := strings.Count(buf.String(), "Cannot reach NTP"); got != 2 {
		t.Fatalf("cooldown expiry should allow one re-warn, got %d:\n%s", got, buf.String())
	}
}

func TestClockState_SmallOffsetSilent(t *testing.T) {
	log, buf := testLogger()
	s := &clockState{}
	s.observe(true, 200*time.Millisecond, log, nil)
	if buf.Len() != 0 {
		t.Fatalf("small offset should be silent, got:\n%s", buf.String())
	}
}
