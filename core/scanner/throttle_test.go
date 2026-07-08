package scanner

import (
	"net/http"
	"testing"
	"time"
)

func TestAdaptiveThrottleIncreasesAndCapsDelay(t *testing.T) {
	throttle := newAdaptiveThrottle(Options{
		AdaptiveThrottle:   true,
		ThrottleStepMs:     100,
		ThrottleMaxDelayMs: 250,
	})
	throttle.recordStatus(http.StatusTooManyRequests)
	throttle.recordStatus(http.StatusServiceUnavailable)
	throttle.recordFailure()

	if got := throttle.currentDelay(); got != 250*time.Millisecond {
		t.Fatalf("delay = %s, want 250ms", got)
	}
}

func TestAdaptiveThrottleDecreasesOnHealthyStatus(t *testing.T) {
	throttle := newAdaptiveThrottle(Options{
		AdaptiveThrottle:   true,
		ThrottleStepMs:     100,
		ThrottleMaxDelayMs: 500,
	})
	throttle.recordStatus(http.StatusTooManyRequests)
	throttle.recordStatus(http.StatusOK)

	if got := throttle.currentDelay(); got != 50*time.Millisecond {
		t.Fatalf("delay = %s, want 50ms", got)
	}
}

func TestNewAdaptiveThrottleDisabled(t *testing.T) {
	if throttle := newAdaptiveThrottle(Options{}); throttle != nil {
		t.Fatal("expected nil throttle when disabled")
	}
}
