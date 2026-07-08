package scanner

import (
	"net/http"
	"sync"
	"time"
)

type adaptiveThrottle struct {
	mu       sync.Mutex
	delay    time.Duration
	step     time.Duration
	maxDelay time.Duration
}

func newAdaptiveThrottle(opts Options) *adaptiveThrottle {
	if !opts.AdaptiveThrottle {
		return nil
	}
	step := time.Duration(opts.ThrottleStepMs) * time.Millisecond
	if step <= 0 {
		step = 100 * time.Millisecond
	}
	maxDelay := time.Duration(opts.ThrottleMaxDelayMs) * time.Millisecond
	if maxDelay <= 0 {
		maxDelay = 2 * time.Second
	}
	if maxDelay < step {
		maxDelay = step
	}
	return &adaptiveThrottle{
		step:     step,
		maxDelay: maxDelay,
	}
}

func (t *adaptiveThrottle) wait() {
	if t == nil {
		return
	}
	delay := t.currentDelay()
	if delay > 0 {
		time.Sleep(delay)
	}
}

func (t *adaptiveThrottle) recordStatus(statusCode int) {
	if t == nil {
		return
	}
	if shouldThrottleStatus(statusCode) {
		t.increase()
		return
	}
	if statusCode >= 200 && statusCode < 500 {
		t.decrease()
	}
}

func (t *adaptiveThrottle) recordFailure() {
	if t == nil {
		return
	}
	t.increase()
}

func (t *adaptiveThrottle) currentDelay() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.delay
}

func (t *adaptiveThrottle) increase() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.delay += t.step
	if t.delay > t.maxDelay {
		t.delay = t.maxDelay
	}
}

func (t *adaptiveThrottle) decrease() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.delay -= t.step / 2
	if t.delay < 0 {
		t.delay = 0
	}
}

func shouldThrottleStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}
