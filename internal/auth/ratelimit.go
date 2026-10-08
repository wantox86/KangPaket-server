package auth

import (
	"sync"
	"time"
)

// Limiter is an in-memory sliding-window limiter keyed by string.
type Limiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
	now    func() time.Time
}

func NewLimiter(limit int, window time.Duration) *Limiter {
	return &Limiter{limit: limit, window: window, hits: map[string][]time.Time{}, now: time.Now}
}

// Allow records an attempt for key. When denied, retryAfter says how long until a slot frees.
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cutoff := now.Add(-l.window)
	hs := l.hits[key]
	i := 0
	for i < len(hs) && !hs[i].After(cutoff) {
		i++
	}
	hs = hs[i:]
	if len(hs) >= l.limit {
		l.hits[key] = hs
		return false, hs[0].Add(l.window).Sub(now)
	}
	l.hits[key] = append(hs, now)
	return true, 0
}

// Cleanup drops keys with no attempts inside the window.
func (l *Limiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := l.now().Add(-l.window)
	for k, hs := range l.hits {
		if len(hs) == 0 || !hs[len(hs)-1].After(cutoff) {
			delete(l.hits, k)
		}
	}
}

func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.hits)
}

// SetClock overrides the time source (tests).
func (l *Limiter) SetClock(f func() time.Time) {
	l.mu.Lock()
	l.now = f
	l.mu.Unlock()
}
