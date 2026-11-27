package auth

import (
	"container/list"
	"sync"
	"time"
)

// DefaultMaxKeys caps the number of tracked keys per Limiter so memory stays
// bounded in small containers (e.g. 128 MiB).
const DefaultMaxKeys = 100_000

// maxEvictProbe bounds how many oldest entries evict inspects while looking for
// a non-blocked key to evict, keeping Allow O(1) amortized.
const maxEvictProbe = 64

type limiterEntry struct {
	key  string
	hits []time.Time
}

// Limiter is an in-memory sliding-window limiter keyed by string.
type Limiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	maxKeys int
	hits    map[string]*list.Element
	order   *list.List // front = least recently active, back = most recently active
	now     func() time.Time
}

func NewLimiter(limit int, window time.Duration) *Limiter {
	return NewLimiterWithMaxKeys(limit, window, DefaultMaxKeys)
}

// NewLimiterWithMaxKeys creates a Limiter bounded to maxKeys entries.
// Non-positive maxKeys falls back to DefaultMaxKeys.
func NewLimiterWithMaxKeys(limit int, window time.Duration, maxKeys int) *Limiter {
	if maxKeys <= 0 {
		maxKeys = DefaultMaxKeys
	}
	return &Limiter{
		limit:   limit,
		window:  window,
		maxKeys: maxKeys,
		hits:    make(map[string]*list.Element),
		order:   list.New(),
		now:     time.Now,
	}
}

func pruneHits(hs []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(hs) && !hs[i].After(cutoff) {
		i++
	}
	return hs[i:]
}

// Allow records an attempt for key. When denied, retryAfter says how long until a slot frees.
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cutoff := now.Add(-l.window)

	if el, exists := l.hits[key]; exists {
		e := el.Value.(*limiterEntry)
		e.hits = pruneHits(e.hits, cutoff)
		if len(e.hits) >= l.limit {
			if len(e.hits) == 0 {
				return false, l.window
			}
			return false, e.hits[0].Add(l.window).Sub(now)
		}
		e.hits = append(e.hits, now)
		l.order.MoveToBack(el)
		return true, 0
	}

	if l.limit <= 0 {
		return false, l.window
	}
	if len(l.hits) >= l.maxKeys {
		l.evict(cutoff)
	}
	el := l.order.PushBack(&limiterEntry{key: key, hits: []time.Time{now}})
	l.hits[key] = el
	return true, 0
}

// evict frees at least one slot when at maxKeys. It first drops expired keys
// from the front of the LRU list (O(1) amortized). If still full, it evicts the
// least-recently-active non-blocked key within maxEvictProbe steps (best-effort
// so currently-blocked keys are not trivially flushed), falling back to the
// oldest key overall if all probed keys are blocked.
func (l *Limiter) evict(cutoff time.Time) {
	for el := l.order.Front(); el != nil; {
		next := el.Next()
		e := el.Value.(*limiterEntry)
		if len(e.hits) == 0 || !e.hits[len(e.hits)-1].After(cutoff) {
			l.order.Remove(el)
			delete(l.hits, e.key)
			el = next
			continue
		}
		break
	}
	if len(l.hits) < l.maxKeys {
		return
	}
	var victim *list.Element
	for el, probed := l.order.Front(), 0; el != nil && probed < maxEvictProbe; el, probed = el.Next(), probed+1 {
		e := el.Value.(*limiterEntry)
		e.hits = pruneHits(e.hits, cutoff)
		if len(e.hits) < l.limit {
			victim = el
			break
		}
	}
	if victim == nil {
		victim = l.order.Front()
	}
	if victim != nil {
		e := victim.Value.(*limiterEntry)
		l.order.Remove(victim)
		delete(l.hits, e.key)
	}
}

// Cleanup drops keys with no attempts inside the window.
func (l *Limiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := l.now().Add(-l.window)
	for k, el := range l.hits {
		e := el.Value.(*limiterEntry)
		if len(e.hits) == 0 || !e.hits[len(e.hits)-1].After(cutoff) {
			l.order.Remove(el)
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
