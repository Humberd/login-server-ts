package limiter

import (
	"sync"
	"time"
)

type FailureLimiter struct {
	limit     int
	window    time.Duration
	mu        sync.Mutex
	failures  map[string]*failures
	lastSweep time.Time
}

type failures struct {
	count int
	first time.Time
}

func NewFailureLimiter(limit int, window time.Duration) *FailureLimiter {
	return &FailureLimiter{
		limit:     limit,
		window:    window,
		failures:  make(map[string]*failures),
		lastSweep: time.Now(),
	}
}

func (l *FailureLimiter) Blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	f, ok := l.failures[key]
	return ok && f.count >= l.limit && time.Since(f.first) < l.window
}

func (l *FailureLimiter) Fail(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if now.Sub(l.lastSweep) >= l.window {
		for key, f := range l.failures {
			if now.Sub(f.first) >= l.window {
				delete(l.failures, key)
			}
		}
		l.lastSweep = now
	}

	for _, key := range keys {
		f, ok := l.failures[key]
		if !ok || now.Sub(f.first) >= l.window {
			f = &failures{first: now}
			l.failures[key] = f
		}
		f.count++
	}
}

func (l *FailureLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.failures, key)
}
