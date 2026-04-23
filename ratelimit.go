// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"sync"
	"time"
)

// PerNodeRateLimiter caps the number of reach records accepted per NodeID
// per minute. Applied on the READ side (in a ledger cache hook) so a
// compromised or buggy node can't hot-loop churn into the mesh.
type PerNodeRateLimiter struct {
	mu    sync.Mutex
	state map[string]*rateEntry
	cap   int           // max records per window
	win   time.Duration // rolling window size (typically 1 minute)
}

type rateEntry struct {
	timestamps []time.Time
}

// NewPerNodeRateLimiter creates a limiter with the given per-window cap.
// Defaults: cap=60, win=1min (matches plan §5.30).
func NewPerNodeRateLimiter(cap int, win time.Duration) *PerNodeRateLimiter {
	if cap <= 0 {
		cap = 60
	}
	if win <= 0 {
		win = time.Minute
	}
	return &PerNodeRateLimiter{
		state: make(map[string]*rateEntry),
		cap:   cap,
		win:   win,
	}
}

// Allow returns true if accepting another record from nodeID is within the
// rate budget. Updates internal state if allowed.
func (l *PerNodeRateLimiter) Allow(nodeID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-l.win)

	e := l.state[nodeID]
	if e == nil {
		e = &rateEntry{}
		l.state[nodeID] = e
	}
	// Prune stale timestamps.
	kept := e.timestamps[:0]
	for _, t := range e.timestamps {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	e.timestamps = kept

	if len(e.timestamps) >= l.cap {
		return false
	}
	e.timestamps = append(e.timestamps, now)
	return true
}

// Size returns the number of tracked nodes (for metrics / diagnostics).
func (l *PerNodeRateLimiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.state)
}
