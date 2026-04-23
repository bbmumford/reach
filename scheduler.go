// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"math/rand"
	"sync"
	"time"
)

// schedulerState describes the publish cadence regime.
type schedulerState uint8

const (
	stateBootstrapping schedulerState = iota // process just started
	stateStable                              // no recent changes
	stateChurning                            // 2+ changes in recent window
)

// scheduler computes the next publish deadline based on recent activity.
// Plus a per-minute leaky bucket that caps worst-case publish frequency.
type scheduler struct {
	cfg *Config

	mu              sync.Mutex
	start           time.Time
	recentChanges   []time.Time // timestamps of publishes-caused-by-change
	publishesThisMin []time.Time // rolling window for rate limit
	state            schedulerState
}

func newScheduler(cfg *Config) *scheduler {
	return &scheduler{
		cfg:   cfg,
		start: time.Now(),
		state: stateBootstrapping,
	}
}

// next returns the duration to wait until the next scheduled publish tick.
// It is called AFTER each tick (whether the tick published or not) to plan
// the next wait.
func (s *scheduler) next(now time.Time) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.updateStateLocked(now)

	var base time.Duration
	switch s.state {
	case stateBootstrapping:
		base = s.cfg.BootstrapInterval
	case stateChurning:
		base = s.cfg.ChurnInterval
	default:
		base = s.cfg.BaseInterval
	}
	return withJitter(base, s.cfg.Jitter)
}

// noteChange records that an address change was detected, so the scheduler
// can promote to CHURNING if changes cluster.
func (s *scheduler) noteChange(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.recentChanges = append(s.recentChanges, now)
	// Prune entries older than 2 minutes (the CHURNING detection window).
	cutoff := now.Add(-2 * time.Minute)
	for i, t := range s.recentChanges {
		if t.After(cutoff) {
			s.recentChanges = s.recentChanges[i:]
			break
		}
		if i == len(s.recentChanges)-1 {
			s.recentChanges = nil
		}
	}
}

// allowPublish returns true if the leaky-bucket cap permits another publish now.
// It also records the publish for subsequent rate accounting.
func (s *scheduler) allowPublish(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := now.Add(-60 * time.Second)
	// Drop old entries.
	kept := s.publishesThisMin[:0]
	for _, t := range s.publishesThisMin {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	s.publishesThisMin = kept

	if len(s.publishesThisMin) >= s.cfg.MaxPublishesPerMin {
		return false
	}
	s.publishesThisMin = append(s.publishesThisMin, now)
	return true
}

// state returns the current scheduler state (for metrics / debug).
func (s *scheduler) stateNow() schedulerState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *scheduler) updateStateLocked(now time.Time) {
	if now.Sub(s.start) < s.cfg.BootstrapDuration {
		s.state = stateBootstrapping
		return
	}
	if len(s.recentChanges) >= 2 {
		s.state = stateChurning
		return
	}
	s.state = stateStable
}

// withJitter applies symmetric full-jitter to a base duration.
// Result is in [base*(1-j/2), base*(1+j/2)] clamped to >= 100ms.
func withJitter(base time.Duration, jitter float64) time.Duration {
	if jitter <= 0 {
		return base
	}
	half := float64(base) * jitter / 2
	delta := (rand.Float64()*2 - 1) * half
	out := time.Duration(float64(base) + delta)
	if out < 100*time.Millisecond {
		return 100 * time.Millisecond
	}
	return out
}
