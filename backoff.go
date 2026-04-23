// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"context"
	"sync"
	"time"
)

// newBackoffWrapper attaches per-discoverer failure-tracking state to any
// Discoverer. Called lazily from publisher.wrapDiscoverers so the state
// persists across publish ticks.
//
// The wrapper is intentionally in the reach package (not discoverer
// subpackage) to avoid an import cycle — the publisher uses the wrapper
// and the discoverer package uses the Discoverer interface.
//
// Schedule on consecutive failures: 1s, 2s, 4s, 8s, 16s, then capped at
// the wrapped discoverer's Interval(). Counter resets on any success.
func newBackoffWrapper(d Discoverer) Discoverer {
	return &backoffDiscoverer{inner: d}
}

type backoffDiscoverer struct {
	inner Discoverer

	mu          sync.Mutex
	failures    int
	nextAttempt time.Time
}

func (b *backoffDiscoverer) Name() string                    { return b.inner.Name() }
func (b *backoffDiscoverer) Source() AddressSource           { return b.inner.Source() }
func (b *backoffDiscoverer) Interval() time.Duration         { return b.inner.Interval() }
func (b *backoffDiscoverer) EnabledFor(provider string) bool { return b.inner.EnabledFor(provider) }

func (b *backoffDiscoverer) Discover(ctx context.Context) ([]Address, error) {
	b.mu.Lock()
	if !time.Now().After(b.nextAttempt) {
		b.mu.Unlock()
		return nil, nil // inside backoff window — benign empty result
	}
	b.mu.Unlock()

	addrs, err := b.inner.Discover(ctx)
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		b.failures++
		delay := time.Second
		for i := 1; i < b.failures && delay < 16*time.Second; i++ {
			delay *= 2
		}
		if iv := b.inner.Interval(); iv > 0 && delay > iv {
			delay = iv
		}
		b.nextAttempt = time.Now().Add(delay)
		return addrs, err
	}
	b.failures = 0
	b.nextAttempt = time.Time{}
	return addrs, nil
}
