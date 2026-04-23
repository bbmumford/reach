// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

// Package discoverer implements the address-source plugins consumed by
// reach.Publisher. Each discoverer runs independently and contributes a
// slice of reach.Address values; the publisher unions and deduplicates them.
package discoverer

import (
	"context"
	"time"

	"github.com/bbmumford/reach"
)

// Base is a convenience embedding for discoverers: it provides Name/Source/
// Interval/EnabledFor using plain fields so concrete types only need to
// implement Discover.
type Base struct {
	NameValue      string
	SourceValue    reach.AddressSource
	IntervalValue  time.Duration
	EnabledValue   func(provider string) bool
}

// Name implements reach.Discoverer.
func (b Base) Name() string { return b.NameValue }

// Source implements reach.Discoverer.
func (b Base) Source() reach.AddressSource { return b.SourceValue }

// Interval implements reach.Discoverer.
func (b Base) Interval() time.Duration { return b.IntervalValue }

// EnabledFor implements reach.Discoverer.
func (b Base) EnabledFor(provider string) bool {
	if b.EnabledValue == nil {
		return true
	}
	return b.EnabledValue(provider)
}

// Discover is a default implementation; override in concrete types.
func (b Base) Discover(context.Context) ([]reach.Address, error) { return nil, nil }

// AllProviders is an EnabledFor that returns true for every platform.
func AllProviders(string) bool { return true }

// NotOn returns an EnabledFor that rejects the named provider(s).
// E.g. NotOn("fly") for a STUN discoverer that would be misleading on Fly.
func NotOn(providers ...string) func(string) bool {
	set := make(map[string]struct{}, len(providers))
	for _, p := range providers {
		set[p] = struct{}{}
	}
	return func(provider string) bool {
		_, banned := set[provider]
		return !banned
	}
}

// Only returns an EnabledFor that accepts only the named provider(s).
func Only(providers ...string) func(string) bool {
	set := make(map[string]struct{}, len(providers))
	for _, p := range providers {
		set[p] = struct{}{}
	}
	return func(provider string) bool {
		_, ok := set[provider]
		return ok
	}
}
