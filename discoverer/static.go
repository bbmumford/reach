// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package discoverer

import (
	"context"
	"time"

	"github.com/bbmumford/reach"
)

// Static emits a fixed address list from operator configuration.
// Useful for dedicated static-IP deployments, development, or any scenario
// where the operator already knows the authoritative address and wants to
// skip all auto-discovery.
type Static struct {
	Base
	addrs []reach.Address
}

// NewStatic creates a Static discoverer that always returns the given list.
// Each returned Address is stamped with Source=SrcStatic and Confidence=100.
func NewStatic(addrs []reach.Address) *Static {
	out := make([]reach.Address, len(addrs))
	for i, a := range addrs {
		if a.Source == reach.SrcUnknown {
			a.Source = reach.SrcStatic
		}
		if a.Confidence == 0 {
			a.Confidence = 100
		}
		out[i] = a
	}
	return &Static{
		Base: Base{
			NameValue:     "static",
			SourceValue:   reach.SrcStatic,
			IntervalValue: 0, // event-only; config doesn't change during process life
			EnabledValue:  AllProviders,
		},
		addrs: out,
	}
}

// Discover returns a copy of the configured address list.
func (s *Static) Discover(_ context.Context) ([]reach.Address, error) {
	out := make([]reach.Address, len(s.addrs))
	now := time.Now()
	for i, a := range s.addrs {
		if a.FirstSeen.IsZero() {
			a.FirstSeen = now
		}
		out[i] = a
	}
	return out, nil
}
