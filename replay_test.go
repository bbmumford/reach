// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"testing"
	"time"
)

func TestReplayGuardAcceptsFirst(t *testing.T) {
	g := NewReplayGuard(0)
	rec := ReachRecord{NodeID: "n", Epoch: 1, HLC: HLC{Wall: 10}}
	if err := g.Check(rec); err != nil {
		t.Fatalf("first record rejected: %v", err)
	}
}

func TestReplayGuardRejectsOlderHLC(t *testing.T) {
	g := NewReplayGuard(0)
	newer := ReachRecord{NodeID: "n", Epoch: 1, HLC: HLC{Wall: 20}}
	older := ReachRecord{NodeID: "n", Epoch: 1, HLC: HLC{Wall: 10}}

	if err := g.Check(newer); err != nil {
		t.Fatal(err)
	}
	if err := g.Check(older); err == nil {
		t.Fatal("older record should have been rejected")
	}
}

func TestReplayGuardAcceptsNewEpoch(t *testing.T) {
	g := NewReplayGuard(0)
	old := ReachRecord{NodeID: "n", Epoch: 1, HLC: HLC{Wall: 100}}
	fresh := ReachRecord{NodeID: "n", Epoch: 2, HLC: HLC{Wall: 1}} // restart
	if err := g.Check(old); err != nil {
		t.Fatal(err)
	}
	if err := g.Check(fresh); err != nil {
		t.Fatalf("new-Epoch record should be accepted even with lower HLC: %v", err)
	}
}

func TestRateLimiterEnforcesCap(t *testing.T) {
	r := NewPerNodeRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !r.Allow("n1") {
			t.Fatalf("rate limit rejected allowed request %d", i)
		}
	}
	if r.Allow("n1") {
		t.Fatal("rate limit should reject 4th request within window")
	}
	if !r.Allow("n2") {
		t.Fatal("rate limit should be per-node")
	}
}
