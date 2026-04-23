// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"sync"
	"testing"
	"time"
)

func TestHLCMonotonic(t *testing.T) {
	clk := NewClock("node-a", nil)
	a := clk.Tick()
	b := clk.Tick()
	c := clk.Tick()
	if a.Compare(b) >= 0 || b.Compare(c) >= 0 {
		t.Fatalf("Tick not monotonic: %s %s %s", a, b, c)
	}
}

func TestHLCClockRollback(t *testing.T) {
	// Synthetic clock that rolls backward between ticks — HLC must still
	// produce strictly increasing timestamps.
	var mu sync.Mutex
	t0 := time.Unix(1_700_000_000, 0)
	walls := []time.Time{t0, t0.Add(time.Millisecond), t0.Add(-time.Second), t0.Add(-10 * time.Second), t0.Add(2 * time.Second)}
	idx := 0
	now := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		t := walls[idx%len(walls)]
		idx++
		return t
	}

	clk := NewClock("node-a", now)
	prev := clk.Tick()
	for i := 0; i < 20; i++ {
		next := clk.Tick()
		if next.Compare(prev) <= 0 {
			t.Fatalf("rollback at step %d: %s -> %s", i, prev, next)
		}
		prev = next
	}
}

func TestHLCObserve(t *testing.T) {
	clk := NewClock("node-a", nil)
	remote := HLC{Wall: time.Now().Add(time.Hour).UnixMicro(), Logical: 99, NodeID: "node-b"}
	clk.Observe(remote)
	next := clk.Tick()
	if next.Compare(remote) <= 0 {
		t.Fatalf("Tick after Observe(remote-in-future) must exceed remote: %s vs %s", next, remote)
	}
}

func TestHLCOrdering(t *testing.T) {
	// Tie-break must be: Wall > Logical > NodeID.
	cases := []struct {
		a, b HLC
		want int
	}{
		{HLC{Wall: 10, Logical: 0, NodeID: "x"}, HLC{Wall: 11, Logical: 0, NodeID: "x"}, -1},
		{HLC{Wall: 10, Logical: 5, NodeID: "a"}, HLC{Wall: 10, Logical: 6, NodeID: "a"}, -1},
		{HLC{Wall: 10, Logical: 5, NodeID: "a"}, HLC{Wall: 10, Logical: 5, NodeID: "b"}, -1},
		{HLC{Wall: 10, Logical: 5, NodeID: "a"}, HLC{Wall: 10, Logical: 5, NodeID: "a"}, 0},
	}
	for _, c := range cases {
		if got := c.a.Compare(c.b); got != c.want {
			t.Errorf("Compare(%v, %v) = %d; want %d", c.a, c.b, got, c.want)
		}
	}
}
