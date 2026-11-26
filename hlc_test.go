// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

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
	remote := HLC{Wall: time.Now().Add(time.Minute).UnixMicro(), Logical: 99, NodeID: "node-b"}
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

// fixedNow returns a clock frozen at the given unix microsecond.
func fixedNow(micros int64) func() time.Time {
	at := time.UnixMicro(micros)
	return func() time.Time { return at }
}

// TestClockIgnoresARemoteBeyondTheSkewBudget: a record stamped an hour ahead
// of this node (a peer whose clock is wrong, or one forging far-future
// stamps) must not drag this node's later records an hour ahead of real
// time; the forward-skew budget is ten minutes.
func TestClockIgnoresARemoteBeyondTheSkewBudget(t *testing.T) {
	const now = int64(1_700_000_000_000_000)
	clk := NewClock("node-a", fixedNow(now))
	remote := HLC{Wall: now + time.Hour.Microseconds(), Logical: 3, NodeID: "node-b"}
	clk.Observe(remote)
	next := clk.Tick()
	if next.Wall >= remote.Wall {
		t.Fatalf("a remote an hour ahead moved the clock: Tick %s after Observe(%s)", next, remote)
	}
	if next.Wall != now {
		t.Fatalf("Tick after a refused remote: got Wall %d, want the frozen wall %d", next.Wall, now)
	}
}

// TestTickIsAtSwarmsMillisecondResolution: the wire stamp is filled from
// swarm's clock, a millisecond wall and a counter, so Wall is a whole
// millisecond in microseconds and ticks within one millisecond count up.
func TestTickIsAtSwarmsMillisecondResolution(t *testing.T) {
	const now = int64(1_700_000_000_123_456)
	clk := NewClock("node-a", fixedNow(now))
	for want := uint32(1); want <= 3; want++ {
		got := clk.Tick()
		if got.Wall != 1_700_000_000_123_000 || got.Logical != want || got.NodeID != "node-a" {
			t.Fatalf("tick %d: got %s, want 1700000000123000.%d@node-a", want, got, want)
		}
	}
	if last := clk.Last(); last.Logical != 3 {
		t.Fatalf("Last after three ticks: got %s", last)
	}
}

// TestObserveOutrunsAMicrosecondRemote: a remote stamped between two
// milliseconds (a clock issuing microsecond walls) is still outrun by the
// next Tick.
func TestObserveOutrunsAMicrosecondRemote(t *testing.T) {
	const now = int64(1_700_000_000_000_000)
	clk := NewClock("node-a", fixedNow(now))
	remote := HLC{Wall: now + 2_500, Logical: 9, NodeID: "node-b"}
	clk.Observe(remote)
	if next := clk.Tick(); next.Compare(remote) <= 0 {
		t.Fatalf("Tick after Observe(%s) = %s, must exceed it", remote, next)
	}
}

// TestObserveOutrunsARemoteLogicalAboveTheCounter: a remote whose Logical is
// above swarm's 16-bit counter is still outrun by the next Tick.
func TestObserveOutrunsARemoteLogicalAboveTheCounter(t *testing.T) {
	const now = int64(1_700_000_000_000_000)
	clk := NewClock("node-a", fixedNow(now))
	remote := HLC{Wall: now + 5_000, Logical: 70_000, NodeID: "node-b"}
	clk.Observe(remote)
	if next := clk.Tick(); next.Compare(remote) <= 0 {
		t.Fatalf("Tick after Observe(%s) = %s, must exceed it", remote, next)
	}
}
