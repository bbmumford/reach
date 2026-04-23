// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// HLC is a Hybrid Logical Clock (Kulkarni et al., 2014).
// It combines wall-clock time with a logical counter so records can be totally
// ordered even when node wall clocks drift. Two HLC values are compared by
// (Wall, Logical, NodeID) tuple.
//
// HLC differs from the Lamport clock already on ledger.Record in that it
// remains close to real time — useful for operators inspecting records — and
// it gives strictly-increasing ordering without cross-node coordination.
type HLC struct {
	Wall    int64  `json:"w"` // unix micros
	Logical uint32 `json:"l"`
	NodeID  string `json:"n,omitempty"` // tie-break; may be omitted to save space when reproducible
}

// IsZero reports whether this is the zero HLC.
func (h HLC) IsZero() bool {
	return h.Wall == 0 && h.Logical == 0 && h.NodeID == ""
}

// Compare returns -1 / 0 / 1 for less / equal / greater.
// Ordering: Wall first, then Logical, then NodeID (lexicographic).
func (h HLC) Compare(other HLC) int {
	if h.Wall < other.Wall {
		return -1
	}
	if h.Wall > other.Wall {
		return 1
	}
	if h.Logical < other.Logical {
		return -1
	}
	if h.Logical > other.Logical {
		return 1
	}
	if h.NodeID < other.NodeID {
		return -1
	}
	if h.NodeID > other.NodeID {
		return 1
	}
	return 0
}

// Less is a convenience for Compare < 0.
func (h HLC) Less(other HLC) bool { return h.Compare(other) < 0 }

// String returns a compact representation: "<wall>.<logical>@<node>".
func (h HLC) String() string {
	var b strings.Builder
	b.WriteString(strconv.FormatInt(h.Wall, 10))
	b.WriteByte('.')
	b.WriteString(strconv.FormatUint(uint64(h.Logical), 10))
	if h.NodeID != "" {
		b.WriteByte('@')
		b.WriteString(h.NodeID)
	}
	return b.String()
}

// Clock produces monotonically-increasing HLC timestamps for a single node.
// Safe for concurrent use.
type Clock struct {
	mu     sync.Mutex
	nodeID string
	last   HLC
	now    func() time.Time
}

// NewClock creates an HLC clock for the given node.
// Pass nil for now to use time.Now.
func NewClock(nodeID string, now func() time.Time) *Clock {
	if now == nil {
		now = time.Now
	}
	return &Clock{nodeID: nodeID, now: now}
}

// Tick produces the next HLC timestamp strictly greater than the previous.
// Monotonicity is preserved even when the wall clock moves backward.
func (c *Clock) Tick() HLC {
	c.mu.Lock()
	defer c.mu.Unlock()

	wall := c.now().UTC().UnixMicro()
	if wall <= c.last.Wall {
		// Wall didn't advance — bump logical.
		c.last = HLC{
			Wall:    c.last.Wall,
			Logical: c.last.Logical + 1,
			NodeID:  c.nodeID,
		}
		return c.last
	}
	c.last = HLC{Wall: wall, Logical: 0, NodeID: c.nodeID}
	return c.last
}

// Observe incorporates a remote HLC into the local clock state.
// Use this on receipt of any ReachRecord so local ticks always outrun what
// the network has seen.
func (c *Clock) Observe(remote HLC) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if remote.Compare(c.last) > 0 {
		c.last = HLC{Wall: remote.Wall, Logical: remote.Logical, NodeID: c.nodeID}
	}
}

// Last returns the most recent HLC produced by Tick (may be zero).
func (c *Clock) Last() HLC {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}
