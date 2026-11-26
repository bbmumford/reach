// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

package reach

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bbmumford/swarm"
)

// HLC is a Hybrid Logical Clock (Kulkarni et al., 2014).
// It combines wall-clock time with a logical counter so records can be totally
// ordered even when node wall clocks drift. Two HLC values are compared by
// (Wall, Logical, NodeID) tuple.
//
// HLC differs from the Lamport clock already on ledger.Record in that it
// remains close to real time — useful for operators inspecting records — and
// it gives strictly-increasing ordering without cross-node coordination.
//
// HLC is the stamp's wire form: every signed ReachRecord and DeltaRecord
// carries it under these JSON keys. Clock fills it from swarm's HLC, so Wall
// holds whole milliseconds expressed in microseconds and Logical swarm's
// 16-bit counter.
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
//
// The stamps come from a swarm.HLC: Tick takes the clock's next stamp and
// writes its millisecond wall (in microseconds) and counter into the wire
// HLC, and Observe folds a received stamp into it. swarm's rules therefore
// hold here too: a counter full within one millisecond carries into the next
// one, and a remote stamp further ahead of this node's wall than swarm's
// forward-skew budget does not move the clock.
type Clock struct {
	nodeID string
	hlc    *swarm.HLC

	// mu makes a Tick's stamp and its record in last one step, so last is
	// always the greatest stamp Tick has returned.
	mu   sync.Mutex
	last HLC
}

// NewClock creates an HLC clock for the given node.
// Pass nil for now to use time.Now.
func NewClock(nodeID string, now func() time.Time) *Clock {
	return &Clock{nodeID: nodeID, hlc: swarm.NewHLCWithNow(now)}
}

// Tick produces the next HLC timestamp strictly greater than the previous.
// Monotonicity is preserved even when the wall clock moves backward.
func (c *Clock) Tick() HLC {
	c.mu.Lock()
	defer c.mu.Unlock()
	wall, counter := swarm.Decompose(c.hlc.Now())
	c.last = HLC{Wall: int64(wall) * 1000, Logical: uint32(counter), NodeID: c.nodeID}
	return c.last
}

// Observe incorporates a remote HLC into the local clock state.
// Use this on receipt of any ReachRecord so local ticks always outrun what
// the network has seen, within swarm's forward-skew budget.
func (c *Clock) Observe(remote HLC) {
	c.hlc.Observe(stampOf(remote))
}

// Last returns the most recent HLC produced by Tick (may be zero).
func (c *Clock) Last() HLC {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// stampOf converts a wire HLC to swarm's packed stamp for Observe. A Wall
// between two milliseconds (a stamp a clock issued at microsecond resolution)
// is taken as the next millisecond, and a Logical above the 16-bit counter as
// a full counter, so the Tick after Observe still compares greater than the
// remote: Compare orders by Wall first, then Logical.
func stampOf(h HLC) uint64 {
	if h.Wall <= 0 {
		return 0
	}
	ms, counter := uint64(h.Wall/1000), h.Logical
	if h.Wall%1000 != 0 {
		ms, counter = ms+1, 0
	}
	if counter > 0xFFFF {
		counter = 0xFFFF
	}
	return swarm.Pack(ms, uint16(counter))
}
