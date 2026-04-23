// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"fmt"
	"sync"
	"time"
)

// ReplayGuard prevents accepting out-of-order or replayed records per node.
// A received record is valid only if its (Epoch, HLC) tuple strictly exceeds
// the last one we saw from that NodeID within the same Epoch.
//
// Use this on the READ path — call Check on every incoming ReachRecord and
// discard any record for which Check returns an error.
type ReplayGuard struct {
	mu     sync.Mutex
	state  map[string]replayEntry
	window time.Duration // how long to keep per-node state; 0 = forever
}

type replayEntry struct {
	Epoch    uint64
	HLC      HLC
	LastSeen time.Time
}

// NewReplayGuard creates a guard that retains per-node state for the given
// window. Pass 0 to retain forever (recommended in long-running processes;
// nodes that are offline > window will be allowed to "re-introduce" on return).
func NewReplayGuard(window time.Duration) *ReplayGuard {
	return &ReplayGuard{
		state:  make(map[string]replayEntry),
		window: window,
	}
}

// Check validates that rec is newer than the last observed (Epoch, HLC) for
// rec.NodeID. On success the state is updated. On failure the state is left
// unchanged and a descriptive error is returned.
func (g *ReplayGuard) Check(rec ReachRecord) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()

	last, ok := g.state[rec.NodeID]
	if !ok {
		g.state[rec.NodeID] = replayEntry{Epoch: rec.Epoch, HLC: rec.HLC, LastSeen: now}
		return nil
	}

	if g.window > 0 && now.Sub(last.LastSeen) > g.window {
		// Outside the replay window — accept as fresh.
		g.state[rec.NodeID] = replayEntry{Epoch: rec.Epoch, HLC: rec.HLC, LastSeen: now}
		return nil
	}

	if rec.Epoch < last.Epoch {
		return fmt.Errorf("reach: replay guard: rec epoch %d < last epoch %d for node %s", rec.Epoch, last.Epoch, rec.NodeID)
	}
	if rec.Epoch == last.Epoch && rec.HLC.Compare(last.HLC) <= 0 {
		return fmt.Errorf("reach: replay guard: HLC %s not newer than %s for node %s", rec.HLC, last.HLC, rec.NodeID)
	}

	g.state[rec.NodeID] = replayEntry{Epoch: rec.Epoch, HLC: rec.HLC, LastSeen: now}
	return nil
}

// Forget drops the stored state for a NodeID. Useful when a node has been
// gracefully removed from the mesh and its record should be allowed to
// re-appear with a fresh Epoch in the future.
func (g *ReplayGuard) Forget(nodeID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.state, nodeID)
}

// Len returns the number of nodes currently tracked (for metrics).
func (g *ReplayGuard) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.state)
}
