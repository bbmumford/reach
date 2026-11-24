// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

package reach

import (
	"strconv"
	"testing"
	"time"
)

// The per-node limiter holds a budget for at most MaxRateLimitedNodes NodeIDs,
// however many a peer mints. The flood cannot reset the budget of a node the
// limiter already tracks, and while the map is full of nodes still below their
// budget a NodeID it does not track is refused.
func TestPerNodeRateLimiterTracksABoundedNumberOfNodes(t *testing.T) {
	l := NewPerNodeRateLimiter(2, time.Minute)
	if !l.Allow("vl1_steady") {
		t.Fatal("a node's first record was refused")
	}
	for i := 0; i < 3*MaxRateLimitedNodes; i++ {
		l.Allow("vl1_minted" + strconv.Itoa(i))
	}
	if n := l.Size(); n > MaxRateLimitedNodes {
		t.Fatalf("the limiter tracks %d nodes, past MaxRateLimitedNodes %d", n, MaxRateLimitedNodes)
	}
	if !l.Allow("vl1_steady") {
		t.Fatal("a tracked node within its cap of 2 was refused after the flood")
	}
	if l.Allow("vl1_steady") {
		t.Fatal("a tracked node past its cap of 2 per window was admitted: the flood reset its budget")
	}
	if l.Allow("vl1_unseen") {
		t.Fatal("a NodeID the full limiter does not track was admitted")
	}
}
