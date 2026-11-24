// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

package reach

import (
	"strconv"
	"testing"
	"time"
)

// The per-node limiter holds a budget for at most MaxRateLimitedNodes NodeIDs,
// however many a peer mints, and still caps each node.
func TestPerNodeRateLimiterTracksABoundedNumberOfNodes(t *testing.T) {
	l := NewPerNodeRateLimiter(2, time.Minute)
	for i := 0; i < 3*MaxRateLimitedNodes; i++ {
		l.Allow("vl1_minted" + strconv.Itoa(i))
	}
	if n := l.Size(); n > MaxRateLimitedNodes {
		t.Fatalf("the limiter tracks %d nodes, past MaxRateLimitedNodes %d", n, MaxRateLimitedNodes)
	}
	if !l.Allow("vl1_steady") || !l.Allow("vl1_steady") {
		t.Fatal("a node within its cap was refused")
	}
	if l.Allow("vl1_steady") {
		t.Fatal("a node past its cap of 2 per window was admitted")
	}
}
