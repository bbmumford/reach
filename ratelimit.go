// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

package reach

import (
	"time"

	"github.com/bbmumford/ratelimit"
)

// MaxRateLimitedNodes is the most NodeIDs a PerNodeRateLimiter holds a budget
// for at once. A record's NodeID is chosen by whoever signs it, so without a
// bound every new key would add an entry for the process's life.
const MaxRateLimitedNodes = 16384

// perNodeLimit names the limiter's one limit; nodeDimension is the dimension
// its buckets are keyed by.
const (
	perNodeLimit  = "reach.node"
	nodeDimension = "node"
)

// PerNodeRateLimiter caps the number of reach records accepted per NodeID
// per window. Applied on the READ side (in a ledger cache hook) so a
// compromised or buggy node can't hot-loop churn into the mesh. Each NodeID
// has a token bucket of cap records refilled over the window, held by a
// ratelimit.RateLimiter whose map holds at most MaxRateLimitedNodes, so the
// NodeIDs a peer mints cannot grow it. The limiter drops a bucket only once it
// is back at capacity (swept after two idle windows, or to make room), so a
// flood of minted NodeIDs cannot reset the budget of a node it tracks; while
// the map is full of nodes still below their budget, Allow refuses a NodeID
// it does not yet track.
type PerNodeRateLimiter struct {
	rl *ratelimit.RateLimiter
}

// NewPerNodeRateLimiter creates a limiter with the given per-window cap.
// Defaults: cap=60, win=1min.
func NewPerNodeRateLimiter(cap int, win time.Duration) *PerNodeRateLimiter {
	if cap <= 0 {
		cap = 60
	}
	if win <= 0 {
		win = time.Minute
	}
	rl := ratelimit.NewRateLimiterWithBounds(2*win, MaxRateLimitedNodes)
	// Register refuses only a nil config or an interval that is not positive,
	// and win is positive here, so its result is dropped.
	_ = rl.Register(perNodeLimit, &ratelimit.RateLimitConfig{
		Mode:       ratelimit.ModeTokenBucket,
		Capacity:   cap,
		RefillRate: cap,
		Interval:   win,
		Dimensions: []string{nodeDimension},
	})
	return &PerNodeRateLimiter{rl: rl}
}

// Allow returns true if accepting another record from nodeID is within the
// rate budget, spending one record of it. It refuses whenever the limiter
// cannot say yes.
func (l *PerNodeRateLimiter) Allow(nodeID string) bool {
	allowed, _, _, err := l.rl.Protect(perNodeLimit, &ratelimit.RateLimitContext{Dimensions: map[string]string{nodeDimension: nodeID}})
	return err == nil && allowed
}

// Size returns the number of tracked nodes (for metrics / diagnostics).
func (l *PerNodeRateLimiter) Size() int {
	return l.rl.BucketCount()
}
