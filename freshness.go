// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"encoding/json"
	"sync"
	"time"
)

// FreshnessTopic is the whisper topic name used for the digest broadcast.
const FreshnessTopic = "reach.freshness"

// FreshnessTracker compares digests broadcast by remote peers against what
// the local cache holds for them. A mismatch means the peer has newer reach
// state than we do — the consumer can trigger a targeted pull.
//
// The tracker is strictly passive storage — it does not itself fetch records.
// Consumers (mesh node / agent) wire OnMismatch to their record-fetch path.
type FreshnessTracker struct {
	mu sync.Mutex

	// per-peer: the last digest we heard from them and when
	peers map[string]freshnessEntry

	onMismatch func(peerNodeID string, peerDigest string)
}

type freshnessEntry struct {
	Digest    string
	HLC       HLC
	ObservedAt time.Time
}

// NewFreshnessTracker returns a tracker ready to ingest broadcasts.
// onMismatch is called (from inside the goroutine that calls Observe) when
// a peer advertises a digest that differs from the previous one we heard
// from them. May be nil; callers can wire it later with SetOnMismatch.
func NewFreshnessTracker(onMismatch func(peerNodeID string, peerDigest string)) *FreshnessTracker {
	return &FreshnessTracker{
		peers:      make(map[string]freshnessEntry),
		onMismatch: onMismatch,
	}
}

// SetOnMismatch replaces the mismatch callback.
func (t *FreshnessTracker) SetOnMismatch(fn func(peerNodeID, peerDigest string)) {
	t.mu.Lock()
	t.onMismatch = fn
	t.mu.Unlock()
}

// Observe records a broadcast from a peer and fires onMismatch if the digest
// is different from the previous observation.
func (t *FreshnessTracker) Observe(payload []byte) error {
	var msg freshnessPayload
	if err := json.Unmarshal(payload, &msg); err != nil {
		return err
	}
	if msg.NodeID == "" || msg.Digest == "" {
		return nil
	}

	t.mu.Lock()
	prev, seen := t.peers[msg.NodeID]
	changed := !seen || prev.Digest != msg.Digest
	t.peers[msg.NodeID] = freshnessEntry{
		Digest:     msg.Digest,
		HLC:        msg.HLC,
		ObservedAt: time.Now(),
	}
	cb := t.onMismatch
	t.mu.Unlock()

	if changed && cb != nil {
		cb(msg.NodeID, msg.Digest)
	}
	return nil
}

// LastDigest returns the most recent digest heard from peerNodeID, or "".
func (t *FreshnessTracker) LastDigest(peerNodeID string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.peers[peerNodeID].Digest
}

// Prune drops entries older than keep. Call periodically from a background
// goroutine to keep the map bounded.
func (t *FreshnessTracker) Prune(keep time.Duration) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-keep)
	removed := 0
	for id, e := range t.peers {
		if e.ObservedAt.Before(cutoff) {
			delete(t.peers, id)
			removed++
		}
	}
	return removed
}
