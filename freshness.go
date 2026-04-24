// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// ReachRecordLookup reads the local cache's latest full-snapshot body for
// a subject NodeID. Consumers (e.g. the ledger cache) implement this so
// the FreshnessClient can compute the cached digest and decide whether
// an announce indicates a stale cache that needs a snapshot request.
//
// Returns nil when no record is cached for nodeID (either never received
// or already evicted).
type ReachRecordLookup interface {
	LookupReachBody(nodeID string) []byte
}

// defaultRequestCooldown is the minimum interval between two outbound
// snapshot requests for the same subject NodeID. Prevents request storms
// when multiple announces arrive faster than the publisher can respond.
// Pick short-enough-to-be-snappy, long-enough-to-not-storm.
const defaultRequestCooldown = 3 * time.Second

// defaultPruneInterval is how often FreshnessClient's background loop
// prunes its tracker + per-peer state maps. Keeps memory bounded.
const defaultPruneInterval = 10 * time.Minute

// defaultPruneKeep is how long a tracker entry survives without being
// refreshed before it's dropped on Prune.
const defaultPruneKeep = 30 * time.Minute

// FreshnessClient turns the passive FreshnessTracker into an active
// participant in the feedback-driven publishing loop:
//
//   - On each FreshnessAnnounce received from a peer, it compares the
//     announced digest against the local cache's digest for that
//     subject. If they differ (or the cache has nothing), it broadcasts
//     a FreshnessRequest so the subject's publisher re-emits a full
//     snapshot.
//
//   - On each FreshnessRequest addressed to this node (SubjectID matches
//     our own NodeID), it calls publisher.ForcePublish with
//     PublishReasonPeerRequest. The scheduler's MaxPublishesPerMin cap
//     absorbs simultaneous requests from multiple peers.
//
//   - A per-subject cooldown on outbound requests suppresses request
//     storms when a single announce fans out to many FreshnessClients.
//
//   - Epoch tracking drops stale announces from prior process lifetimes:
//     a publisher that just restarted with Epoch=N+1 will supersede any
//     lingering announce from Epoch=N.
//
// The client is safe for concurrent use and Start/Stop are idempotent.
type FreshnessClient struct {
	bus       FreshnessBus
	cache     ReachRecordLookup
	publisher *Publisher // inbound requests → ForcePublish; may be nil
	tracker   *FreshnessTracker
	nodeID    string
	clock     *Clock

	cooldown time.Duration

	mu            sync.Mutex
	lastRequestAt map[string]time.Time // subject → last outbound request
	peerEpochs    map[string]uint64    // peer NodeID → highest Epoch observed
	started       bool
	unsubscribe   func()
	stopCh        chan struct{}
	doneCh        chan struct{}
}

// NewFreshnessClient constructs a client. Any of publisher/cache may be
// nil; a nil cache disables announce-driven requests (Announces still
// populate the tracker for digest introspection), a nil publisher
// disables inbound request handling (safe for pure-consumer nodes that
// don't publish their own reach records).
func NewFreshnessClient(bus FreshnessBus, cache ReachRecordLookup, publisher *Publisher, nodeID string, clock *Clock) *FreshnessClient {
	if clock == nil {
		clock = NewClock(nodeID, nil)
	}
	fc := &FreshnessClient{
		bus:           bus,
		cache:         cache,
		publisher:     publisher,
		nodeID:        nodeID,
		clock:         clock,
		cooldown:      defaultRequestCooldown,
		lastRequestAt: make(map[string]time.Time),
		peerEpochs:    make(map[string]uint64),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
	fc.tracker = NewFreshnessTracker(func(peerNodeID, peerDigest string) {
		fc.onMismatch(peerNodeID, peerDigest)
	})
	return fc
}

// SetCooldown adjusts the per-subject outbound-request cooldown. Must be
// called before Start.
func (fc *FreshnessClient) SetCooldown(d time.Duration) {
	fc.cooldown = d
}

// Start subscribes to the FreshnessBus and kicks off the prune loop.
// Safe to call multiple times — additional calls no-op.
func (fc *FreshnessClient) Start(ctx context.Context) {
	fc.mu.Lock()
	if fc.started {
		fc.mu.Unlock()
		return
	}
	fc.started = true
	fc.mu.Unlock()

	fc.unsubscribe = fc.bus.SubscribeFreshness(fc.onMessage)

	go fc.runPrune(ctx)
}

// Stop unsubscribes and waits for the prune loop to exit.
func (fc *FreshnessClient) Stop() {
	fc.mu.Lock()
	if !fc.started {
		fc.mu.Unlock()
		return
	}
	fc.started = false
	fc.mu.Unlock()

	if fc.unsubscribe != nil {
		fc.unsubscribe()
	}
	close(fc.stopCh)
	<-fc.doneCh
}

// onMessage is invoked for every freshness payload received on the bus.
// May be called concurrently from multiple goroutines.
func (fc *FreshnessClient) onMessage(payload []byte) {
	var msg freshnessPayload
	if err := json.Unmarshal(payload, &msg); err != nil {
		return
	}
	if msg.NodeID == "" {
		return
	}
	// Loop prevention: drop our own messages.
	if msg.From != "" && msg.From == fc.nodeID {
		return
	}
	// Epoch guard for announces from a known publisher.
	if (msg.Kind == FreshnessAnnounce || msg.Kind == 0) && msg.From == msg.NodeID && msg.Epoch > 0 {
		fc.mu.Lock()
		last, ok := fc.peerEpochs[msg.NodeID]
		if ok && msg.Epoch < last {
			fc.mu.Unlock()
			return
		}
		if msg.Epoch > last {
			fc.peerEpochs[msg.NodeID] = msg.Epoch
		}
		fc.mu.Unlock()
	}

	switch msg.Kind {
	case FreshnessAnnounce, 0: // Kind=0 is legacy/unspecified — treat as announce
		_ = fc.tracker.Observe(payload)
	case FreshnessRequest:
		fc.handleRequest(msg)
	}
}

// onMismatch fires when the tracker sees a digest differing from the
// previous observation (or the first-ever observation for this peer).
// If the cache also disagrees with the announced digest, broadcast a
// request.
func (fc *FreshnessClient) onMismatch(peerNodeID, peerDigest string) {
	// If no cache is wired, we can't compare — skip the request flow.
	// The tracker still records the announce for consumers that want
	// to query LastDigest directly.
	if fc.cache == nil {
		return
	}
	cachedDigest := ""
	if body := fc.cache.LookupReachBody(peerNodeID); body != nil {
		if d, ok := digestFromReachBody(body); ok {
			cachedDigest = d
		}
	}
	if cachedDigest != "" && cachedDigest == peerDigest {
		return // cache is current
	}
	if !fc.requestAllowed(peerNodeID) {
		return
	}
	req := freshnessPayload{
		Kind:   FreshnessRequest,
		NodeID: peerNodeID,
		Digest: cachedDigest,
		From:   fc.nodeID,
		HLC:    fc.clock.Last(),
	}
	raw, err := json.Marshal(&req)
	if err != nil {
		return
	}
	_ = fc.bus.PublishDigest(raw)
}

// handleRequest handles inbound FreshnessRequest messages. If the subject
// matches our NodeID and a publisher is wired, trigger a forced publish.
func (fc *FreshnessClient) handleRequest(msg freshnessPayload) {
	if msg.NodeID != fc.nodeID {
		return
	}
	if fc.publisher == nil {
		return
	}
	// Optional optimisation: if the requester's Digest matches our current
	// LastDigest we could skip — but the publisher's own skip-on-digest
	// already handles that at publishOnce time, and ForcePublish honours
	// the bypass so the publisher re-emits unconditionally. That's fine:
	// the scheduler's leaky bucket still prevents thrashing.
	fc.publisher.ForcePublish(PublishReasonPeerRequest)
}

// requestAllowed returns true if we haven't sent an outbound request for
// the same subject within cooldown. Records the time on success.
func (fc *FreshnessClient) requestAllowed(subject string) bool {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	now := time.Now()
	if last, ok := fc.lastRequestAt[subject]; ok && now.Sub(last) < fc.cooldown {
		return false
	}
	fc.lastRequestAt[subject] = now
	return true
}

// runPrune is the background maintenance loop — bounds memory usage.
func (fc *FreshnessClient) runPrune(ctx context.Context) {
	defer close(fc.doneCh)
	ticker := time.NewTicker(defaultPruneInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-fc.stopCh:
			return
		case <-ticker.C:
			fc.tracker.Prune(defaultPruneKeep)
			fc.pruneState(defaultPruneKeep)
		}
	}
}

func (fc *FreshnessClient) pruneState(keep time.Duration) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	cutoff := time.Now().Add(-keep)
	for k, t := range fc.lastRequestAt {
		if t.Before(cutoff) {
			delete(fc.lastRequestAt, k)
		}
	}
}

// digestFromReachBody extracts the address-set digest from a full
// ReachRecord body. Returns ("", false) if the body is a delta or can't
// be unmarshalled.
func digestFromReachBody(body []byte) (string, bool) {
	var r ReachRecord
	if err := json.Unmarshal(body, &r); err != nil {
		return "", false
	}
	if IsDelta(r.SchemaVersion) {
		return "", false
	}
	return Digest(r.AddressSet), true
}

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
