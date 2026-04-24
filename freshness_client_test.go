// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// inMemoryBus is a trivial FreshnessBus backed by in-process fan-out.
// All subscribers see every published message. Used by the tests below
// to simulate peer ↔ peer message flow.
type inMemoryBus struct {
	mu          sync.Mutex
	subscribers []func([]byte)
}

func newInMemoryBus() *inMemoryBus { return &inMemoryBus{} }

func (b *inMemoryBus) PublishDigest(payload []byte) error {
	b.mu.Lock()
	subs := make([]func([]byte), 0, len(b.subscribers))
	for _, s := range b.subscribers {
		if s != nil {
			subs = append(subs, s)
		}
	}
	b.mu.Unlock()
	for _, s := range subs {
		dup := make([]byte, len(payload))
		copy(dup, payload)
		s(dup)
	}
	return nil
}

func (b *inMemoryBus) SubscribeFreshness(h func([]byte)) func() {
	b.mu.Lock()
	b.subscribers = append(b.subscribers, h)
	idx := len(b.subscribers) - 1
	b.mu.Unlock()
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if idx < len(b.subscribers) {
			b.subscribers[idx] = nil
		}
	}
}

// mapLookup implements ReachRecordLookup over an in-memory map.
type mapLookup struct {
	mu    sync.Mutex
	bodies map[string][]byte
}

func newMapLookup() *mapLookup { return &mapLookup{bodies: map[string][]byte{}} }

func (m *mapLookup) LookupReachBody(nodeID string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.bodies[nodeID]
	if !ok {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func (m *mapLookup) set(nodeID string, body []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bodies[nodeID] = body
}

// TestFreshnessClient_AnnounceTriggersRequestOnCacheMiss verifies that
// a peer's FreshnessAnnounce with a digest we don't have leads to a
// FreshnessRequest being broadcast.
func TestFreshnessClient_AnnounceTriggersRequestOnCacheMiss(t *testing.T) {
	bus := newInMemoryBus()
	cache := newMapLookup() // empty — we have nothing cached

	fc := NewFreshnessClient(bus, cache, nil, "receiver", nil)
	fc.SetCooldown(100 * time.Millisecond)
	fc.Start(context.Background())
	defer fc.Stop()

	// Count request broadcasts.
	var requests int32
	bus.SubscribeFreshness(func(payload []byte) {
		var msg freshnessPayload
		if err := json.Unmarshal(payload, &msg); err != nil {
			return
		}
		if msg.Kind == FreshnessRequest {
			atomic.AddInt32(&requests, 1)
		}
	})

	// Peer announces its digest.
	announce := freshnessPayload{
		Kind:   FreshnessAnnounce,
		NodeID: "peer1",
		Digest: "digest-xyz",
		From:   "peer1",
		Epoch:  1,
	}
	raw, _ := json.Marshal(&announce)
	_ = bus.PublishDigest(raw)

	// Give the client's async handler + tracker time to react.
	time.Sleep(50 * time.Millisecond)

	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("expected 1 request broadcast after cache-miss announce, got %d", got)
	}
}

// TestFreshnessClient_AnnounceSuppressedWhenCacheHasMatchingDigest:
// if the cache already has the same digest the peer announced, we
// should NOT send a request.
func TestFreshnessClient_AnnounceSuppressedWhenCacheHasMatchingDigest(t *testing.T) {
	bus := newInMemoryBus()
	cache := newMapLookup()

	// Seed the cache with a record whose address-set hashes to a known digest.
	peerAddrs := []Address{
		{Host: "1.1.1.1", Port: 9000, Proto: "udp", Scope: ScopePublic, Source: SrcSTUN},
	}
	peerDigest := Digest(peerAddrs)
	peerRec := ReachRecord{
		NodeID:        "peer1",
		AddressSet:    peerAddrs,
		SchemaVersion: SchemaVersion,
	}
	peerBody, _ := json.Marshal(&peerRec)
	cache.set("peer1", peerBody)

	fc := NewFreshnessClient(bus, cache, nil, "receiver", nil)
	fc.SetCooldown(100 * time.Millisecond)
	fc.Start(context.Background())
	defer fc.Stop()

	var requests int32
	bus.SubscribeFreshness(func(payload []byte) {
		var msg freshnessPayload
		if err := json.Unmarshal(payload, &msg); err != nil {
			return
		}
		if msg.Kind == FreshnessRequest {
			atomic.AddInt32(&requests, 1)
		}
	})

	announce := freshnessPayload{
		Kind:   FreshnessAnnounce,
		NodeID: "peer1",
		Digest: peerDigest, // matches cache
		From:   "peer1",
		Epoch:  1,
	}
	raw, _ := json.Marshal(&announce)
	_ = bus.PublishDigest(raw)

	time.Sleep(50 * time.Millisecond)

	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Fatalf("expected 0 requests when cache matches announce, got %d", got)
	}
}

// TestFreshnessClient_RequestCooldown: after a request has been sent for
// a subject, a second announce within the cooldown window does NOT
// trigger another request.
func TestFreshnessClient_RequestCooldown(t *testing.T) {
	bus := newInMemoryBus()
	cache := newMapLookup() // empty

	fc := NewFreshnessClient(bus, cache, nil, "receiver", nil)
	fc.SetCooldown(500 * time.Millisecond)
	fc.Start(context.Background())
	defer fc.Stop()

	var requests int32
	bus.SubscribeFreshness(func(payload []byte) {
		var msg freshnessPayload
		if err := json.Unmarshal(payload, &msg); err != nil {
			return
		}
		if msg.Kind == FreshnessRequest {
			atomic.AddInt32(&requests, 1)
		}
	})

	// Two announces in quick succession for the same peer.
	// First will trigger via the first-seen mismatch. Second will trigger
	// via digest-change IF the digest differs; we keep digest identical so
	// the tracker's Observe only fires onMismatch for the FIRST announce.
	announce := freshnessPayload{
		Kind:   FreshnessAnnounce,
		NodeID: "peer1",
		Digest: "a",
		From:   "peer1",
		Epoch:  1,
	}
	raw, _ := json.Marshal(&announce)
	_ = bus.PublishDigest(raw)
	time.Sleep(10 * time.Millisecond)

	// Change digest to trigger another onMismatch — cooldown should suppress.
	announce.Digest = "b"
	raw2, _ := json.Marshal(&announce)
	_ = bus.PublishDigest(raw2)
	time.Sleep(50 * time.Millisecond)

	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("cooldown violated: got %d requests (expected 1)", got)
	}

	// After cooldown, another digest change should fire again.
	time.Sleep(550 * time.Millisecond)
	announce.Digest = "c"
	raw3, _ := json.Marshal(&announce)
	_ = bus.PublishDigest(raw3)
	time.Sleep(50 * time.Millisecond)

	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Fatalf("expected 2 requests after cooldown expiry, got %d", got)
	}
}

// TestFreshnessClient_InboundRequestTriggersForcePublish verifies that
// a FreshnessRequest addressed to our NodeID flows into publisher.ForcePublish.
func TestFreshnessClient_InboundRequestTriggersForcePublish(t *testing.T) {
	bus := newInMemoryBus()
	cache := newMapLookup()

	// Build a minimal Publisher with a forceCh we can observe. We don't
	// run it — we just watch forceCh for the request.
	pub := &Publisher{
		cfg:     &Config{NodeID: "self"},
		forceCh: make(chan PublishReason, 4),
	}

	fc := NewFreshnessClient(bus, cache, pub, "self", nil)
	fc.Start(context.Background())
	defer fc.Stop()

	// Peer sends a request for our NodeID.
	req := freshnessPayload{
		Kind:   FreshnessRequest,
		NodeID: "self",
		From:   "peer1",
	}
	raw, _ := json.Marshal(&req)
	_ = bus.PublishDigest(raw)

	select {
	case reason := <-pub.forceCh:
		if reason != PublishReasonPeerRequest {
			t.Fatalf("expected PublishReasonPeerRequest, got %q", reason)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatalf("no ForcePublish triggered by inbound request")
	}
}

// TestFreshnessClient_InboundRequestIgnoredIfNotForUs verifies we don't
// react to requests addressed to other NodeIDs.
func TestFreshnessClient_InboundRequestIgnoredIfNotForUs(t *testing.T) {
	bus := newInMemoryBus()
	cache := newMapLookup()

	pub := &Publisher{
		cfg:     &Config{NodeID: "self"},
		forceCh: make(chan PublishReason, 4),
	}

	fc := NewFreshnessClient(bus, cache, pub, "self", nil)
	fc.Start(context.Background())
	defer fc.Stop()

	req := freshnessPayload{
		Kind:   FreshnessRequest,
		NodeID: "someone-else",
		From:   "peer1",
	}
	raw, _ := json.Marshal(&req)
	_ = bus.PublishDigest(raw)

	select {
	case reason := <-pub.forceCh:
		t.Fatalf("unexpected ForcePublish: %q", reason)
	case <-time.After(100 * time.Millisecond):
		// Correct: no force publish.
	}
}

// TestFreshnessClient_OwnMessagesIgnored: loop-prevention — if From
// matches our NodeID we don't react.
func TestFreshnessClient_OwnMessagesIgnored(t *testing.T) {
	bus := newInMemoryBus()
	cache := newMapLookup()

	pub := &Publisher{
		cfg:     &Config{NodeID: "self"},
		forceCh: make(chan PublishReason, 4),
	}

	fc := NewFreshnessClient(bus, cache, pub, "self", nil)
	fc.Start(context.Background())
	defer fc.Stop()

	// Our own request (e.g. echoed back by broadcast).
	req := freshnessPayload{
		Kind:   FreshnessRequest,
		NodeID: "self",
		From:   "self", // our own node
	}
	raw, _ := json.Marshal(&req)
	_ = bus.PublishDigest(raw)

	select {
	case reason := <-pub.forceCh:
		t.Fatalf("our own request triggered force publish: %q", reason)
	case <-time.After(100 * time.Millisecond):
		// Correct.
	}
}
