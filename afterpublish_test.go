// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"
)

// TestAfterPublishFiresOnInitialPublish verifies the hook fires
// exactly once for the bootstrap full-snapshot emit and the
// PublishInfo carries the just-signed digest + addresses.
func TestAfterPublishFiresOnInitialPublish(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	mem := &memLedger{}
	addrs := []Address{
		{Host: "1.2.3.4", Port: 41641, Proto: "udp", Scope: ScopePublic, Source: SrcStatic, Confidence: 100},
	}
	disc := &staticDiscoverer{name: "static-test", source: SrcStatic, addrs: addrs}

	var mu sync.Mutex
	var infos []PublishInfo
	pub, err := NewPublisher(Config{
		NodeID:      "node-a",
		Region:      "iad",
		Signer:      priv,
		Ledger:      mem,
		Discoverers: []Discoverer{disc},
		AfterPublish: func(info PublishInfo) {
			mu.Lock()
			infos = append(infos, info)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := pub.publishOnce(context.Background(), PublishReasonBootstrap); err != nil {
		t.Fatalf("publish: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(infos) != 1 {
		t.Fatalf("expected 1 AfterPublish call, got %d", len(infos))
	}
	info := infos[0]
	if info.Reason != PublishReasonBootstrap {
		t.Errorf("wrong reason: %v", info.Reason)
	}
	if info.Digest == "" {
		t.Error("digest missing")
	}
	if len(info.Addresses) != 1 {
		t.Errorf("expected 1 address, got %d", len(info.Addresses))
	}
	if info.Addresses[0] != "1.2.3.4:41641" {
		t.Errorf("bad address: %q", info.Addresses[0])
	}
	if !info.Full {
		t.Error("bootstrap must be marked as Full snapshot")
	}
}

// TestAfterPublishNotFiredOnSkip verifies the hook stays silent when
// publishOnce short-circuits on an unchanged digest — matches the
// semantics the agent's PEX refresher depends on.
func TestAfterPublishNotFiredOnSkip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	mem := &memLedger{}
	addrs := []Address{
		{Host: "1.2.3.4", Port: 41641, Proto: "udp", Scope: ScopePublic, Source: SrcStatic, Confidence: 100},
	}
	disc := &staticDiscoverer{name: "static-test", source: SrcStatic, addrs: addrs}

	var calls int
	var mu sync.Mutex
	pub, err := NewPublisher(Config{
		NodeID:      "node-a",
		Region:      "iad",
		Signer:      priv,
		Ledger:      mem,
		Discoverers: []Discoverer{disc},
		AfterPublish: func(info PublishInfo) {
			mu.Lock()
			calls++
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// First publish: fires.
	_ = pub.publishOnce(context.Background(), PublishReasonBootstrap)
	// Second publish with same addresses + timer reason: should skip.
	_ = pub.publishOnce(context.Background(), PublishReasonTimer)

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("expected 1 call (bootstrap only), got %d", calls)
	}
}

// TestAfterPublishRunsOutsideLock verifies the hook can call back
// into the publisher (MetadataSnapshot, CurrentAddresses) without
// deadlock — the property that makes the hook safe for the agent's
// refreshPEX pattern.
func TestAfterPublishRunsOutsideLock(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	mem := &memLedger{}
	addrs := []Address{
		{Host: "9.9.9.9", Port: 41641, Proto: "udp", Scope: ScopePublic, Source: SrcStatic, Confidence: 100},
	}
	disc := &staticDiscoverer{name: "static-test", source: SrcStatic, addrs: addrs}

	var currentAddrs []string
	var pubRef *Publisher
	done := make(chan struct{}, 1)
	pub, err := NewPublisher(Config{
		NodeID:      "node-a",
		Region:      "iad",
		Signer:      priv,
		Ledger:      mem,
		Discoverers: []Discoverer{disc},
		AfterPublish: func(info PublishInfo) {
			// Would deadlock if publisher held its lock across the
			// hook — CurrentAddresses takes the same p.mu.
			if pubRef != nil {
				currentAddrs = append(currentAddrs, pubRef.CurrentAddresses()...)
			}
			select {
			case done <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	pubRef = pub

	_ = pub.publishOnce(context.Background(), PublishReasonBootstrap)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("AfterPublish never called back")
	}
	if len(currentAddrs) != 1 {
		t.Errorf("expected 1 address, got %d", len(currentAddrs))
	}
}
