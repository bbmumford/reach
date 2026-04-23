// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"sync"
	"testing"
	"time"

	lad "github.com/bbmumford/ledger"
)

// --- mock LedgerAppender for tests ---------------------------------------

type memLedger struct {
	mu      sync.Mutex
	records []lad.Record
}

func (m *memLedger) Append(_ context.Context, rec lad.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	dup := rec
	dup.Body = append([]byte(nil), rec.Body...)
	m.records = append(m.records, dup)
	return nil
}

func (m *memLedger) all() []lad.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]lad.Record(nil), m.records...)
}

// --- stub discoverer ------------------------------------------------------

type staticDiscoverer struct {
	name    string
	source  AddressSource
	addrs   []Address
	callCnt int
	mu      sync.Mutex
}

func (s *staticDiscoverer) Name() string                    { return s.name }
func (s *staticDiscoverer) Source() AddressSource           { return s.source }
func (s *staticDiscoverer) Interval() time.Duration         { return 5 * time.Minute }
func (s *staticDiscoverer) EnabledFor(string) bool          { return true }
func (s *staticDiscoverer) Discover(_ context.Context) ([]Address, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callCnt++
	out := make([]Address, len(s.addrs))
	copy(out, s.addrs)
	return out, nil
}

// -------------------------------------------------------------------------

func TestPublisherDigestSkip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	mem := &memLedger{}
	addrs := []Address{
		{Host: "1.2.3.4", Port: 41641, Proto: "udp", Scope: ScopePublic, Source: SrcStatic, Confidence: 100},
	}
	disc := &staticDiscoverer{name: "static-test", source: SrcStatic, addrs: addrs}

	pub, err := NewPublisher(Config{
		NodeID:      "node-a",
		Region:      "iad",
		Signer:      priv,
		Ledger:      mem,
		Discoverers: []Discoverer{disc},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Two publishes in quick succession with identical address set.
	if err := pub.publishOnce(context.Background(), PublishReasonBootstrap); err != nil {
		t.Fatal(err)
	}
	// Second publish should skip on digest match (plan §5.1).
	if err := pub.publishOnce(context.Background(), PublishReasonTimer); err != nil {
		t.Fatal(err)
	}
	got := mem.all()
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 ledger append (digest skip), got %d", len(got))
	}
}

func TestPublisherSignAndICE(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	mem := &memLedger{}
	addrs := []Address{
		{Host: "1.2.3.4", Port: 41641, Proto: "udp", Scope: ScopePublic, Source: SrcDNS, Confidence: 70},
	}
	disc := &staticDiscoverer{name: "dns", source: SrcDNS, addrs: addrs}

	pub, err := NewPublisher(Config{
		NodeID:      "node-a",
		Region:      "iad",
		Signer:      priv,
		Ledger:      mem,
		Discoverers: []Discoverer{disc},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.publishOnce(context.Background(), PublishReasonBootstrap); err != nil {
		t.Fatal(err)
	}
	recs := mem.all()
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	var rec ReachRecord
	if err := json.Unmarshal(recs[0].Body, &rec); err != nil {
		t.Fatal(err)
	}
	if err := Verify(rec); err != nil {
		t.Fatalf("signed record must verify: %v", err)
	}
	if len(rec.ICECandidates) == 0 {
		t.Fatal("expected ICE candidates populated (plan §6a)")
	}
	if len(rec.AddressSet) == 0 {
		t.Fatal("expected enriched AddressSet populated")
	}
}

func TestPublisherDeltaAfterSnapshot(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	mem := &memLedger{}
	addrs := []Address{
		{Host: "1.2.3.4", Port: 41641, Proto: "udp", Scope: ScopePublic, Source: SrcDNS, Confidence: 70},
	}
	disc := &staticDiscoverer{name: "dns", source: SrcDNS, addrs: addrs}

	pub, err := NewPublisher(Config{
		NodeID:         "node-a",
		Region:         "iad",
		Signer:         priv,
		Ledger:         mem,
		Discoverers:    []Discoverer{disc},
		DeltaThreshold: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	// First publish = full snapshot (bootstrap).
	if err := pub.publishOnce(context.Background(), PublishReasonBootstrap); err != nil {
		t.Fatal(err)
	}
	// Second publish with CHANGED addrs = delta.
	disc.addrs = append(addrs, Address{Host: "5.6.7.8", Port: 41641, Proto: "udp", Scope: ScopePublic, Source: SrcDNS, Confidence: 70})
	if err := pub.publishOnce(context.Background(), PublishReasonTimer); err != nil {
		t.Fatal(err)
	}
	recs := mem.all()
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	// Second record must be a delta — discriminate by the flag bit in SchemaVersion.
	var probe struct {
		SchemaVersion uint16 `json:"v"`
	}
	if err := json.Unmarshal(recs[1].Body, &probe); err != nil {
		t.Fatal(err)
	}
	if !IsDelta(probe.SchemaVersion) {
		t.Fatalf("second publish should be a delta, SchemaVersion=%d", probe.SchemaVersion)
	}
}

func TestPublisherMissingSignerRejected(t *testing.T) {
	_, err := NewPublisher(Config{
		NodeID: "n1",
		Ledger: &memLedger{},
	})
	if err == nil {
		t.Fatal("NewPublisher without Signer should error")
	}
}
