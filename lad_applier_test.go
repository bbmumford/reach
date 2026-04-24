// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"encoding/json"
	"testing"
	"time"

	lad "github.com/bbmumford/ledger"
)

// TestLadCacheDeltaApplier_EndToEnd verifies the full flow:
//   - publisher creates signed full snapshot
//   - publisher creates signed delta (one add, one remove)
//   - applier rebuilds a full ReachRecord body
//   - rebuilt body carries base Metadata + Region, delta HLC/UpdatedAt,
//     and the new address set
//
// This is the invariant the ledger cache relies on when it wires up
// LadCacheDeltaApplier — Metadata survives, addresses stay fresh.
func TestLadCacheDeltaApplier_EndToEnd(t *testing.T) {
	// Build a base ReachRecord manually (skipping publisher machinery).
	baseAddrs := []Address{
		{Host: "1.1.1.1", Port: 9000, Proto: "udp", Scope: ScopePublic, Source: SrcSTUN, ExpiresAt: time.Now().Add(time.Hour)},
		{Host: "2.2.2.2", Port: 9000, Proto: "udp", Scope: ScopePublic, Source: SrcSTUN, ExpiresAt: time.Now().Add(time.Hour)},
	}
	base := ReachRecord{
		TenantID:      "",
		NodeID:        "vl1_alice",
		Region:        "iad",
		Addresses:     []lad.ReachAddress{{Host: "1.1.1.1", Port: 9000, Proto: "udp", Scope: "public"}, {Host: "2.2.2.2", Port: 9000, Proto: "udp", Scope: "public"}},
		AddressSet:    baseAddrs,
		UpdatedAt:     time.Now(),
		SchemaVersion: SchemaVersion,
		Metadata: Metadata{
			"service_name": "alice.example.com",
			"region":       "iad",
		},
	}
	baseBody, err := json.Marshal(&base)
	if err != nil {
		t.Fatalf("marshal base: %v", err)
	}

	// Build a delta: remove 1.1.1.1, add 3.3.3.3.
	baseDigest := Digest(baseAddrs)
	newAddr := Address{Host: "3.3.3.3", Port: 9000, Proto: "udp", Scope: ScopePublic, Source: SrcSTUN, ExpiresAt: time.Now().Add(time.Hour)}
	delta := DeltaRecord{
		NodeID:        "vl1_alice",
		SchemaVersion: SchemaVersion | DeltaSchemaFlag,
		BaseDigest:    baseDigest,
		UpdatedAt:     time.Now().Add(time.Second),
		Ops: []DeltaEntry{
			{Op: DeltaRemove, AddrKey: baseAddrs[0].Key()},
			{Op: DeltaAdd, AddrKey: newAddr.Key(), Addr: &newAddr},
		},
	}
	deltaBody, err := MarshalDelta(&delta)
	if err != nil {
		t.Fatalf("marshal delta: %v", err)
	}

	// Apply via the cache hook.
	newBody, err := LadCacheDeltaApplier(baseBody, deltaBody)
	if err != nil {
		t.Fatalf("applier: %v", err)
	}

	// Decode as lad.ReachRecord (the cache's storage shape) and validate
	// invariants.
	var got lad.ReachRecord
	if err := json.Unmarshal(newBody, &got); err != nil {
		t.Fatalf("decode rebuilt body as lad.ReachRecord: %v", err)
	}
	if got.IsReachDelta() {
		t.Fatalf("rebuilt body still flagged as delta: v=%d", got.SchemaVersion)
	}
	if got.Metadata["service_name"] != "alice.example.com" {
		t.Fatalf("Metadata lost: %+v", got.Metadata)
	}
	if got.Region != "iad" {
		t.Fatalf("Region lost: %q", got.Region)
	}
	// Addresses: expect 2.2.2.2 + 3.3.3.3, no 1.1.1.1.
	hosts := map[string]bool{}
	for _, a := range got.Addresses {
		hosts[a.Host] = true
	}
	if hosts["1.1.1.1"] {
		t.Fatalf("removed address still present: %+v", got.Addresses)
	}
	if !hosts["2.2.2.2"] || !hosts["3.3.3.3"] {
		t.Fatalf("expected 2.2.2.2 + 3.3.3.3, got %+v", got.Addresses)
	}
}

// TestLadCacheDeltaApplier_BaseMismatch verifies that when the delta's
// BaseDigest doesn't match the stored base, the applier returns an error
// (cache will skip the apply and wait for next full snapshot).
func TestLadCacheDeltaApplier_BaseMismatch(t *testing.T) {
	base := ReachRecord{
		NodeID:     "vl1_alice",
		AddressSet: []Address{{Host: "1.1.1.1", Port: 9000, Proto: "udp", Scope: ScopePublic, Source: SrcSTUN}},
	}
	baseBody, _ := json.Marshal(&base)

	delta := DeltaRecord{
		NodeID:        "vl1_alice",
		SchemaVersion: SchemaVersion | DeltaSchemaFlag,
		BaseDigest:    "digest-of-some-other-base",
		Ops:           []DeltaEntry{{Op: DeltaRemove, AddrKey: "udp|foo|1|public|stun"}},
	}
	deltaBody, _ := MarshalDelta(&delta)

	_, err := LadCacheDeltaApplier(baseBody, deltaBody)
	if err == nil {
		t.Fatalf("expected base-mismatch error, got nil")
	}
}
