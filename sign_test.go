// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub

	rec := ReachRecord{
		NodeID:        "node-a",
		TenantID:      "tenant-x",
		SchemaVersion: 1,
		HLC:           HLC{Wall: 1, Logical: 2, NodeID: "node-a"},
		Epoch:         42,
		Region:        "iad",
		AddressSet: []Address{
			{Host: "1.2.3.4", Port: 41641, Proto: "udp", Scope: ScopePublic, Source: SrcDNS, Confidence: 70},
		},
		UpdatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	Sign(&rec, priv)

	if err := Verify(rec); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsTamperedAddressSet(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := ReachRecord{
		NodeID:        "node-a",
		SchemaVersion: 1,
		HLC:           HLC{Wall: 1},
		AddressSet: []Address{
			{Host: "1.2.3.4", Port: 41641, Proto: "udp", Scope: ScopePublic, Source: SrcDNS},
		},
	}
	Sign(&rec, priv)

	// Mutate an address post-signature — signature must no longer verify.
	rec.AddressSet = []Address{
		{Host: "9.9.9.9", Port: 41641, Proto: "udp", Scope: ScopePublic, Source: SrcDNS},
	}
	if err := Verify(rec); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid, got %v", err)
	}
}

func TestVerifyRejectsUnsigned(t *testing.T) {
	rec := ReachRecord{NodeID: "node-a", SchemaVersion: 1}
	if err := Verify(rec); !errors.Is(err, ErrUnsignedRecord) {
		t.Fatalf("expected ErrUnsignedRecord, got %v", err)
	}
}
