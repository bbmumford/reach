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

// TestVerifyCoversMetadata locks in that a peer cannot re-marshal a signed
// record with different metadata and have it still verify.
func TestVerifyCoversMetadata(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := ReachRecord{
		NodeID:        "node-a",
		SchemaVersion: 1,
		HLC:           HLC{Wall: 1},
		Metadata: Metadata{
			"service_name": "devices.orbtr.io",
			"roles":        "anchor",
		},
	}
	Sign(&rec, priv)

	// Tamper with a metadata value — signature must no longer verify.
	rec.Metadata["roles"] = "admin"
	if err := Verify(rec); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid after metadata tamper, got %v", err)
	}

	// Also tamper by ADDING a new metadata key.
	rec2 := ReachRecord{
		NodeID:        "node-a",
		SchemaVersion: 1,
		HLC:           HLC{Wall: 1},
		Metadata:      Metadata{"service_name": "devices.orbtr.io"},
	}
	Sign(&rec2, priv)
	rec2.Metadata["roles"] = "forged"
	if err := Verify(rec2); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid after metadata add, got %v", err)
	}
}
