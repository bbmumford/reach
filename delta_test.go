// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestComputeDeltaRoundTrip(t *testing.T) {
	prev := []Address{
		{Host: "1.2.3.4", Port: 41641, Proto: "udp", Scope: ScopePublic, Source: SrcDNS, Confidence: 70},
		{Host: "10.0.0.5", Port: 41641, Proto: "udp", Scope: ScopePrivate, Source: SrcInterface, Confidence: 80},
	}
	next := []Address{
		// 1.2.3.4 removed
		{Host: "10.0.0.5", Port: 41641, Proto: "udp", Scope: ScopePrivate, Source: SrcInterface, Confidence: 80},
		// 5.6.7.8 added
		{Host: "5.6.7.8", Port: 41641, Proto: "udp", Scope: ScopePublic, Source: SrcSTUN, Confidence: 40},
	}
	ops := computeDelta(prev, next)
	if len(ops) != 2 {
		t.Fatalf("expected 2 ops (1 add + 1 remove), got %d: %+v", len(ops), ops)
	}

	// Apply delta to prev — must equal next (modulo sort order).
	base := append([]Address(nil), prev...)
	baseDigest := Digest(base)
	drec := DeltaRecord{BaseDigest: baseDigest, Ops: ops}

	rebuilt, err := ApplyDelta(base, drec)
	if err != nil {
		t.Fatal(err)
	}
	if Digest(rebuilt) != Digest(next) {
		t.Fatalf("roundtrip digest mismatch: got %s want %s", Digest(rebuilt), Digest(next))
	}
}

func TestApplyDeltaBaseMismatch(t *testing.T) {
	prev := []Address{{Host: "1.2.3.4", Port: 41641, Proto: "udp", Scope: ScopePublic, Source: SrcDNS}}
	next := []Address{{Host: "5.6.7.8", Port: 41641, Proto: "udp", Scope: ScopePublic, Source: SrcDNS}}
	ops := computeDelta(prev, next)
	drec := DeltaRecord{BaseDigest: "wrong-digest", Ops: ops}

	_, err := ApplyDelta(prev, drec)
	if !errors.Is(err, ErrDeltaBaseMismatch) {
		t.Fatalf("expected ErrDeltaBaseMismatch, got %v", err)
	}
}

func TestDeltaSignVerifyRoundTrip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	drec := DeltaRecord{
		NodeID:        "n1",
		TenantID:      "t1",
		SchemaVersion: SchemaVersion | DeltaSchemaFlag,
		HLC:           HLC{Wall: 123, Logical: 4},
		Epoch:         7,
		BaseDigest:    "abc",
		Ops: []DeltaEntry{
			{Op: DeltaAdd, AddrKey: "udp|1.2.3.4|41641|public|dns"},
		},
		UpdatedAt: time.Now(),
	}
	signDelta(&drec, priv)
	if err := VerifyDelta(drec); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Tamper with an op — must fail.
	drec.Ops[0].AddrKey = "tampered"
	if err := VerifyDelta(drec); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid after tamper, got %v", err)
	}
}

func TestIsDeltaFlag(t *testing.T) {
	if IsDelta(SchemaVersion) {
		t.Fatal("vanilla SchemaVersion should NOT be delta")
	}
	if !IsDelta(SchemaVersion | DeltaSchemaFlag) {
		t.Fatal("flag-tagged SchemaVersion should be delta")
	}
}
