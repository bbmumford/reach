// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"testing"
	"time"

	lad "github.com/bbmumford/ledger"
)

// TestDeriveMemberPassthrough verifies the default mirror is identity —
// every metadata key becomes the same attrs key, unchanged.
func TestDeriveMemberPassthrough(t *testing.T) {
	rec := ReachRecord{
		NodeID: "n1",
		Metadata: Metadata{
			"service_name": "devices.orbtr.io",
			"region":       "iad",
			"roles":        "anchor,platform.tenant",
			"fly_machine":  "abc123",
		},
		UpdatedAt: time.Unix(1000, 0),
	}
	m, ok := DeriveMember(rec)
	if !ok {
		t.Fatal("DeriveMember returned !ok")
	}
	if m.Attrs["service_name"] != "devices.orbtr.io" {
		t.Errorf("service_name: %q", m.Attrs["service_name"])
	}
	if m.Attrs["region"] != "iad" {
		t.Errorf("region: %q", m.Attrs["region"])
	}
	if m.Attrs["roles"] != "anchor,platform.tenant" {
		t.Errorf("roles: %q", m.Attrs["roles"])
	}
	if m.Attrs["fly_machine"] != "abc123" {
		t.Errorf("fly_machine: %q", m.Attrs["fly_machine"])
	}
}

// TestDeriveMemberAgentStyle verifies an agent-shaped metadata set passes
// through cleanly — no hostname/service_name conflation, each consumer's
// conventions respected.
func TestDeriveMemberAgentStyle(t *testing.T) {
	rec := ReachRecord{
		NodeID: "n1",
		Metadata: Metadata{
			"hostname":    "alice-laptop",
			"device_id":   "dev-abc",
			"os":          "darwin",
			"app_version": "v0.0.6",
		},
	}
	m, ok := DeriveMember(rec)
	if !ok {
		t.Fatal("DeriveMember returned !ok")
	}
	if m.Attrs["hostname"] != "alice-laptop" {
		t.Errorf("hostname: %q", m.Attrs["hostname"])
	}
	if m.Attrs["device_id"] != "dev-abc" {
		t.Errorf("device_id: %q", m.Attrs["device_id"])
	}
	if _, leaked := m.Attrs["service_name"]; leaked {
		t.Error("agent-shape metadata should not produce service_name attr")
	}
}

// TestDeriveMemberKeyMap verifies consumers can remap metadata keys.
func TestDeriveMemberKeyMap(t *testing.T) {
	rec := ReachRecord{
		NodeID:   "n1",
		Metadata: Metadata{"hostname": "alice-laptop", "ssn": "secret"},
	}
	cfg := MirrorConfig{
		KeyMap: map[string]string{
			"hostname": "host",
			"ssn":      "", // explicit skip
		},
	}
	m, ok := DeriveMemberWith(cfg, rec)
	if !ok {
		t.Fatal("DeriveMemberWith returned !ok")
	}
	if m.Attrs["host"] != "alice-laptop" {
		t.Errorf("host: %q", m.Attrs["host"])
	}
	if _, leaked := m.Attrs["hostname"]; leaked {
		t.Error("unmapped original key leaked: hostname")
	}
	if _, leaked := m.Attrs["ssn"]; leaked {
		t.Error("explicitly-skipped key leaked: ssn")
	}
}

// TestDeriveMemberSkipUnmapped verifies strict-filter mode excludes all
// metadata keys not in the KeyMap.
func TestDeriveMemberSkipUnmapped(t *testing.T) {
	rec := ReachRecord{
		NodeID: "n1",
		Metadata: Metadata{
			"hostname": "alice-laptop",
			"keep_me":  "ok",
			"drop_me":  "out",
		},
	}
	cfg := MirrorConfig{
		KeyMap:       map[string]string{"hostname": "host", "keep_me": "kept"},
		SkipUnmapped: true,
	}
	m, ok := DeriveMemberWith(cfg, rec)
	if !ok {
		t.Fatal("DeriveMemberWith returned !ok")
	}
	if m.Attrs["host"] != "alice-laptop" || m.Attrs["kept"] != "ok" {
		t.Errorf("expected remapped keys, got %v", m.Attrs)
	}
	if _, leaked := m.Attrs["drop_me"]; leaked {
		t.Error("SkipUnmapped=true should exclude unmapped keys")
	}
}

// TestDeriveMemberPrimaryKeyGate verifies PrimaryKey filtering.
func TestDeriveMemberPrimaryKeyGate(t *testing.T) {
	// Record WITHOUT service_name is skipped.
	rec := ReachRecord{
		NodeID:   "n1",
		Metadata: Metadata{"hostname": "alice-laptop"},
	}
	cfg := MirrorConfig{PrimaryKey: "service_name"}
	if _, ok := DeriveMemberWith(cfg, rec); ok {
		t.Error("PrimaryKey-gated mirror should skip records without the key")
	}

	// Record WITH service_name is emitted.
	rec2 := ReachRecord{
		NodeID:   "n1",
		Metadata: Metadata{"service_name": "devices.orbtr.io"},
	}
	if _, ok := DeriveMemberWith(cfg, rec2); !ok {
		t.Error("PrimaryKey-gated mirror should emit when key present")
	}
}

// TestDeriveMemberDeriverOverride verifies full override bypasses all mapping.
func TestDeriveMemberDeriverOverride(t *testing.T) {
	rec := ReachRecord{NodeID: "n1", Metadata: Metadata{"x": "y"}}
	called := false
	cfg := MirrorConfig{
		KeyMap: map[string]string{"x": "should_not_be_used"},
		Deriver: func(r ReachRecord) (lad.MemberRecord, bool) {
			called = true
			return lad.MemberRecord{
				NodeID: r.NodeID,
				Attrs:  map[string]string{"custom": "yes"},
			}, true
		},
	}
	m, ok := DeriveMemberWith(cfg, rec)
	if !ok || !called {
		t.Fatalf("deriver override not invoked: ok=%v called=%v", ok, called)
	}
	if m.Attrs["custom"] != "yes" {
		t.Errorf("Attrs: %v", m.Attrs)
	}
	if _, leaked := m.Attrs["should_not_be_used"]; leaked {
		t.Error("KeyMap leaked through deriver override")
	}
}

// TestDeriveMemberEmptyMetadata skips synthesis when Metadata is empty.
func TestDeriveMemberEmptyMetadata(t *testing.T) {
	if _, ok := DeriveMember(ReachRecord{NodeID: "n1"}); ok {
		t.Error("DeriveMember returned ok on empty Metadata")
	}
}
