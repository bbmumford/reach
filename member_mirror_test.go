// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"strings"
	"testing"
	"time"

	lad "github.com/bbmumford/ledger"
)

func TestDeriveMemberDefaultConvention(t *testing.T) {
	rec := ReachRecord{
		NodeID:      "n1",
		ServiceName: "devices.orbtr.io",
		Region:      "iad",
		Roles:       []string{"anchor", "platform.tenant"},
		UpdatedAt:   time.Unix(1000, 0),
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
}

func TestDeriveMemberCustomConvention(t *testing.T) {
	rec := ReachRecord{
		NodeID:      "n1",
		ServiceName: "my-service",
		Region:      "eu-west-1",
		Roles:       []string{"tagA", "tagB"},
	}
	// Consumer with different attr keys + pipe-joined roles.
	cfg := MirrorConfig{
		AttrKeyServiceName: "svc",
		AttrKeyRegion:      "rgn",
		AttrKeyRoles:       "tags",
		RoleJoiner:         "|",
	}
	m, ok := DeriveMemberWith(cfg, rec)
	if !ok {
		t.Fatal("DeriveMemberWith returned !ok")
	}
	if _, wrongKey := m.Attrs["service_name"]; wrongKey {
		t.Error("default 'service_name' leaked into custom-config output")
	}
	if m.Attrs["svc"] != "my-service" {
		t.Errorf("svc: %q", m.Attrs["svc"])
	}
	if m.Attrs["rgn"] != "eu-west-1" {
		t.Errorf("rgn: %q", m.Attrs["rgn"])
	}
	if m.Attrs["tags"] != "tagA|tagB" {
		t.Errorf("tags: %q", m.Attrs["tags"])
	}
}

func TestDeriveMemberDeriverOverride(t *testing.T) {
	// Deriver override takes precedence over attr-key config.
	rec := ReachRecord{NodeID: "n1", ServiceName: "svc"}
	called := false
	cfg := MirrorConfig{
		AttrKeyServiceName: "service_name",  // should be ignored
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
	if _, leaked := m.Attrs["service_name"]; leaked {
		t.Error("default mapping leaked through deriver override")
	}
}

func TestDeriveMemberEmptyServiceName(t *testing.T) {
	// Default convention skips synthesis when ServiceName is empty.
	_, ok := DeriveMember(ReachRecord{NodeID: "n1", ServiceName: ""})
	if ok {
		t.Error("DeriveMember returned ok on empty ServiceName")
	}
}

func TestMirrorConfigDefaultsFillOnly(t *testing.T) {
	// Partial config: only overrides the keys you set.
	cfg := MirrorConfig{AttrKeyRoles: "tags"}.withDefaults()
	if cfg.AttrKeyServiceName != "service_name" {
		t.Errorf("service_name default not applied: %q", cfg.AttrKeyServiceName)
	}
	if cfg.AttrKeyRegion != "region" {
		t.Errorf("region default not applied: %q", cfg.AttrKeyRegion)
	}
	if cfg.AttrKeyRoles != "tags" {
		t.Errorf("explicit roles override lost: %q", cfg.AttrKeyRoles)
	}
	if cfg.RoleJoiner != "," {
		t.Errorf("default joiner not applied: %q", cfg.RoleJoiner)
	}
}

// Sentinel to make strings used.
var _ = strings.Join
