// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	lad "github.com/bbmumford/ledger"
)

// MirrorConfig customises how the member mirror projects a ReachRecord into
// a legacy MemberRecord. Zero-value config matches the convention used by
// HSTLES mesh fleet + ORBTR agent (service_name / region / roles attrs,
// comma-joined roles). Third-party consumers with different conventions can
// override every aspect.
type MirrorConfig struct {
	// AttrKeyServiceName — attrs key for the ServiceName field.
	// Default "service_name".
	AttrKeyServiceName string

	// AttrKeyRegion — attrs key for the Region field.
	// Default "region".
	AttrKeyRegion string

	// AttrKeyRoles — attrs key for the joined role list.
	// Default "roles".
	AttrKeyRoles string

	// RoleJoiner — separator for joining Roles into a single attrs value.
	// Default "," (comma).
	RoleJoiner string

	// Deriver — full override. When non-nil, WrapMemberMirror calls this
	// instead of the default projection and ignores every other field.
	// Use when the consumer's MemberRecord convention doesn't fit the
	// simple attr-key-mapping model (e.g. one MemberRecord per role, or
	// role metadata encoded as JSON in a single attr value).
	Deriver func(ReachRecord) (lad.MemberRecord, bool)
}

func (c MirrorConfig) withDefaults() MirrorConfig {
	if c.AttrKeyServiceName == "" {
		c.AttrKeyServiceName = "service_name"
	}
	if c.AttrKeyRegion == "" {
		c.AttrKeyRegion = "region"
	}
	if c.AttrKeyRoles == "" {
		c.AttrKeyRoles = "roles"
	}
	if c.RoleJoiner == "" {
		c.RoleJoiner = ","
	}
	return c
}

// deriveWith applies a MirrorConfig to project a ReachRecord into a MemberRecord.
func deriveWith(cfg MirrorConfig, r ReachRecord) (lad.MemberRecord, bool) {
	if cfg.Deriver != nil {
		return cfg.Deriver(r)
	}
	if r.ServiceName == "" {
		return lad.MemberRecord{}, false
	}
	attrs := map[string]string{
		cfg.AttrKeyServiceName: r.ServiceName,
	}
	if r.Region != "" {
		attrs[cfg.AttrKeyRegion] = r.Region
	}
	if len(r.Roles) > 0 {
		attrs[cfg.AttrKeyRoles] = strings.Join(r.Roles, cfg.RoleJoiner)
	}
	return lad.MemberRecord{
		NodeID:    r.NodeID,
		CreatedAt: r.UpdatedAt,
		Attrs:     attrs,
	}, true
}

// DeriveMember projects a ReachRecord's identity fields into the legacy
// MemberRecord shape using the default (HSTLES / ORBTR agent) convention.
// For custom conventions use DeriveMemberWith + a populated MirrorConfig.
//
// Returns (record, true) when ServiceName is non-empty. Returns (_, false)
// when the reach record carries no identity fields to mirror.
func DeriveMember(r ReachRecord) (lad.MemberRecord, bool) {
	return deriveWith(MirrorConfig{}.withDefaults(), r)
}

// DeriveMemberWith is the configurable variant of DeriveMember.
func DeriveMemberWith(cfg MirrorConfig, r ReachRecord) (lad.MemberRecord, bool) {
	return deriveWith(cfg.withDefaults(), r)
}

// WrapMemberMirror wraps an inner ledger.Ledger so that every TopicReach
// Append call ALSO synthesizes and appends a mirrored TopicMember record.
// The mirror travels on the same gossip path as the Reach record and keeps
// help.orbtr.io's existing topology grouping code working verbatim, even
// though the authoritative data lives in the Reach record.
//
// Uses the default MirrorConfig (HSTLES / ORBTR agent convention). For
// custom conventions use WrapMemberMirrorWith.
//
// The mirror is unsigned — consumers that want signed Member data should
// read ServiceName directly from the Reach record (which IS signed).
func WrapMemberMirror(inner lad.Ledger) lad.Ledger {
	return &memberMirroredLedger{inner: inner, cfg: MirrorConfig{}.withDefaults()}
}

// WrapMemberMirrorWith is the configurable variant of WrapMemberMirror.
// Consumers with non-default MemberRecord conventions (alternate attr keys,
// role joiners, or a fully custom derivation) pass their MirrorConfig here.
func WrapMemberMirrorWith(inner lad.Ledger, cfg MirrorConfig) lad.Ledger {
	return &memberMirroredLedger{inner: inner, cfg: cfg.withDefaults()}
}

type memberMirroredLedger struct {
	inner lad.Ledger
	cfg   MirrorConfig
}

func (m *memberMirroredLedger) Head(ctx context.Context) (lad.CausalWatermark, error) {
	return m.inner.Head(ctx)
}

func (m *memberMirroredLedger) Append(ctx context.Context, rec lad.Record) error {
	if err := m.inner.Append(ctx, rec); err != nil {
		return err
	}
	// Only mirror Reach records (and only full snapshots — deltas don't
	// carry ServiceName, and doing a full synthesise from a delta would
	// need to round-trip through the base snapshot).
	if rec.Topic != lad.TopicReach {
		return nil
	}
	var reachRec ReachRecord
	if err := json.Unmarshal(rec.Body, &reachRec); err != nil {
		return nil // not our shape — skip silently
	}
	if IsDelta(reachRec.SchemaVersion) {
		return nil
	}
	member, ok := deriveWith(m.cfg, reachRec)
	if !ok {
		return nil
	}
	body, err := json.Marshal(member)
	if err != nil {
		return nil
	}
	envelope := lad.Record{
		Topic:        lad.TopicMember,
		TenantID:     rec.TenantID,
		NodeID:       rec.NodeID,
		Body:         body,
		Timestamp:    rec.Timestamp,
		LamportClock: rec.LamportClock,
		HLCTimestamp: rec.HLCTimestamp,
	}
	// Best-effort — if the mirror append fails, the Reach record is still
	// live and authoritative. Don't surface the mirror error to the caller.
	_ = m.inner.Append(ctx, envelope)
	return nil
}

func (m *memberMirroredLedger) BatchAppend(ctx context.Context, records []lad.Record) error {
	if err := m.inner.BatchAppend(ctx, records); err != nil {
		return err
	}
	// Mirror each Reach record to a Member entry in the same batch.
	for _, rec := range records {
		if rec.Topic != lad.TopicReach {
			continue
		}
		var reachRec ReachRecord
		if err := json.Unmarshal(rec.Body, &reachRec); err != nil {
			continue
		}
		if IsDelta(reachRec.SchemaVersion) {
			continue
		}
		member, ok := deriveWith(m.cfg, reachRec)
		if !ok {
			continue
		}
		body, err := json.Marshal(member)
		if err != nil {
			continue
		}
		_ = m.inner.Append(ctx, lad.Record{
			Topic:        lad.TopicMember,
			TenantID:     rec.TenantID,
			NodeID:       rec.NodeID,
			Body:         body,
			Timestamp:    rec.Timestamp,
			LamportClock: rec.LamportClock,
			HLCTimestamp: rec.HLCTimestamp,
		})
	}
	return nil
}

func (m *memberMirroredLedger) Stream(ctx context.Context, from lad.CausalWatermark, topics []lad.Topic) (<-chan lad.Record, error) {
	return m.inner.Stream(ctx, from, topics)
}

// Snapshot is not mirrored — consumers that walk snapshots see the underlying
// ledger directly; mirroring would double-count synthesised records.
func (m *memberMirroredLedger) Snapshot(ctx context.Context) (io.ReadCloser, error) {
	_ = ctx
	return nil, errors.New("reach: snapshot via mirrored ledger unsupported")
}
