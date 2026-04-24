// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	lad "github.com/bbmumford/ledger"
)

// MirrorConfig customises how the member mirror projects a ReachRecord's
// Metadata into legacy MemberRecord.Attrs. Zero-value config passes Metadata
// through verbatim (key-for-key). Consumers that need different attr keys
// supply a KeyMap; consumers with entirely different MemberRecord semantics
// supply a full Deriver.
type MirrorConfig struct {
	// KeyMap optionally renames metadata keys when projecting into Attrs.
	//   Metadata["hostname"] → Attrs["host"]        — KeyMap["hostname"]="host"
	//   Metadata["secret"]  → (skipped)             — KeyMap["secret"]=""
	//   Metadata["anything"]→ Attrs["anything"]     — default passthrough
	// A nil KeyMap means identity (all metadata keys → same attrs keys).
	KeyMap map[string]string

	// SkipUnmapped — when true, only keys present in KeyMap are projected.
	// Use for consumers that want strict filtering instead of passthrough.
	SkipUnmapped bool

	// PrimaryKey is the metadata key whose presence is required to synthesise
	// a MemberRecord at all. When empty (default), any non-empty metadata
	// triggers a Member synthesis. When set (e.g. "service_name"), records
	// without that key are skipped. Useful for consumers that only want
	// certain classes of node (named services) in the legacy topic.
	PrimaryKey string

	// Deriver — full override. When non-nil, bypasses the attr-key model
	// and calls this function for every projection. Use when the consumer's
	// MemberRecord convention doesn't fit simple KV mapping (e.g. one record
	// per role, or metadata encoded as JSON in a single attr value).
	Deriver func(ReachRecord) (lad.MemberRecord, bool)
}

// deriveWith applies a MirrorConfig to project a ReachRecord into a MemberRecord.
//
// ExpiresAt on the synthesized MemberRecord is inherited from ReachRecord.
// This ties the Member's cache lifetime directly to the Reach record's —
// when a fresh Reach publish arrives, the mirror synthesizes a Member with
// the new, later ExpiresAt; the cache's TTL eviction sees the refresh and
// keeps the Member alive. Without this, the Member inherited a zero
// ExpiresAt and was evicted on whatever default policy the cache applied,
// which is often shorter than the Reach TTL and causes Members to decay
// independently of the authoritative Reach state.
func deriveWith(cfg MirrorConfig, r ReachRecord) (lad.MemberRecord, bool) {
	if cfg.Deriver != nil {
		return cfg.Deriver(r)
	}
	if len(r.Metadata) == 0 {
		return lad.MemberRecord{}, false
	}
	if cfg.PrimaryKey != "" {
		if _, ok := r.Metadata[cfg.PrimaryKey]; !ok {
			return lad.MemberRecord{}, false
		}
	}
	attrs := make(map[string]string, len(r.Metadata))
	for k, v := range r.Metadata {
		if cfg.KeyMap != nil {
			if newKey, remapped := cfg.KeyMap[k]; remapped {
				if newKey == "" {
					continue // explicit skip
				}
				attrs[newKey] = v
				continue
			}
			if cfg.SkipUnmapped {
				continue
			}
		}
		attrs[k] = v
	}
	if len(attrs) == 0 {
		return lad.MemberRecord{}, false
	}
	return lad.MemberRecord{
		NodeID:    r.NodeID,
		CreatedAt: r.UpdatedAt,
		ExpiresAt: r.ExpiresAt,
		Attrs:     attrs,
	}, true
}

// DeriveMember projects a ReachRecord's Metadata into the legacy MemberRecord
// shape with verbatim key passthrough. For custom conventions use
// DeriveMemberWith + a populated MirrorConfig.
//
// Returns (record, true) when Metadata is non-empty. Returns (_, false) when
// the reach record carries no metadata to mirror.
func DeriveMember(r ReachRecord) (lad.MemberRecord, bool) {
	return deriveWith(MirrorConfig{}, r)
}

// DeriveMemberWith is the configurable variant of DeriveMember.
func DeriveMemberWith(cfg MirrorConfig, r ReachRecord) (lad.MemberRecord, bool) {
	return deriveWith(cfg, r)
}

// WrapMemberMirror wraps an inner ledger.Ledger so that every TopicReach
// Append call ALSO synthesizes and appends a mirrored TopicMember record.
// The mirror travels on the same gossip path as the Reach record and keeps
// topology dashboards that still read TopicMember working unchanged, even
// though the authoritative data lives in the signed Reach record.
//
// Uses the default MirrorConfig (verbatim passthrough of Metadata → Attrs).
// For custom conventions use WrapMemberMirrorWith.
//
// The mirror is unsigned — consumers that want signed Member data should
// read Metadata directly from the Reach record (which IS signed).
func WrapMemberMirror(inner lad.Ledger) lad.Ledger {
	return &memberMirroredLedger{inner: inner, cfg: MirrorConfig{}}
}

// WrapMemberMirrorWith is the configurable variant of WrapMemberMirror.
// Consumers with non-default MemberRecord conventions (key renames, strict
// filtering, PrimaryKey gating, or a full custom derivation) pass their
// MirrorConfig here.
func WrapMemberMirrorWith(inner lad.Ledger, cfg MirrorConfig) lad.Ledger {
	return &memberMirroredLedger{inner: inner, cfg: cfg}
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
		// Inherit ExpiresAt from the Reach record's envelope so the cache
		// TTL eviction treats Member and Reach as a coupled pair. A fresh
		// Reach publish automatically refreshes its paired Member's TTL.
		ExpiresAt:    rec.ExpiresAt,
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
