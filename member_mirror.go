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

// DeriveMember projects a ReachRecord's identity fields into the legacy
// MemberRecord shape. Consumers that still read TopicMember for service
// grouping (e.g. topology dashboards) call this to get the materialized
// view without needing a second publish.
//
// Returns (record, true) when ServiceName is non-empty. Returns (_, false)
// when the reach record carries no identity fields to mirror.
func DeriveMember(r ReachRecord) (lad.MemberRecord, bool) {
	if r.ServiceName == "" {
		return lad.MemberRecord{}, false
	}
	attrs := map[string]string{
		"service_name": r.ServiceName,
	}
	if r.Region != "" {
		attrs["region"] = r.Region
	}
	if len(r.Roles) > 0 {
		attrs["roles"] = strings.Join(r.Roles, ",")
	}
	return lad.MemberRecord{
		NodeID:    r.NodeID,
		CreatedAt: r.UpdatedAt,
		Attrs:     attrs,
	}, true
}

// WrapMemberMirror wraps an inner ledger.Ledger so that every TopicReach
// Append call ALSO synthesizes and appends a mirrored TopicMember record.
// The mirror travels on the same gossip path as the Reach record and keeps
// help.orbtr.io's existing topology grouping code working verbatim, even
// though the authoritative data lives in the Reach record.
//
// The mirror is unsigned — consumers that want signed Member data should
// read ServiceName directly from the Reach record (which IS signed).
func WrapMemberMirror(inner lad.Ledger) lad.Ledger {
	return &memberMirroredLedger{inner: inner}
}

type memberMirroredLedger struct {
	inner lad.Ledger
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
	member, ok := DeriveMember(reachRec)
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
		member, ok := DeriveMember(reachRec)
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
