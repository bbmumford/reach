// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	lad "github.com/bbmumford/ledger"
)

// ErrRecordRejected is returned when CacheApplyHook rejects a record.
// Detail string is attached to help distinguish sig vs replay vs rate-limit.
var ErrRecordRejected = errors.New("reach: record rejected")

// CacheApplyHook is the enforcement-layer adapter that enforces signature
// verification, replay protection, and per-node rate limiting on every
// ReachRecord (and DeltaRecord) that arrives at the ledger cache.
//
// Consumers wrap their native ledger.Ledger with this hook so §5.13
// (signature verify), §5.22 (HLC conflict + epoch), §5.30 (rate limit),
// and §5.31 (replay guard) are actually enforced rather than advisory.
//
// Usage:
//
//	hook := reach.NewCacheApplyHook(reach.CacheHookConfig{
//	    RequireValidSig: true,
//	    Metrics:         metrics,
//	})
//	wrapped := hook.Wrap(myLedger)
//	// or call hook.Check(rec) directly inside a custom Apply implementation.
type CacheApplyHook struct {
	cfg CacheHookConfig

	replay *ReplayGuard
	rate   *PerNodeRateLimiter
}

// CacheHookConfig bundles tunables for the cache-side enforcement hook.
type CacheHookConfig struct {
	// RequireValidSig rejects any TopicReach record that fails Verify().
	// Default true — flip to false only during a staged rollout when peers
	// may briefly emit unsigned records.
	RequireValidSig bool

	// ReplayWindow bounds how long per-node replay state is retained.
	// Nodes that re-introduce after the window are accepted with fresh Epoch.
	// Default 0 = forever.
	ReplayWindow int // seconds

	// RatePerMin is the per-NodeID publish cap. Default 60.
	RatePerMin int

	// Metrics receives enforcement events (sig rejected, rate-limited, etc).
	// Defaults to NullMetrics{}.
	Metrics Metrics
}

// NewCacheApplyHook constructs the hook with its internal guard + limiter.
func NewCacheApplyHook(cfg CacheHookConfig) *CacheApplyHook {
	if cfg.Metrics == nil {
		cfg.Metrics = NullMetrics{}
	}
	return &CacheApplyHook{
		cfg:    cfg,
		replay: NewReplayGuard(0),
		rate:   NewPerNodeRateLimiter(cfg.RatePerMin, 0),
	}
}

// Wrap returns a ledger.Ledger that invokes Check on every TopicReach
// record before delegating to the inner ledger. Records on other topics
// pass through unchanged.
func (h *CacheApplyHook) Wrap(inner lad.Ledger) lad.Ledger {
	return &hookedLedger{inner: inner, hook: h}
}

// Check validates a single incoming ledger.Record against the reach
// enforcement rules. Returns nil when the record should be applied,
// ErrRecordRejected (wrapped) when it should be dropped.
func (h *CacheApplyHook) Check(rec lad.Record) error {
	if rec.Topic != lad.TopicReach {
		return nil
	}
	// Two body shapes: ReachRecord and DeltaRecord — discriminate via
	// SchemaVersion's high bit.
	var probe struct {
		NodeID        string `json:"node_id"`
		SchemaVersion uint16 `json:"v"`
		HLC           HLC    `json:"hlc"`
		Epoch         uint64 `json:"epoch"`
	}
	if err := json.Unmarshal(rec.Body, &probe); err != nil {
		h.cfg.Metrics.SignatureInvalid()
		return fmt.Errorf("%w: unmarshal probe: %v", ErrRecordRejected, err)
	}

	if !h.rate.Allow(probe.NodeID) {
		h.cfg.Metrics.RateLimited(probe.NodeID)
		return fmt.Errorf("%w: rate limit exceeded for %s", ErrRecordRejected, probe.NodeID)
	}

	if IsDelta(probe.SchemaVersion) {
		var d DeltaRecord
		if err := json.Unmarshal(rec.Body, &d); err != nil {
			h.cfg.Metrics.SignatureInvalid()
			return fmt.Errorf("%w: unmarshal delta: %v", ErrRecordRejected, err)
		}
		if h.cfg.RequireValidSig {
			if err := VerifyDelta(d); err != nil {
				h.cfg.Metrics.SignatureInvalid()
				return fmt.Errorf("%w: delta signature: %v", ErrRecordRejected, err)
			}
		}
		// Replay guard uses a fake "reach" record carrying the same identity
		// fields — same guard state, same monotonicity semantics.
		if err := h.replay.Check(ReachRecord{NodeID: d.NodeID, Epoch: d.Epoch, HLC: d.HLC}); err != nil {
			return fmt.Errorf("%w: %v", ErrRecordRejected, err)
		}
		return nil
	}

	var r ReachRecord
	if err := json.Unmarshal(rec.Body, &r); err != nil {
		h.cfg.Metrics.SignatureInvalid()
		return fmt.Errorf("%w: unmarshal reach: %v", ErrRecordRejected, err)
	}
	if h.cfg.RequireValidSig {
		if err := Verify(r); err != nil {
			h.cfg.Metrics.SignatureInvalid()
			return fmt.Errorf("%w: reach signature: %v", ErrRecordRejected, err)
		}
	}
	if err := h.replay.Check(r); err != nil {
		return fmt.Errorf("%w: %v", ErrRecordRejected, err)
	}
	return nil
}

// hookedLedger intercepts Append and enforces the CacheApplyHook checks.
// All other methods proxy through unchanged.
type hookedLedger struct {
	inner lad.Ledger
	hook  *CacheApplyHook
}

func (h *hookedLedger) Head(ctx context.Context) (lad.CausalWatermark, error) {
	return h.inner.Head(ctx)
}

func (h *hookedLedger) Append(ctx context.Context, rec lad.Record) error {
	if err := h.hook.Check(rec); err != nil {
		return err
	}
	return h.inner.Append(ctx, rec)
}

func (h *hookedLedger) BatchAppend(ctx context.Context, records []lad.Record) error {
	for _, rec := range records {
		if err := h.hook.Check(rec); err != nil {
			return err
		}
	}
	return h.inner.BatchAppend(ctx, records)
}

func (h *hookedLedger) Stream(ctx context.Context, from lad.CausalWatermark, topics []lad.Topic) (<-chan lad.Record, error) {
	return h.inner.Stream(ctx, from, topics)
}

func (h *hookedLedger) Snapshot(ctx context.Context) (io.ReadCloser, error) {
	return h.inner.Snapshot(ctx)
}
