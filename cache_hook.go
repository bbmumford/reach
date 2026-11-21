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
//
// The record is verified first, and rate and replay state are charged to the
// NodeID its key proves, never to the NodeID it claims: a record any key can
// sign must not spend another node's rate budget or move its replay state. A
// record that fails verification is refused when RequireValidSig is set;
// otherwise it is charged under unverifiedKey, apart from every verified node.
func (h *CacheApplyHook) Check(rec lad.Record) error {
	if rec.Topic != lad.TopicReach {
		return nil
	}
	// Two body shapes: ReachRecord and DeltaRecord — discriminate via
	// SchemaVersion's high bit.
	var probe struct {
		SchemaVersion uint16 `json:"v"`
	}
	if err := json.Unmarshal(rec.Body, &probe); err != nil {
		h.cfg.Metrics.SignatureInvalid()
		return fmt.Errorf("%w: unmarshal probe: %v", ErrRecordRejected, err)
	}

	if IsDelta(probe.SchemaVersion) {
		var d DeltaRecord
		if err := json.Unmarshal(rec.Body, &d); err != nil {
			h.cfg.Metrics.SignatureInvalid()
			return fmt.Errorf("%w: unmarshal delta: %v", ErrRecordRejected, err)
		}
		id, err := verifiedDeltaNodeID(&d)
		if err != nil {
			if h.cfg.RequireValidSig {
				h.cfg.Metrics.SignatureInvalid()
				return fmt.Errorf("%w: delta signature: %v", ErrRecordRejected, err)
			}
			id = unverifiedKey(d.NodeID)
		}
		// Replay guard uses a fake "reach" record carrying the same identity
		// fields — same guard state, same monotonicity semantics.
		return h.admit(id, d.NodeID, d.Epoch, d.HLC)
	}

	var r ReachRecord
	if err := json.Unmarshal(rec.Body, &r); err != nil {
		h.cfg.Metrics.SignatureInvalid()
		return fmt.Errorf("%w: unmarshal reach: %v", ErrRecordRejected, err)
	}
	id, err := verifiedNodeID(&r)
	if err != nil {
		if h.cfg.RequireValidSig {
			h.cfg.Metrics.SignatureInvalid()
			return fmt.Errorf("%w: reach signature: %v", ErrRecordRejected, err)
		}
		id = unverifiedKey(r.NodeID)
	}
	return h.admit(id, r.NodeID, r.Epoch, r.HLC)
}

// admit charges one record to id's rate budget and then to id's replay state.
// claimed is the NodeID the record names, reported to Metrics.
func (h *CacheApplyHook) admit(id, claimed string, epoch uint64, hlc HLC) error {
	if !h.rate.Allow(id) {
		h.cfg.Metrics.RateLimited(claimed)
		return fmt.Errorf("%w: rate limit exceeded for %s", ErrRecordRejected, claimed)
	}
	if err := h.replay.Check(ReachRecord{NodeID: id, Epoch: epoch, HLC: hlc}); err != nil {
		return fmt.Errorf("%w: %v", ErrRecordRejected, err)
	}
	return nil
}

// unverifiedKey is the rate and replay key of a record whose signature or
// NodeID binding did not verify. Every verified key is an aether NodeID and
// begins "vl1_", so a key with this prefix never equals one.
func unverifiedKey(claimed string) string {
	return "unverified:" + claimed
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

// StreamWithEnd forwards to the inner ledger's, so a consumer handed this
// wrapper reads why its stream ended: loom's gossip.Synchronizer.Sync takes
// lad.EndReportingLedger, streams again after lad.ErrStreamOverflow and stops
// at lad.ErrLedgerClosed, and without this method it would restart on every
// end, the close included, until its own context ended. An inner ledger that
// does not report its ends gives a StreamEnd that is never set, which reads
// the same as streaming the inner ledger directly.
func (h *hookedLedger) StreamWithEnd(ctx context.Context, from lad.CausalWatermark, topics []lad.Topic) (<-chan lad.Record, *lad.StreamEnd, error) {
	if er, ok := h.inner.(lad.EndReportingLedger); ok {
		return er.StreamWithEnd(ctx, from, topics)
	}
	out, err := h.inner.Stream(ctx, from, topics)
	return out, &lad.StreamEnd{}, err
}

func (h *hookedLedger) Snapshot(ctx context.Context) (io.ReadCloser, error) {
	return h.inner.Snapshot(ctx)
}
