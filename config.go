// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"context"
	"crypto/ed25519"
	"time"

	lad "github.com/bbmumford/ledger"
)

// LedgerAppender is the write-side interface the Publisher needs.
// Satisfied by ledger.Ledger and by any consumer-local adapter (e.g. the
// ORBTR agent's DirectoryCache.Apply wrapper).
type LedgerAppender interface {
	Append(ctx context.Context, rec lad.Record) error
}

// FreshnessBus is the gossip surface the Publisher uses to emit and receive
// compact freshness messages (digest announcements + snapshot requests).
// Satisfied by a thin wrapper around whisper.Engine.
//
// The feedback-driven design:
//   - After each publish, the Publisher announces its current digest.
//   - Peers compare the announced digest to their cached record's digest.
//     If they don't match (or the peer has no cached record), the peer
//     broadcasts a snapshot request naming the NodeID and their known
//     digest.
//   - The original publisher sees the request, calls
//     ForcePublish(PublishReasonPeerRequest), and a fresh full snapshot
//     flows out via the ledger — satisfying the requesting peer's cache
//     within one gossip round.
//
// This eliminates the polling model ("republish every N minutes") in the
// steady state: a publisher only emits when a peer actually needs the
// snapshot. The scheduler's timer + record-TTL floor remain as defensive
// fallbacks for the case where the FreshnessBus itself is silent.
type FreshnessBus interface {
	// PublishDigest broadcasts the payload to all peers. Non-blocking —
	// drops on backpressure. Used for both announcements and requests.
	PublishDigest(payload []byte) error

	// SubscribeFreshness delivers freshness payloads received from peers
	// to handler. Returns an unsubscribe function. Implementations MAY
	// deliver handler concurrently; handler must be safe for concurrent
	// invocation.
	SubscribeFreshness(handler func(payload []byte)) (unsubscribe func())
}

// Discoverer is the contract implemented by every address source.
// A discoverer is lightweight: it runs on demand (Discover) and optionally
// signals changes via an event bus subscription.
type Discoverer interface {
	// Name is a short human identifier used in logs and metrics.
	Name() string

	// Source identifies the class of addresses this discoverer produces.
	Source() AddressSource

	// Discover returns the current address set for this source.
	// Returning an empty slice with no error means "I tried and found
	// nothing" (normal for e.g. STUN on a fully private network).
	Discover(ctx context.Context) ([]Address, error)

	// Interval hints at how often the scheduler should re-run Discover
	// when no event fires. 0 means "event-driven only" — the scheduler
	// will never poll this discoverer on a timer.
	Interval() time.Duration

	// EnabledFor returns true if this discoverer should run on a platform
	// with the given provider name ("fly", "aws", "gcp", "k8s", "dev", "").
	// Empty provider means "any".
	EnabledFor(provider string) bool
}

// Profile is a hint to the scheduler about expected churn patterns.
// Server-class nodes use ProfileFleet; laptop/desktop agents use ProfileAgent.
type Profile uint8

const (
	ProfileFleet Profile = iota // cloud fleet nodes — stable
	ProfileAgent                // user devices — roaming, sleep, cellular
)

// Config bundles everything a Publisher needs.
// Sensible defaults apply when fields are left zero.
type Config struct {
	// ── Identity ────────────────────────────────────────────────────
	NodeID   string
	TenantID string
	Region   string

	// Metadata is the consumer-defined identity blob carried in every
	// signed ReachRecord. Consumers decide what goes in here — the reach
	// package just signs and ships. Typical keys vary per consumer: a
	// mesh node puts "service_name" + "roles" + "region"; an agent puts
	// "hostname" + "device_id" + "os"; a third party puts whatever it
	// needs. See metadata.go for per-consumer conventions. The ledger
	// cache derives lad.MemberRecord views on read from this map, so
	// consumers don't need a parallel Member publish path.
	Metadata Metadata

	// OrgID groups nodes whose private addresses should be mutually visible
	// but hidden from non-org peers. May be empty for single-tenant deployments.
	OrgID string

	// Ed25519 private key for signing ReachRecord. Required.
	Signer ed25519.PrivateKey

	// ── Sinks ───────────────────────────────────────────────────────
	Ledger   LedgerAppender
	Whisper  FreshnessBus // optional — disables freshness gossip when nil
	Clock    *Clock       // optional — uses NewClock(NodeID, nil) when nil

	// ── Discovery ───────────────────────────────────────────────────
	Discoverers []Discoverer
	Provider    string // e.g. "fly"; drives discoverer gating via EnabledFor

	// ── Cadence ─────────────────────────────────────────────────────
	Profile Profile

	BaseInterval        time.Duration // default 5min (ProfileFleet) / 15min (ProfileAgent)
	ChurnInterval       time.Duration // default 15s
	BootstrapInterval   time.Duration // default 2s
	BootstrapDuration   time.Duration // default 30s
	FreshnessInterval   time.Duration // default 30s; 0 disables freshness gossip
	Jitter              float64       // default 0.5 (50% full-jitter)
	MaxPublishesPerMin  int           // default 10 (leaky-bucket cap)

	// ── Address TTLs per source ────────────────────────────────────
	TTLPerSource map[AddressSource]time.Duration

	// ── Privacy ─────────────────────────────────────────────────────
	OrgKey OrgKey // when present, private-scope addresses go in EncryptedOrg

	// ── Persistence ────────────────────────────────────────────────
	PersistPath string // last-good record JSON; empty disables persistence

	// ── Startup ─────────────────────────────────────────────────────
	// Epoch bumps on every process restart. Callers should persist this
	// across restarts (e.g. PersistPath) to guarantee strict monotonicity
	// even across crashes; the publisher seeds Epoch to time.Now().Unix()
	// when zero.
	Epoch uint64

	// ── Metrics ─────────────────────────────────────────────────────
	Metrics Metrics // optional; use NullMetrics{} to disable

	// ── Delta publishes ─────────────────────────────────────────────
	// DeltaThreshold is the minimum number of publishes between full
	// snapshots. Smaller values produce more snapshots (heavier on
	// bandwidth but self-healing against dropped deltas). 0 = use
	// default (32 publishes or 5 minutes, whichever first).
	DeltaThreshold int

	// DeltaMaxAge forces a full snapshot after this wall-clock duration
	// even when the delta-count hasn't hit DeltaThreshold. Default 5min.
	DeltaMaxAge time.Duration

	// ── Probing ─────────────────────────────────────────────────────
	// Prober verifies advertised addresses via peer echo. Supply a
	// non-nil VerifyTransport to enable — when left nil the publisher
	// emits addresses with their discoverer-initial Confidence and never
	// upgrades them to ≥60 via quorum.
	VerifyTransport VerifyTransport

	// PeerSelector returns a small set of peers the prober asks to verify
	// each published address. Typical wiring: the consumer's mesh peer
	// manager selects 2-4 peers in distinct regions. Nil disables probing
	// even when VerifyTransport is set.
	PeerSelector func() []PeerInfo

	// RegionRTTTracker aggregates prober RTT samples so the publisher can
	// compute Address.RegionPriority adaptively. Nil = no adaptive priority.
	// Publisher constructs a default tracker when the field is nil AND
	// probing is enabled, so callers don't have to wire one explicitly.
	RTTTracker *RegionRTTTracker
}

// defaults fills in any zero-valued fields with sensible production defaults.
func (c *Config) defaults() {
	if c.BaseInterval == 0 {
		switch c.Profile {
		case ProfileAgent:
			c.BaseInterval = 15 * time.Minute
		default:
			c.BaseInterval = 5 * time.Minute
		}
	}
	if c.ChurnInterval == 0 {
		c.ChurnInterval = 15 * time.Second
	}
	if c.BootstrapInterval == 0 {
		c.BootstrapInterval = 2 * time.Second
	}
	if c.BootstrapDuration == 0 {
		c.BootstrapDuration = 30 * time.Second
	}
	if c.FreshnessInterval == 0 {
		c.FreshnessInterval = 30 * time.Second
	}
	if c.Jitter == 0 {
		c.Jitter = 0.5
	}
	if c.MaxPublishesPerMin == 0 {
		c.MaxPublishesPerMin = 10
	}
	if c.Clock == nil {
		c.Clock = NewClock(c.NodeID, nil)
	}
	if c.Epoch == 0 {
		c.Epoch = uint64(time.Now().UTC().UnixNano())
	}
	if c.TTLPerSource == nil {
		c.TTLPerSource = DefaultTTLs()
	}
	if c.Metrics == nil {
		c.Metrics = NullMetrics{}
	}
	if c.VerifyTransport != nil && c.RTTTracker == nil {
		c.RTTTracker = NewRegionRTTTracker(0)
	}
	if c.DeltaThreshold == 0 {
		c.DeltaThreshold = 32
	}
	if c.DeltaMaxAge == 0 {
		c.DeltaMaxAge = 5 * time.Minute
	}
}

// DefaultTTLs returns the recommended per-source TTL map.
//   DNS (anycast / dedicated) — 1h  (stable, authoritative)
//   STUN reflexive            — 2m  (NAT binding ephemeral)
//   Interface IPv6 ULA        — 30m (stable on Fly 6pn)
//   Interface public IPv4     — 5m  (DHCP / cloud changes)
//   ICE TURN relay            — 1m  (allocation-bound)
//   Reflection (peer-observed)— 10m (single observer may be wrong)
//   Static / config override  — 24h (operator guaranteed — effectively forever)
func DefaultTTLs() map[AddressSource]time.Duration {
	return map[AddressSource]time.Duration{
		SrcStatic:      24 * time.Hour,
		SrcDNS:         1 * time.Hour,
		SrcPlatformEnv: 1 * time.Hour,
		SrcIMDS:        1 * time.Hour,
		SrcK8sDownward: 30 * time.Minute,
		SrcInterface:   15 * time.Minute,
		SrcSTUN:        2 * time.Minute,
		SrcTURN:        1 * time.Minute,
		SrcReflection:  10 * time.Minute,
		SrcICE:         5 * time.Minute,
		SrcUPnP:        10 * time.Minute,
	}
}
