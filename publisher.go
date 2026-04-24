// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"sort"
	"sync"
	"time"

	lad "github.com/bbmumford/ledger"
)

// ErrMissingConfig is returned by NewPublisher when a required Config field is zero.
var ErrMissingConfig = errors.New("reach: missing required config")

// Publisher discovers and publishes self-reachability to the ledger.
// One Publisher per node. Run() drives the whole lifecycle.
type Publisher struct {
	cfg *Config

	scheduler *scheduler
	prober    *Prober // nil when VerifyTransport not configured
	eventCh   chan AddressChange // external events (netlink, role change, etc.)
	forceCh   chan PublishReason // internal "publish now" requests

	// State.
	mu                 sync.Mutex
	lastDigest         string
	lastAddresses      []Address
	lastPublishedAt    time.Time
	lastFullSnapAt     time.Time
	deltasSinceFull    int
	shuttingDown       bool
	wrappedDiscoverers []Discoverer // cached backoff-wrapped discoverers

	// refreshJitter is a per-publisher offset drawn once at construction.
	// Applied to the record-TTL refresh floor so publishers across a
	// fleet don't align their refresh cycles — a rolling deploy would
	// otherwise produce a synchronized TTL-expiry wave where every
	// node's records age out together and receivers' caches trough
	// before the next refresh wave arrives. Range: 1 ± recordRefreshJitterPct.
	refreshJitter float64
}

// AddressChange is emitted by the event bus when something suggests the node's
// reachability has changed (interface up/down, DHCP renew, sleep/wake, etc.).
type AddressChange struct {
	Source string    // human description (e.g. "netlink:eth0:down")
	At     time.Time
}

// NewPublisher validates config and constructs a ready-to-Run Publisher.
func NewPublisher(cfg Config) (*Publisher, error) {
	if cfg.NodeID == "" {
		return nil, fmt.Errorf("%w: NodeID", ErrMissingConfig)
	}
	if cfg.Signer == nil {
		return nil, fmt.Errorf("%w: Signer", ErrMissingConfig)
	}
	if cfg.Ledger == nil {
		return nil, fmt.Errorf("%w: Ledger", ErrMissingConfig)
	}
	cfg.defaults()

	p := &Publisher{
		cfg:           &cfg,
		scheduler:     newScheduler(&cfg),
		eventCh:       make(chan AddressChange, 32),
		forceCh:       make(chan PublishReason, 4),
		refreshJitter: 1.0 + (rand.Float64()*2-1)*recordRefreshJitterPct,
	}
	if cfg.VerifyTransport != nil {
		p.prober = NewProber(cfg.VerifyTransport, ProberConfig{
			Metrics:               cfg.Metrics,
			RTTTracker:            cfg.RTTTracker,
			MinRegionsForVerified: 2,
		})
	}
	return p, nil
}

// Run blocks until ctx is cancelled. It runs the discoverer orchestrator on
// schedule and in response to events, and publishes to the ledger whenever
// the address set digest changes.
//
// On ctx cancel it publishes a shutdown tombstone before returning.
func (p *Publisher) Run(ctx context.Context) {
	// Restore persisted digest BEFORE the initial publish so a cold restart
	// with no address-set change can skip the initial publish entirely.
	// Also seeds Epoch from disk when available so epoch never moves
	// backward across restarts (plan §5.3 / §5.31).
	_ = p.loadLastGood()

	// Prime: run a full discovery cycle synchronously so the initial publish
	// happens within the caller's bootstrap window.
	if err := p.publishOnce(ctx, PublishReasonBootstrap); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("[reach] initial publish failed: %v", err)
	}

	timer := time.NewTimer(p.scheduler.next(time.Now()))
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			p.publishTombstone(context.Background(), "shutdown")
			return

		case <-timer.C:
			if err := p.publishOnce(ctx, PublishReasonTimer); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("[reach] timer publish: %v", err)
			}
			timer.Reset(p.scheduler.next(time.Now()))

		case ev := <-p.eventCh:
			// Address-change event: try to publish immediately.
			p.scheduler.noteChange(ev.At)
			if err := p.publishOnce(ctx, PublishReasonEvent); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("[reach] event publish: %v", err)
			}
			// Reset timer so we don't burst on top of the event.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(p.scheduler.next(time.Now()))

		case reason := <-p.forceCh:
			if err := p.publishOnce(ctx, reason); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("[reach] forced publish: %v", err)
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(p.scheduler.next(time.Now()))
		}
	}
}

// NotifyAddressChange signals an external event source (e.g. netlink) that the
// node's reachability may have changed. Non-blocking — drops on full queue,
// because the timer will eventually catch up anyway.
func (p *Publisher) NotifyAddressChange(source string) {
	select {
	case p.eventCh <- AddressChange{Source: source, At: time.Now()}:
	default:
	}
}

// ForcePublish requests an immediate publish. Non-blocking. Intended for
// role changes, epoch bumps, and manual operator triggers.
func (p *Publisher) ForcePublish(reason PublishReason) {
	select {
	case p.forceCh <- reason:
	default:
	}
}

// NotifyRoleChange is the consumer-facing hook consumed when the mesh
// runtime mutates a node's role set. It stamps the agent-profile or
// edge-anchor capability bit on subsequent publishes and forces an immediate
// re-publish so peers see the change in the next gossip round. Plan §5.4
// event #9.
func (p *Publisher) NotifyRoleChange() {
	p.ForcePublish(PublishReasonEvent)
}

// SetMetadata atomically replaces the publisher's Metadata map and triggers
// an immediate signed re-publish. The input is cloned so the caller can
// mutate safely after the call returns.
func (p *Publisher) SetMetadata(meta Metadata) {
	p.mu.Lock()
	p.cfg.Metadata = meta.Clone()
	p.mu.Unlock()
	p.ForcePublish(PublishReasonEvent)
}

// SetMetadataValue atomically updates a single metadata key and triggers an
// immediate signed re-publish. Useful for role-promotion paths that want to
// flip one attribute without re-supplying the whole map.
//
// Passing an empty value removes the key.
func (p *Publisher) SetMetadataValue(key, value string) {
	p.mu.Lock()
	if p.cfg.Metadata == nil {
		p.cfg.Metadata = make(Metadata)
	}
	if value == "" {
		delete(p.cfg.Metadata, key)
	} else {
		p.cfg.Metadata[key] = value
	}
	p.mu.Unlock()
	p.ForcePublish(PublishReasonEvent)
}

// Metadata returns a snapshot of the current metadata map — safe to mutate.
func (p *Publisher) MetadataSnapshot() Metadata {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg.Metadata.Clone()
}

// CurrentAddresses returns the last-published address set as "host:port"
// strings suitable for PEX advertisements. Returns nil when nothing has
// been published yet (the publisher's initial discovery cycle is
// pending). Thread-safe; snapshots under the publisher's internal lock
// so callers get a consistent view that doesn't race with an in-flight
// publish.
func (p *Publisher) CurrentAddresses() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.lastAddresses) == 0 {
		return nil
	}
	out := make([]string, 0, len(p.lastAddresses))
	for _, a := range p.lastAddresses {
		if a.Host == "" {
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d", a.Host, a.Port))
	}
	return out
}

// LastDigest returns the digest of the most recently published address set.
// Useful for freshness-gossip digesting and admin debugging.
func (p *Publisher) LastDigest() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastDigest
}

// publishOnce runs the full discovery + publish cycle. It is the heart of the
// publisher: gather → fingerprint → skip-if-unchanged → sign → append.
func (p *Publisher) publishOnce(ctx context.Context, reason PublishReason) error {
	p.cfg.Metrics.PublishAttempt(reason)

	now := time.Now().UTC()
	addrs, err := p.discoverAll(ctx)
	if err != nil {
		p.cfg.Metrics.PublishFailed(err)
		return err
	}
	addrs = p.applyTTLs(addrs, now)

	if len(addrs) == 0 {
		p.cfg.Metrics.PublishSkipped(SkipEmptyAddrSet)
		return nil
	}
	if !anyPublic(addrs) && reason != PublishReasonBootstrap {
		p.cfg.Metrics.PublishSkipped(SkipNoPublicAddr)
		return nil
	}

	// Probe: ask peers to verify each public address. Successful verification
	// bumps Confidence to ≥60 and stamps LastVerified + RTTMicros. Failures
	// demote to <20. When probing isn't configured (no VerifyTransport) this
	// is a no-op and Confidence stays at discoverer-initial values.
	addrs = p.applyProbes(ctx, addrs)
	// Enrich RegionPriority from the RTT tracker so peers dial the
	// region-nearest entry first.
	addrs = p.applyRegionPriority(addrs)
	// Age-based GC: §5.20 — drop non-Static addresses we haven't verified
	// in 30min. TTL-expired entries were already dropped in applyTTLs;
	// this catches entries whose TTL is longer than the verify window.
	addrs = p.applyVerificationGC(addrs, now)

	digest := Digest(addrs)

	p.mu.Lock()
	unchanged := digest == p.lastDigest && !p.needsTTLRefresh(now)
	p.mu.Unlock()

	if unchanged && reason != PublishReasonEpoch && reason != PublishReasonBootstrap && reason != PublishReasonPeerRequest {
		p.cfg.Metrics.PublishSkipped(SkipDigestMatch)
		return nil
	}

	if !p.scheduler.allowPublish(now) {
		p.cfg.Metrics.PublishSkipped(SkipRateLimit)
		return nil
	}

	// Decide between full snapshot vs delta. First publish is always full;
	// every DeltaThreshold publishes (or DeltaMaxAge) is full; anything in
	// between that actually has a prior state can ship as a delta.
	p.mu.Lock()
	prevAddrs := p.lastAddresses
	prevDigest := p.lastDigest
	snapAge := now.Sub(p.lastFullSnapAt)
	deltasSince := p.deltasSinceFull
	p.mu.Unlock()

	fullSnapshot := reason == PublishReasonBootstrap ||
		reason == PublishReasonEpoch ||
		prevDigest == "" ||
		deltasSince >= p.cfg.DeltaThreshold ||
		snapAge >= p.cfg.DeltaMaxAge

	var recordBytes int
	if fullSnapshot {
		rec := p.buildRecord(addrs, now)
		if err := p.appendToLedger(ctx, rec); err != nil {
			p.cfg.Metrics.PublishFailed(err)
			return err
		}
		recordBytes = approxRecordBytes(rec)
		_ = p.saveLastGood(rec)
		p.mu.Lock()
		p.lastFullSnapAt = now
		p.deltasSinceFull = 0
		p.mu.Unlock()
	} else {
		ops := computeDelta(prevAddrs, addrs)
		if len(ops) == 0 {
			// No structural change reached this branch (TTL refresh path
			// would have taken us here with fullSnapshot=false and no ops).
			// Skip the append; the digest guard upstream already prevented
			// a spurious identical publish.
			p.cfg.Metrics.PublishSkipped(SkipDigestMatch)
			return nil
		}
		drec := p.buildDelta(ops, prevDigest, now)
		if err := p.appendDeltaToLedger(ctx, drec); err != nil {
			p.cfg.Metrics.PublishFailed(err)
			return err
		}
		recordBytes = approxDeltaBytes(drec)
		p.mu.Lock()
		p.deltasSinceFull++
		p.mu.Unlock()
	}

	p.broadcastFreshness(digest)

	p.mu.Lock()
	p.lastDigest = digest
	p.lastAddresses = addrs
	p.lastPublishedAt = now
	p.mu.Unlock()

	p.cfg.Metrics.PublishSucceeded(recordBytes)
	if digest != prevDigest {
		p.scheduler.noteChange(now)
	}

	// Fire the post-publish hook outside the lock so handlers can call
	// back into the publisher (ForcePublish, CurrentAddresses, etc.)
	// without deadlock. Addresses are snapshotted from the value we just
	// signed rather than re-reading state so the hook observes exactly
	// the set that appeared on the wire, even if a concurrent event
	// triggers another publish immediately after.
	if p.cfg.AfterPublish != nil {
		hostPorts := make([]string, 0, len(addrs))
		for _, a := range addrs {
			if a.Host == "" {
				continue
			}
			hostPorts = append(hostPorts, fmt.Sprintf("%s:%d", a.Host, a.Port))
		}
		p.cfg.AfterPublish(PublishInfo{
			Reason:    reason,
			Digest:    digest,
			Addresses: hostPorts,
			Full:      fullSnapshot,
			At:        now,
		})
	}
	return nil
}

// discoverAll runs every configured discoverer concurrently and returns the
// union of their results. Discoverers that error are logged and skipped —
// a partial result set is preferable to no publish at all.
//
// Each discoverer is wrapped in per-instance exponential-backoff state so
// a persistently-failing source (e.g. STUN server down, IMDS unreachable)
// doesn't block every publish tick and doesn't flood logs/metrics. See
// discoverer.WithBackoff for the schedule (1s, 2s, 4s, 8s, 16s, capped at
// Interval).
func (p *Publisher) discoverAll(ctx context.Context) ([]Address, error) {
	if len(p.cfg.Discoverers) == 0 {
		return nil, nil
	}

	type dresult struct {
		name  string
		addrs []Address
		err   error
		dur   time.Duration
	}
	resCh := make(chan dresult, len(p.cfg.Discoverers))

	// First call wraps each discoverer in backoff state (sync.Once-style
	// inside backoffState). The wrapper is cached on the Publisher so the
	// failure counter persists across ticks.
	wrapped := p.wrapDiscoverers()

	var wg sync.WaitGroup
	for _, d := range wrapped {
		if !d.EnabledFor(p.cfg.Provider) {
			continue
		}
		wg.Add(1)
		go func(d Discoverer) {
			defer wg.Done()
			start := time.Now()
			// 500ms deadline on bootstrap for tight first-publish budget;
			// 3s otherwise — IMDS and DNS can genuinely take that long.
			budget := 3 * time.Second
			if time.Since(p.scheduler.start) < p.cfg.BootstrapDuration/3 {
				budget = 500 * time.Millisecond
			}
			dctx, cancel := context.WithTimeout(ctx, budget)
			defer cancel()
			a, err := d.Discover(dctx)
			resCh <- dresult{name: d.Name(), addrs: a, err: err, dur: time.Since(start)}
		}(d)
	}
	go func() { wg.Wait(); close(resCh) }()

	seen := make(map[string]Address)
	for r := range resCh {
		p.cfg.Metrics.DiscovererRun(r.name, r.dur, len(r.addrs), r.err)
		if r.err != nil {
			continue
		}
		for _, a := range r.addrs {
			// Deduplicate by Key — prefer the entry with the earlier-declared
			// source (static > dns > env > iface > stun > reflection > turn).
			key := a.Key()
			if existing, ok := seen[key]; ok {
				if sourceRank(existing.Source) <= sourceRank(a.Source) {
					continue
				}
			}
			seen[key] = a
		}
	}

	out := make([]Address, 0, len(seen))
	for _, a := range seen {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, nil
}

// wrapDiscoverers lazily wraps every configured discoverer in its own
// backoff state on first call, then returns the cached wrapped slice.
// Using per-instance backoff means a temporarily-failing STUN server
// doesn't poison IMDS or DNS.
//
// The wrapping layer is imported from the discoverer subpackage via an
// interface-typed constructor so we don't pull its package into the
// hot-path. We use a local adapter type to avoid an import cycle between
// reach and reach/discoverer.
func (p *Publisher) wrapDiscoverers() []Discoverer {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.wrappedDiscoverers != nil {
		return p.wrappedDiscoverers
	}
	out := make([]Discoverer, len(p.cfg.Discoverers))
	for i, d := range p.cfg.Discoverers {
		out[i] = newBackoffWrapper(d)
	}
	p.wrappedDiscoverers = out
	return out
}

// applyProbes verifies each public address against the configured peer set
// and updates Confidence + LastVerified + RTT on the returned entries.
// No-op when prober is nil or PeerSelector returns no peers.
func (p *Publisher) applyProbes(ctx context.Context, addrs []Address) []Address {
	if p.prober == nil || p.cfg.PeerSelector == nil {
		return addrs
	}
	peers := p.cfg.PeerSelector()
	if len(peers) == 0 {
		return addrs
	}
	for i, a := range addrs {
		if a.Scope != ScopePublic {
			continue
		}
		addrs[i] = p.prober.Verify(ctx, a, peers)
	}
	return addrs
}

// applyRegionPriority stamps adaptive RegionPriority from the RTT tracker
// onto every public-scope address. When no tracker is configured the field
// is left untouched (discoverers can still set static hints).
func (p *Publisher) applyRegionPriority(addrs []Address) []Address {
	if p.cfg.RTTTracker == nil {
		return addrs
	}
	for i, a := range addrs {
		if a.Scope != ScopePublic {
			continue
		}
		prio := p.cfg.RTTTracker.PriorityFor(a.Key())
		if len(prio) > 0 {
			if addrs[i].RegionPriority == nil {
				addrs[i].RegionPriority = prio
			} else {
				// Merge: tracker wins on conflict (it has live data).
				for k, v := range prio {
					addrs[i].RegionPriority[k] = v
				}
			}
		}
	}
	return addrs
}

// applyVerificationGC drops non-Static addresses whose LastVerified is older
// than 30 minutes. Static and never-probed addresses (LastVerified zero) are
// preserved — only verified-but-gone-stale entries are removed.
func (p *Publisher) applyVerificationGC(addrs []Address, now time.Time) []Address {
	const staleWindow = 30 * time.Minute
	out := addrs[:0]
	for _, a := range addrs {
		if a.Source != SrcStatic && !a.LastVerified.IsZero() && now.Sub(a.LastVerified) > staleWindow {
			p.cfg.Metrics.AddressExpired(a.Source)
			continue
		}
		out = append(out, a)
	}
	return out
}

// applyTTLs fills in missing FirstSeen/ExpiresAt per discoverer's source
// and drops addresses that are already past their per-address expiry.
func (p *Publisher) applyTTLs(addrs []Address, now time.Time) []Address {
	out := addrs[:0]
	for _, a := range addrs {
		if a.FirstSeen.IsZero() {
			a.FirstSeen = now
		}
		if a.ExpiresAt.IsZero() {
			if ttl, ok := p.cfg.TTLPerSource[a.Source]; ok && ttl > 0 {
				a.ExpiresAt = now.Add(ttl)
			} else {
				a.ExpiresAt = now.Add(10 * time.Minute)
			}
		}
		if a.IsExpired(now) {
			p.cfg.Metrics.AddressExpired(a.Source)
			continue
		}
		out = append(out, a)
	}
	return out
}

// recordTTL is the Publisher's record-level TTL — the value it writes into
// ReachRecord.ExpiresAt and the upper bound the LAD cache respects before
// evicting a stale record. Also drives the record-level refresh floor in
// needsTTLRefresh so the publisher re-publishes a full snapshot long
// before the cache expires the record, even when discoverers produce
// addresses with zero per-address ExpiresAt (e.g. Fly IMDS static IPs).
const recordTTL = 10 * time.Minute

// recordRefreshFraction is the nominal fraction of recordTTL after which
// the publisher forces a re-publish. Per-publisher jitter (below) offsets
// this by ±15% so publishers across a fleet don't align their refresh
// cycles — without jitter, a rolling deploy creates a synchronized
// TTL-expiry wave where every node's records age out at roughly the
// same time and the receivers' caches trough together before the next
// refresh wave arrives.
const recordRefreshFraction = 0.5

// recordRefreshJitterPct is the ± fraction applied to the per-publisher
// refresh floor to decorrelate refresh timing across a fleet. Drawn
// once per Publisher at construction so each publisher's refresh cadence
// is stable (consistent from one refresh to the next) but different from
// its peers'.
const recordRefreshJitterPct = 0.15

// refreshFloor returns the per-publisher jittered interval after which
// a full-snapshot re-publish is forced regardless of digest stability.
// Computed once per call from the publisher's stable refreshJitter so
// the floor doesn't drift mid-lifetime. The stable-jitter design keeps
// a single publisher's cadence predictable (you can reason about "this
// node refreshes every ~5 min") while decorrelating across the fleet.
func (p *Publisher) refreshFloor() time.Duration {
	j := p.refreshJitter
	if j <= 0 {
		// Defensive fallback if a caller constructed a Publisher
		// without NewPublisher (tests may do this) — collapse to
		// the un-jittered nominal floor rather than never refreshing.
		j = 1.0
	}
	return time.Duration(float64(recordTTL) * recordRefreshFraction * j)
}

// needsTTLRefresh reports whether the publisher should emit a fresh full
// snapshot even when the address-set digest is unchanged. Returns true when
// EITHER:
//   - any address is within 1/3 of its per-address TTL, OR
//   - the last full snapshot is older than the per-publisher jittered
//     refresh floor.
//
// The second condition covers publishers whose discoverers all return
// zero-ExpiresAt addresses (static IPs, Fly IMDS) — without it they emit
// exactly one full snapshot at startup and then skip forever while
// receivers' caches silently evict at the 10-min ExpiresAt. The jitter
// prevents synchronized refresh waves across a fleet deployed within the
// same rolling-upgrade window.
//
// Caller holds p.mu.
func (p *Publisher) needsTTLRefresh(now time.Time) bool {
	// Record-level floor — covers all-zero per-address ExpiresAt.
	if !p.lastFullSnapAt.IsZero() {
		floor := p.refreshFloor()
		if now.Sub(p.lastFullSnapAt) >= floor {
			return true
		}
	}
	// Per-address checks — trigger earlier if any single address is close
	// to its own TTL (e.g. STUN addresses often have shorter per-address
	// TTLs than the record TTL).
	for _, a := range p.lastAddresses {
		if a.ExpiresAt.IsZero() {
			continue
		}
		remaining := a.ExpiresAt.Sub(now)
		total := a.ExpiresAt.Sub(a.FirstSeen)
		if total > 0 && remaining < total/3 {
			return true
		}
	}
	return false
}

// buildRecord constructs the ReachRecord ready for signing and appending.
func (p *Publisher) buildRecord(addrs []Address, now time.Time) ReachRecord {
	hlc := p.cfg.Clock.Tick()

	// Separate private (for org-encryption) from public (flat + AddressSet).
	var publicSet []Address
	var privateSet []Address
	for _, a := range addrs {
		if a.Scope == ScopePrivate || a.Scope == ScopeOrg {
			privateSet = append(privateSet, a)
		} else {
			publicSet = append(publicSet, a)
		}
	}

	// Flat Addresses slice — legacy compatibility for ledger cache / older readers.
	flat := make([]lad.ReachAddress, 0, len(publicSet)+len(privateSet))
	for _, a := range addrs {
		flat = append(flat, lad.ReachAddress{
			Host:  a.Host,
			Port:  int(a.Port),
			Proto: a.Proto,
			Scope: string(a.Scope),
		})
	}

	// Record-level ExpiresAt: floor at recordTTL (matches the record-level
	// refresh floor in needsTTLRefresh), extended further out by any
	// per-address ExpiresAt that's already later.
	recordExpiry := now.Add(recordTTL)
	for _, a := range addrs {
		if a.ExpiresAt.After(recordExpiry) {
			recordExpiry = a.ExpiresAt
		}
	}

	rec := ReachRecord{
		TenantID:      p.cfg.TenantID,
		NodeID:        p.cfg.NodeID,
		Seq:           uint64(hlc.Wall),
		Addresses:     flat,
		Region:        p.cfg.Region,
		ExpiresAt:     recordExpiry,
		UpdatedAt:     now,
		SchemaVersion: SchemaVersion,
		HLC:           hlc,
		Epoch:         p.cfg.Epoch,
		AddressSet:    append([]Address(nil), publicSet...),
		ICECandidates: BuildICECandidates(publicSet),
		Metadata:      p.cfg.Metadata.Clone(),
	}

	// Seal private addresses for same-org peers if we have a key.
	if len(privateSet) > 0 && len(p.cfg.OrgKey.Key) > 0 {
		if section, err := SealOrg(privateSet, p.cfg.OrgKey); err == nil {
			rec.EncryptedOrg = section
		} else {
			log.Printf("[reach] seal org: %v", err)
			// Fall back: advertise in public AddressSet with Scope="private".
			rec.AddressSet = append(rec.AddressSet, privateSet...)
		}
	} else {
		// No org key configured — private addresses still get advertised in
		// AddressSet (same-org determination happens on read).
		rec.AddressSet = append(rec.AddressSet, privateSet...)
	}

	Sign(&rec, p.cfg.Signer)
	return rec
}

// buildDelta constructs a signed DeltaRecord describing the transformation
// from the node's last full-snapshot AddressSet to the current one.
func (p *Publisher) buildDelta(ops []DeltaEntry, baseDigest string, now time.Time) DeltaRecord {
	hlc := p.cfg.Clock.Tick()
	drec := DeltaRecord{
		NodeID:        p.cfg.NodeID,
		TenantID:      p.cfg.TenantID,
		SchemaVersion: SchemaVersion | DeltaSchemaFlag,
		HLC:           hlc,
		Epoch:         p.cfg.Epoch,
		BaseDigest:    baseDigest,
		Ops:           ops,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(p.cfg.DeltaMaxAge),
	}
	// Delta is signed by the same Ed25519 key as the full record; the
	// canonical form hashes (node, base, ops) so a tampered op fails verify.
	signDelta(&drec, p.cfg.Signer)
	return drec
}

// appendDeltaToLedger emits a DeltaRecord to the ledger using the reach
// topic with SchemaVersion flagged — readers know to unmarshal as delta.
func (p *Publisher) appendDeltaToLedger(ctx context.Context, drec DeltaRecord) error {
	body, err := MarshalDelta(&drec)
	if err != nil {
		return fmt.Errorf("marshal delta: %w", err)
	}
	envelope := lad.Record{
		Topic:        lad.TopicReach,
		TenantID:     drec.TenantID,
		NodeID:       drec.NodeID,
		Body:         body,
		Timestamp:    drec.UpdatedAt,
		LamportClock: uint64(drec.HLC.Wall),
		HLCTimestamp: uint64(drec.HLC.Wall),
		ExpiresAt:    drec.ExpiresAt,
		AuthorPubKey: drec.PubKey,
		Signature:    drec.Signature,
	}
	return p.cfg.Ledger.Append(ctx, envelope)
}

// approxDeltaBytes returns the JSON byte count for metrics.
func approxDeltaBytes(drec DeltaRecord) int {
	b, _ := MarshalDelta(&drec)
	return len(b)
}

// appendToLedger wraps a ReachRecord in a ledger envelope and appends it.
func (p *Publisher) appendToLedger(ctx context.Context, rec ReachRecord) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal reach record: %w", err)
	}
	envelope := lad.Record{
		Topic:        lad.TopicReach,
		TenantID:     rec.TenantID,
		NodeID:       rec.NodeID,
		Body:         body,
		Timestamp:    rec.UpdatedAt,
		LamportClock: uint64(rec.HLC.Wall),
		HLCTimestamp: uint64(rec.HLC.Wall),
		ExpiresAt:    rec.ExpiresAt,
		AuthorPubKey: rec.PubKey,
		Signature:    rec.Signature,
	}
	if rec.Tombstone != nil {
		envelope.Tombstone = true
		envelope.TombstoneReason = rec.Tombstone.Reason
		envelope.DeletedAt = rec.UpdatedAt
	}
	return p.cfg.Ledger.Append(ctx, envelope)
}

// broadcastFreshness emits the digest announce to peers via the freshness
// bus. Peers compare against their cache and request a snapshot on mismatch
// (see FreshnessClient). Best-effort; a miss just means a peer catches up
// on the next gossip round.
func (p *Publisher) broadcastFreshness(digest string) {
	if p.cfg.Whisper == nil || p.cfg.FreshnessInterval == 0 {
		return
	}
	payload := freshnessPayload{
		Kind:   FreshnessAnnounce,
		NodeID: p.cfg.NodeID,
		Digest: digest,
		From:   p.cfg.NodeID,
		HLC:    p.cfg.Clock.Last(),
		Epoch:  p.cfg.Epoch,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_ = p.cfg.Whisper.PublishDigest(raw)
}

// publishTombstone announces graceful shutdown.
func (p *Publisher) publishTombstone(ctx context.Context, reason string) {
	p.mu.Lock()
	p.shuttingDown = true
	p.mu.Unlock()

	hlc := p.cfg.Clock.Tick()
	now := time.Now().UTC()
	rec := ReachRecord{
		TenantID:      p.cfg.TenantID,
		NodeID:        p.cfg.NodeID,
		Seq:           uint64(hlc.Wall),
		Region:        p.cfg.Region,
		ExpiresAt:     now.Add(5 * time.Minute),
		UpdatedAt:     now,
		SchemaVersion: SchemaVersion,
		HLC:           hlc,
		Epoch:         p.cfg.Epoch,
		Tombstone:     &TombstoneInfo{Reason: reason},
	}
	Sign(&rec, p.cfg.Signer)

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := p.appendToLedger(ctx, rec); err != nil {
		log.Printf("[reach] publish tombstone: %v", err)
		return
	}
	p.cfg.Metrics.TombstonePublished(reason)
}

// FreshnessKind discriminates the two message types on the freshness topic.
// Kind 0 is reserved as "unspecified" so unknown kinds decode safely.
type FreshnessKind uint8

const (
	// FreshnessAnnounce: a publisher is announcing its current digest.
	// Receivers compare against their cache and request a snapshot on
	// mismatch.
	FreshnessAnnounce FreshnessKind = 1

	// FreshnessRequest: a receiver is asking the subject NodeID to
	// publish a fresh full snapshot. The subject node's publisher hits
	// ForcePublish(PublishReasonPeerRequest) on receipt.
	FreshnessRequest FreshnessKind = 2
)

// freshnessPayload is the wire format of a reach.freshness message. Covers
// both announces (Kind=Announce; From==NodeID==publisher) and requests
// (Kind=Request; NodeID=subject; From=requester).
type freshnessPayload struct {
	Kind   FreshnessKind `json:"k,omitempty"` // 0 = legacy-treated-as-announce
	NodeID string        `json:"n"`           // subject (whom the message is about)
	Digest string        `json:"d,omitempty"` // announce: current; request: requester's known digest
	From   string        `json:"f,omitempty"` // sender (loop prevention)
	HLC    HLC           `json:"h"`
	Epoch  uint64        `json:"e,omitempty"` // sender's process Epoch (stale-announce guard)
}

func anyPublic(addrs []Address) bool {
	for _, a := range addrs {
		if a.Scope == ScopePublic {
			return true
		}
	}
	return false
}

func sourceRank(s AddressSource) int {
	// Lower rank = higher preference (wins dedup).
	switch s {
	case SrcStatic:
		return 0
	case SrcPlatformEnv:
		return 1
	case SrcDNS:
		return 2
	case SrcIMDS, SrcK8sDownward:
		return 3
	case SrcInterface:
		return 4
	case SrcUPnP:
		return 5
	case SrcSTUN:
		return 6
	case SrcICE:
		return 7
	case SrcReflection:
		return 8
	case SrcTURN:
		return 9
	default:
		return 99
	}
}

func approxRecordBytes(rec ReachRecord) int {
	b, _ := json.Marshal(rec)
	return len(b)
}
