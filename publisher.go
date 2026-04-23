// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
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
	eventCh   chan AddressChange // external events (netlink, role change, etc.)
	forceCh   chan PublishReason // internal "publish now" requests

	// State.
	mu              sync.Mutex
	lastDigest      string
	lastAddresses   []Address
	lastPublishedAt time.Time
	shuttingDown    bool
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

	return &Publisher{
		cfg:       &cfg,
		scheduler: newScheduler(&cfg),
		eventCh:   make(chan AddressChange, 32),
		forceCh:   make(chan PublishReason, 4),
	}, nil
}

// Run blocks until ctx is cancelled. It runs the discoverer orchestrator on
// schedule and in response to events, and publishes to the ledger whenever
// the address set digest changes.
//
// On ctx cancel it publishes a shutdown tombstone before returning.
func (p *Publisher) Run(ctx context.Context) {
	// Prime: run a full discovery cycle synchronously so the initial publish
	// happens within the caller's bootstrap window.
	if err := p.publishOnce(ctx, PublishReasonBootstrap); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("[reach] initial publish failed: %v", err)
	}

	// Restore persisted digest so we can skip re-publishing if nothing changed.
	_ = p.loadLastGood()

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

	digest := Digest(addrs)

	p.mu.Lock()
	unchanged := digest == p.lastDigest && !p.needsTTLRefresh(now)
	p.mu.Unlock()

	if unchanged && reason != PublishReasonEpoch && reason != PublishReasonBootstrap {
		p.cfg.Metrics.PublishSkipped(SkipDigestMatch)
		return nil
	}

	if !p.scheduler.allowPublish(now) {
		p.cfg.Metrics.PublishSkipped(SkipRateLimit)
		return nil
	}

	rec := p.buildRecord(addrs, now)
	if err := p.appendToLedger(ctx, rec); err != nil {
		p.cfg.Metrics.PublishFailed(err)
		return err
	}
	p.broadcastFreshness(digest)

	p.mu.Lock()
	p.lastDigest = digest
	p.lastAddresses = addrs
	p.lastPublishedAt = now
	p.mu.Unlock()

	_ = p.saveLastGood(rec)

	p.cfg.Metrics.PublishSucceeded(approxRecordBytes(rec))
	if digest != p.lastDigest {
		p.scheduler.noteChange(now)
	}
	return nil
}

// discoverAll runs every configured discoverer concurrently and returns the
// union of their results. Discoverers that error are logged and skipped —
// a partial result set is preferable to no publish at all.
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

	var wg sync.WaitGroup
	for _, d := range p.cfg.Discoverers {
		if !d.EnabledFor(p.cfg.Provider) {
			continue
		}
		wg.Add(1)
		go func(d Discoverer) {
			defer wg.Done()
			start := time.Now()
			dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
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

// needsTTLRefresh reports whether any address is within one-third of its TTL.
// Caller holds p.mu.
func (p *Publisher) needsTTLRefresh(now time.Time) bool {
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

	// Record-level ExpiresAt = max of per-address ExpiresAt.
	recordExpiry := now.Add(10 * time.Minute)
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

// broadcastFreshness emits the digest to peers via the freshness bus.
// Best-effort; a miss just means a peer catches up on the next gossip round.
func (p *Publisher) broadcastFreshness(digest string) {
	if p.cfg.Whisper == nil || p.cfg.FreshnessInterval == 0 {
		return
	}
	payload := freshnessPayload{
		NodeID: p.cfg.NodeID,
		Digest: digest,
		HLC:    p.cfg.Clock.Last(),
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

// freshnessPayload is the wire format of a reach.freshness broadcast.
type freshnessPayload struct {
	NodeID string `json:"n"`
	Digest string `json:"d"`
	HLC    HLC    `json:"h"`
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
