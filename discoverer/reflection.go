// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package discoverer

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/bbmumford/reach"
)

// Reflection emits addresses learned from remote peers that observed this
// node's inbound traffic (typical source: X-VL1-Observed-IP headers set by
// bootstrap anchors). Each observation is low-confidence on its own — only
// when a quorum of observations agree does the address get promoted.
//
// Consumers Record() each observation. The discoverer aggregates internally
// and Discover() returns a deduplicated, quorum-weighted list.
type Reflection struct {
	Base

	quorum       int
	mustDiffer   bool // require observations from distinct regions
	observationTTL time.Duration
	udpPort      uint16

	mu      sync.Mutex
	seen    map[string][]observation // addrKey -> observations
}

type observation struct {
	Host      string
	Port      uint16
	Proto     string
	FromNode  string
	FromRegion string
	At        time.Time
}

// NewReflection constructs a reflection aggregator.
// quorum is the minimum distinct observations required before an address
// graduates from Confidence=20 to Confidence=60. mustDifferByRegion requires
// the observers to be in different regions (defense against single-org adversary).
func NewReflection(quorum int, mustDifferByRegion bool, udpPort uint16) *Reflection {
	if quorum <= 0 {
		quorum = 3
	}
	return &Reflection{
		Base: Base{
			NameValue:     "reflection",
			SourceValue:   reach.SrcReflection,
			IntervalValue: 2 * time.Minute,
			EnabledValue:  AllProviders,
		},
		quorum:         quorum,
		mustDiffer:     mustDifferByRegion,
		observationTTL: 30 * time.Minute,
		udpPort:        udpPort,
		seen:           make(map[string][]observation),
	}
}

// Record ingests a single peer's observation of our reflexive address.
// Called by the consuming mesh node whenever a peer sends X-VL1-Observed-IP
// (or equivalent). Safe for concurrent use.
func (r *Reflection) Record(host string, port uint16, proto, fromNode, fromRegion string) {
	if host == "" {
		return
	}
	key := proto + "|" + host + "|" + u16(port)

	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()

	// Prune stale entries for this key first.
	cutoff := now.Add(-r.observationTTL)
	existing := r.seen[key]
	kept := existing[:0]
	for _, o := range existing {
		if o.At.After(cutoff) {
			kept = append(kept, o)
		}
	}

	// Dedup per observer: a peer updating its observation replaces, not adds.
	for i, o := range kept {
		if o.FromNode == fromNode {
			kept[i] = observation{Host: host, Port: port, Proto: proto, FromNode: fromNode, FromRegion: fromRegion, At: now}
			r.seen[key] = kept
			return
		}
	}
	kept = append(kept, observation{Host: host, Port: port, Proto: proto, FromNode: fromNode, FromRegion: fromRegion, At: now})
	r.seen[key] = kept
}

// Discover returns addresses sorted by observation strength.
func (r *Reflection) Discover(_ context.Context) ([]reach.Address, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.observationTTL)
	var out []reach.Address

	for _, obs := range r.seen {
		// Prune stale.
		kept := obs[:0]
		for _, o := range obs {
			if o.At.After(cutoff) {
				kept = append(kept, o)
			}
		}
		if len(kept) == 0 {
			continue
		}
		first := kept[0]

		// Count distinct observers (+ regions if mustDiffer).
		observers := make(map[string]struct{}, len(kept))
		regions := make(map[string]struct{}, len(kept))
		for _, o := range kept {
			observers[o.FromNode] = struct{}{}
			if o.FromRegion != "" {
				regions[o.FromRegion] = struct{}{}
			}
		}

		var confidence uint8 = 20 // baseline — single observer
		meetsQuorum := len(observers) >= r.quorum
		if r.mustDiffer {
			meetsQuorum = meetsQuorum && len(regions) >= r.quorum
		}
		if meetsQuorum {
			confidence = 60
		}

		out = append(out, reach.Address{
			Host:       first.Host,
			Port:       first.Port,
			Proto:      first.Proto,
			Scope:      reach.ScopePublic,
			Family:     familyOf(first.Host),
			Source:     reach.SrcReflection,
			Confidence: confidence,
			FirstSeen:  oldest(kept),
			Tags:       []string{"observers:" + u16(uint16(len(observers)))},
		})
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Confidence > out[j].Confidence
	})
	return out, nil
}

func oldest(obs []observation) time.Time {
	if len(obs) == 0 {
		return time.Time{}
	}
	min := obs[0].At
	for _, o := range obs[1:] {
		if o.At.Before(min) {
			min = o.At
		}
	}
	return min
}

func familyOf(host string) reach.Family {
	// Crude but sufficient — a proper IP parse would be overkill here.
	for _, c := range host {
		if c == ':' {
			return reach.FamilyIPv6
		}
		if c == '.' {
			return reach.FamilyIPv4
		}
	}
	return reach.FamilyHostname
}

func u16(v uint16) string {
	if v == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
