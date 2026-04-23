// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package discoverer

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/bbmumford/reach"
)

// DNS resolves the node's own public domain to discover its authoritative
// public IPs. This is the preferred discovery source on Fly.io (where STUN
// reveals the egress IP, not the ingress anycast IP) and any platform where
// the node's public DNS name is stable.
//
// Also advertises the hostname itself as a WSS + TLS bootstrap address so
// peers can dial via :443 even without an IP literal.
type DNS struct {
	Base
	hostname string
	udpPort  uint16
}

// NewDNS constructs a DNS discoverer for the given public domain and UDP port.
// hostname is resolved at every Discover call; fresh IPs on every tick.
func NewDNS(hostname string, udpPort uint16) *DNS {
	return &DNS{
		Base: Base{
			NameValue:     "dns",
			SourceValue:   reach.SrcDNS,
			IntervalValue: 5 * time.Minute,
			EnabledValue:  AllProviders,
		},
		hostname: hostname,
		udpPort:  udpPort,
	}
}

// Discover resolves the configured hostname and returns one UDP address per
// resolved IP plus WSS + TLS address entries for the hostname itself.
func (d *DNS) Discover(ctx context.Context) ([]reach.Address, error) {
	if d.hostname == "" {
		return nil, nil
	}
	resolver := net.DefaultResolver
	ips, err := resolver.LookupHost(ctx, d.hostname)
	if err != nil {
		// Non-fatal — the publisher tolerates empty results.
		return nil, nil
	}

	now := time.Now()
	out := make([]reach.Address, 0, len(ips)+2)
	for _, ipStr := range ips {
		parsed := net.ParseIP(ipStr)
		if parsed == nil || parsed.IsLoopback() || parsed.IsUnspecified() {
			continue
		}
		family := reach.FamilyIPv6
		if parsed.To4() != nil {
			family = reach.FamilyIPv4
		}
		out = append(out, reach.Address{
			Host:       ipStr,
			Port:       d.udpPort,
			Proto:      "udp",
			Scope:      reach.ScopePublic,
			Family:     family,
			Source:     reach.SrcDNS,
			Confidence: 70, // high trust — DNS authoritative for own domain
			FirstSeen:  now,
		})
	}

	// Hostname-as-address for WSS + TLS bootstrap
	out = append(out, reach.Address{
		Host:       d.hostname,
		Port:       443,
		Proto:      "wss",
		Scope:      reach.ScopePublic,
		Family:     reach.FamilyHostname,
		Source:     reach.SrcDNS,
		Confidence: 80,
		FirstSeen:  now,
	}, reach.Address{
		Host:       d.hostname,
		Port:       443,
		Proto:      "tls",
		Scope:      reach.ScopePublic,
		Family:     reach.FamilyHostname,
		Source:     reach.SrcDNS,
		Confidence: 80,
		FirstSeen:  now,
	})

	// Anycast heuristic: if the hostname resolved to multiple IPs across
	// different /16 ranges, tag them CapAnycast so peers can weight regional
	// preference accordingly.
	if isLikelyAnycast(ips) {
		for i := range out {
			if out[i].Family == reach.FamilyIPv4 || out[i].Family == reach.FamilyIPv6 {
				out[i].Capabilities = out[i].Capabilities.Set(reach.CapAnycast)
			}
		}
	}

	return out, nil
}

// isLikelyAnycast checks whether a list of resolved IPs spans enough diverse
// /16 ranges to suggest anycast DNS (as opposed to a single dedicated IP).
// Heuristic — not authoritative, just drives RegionPriority hints.
func isLikelyAnycast(ips []string) bool {
	prefixes := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		i := strings.LastIndex(ip, ".")
		if i < 0 {
			continue
		}
		j := strings.LastIndex(ip[:i], ".")
		if j < 0 {
			continue
		}
		prefixes[ip[:j]] = struct{}{}
	}
	return len(prefixes) >= 2
}
