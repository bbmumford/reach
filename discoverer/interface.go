// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package discoverer

import (
	"context"
	"net"
	"time"

	"github.com/bbmumford/reach"
)

// Interface enumerates the local network interfaces and emits one Address
// per routable private address found. Intended for same-org reachability
// (fdaa: on Fly, VPC IPs on AWS/GCP, RFC1918 on LAN).
//
// Docker bridge IPs (172.16.0.0/12) are filtered — they aren't routable
// between hosts so publishing them would mislead peers.
type Interface struct {
	Base
	udpPort uint16
}

// NewInterface constructs an interface-enumeration discoverer for the given
// UDP port. Runs every 15 minutes by default — interface churn that matters
// should drive an event through the event bus rather than polling.
func NewInterface(udpPort uint16) *Interface {
	return &Interface{
		Base: Base{
			NameValue:     "interface",
			SourceValue:   reach.SrcInterface,
			IntervalValue: 15 * time.Minute,
			EnabledValue:  AllProviders,
		},
		udpPort: udpPort,
	}
}

// Discover walks net.Interfaces() and returns routable private addresses.
func (i *Interface) Discover(_ context.Context) ([]reach.Address, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil // non-fatal
	}
	now := time.Now()
	var out []reach.Address
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP
			if !isRoutablePrivate(ip) {
				continue
			}
			family := reach.FamilyIPv6
			if ip.To4() != nil {
				family = reach.FamilyIPv4
			}
			out = append(out, reach.Address{
				Host:       ip.String(),
				Port:       i.udpPort,
				Proto:      "udp",
				Scope:      reach.ScopePrivate,
				Family:     family,
				Source:     reach.SrcInterface,
				Confidence: 80, // we literally see the address; high trust
				FirstSeen:  now,
				Tags:       []string{"iface:" + iface.Name},
			})
		}
	}
	return out, nil
}

// isRoutablePrivate matches HSTLES Library's existing filter:
//   - RFC1918 IPv4 (except 172.16/12 Docker bridge) → true
//   - IPv6 ULA (fd00::/8) → true
//   - Loopback, link-local, unspecified → false
//   - Public addresses → false (those belong to a different discoverer)
func isRoutablePrivate(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return false
	}
	if !ip.IsPrivate() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return false
	}
	return true
}
