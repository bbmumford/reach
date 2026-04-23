// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package discoverer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/bbmumford/reach"
	"github.com/pion/stun/v3"
)

// STUN discovers the node's server-reflexive address by sending a RFC 5389
// Binding Request to a STUN server (typically relay.orbtr.io:3478).
//
// Disabled by default on Fly.io — Fly's egress IP differs from the dedicated
// anycast ingress IP, so STUN returns a misleading answer there. DNS self-
// resolution is the correct source on Fly.
type STUN struct {
	Base
	serverAddrs []string
	udpPort     uint16
	timeout     time.Duration
}

// NewSTUN constructs a STUN discoverer against a set of server addresses
// (host:port). Multiple servers give fault tolerance; first response wins.
func NewSTUN(udpPort uint16, serverAddrs ...string) *STUN {
	return &STUN{
		Base: Base{
			NameValue:     "stun",
			SourceValue:   reach.SrcSTUN,
			IntervalValue: 2 * time.Minute,
			EnabledValue:  NotOn("fly"),
		},
		serverAddrs: serverAddrs,
		udpPort:     udpPort,
		timeout:     3 * time.Second,
	}
}

// Discover dials each configured server in turn and returns the first
// reflexive address observed. On total failure returns no addresses and no
// error — STUN absence is normal on fully-private networks.
func (s *STUN) Discover(ctx context.Context) ([]reach.Address, error) {
	if len(s.serverAddrs) == 0 {
		return nil, nil
	}

	for _, addr := range s.serverAddrs {
		a, err := s.probe(ctx, addr)
		if err == nil && a != nil {
			return []reach.Address{*a}, nil
		}
	}
	return nil, nil
}

func (s *STUN) probe(ctx context.Context, serverAddr string) (*reach.Address, error) {
	dialCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("stun dial %s: %w", serverAddr, err)
	}
	defer conn.Close()

	client, err := stun.NewClient(conn)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	var reflexIP net.IP
	var reflexPort uint16
	var cbErr error

	err = client.Do(message, func(res stun.Event) {
		if res.Error != nil {
			cbErr = res.Error
			return
		}
		var xorAddr stun.XORMappedAddress
		if xerr := xorAddr.GetFrom(res.Message); xerr == nil {
			reflexIP = xorAddr.IP
			reflexPort = uint16(xorAddr.Port)
			return
		}
		// Fall back to unencoded MAPPED-ADDRESS if server didn't include XOR variant.
		var mapped stun.MappedAddress
		if merr := mapped.GetFrom(res.Message); merr == nil {
			reflexIP = mapped.IP
			reflexPort = uint16(mapped.Port)
			return
		}
		cbErr = errors.New("stun: no mapped-address attribute in response")
	})
	if err != nil {
		return nil, err
	}
	if cbErr != nil {
		return nil, cbErr
	}
	if reflexIP == nil {
		return nil, nil
	}

	family := reach.FamilyIPv6
	if reflexIP.To4() != nil {
		family = reach.FamilyIPv4
	}

	return &reach.Address{
		Host:       reflexIP.String(),
		Port:       s.udpPort, // advertise OUR UDP port, not the STUN-reported port
		Proto:      "udp",
		Scope:      reach.ScopePublic,
		Family:     family,
		Source:     reach.SrcSTUN,
		Confidence: 40, // unverified — a REACH_VERIFY probe must promote to ≥60
		FirstSeen:  time.Now(),
		Tags:       []string{"stun:" + serverAddr, "reflex_port:" + u16(reflexPort)},
	}, nil
}
