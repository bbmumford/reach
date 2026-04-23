// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package discoverer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/bbmumford/reach"
	"github.com/pion/stun/v3"
)

// STUNAuth carries credentials for a STUN server that requires
// MESSAGE-INTEGRITY (RFC 5389 long-term credential mechanism).
// Most public STUN servers are unauthenticated and leave this zero.
type STUNAuth struct {
	Username string
	Realm    string
	Password string
}

// STUNAuthFunc returns credentials on demand so callers can rotate them.
// Called once per Discover() pass. Return an empty STUNAuth and nil error
// to probe without MESSAGE-INTEGRITY.
type STUNAuthFunc func(ctx context.Context) (STUNAuth, error)

// STUNConfig configures a STUN discoverer.
type STUNConfig struct {
	// ServerAddrs is the ordered list of STUN servers to probe (host:port).
	// First successful response wins.
	ServerAddrs []string

	// UDPPort is the UDP port WE bind for mesh traffic. It is advertised in
	// the resulting reach.Address; NOT the STUN server's port.
	UDPPort uint16

	// AuthFunc returns credentials for servers that require
	// MESSAGE-INTEGRITY. Leave nil for anonymous STUN (the common case).
	AuthFunc STUNAuthFunc

	// Timeout bounds each server probe. Default 3 s.
	Timeout time.Duration

	// EnabledFunc overrides the default platform gating ("not fly").
	EnabledFunc func(provider string) bool
}

// NATType classifies the node's NAT behaviour based on RFC 5780 probing.
// Derived from two Binding Requests against the same STUN server: if the
// reflexive addresses match for two requests sent from the same local port,
// the NAT is endpoint-independent; if they differ, it's symmetric.
//
// The publisher uses this to decide whether to publish the srflx address:
// symmetric NATs rewrite the source port per destination, so the reflexive
// address is useless for peer-to-peer dial. Symmetric nodes advertise only
// TURN and WSS addresses.
type NATType string

const (
	NATUnknown      NATType = ""
	NATOpen         NATType = "open"            // no NAT / endpoint-independent mapping
	NATSymmetric    NATType = "symmetric"       // rewrites source port per dest; srflx unusable
	NATRestricted   NATType = "restricted"      // address-dependent filtering
)

// STUN discovers the node's server-reflexive address by sending RFC 5389
// Binding Requests to one or more STUN servers. Probes two servers in
// sequence to classify NAT behaviour per RFC 5780 §4.3.
//
// Disabled by default on Fly.io — Fly's egress IP differs from the dedicated
// anycast ingress IP, so STUN returns a misleading answer there. DNS self-
// resolution is the correct source on Fly.
//
// Anonymous STUN (no auth) works against any public STUN server. For servers
// that require MESSAGE-INTEGRITY (long-term credential mechanism per
// RFC 5389 §10.2.2) supply STUNConfig.AuthFunc.
type STUN struct {
	Base
	cfg STUNConfig

	mu         sync.Mutex
	lastNATType NATType
}

// NewSTUN constructs a STUN discoverer from a STUNConfig.
func NewSTUN(cfg STUNConfig) *STUN {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	enabled := cfg.EnabledFunc
	if enabled == nil {
		enabled = NotOn("fly")
	}
	return &STUN{
		Base: Base{
			NameValue:     "stun",
			SourceValue:   reach.SrcSTUN,
			IntervalValue: 2 * time.Minute,
			EnabledValue:  enabled,
		},
		cfg: cfg,
	}
}

// Discover dials each configured server in turn and returns the first
// reflexive address observed. When two or more servers are configured,
// it also classifies NAT type by comparing reflexive mappings (RFC 5780
// §4.3): matching XOR-MAPPED addresses across distinct servers imply
// endpoint-independent mapping; differing addresses imply symmetric NAT.
func (s *STUN) Discover(ctx context.Context) ([]reach.Address, error) {
	if len(s.cfg.ServerAddrs) == 0 {
		return nil, nil
	}

	var auth STUNAuth
	if s.cfg.AuthFunc != nil {
		a, err := s.cfg.AuthFunc(ctx)
		if err != nil {
			return nil, fmt.Errorf("stun auth: %w", err)
		}
		auth = a
	}

	var first *reach.Address
	var second *reach.Address
	for _, addr := range s.cfg.ServerAddrs {
		a, err := s.probe(ctx, addr, auth)
		if err != nil || a == nil {
			continue
		}
		if first == nil {
			first = a
			continue
		}
		second = a
		break
	}
	if first == nil {
		return nil, nil
	}

	natType := NATUnknown
	if second != nil {
		if first.Host == second.Host {
			natType = NATOpen
		} else {
			natType = NATSymmetric
		}
	}
	s.mu.Lock()
	s.lastNATType = natType
	s.mu.Unlock()

	// Symmetric NAT: srflx address is useless for peers dialling from any
	// other source (the NAT will rewrite the source port per destination).
	// Publish with Capabilities=0, low confidence and a tag so the publisher
	// can downgrade — but do not fully suppress: some peers may still land
	// via hole-punching if we coordinate via TURN.
	if natType == NATSymmetric {
		first.Confidence = 15
		first.Tags = append(first.Tags, "nat:symmetric")
	} else if natType == NATOpen {
		first.Confidence = 50
		first.Tags = append(first.Tags, "nat:open")
	}
	return []reach.Address{*first}, nil
}

// LastNATType returns the most recently classified NAT type (or NATUnknown
// before the first successful multi-server probe). Consumers that want to
// react to NAT changes poll this.
func (s *STUN) LastNATType() NATType {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastNATType
}

func (s *STUN) probe(ctx context.Context, serverAddr string, auth STUNAuth) (*reach.Address, error) {
	dialCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
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

	// Build the request — anonymous by default, add integrity attributes when
	// credentials are supplied.
	setters := []stun.Setter{stun.TransactionID, stun.BindingRequest}
	if auth.Username != "" {
		setters = append(setters,
			stun.NewUsername(auth.Username),
			stun.NewRealm(auth.Realm),
			stun.NewLongTermIntegrity(auth.Username, auth.Realm, auth.Password),
			stun.Fingerprint,
		)
	}
	message, err := stun.Build(setters...)
	if err != nil {
		return nil, fmt.Errorf("stun build: %w", err)
	}

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
		Port:       s.cfg.UDPPort, // advertise OUR UDP port, not the STUN-reported port
		Proto:      "udp",
		Scope:      reach.ScopePublic,
		Family:     family,
		Source:     reach.SrcSTUN,
		Confidence: 40, // unverified — a REACH_VERIFY probe must promote to >=60
		FirstSeen:  time.Now(),
		Tags:       []string{"stun:" + serverAddr, "reflex_port:" + u16(reflexPort)},
	}, nil
}

// StaticSTUNAuth returns an AuthFunc that always returns the same credentials.
// Useful when the STUN server uses a long-term credential and you have a
// single username/password pair provisioned out of band.
func StaticSTUNAuth(username, realm, password string) STUNAuthFunc {
	return func(context.Context) (STUNAuth, error) {
		return STUNAuth{Username: username, Realm: realm, Password: password}, nil
	}
}
