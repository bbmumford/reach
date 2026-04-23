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

// STUN discovers the node's server-reflexive address by sending RFC 5389
// Binding Requests to one or more STUN servers.
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
// reflexive address observed.
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

	for _, addr := range s.cfg.ServerAddrs {
		a, err := s.probe(ctx, addr, auth)
		if err == nil && a != nil {
			return []reach.Address{*a}, nil
		}
	}
	return nil, nil
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
