// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package discoverer

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/bbmumford/reach"
	"github.com/pion/turn/v4"
	"golang.org/x/crypto/hkdf"
)

// TURN allocates a UDP relay on a fleet TURN server (typically
// relay.orbtr.io:3478) and publishes the allocated (ip, port) as a
// reach.Address with Source=SrcTURN.
//
// The allocation is refreshed every 9 minutes; default TURN lifetime is 10.
// On Close the relay socket and refresh goroutine are torn down cleanly.
//
// Credentials follow the orbtr relay's format:
//
//	username = "{unix_expiry}:{tenant_id}:{session_id}"
//	key      = HKDF(tenantPSK, salt="orbtr-turn-v1", info=tenantID)
//	password = base64(HMAC-SHA1(key, username))
//
// Only a subset of runs need a relay (§5.28 gating). The publisher invokes
// Allocate when: (a) no public-scope address graduated past Confidence=60
// after bootstrap, OR (b) peer probes failed to verify the self-published
// public addresses from >=2 distinct regions.
type TURN struct {
	Base

	serverAddr string
	tenantID   string
	sessionID  string
	tenantPSK  []byte
	realm      string

	mu       sync.Mutex
	active   *allocation
}

type allocation struct {
	client    *turn.Client
	relayConn net.PacketConn
	relayAddr net.Addr
	region    string
	expires   time.Time
	stop      chan struct{}
}

// NewTURN constructs a TURN discoverer.
// tenantPSK is the same shared secret the relay's tenantkeys.LookupPSK returns.
// Zero tenantPSK disables the discoverer entirely (EnabledFor returns false).
func NewTURN(serverAddr, tenantID, sessionID, realm string, tenantPSK []byte) *TURN {
	t := &TURN{
		serverAddr: serverAddr,
		tenantID:   tenantID,
		sessionID:  sessionID,
		tenantPSK:  tenantPSK,
		realm:      realm,
	}
	enabled := func(provider string) bool {
		return len(tenantPSK) > 0 && serverAddr != "" && tenantID != ""
	}
	t.Base = Base{
		NameValue:     "turn",
		SourceValue:   reach.SrcTURN,
		IntervalValue: 9 * time.Minute, // allocation refresh cadence
		EnabledValue:  enabled,
	}
	if realm == "" {
		t.realm = "orbtr.io"
	}
	return t
}

// Discover allocates (or keeps alive) a TURN relay and returns its address.
// Subsequent calls reuse the active allocation until it expires.
func (t *TURN) Discover(ctx context.Context) ([]reach.Address, error) {
	t.mu.Lock()
	alloc := t.active
	t.mu.Unlock()

	now := time.Now()
	if alloc != nil && alloc.expires.After(now.Add(90*time.Second)) {
		return []reach.Address{t.addressFrom(alloc)}, nil
	}

	// Allocate fresh.
	newAlloc, err := t.allocate(ctx)
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	if t.active != nil {
		t.closeAllocLocked(t.active)
	}
	t.active = newAlloc
	t.mu.Unlock()

	return []reach.Address{t.addressFrom(newAlloc)}, nil
}

// Close tears down the active allocation.
func (t *TURN) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active != nil {
		t.closeAllocLocked(t.active)
		t.active = nil
	}
	return nil
}

func (t *TURN) closeAllocLocked(a *allocation) {
	select {
	case <-a.stop:
	default:
		close(a.stop)
	}
	if a.relayConn != nil {
		_ = a.relayConn.Close()
	}
	if a.client != nil {
		a.client.Close()
	}
}

func (t *TURN) addressFrom(a *allocation) reach.Address {
	host, portStr, _ := net.SplitHostPort(a.relayAddr.String())
	port, _ := strconv.Atoi(portStr)
	family := reach.FamilyIPv6
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		family = reach.FamilyIPv4
	}
	regionPriority := map[string]uint8{}
	if a.region != "" {
		regionPriority[a.region] = 80
	}
	regionPriority["*"] = 20

	return reach.Address{
		Host:       host,
		Port:       uint16(port),
		Proto:      "udp",
		Scope:      reach.ScopePublic,
		Family:     family,
		Source:     reach.SrcTURN,
		Confidence: 60, // relay literally owns the socket — high trust
		FirstSeen:  time.Now(),
		ExpiresAt:  a.expires,
		RegionPriority: regionPriority,
		Capabilities: reach.CapRelay,
		Tags:       []string{"turn:" + t.serverAddr},
	}
}

func (t *TURN) allocate(ctx context.Context) (*allocation, error) {
	_ = ctx // reserved for future per-call deadline on pion/turn

	// pion/turn wants a PacketConn — use ListenPacket on an ephemeral UDP port.
	// Resolving serverAddr here validates the format before we touch the socket.
	if _, _, err := net.SplitHostPort(t.serverAddr); err != nil {
		return nil, fmt.Errorf("turn: invalid server addr %q: %w", t.serverAddr, err)
	}
	conn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("turn: listen packet: %w", err)
	}

	expiry := time.Now().Add(15 * time.Minute).Unix()
	username := fmt.Sprintf("%d:%s:%s", expiry, t.tenantID, t.sessionID)
	password, err := buildTURNPassword(username, t.tenantPSK, t.tenantID)
	if err != nil {
		conn.Close()
		return nil, err
	}

	client, err := turn.NewClient(&turn.ClientConfig{
		Conn:           conn,
		STUNServerAddr: t.serverAddr,
		TURNServerAddr: t.serverAddr,
		Username:       username,
		Password:       password,
		Realm:          t.realm,
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("turn client: %w", err)
	}
	if err := client.Listen(); err != nil {
		client.Close()
		conn.Close()
		return nil, fmt.Errorf("turn listen: %w", err)
	}

	relayConn, err := client.Allocate()
	if err != nil {
		client.Close()
		conn.Close()
		return nil, fmt.Errorf("turn allocate: %w", err)
	}

	a := &allocation{
		client:    client,
		relayConn: relayConn,
		relayAddr: relayConn.LocalAddr(),
		expires:   time.Now().Add(10 * time.Minute),
		stop:      make(chan struct{}),
	}

	// Refresh loop — re-allocate every 9 minutes to stay below the 10-minute default lifetime.
	go func() {
		ticker := time.NewTicker(9 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-a.stop:
				return
			case <-ticker.C:
				// pion/turn doesn't expose a pure refresh — re-Allocate is a no-op
				// for an already-allocated client and extends the lifetime.
				if _, err := client.Allocate(); err != nil {
					// Non-fatal; next Discover tick will allocate fresh.
					return
				}
				a.expires = time.Now().Add(10 * time.Minute)
			}
		}
	}()

	return a, nil
}

// buildTURNPassword derives the TURN REST-API password for a given username,
// matching relay.orbtr.io's deriveTurnSecret + computeTurnHMAC pipeline.
func buildTURNPassword(username string, tenantPSK []byte, tenantID string) (string, error) {
	if len(tenantPSK) == 0 {
		return "", errors.New("reach: empty tenant PSK")
	}
	r := hkdf.New(sha256.New, tenantPSK, []byte("orbtr-turn-v1"), []byte(tenantID))
	derived := make([]byte, 32)
	if _, err := io.ReadFull(r, derived); err != nil {
		return "", fmt.Errorf("reach: hkdf derive: %w", err)
	}
	secret := hex.EncodeToString(derived)

	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(username))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}
