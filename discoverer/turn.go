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

// Credential is a username+password pair for a single TURN allocation.
// Some callers compute this statically; others derive it per-allocation via
// Config.CredentialFunc so credentials rotate.
type Credential struct {
	Username string
	Password string
	Expires  time.Time // informational; the discoverer always refreshes before 10min
}

// CredentialFunc returns fresh credentials each time it's called. The TURN
// discoverer calls it once per allocation (every 9 minutes).
type CredentialFunc func(ctx context.Context) (Credential, error)

// TURN allocates a UDP relay on a TURN server chosen by the consumer and
// publishes the allocated (ip, port) as a reach.Address with Source=SrcTURN.
//
// The allocation is refreshed every 9 minutes; default TURN lifetime is 10.
// On Close the relay socket and refresh goroutine are torn down cleanly.
//
// Credentials are fully pluggable via TURNConfig. Three common modes:
//
//   1. Static long-term: set TURNConfig.Username + TURNConfig.Password.
//      Works with any TURN server configured for static users.
//
//   2. Standard TURN REST API (RFC draft-uberti-behave-turn-rest): supply a
//      CredentialFunc that computes
//        password = base64(HMAC-SHA1(shared_secret, username))
//      where username = "{expiry}:{userID}" and shared_secret is configured
//      on both client and server. The helper StandardRESTCredentials() builds
//      this for you.
//
//   3. Custom schemes (tenant-keyed HKDF, mTLS, etc.): supply your own
//      CredentialFunc. Helpers HKDFHMACCredentials() and BuildTURNPassword()
//      cover the HKDF-derived-secret variant that some multi-tenant relays
//      (including ORBTR's relay.orbtr.io) use.
type TURN struct {
	Base

	serverAddr string
	realm      string
	credFn     CredentialFunc

	mu     sync.Mutex
	active *allocation
}

type allocation struct {
	client    *turn.Client
	relayConn net.PacketConn
	relayAddr net.Addr
	region    string
	expires   time.Time
	stop      chan struct{}
}

// TURNConfig configures a TURN discoverer. Pick exactly ONE of:
//
//   a) Username + Password (static long-term credentials)
//   b) CredentialFunc       (dynamic, called per allocation)
type TURNConfig struct {
	// ServerAddr is the host:port of the TURN server (UDP).
	ServerAddr string

	// Realm sets the TURN REALM attribute. Leave empty unless the server
	// explicitly requires a realm.
	Realm string

	// Username + Password for static long-term credentials. Ignored when
	// CredentialFunc is set.
	Username string
	Password string

	// CredentialFunc supplies fresh credentials on each allocation.
	// Takes precedence over Username/Password.
	CredentialFunc CredentialFunc
}

// NewTURN constructs a TURN discoverer. EnabledFor returns false until
// the server address + some credential source are configured.
func NewTURN(cfg TURNConfig) *TURN {
	credFn := cfg.CredentialFunc
	if credFn == nil && cfg.Username != "" {
		user, pass := cfg.Username, cfg.Password
		credFn = func(context.Context) (Credential, error) {
			return Credential{Username: user, Password: pass}, nil
		}
	}
	t := &TURN{
		serverAddr: cfg.ServerAddr,
		realm:      cfg.Realm,
		credFn:     credFn,
	}
	enabled := func(provider string) bool {
		return cfg.ServerAddr != "" && credFn != nil
	}
	t.Base = Base{
		NameValue:     "turn",
		SourceValue:   reach.SrcTURN,
		IntervalValue: 9 * time.Minute, // allocation refresh cadence
		EnabledValue:  enabled,
	}
	return t
}

// StandardRESTCredentials builds a CredentialFunc for RFC-style TURN REST API
// servers that expect:
//
//	username = "{expiry_unix}:{userID}"
//	password = base64(HMAC-SHA1(sharedSecret, username))
//
// ttl controls how long each credential remains valid after minting.
// The shared_secret must match the value configured on the TURN server via
// `--static-auth-secret` (coturn), the `sharedSecret` option (pion/turn), or
// the equivalent setting on other servers.
func StandardRESTCredentials(userID string, sharedSecret []byte, ttl time.Duration) CredentialFunc {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return func(context.Context) (Credential, error) {
		if len(sharedSecret) == 0 {
			return Credential{}, errors.New("reach/discoverer: empty TURN shared secret")
		}
		exp := time.Now().Add(ttl).Unix()
		username := fmt.Sprintf("%d:%s", exp, userID)
		mac := hmac.New(sha1.New, sharedSecret)
		mac.Write([]byte(username))
		return Credential{
			Username: username,
			Password: base64.StdEncoding.EncodeToString(mac.Sum(nil)),
			Expires:  time.Unix(exp, 0),
		}, nil
	}
}

// HKDFHMACCredentials builds a CredentialFunc for multi-tenant TURN servers
// that expect an HKDF-derived-then-HMAC password pipeline (the scheme ORBTR's
// relay.orbtr.io uses):
//
//	username = "{expiry_unix}:{tenantID}:{sessionID}"
//	key      = HKDF-SHA256(tenantPSK, salt=hkdfSalt, info=tenantID)[:32]
//	password = base64(HMAC-SHA1(hex(key), username))
//
// Both sides (client + server) must derive with identical hkdfSalt. tenantPSK
// is the per-tenant shared secret provisioned out-of-band.
func HKDFHMACCredentials(tenantID, sessionID string, tenantPSK, hkdfSalt []byte, ttl time.Duration) CredentialFunc {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return func(context.Context) (Credential, error) {
		exp := time.Now().Add(ttl).Unix()
		username := fmt.Sprintf("%d:%s:%s", exp, tenantID, sessionID)
		password, err := BuildTURNPassword(username, tenantPSK, hkdfSalt, tenantID)
		if err != nil {
			return Credential{}, err
		}
		return Credential{Username: username, Password: password, Expires: time.Unix(exp, 0)}, nil
	}
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
	// Resolve credentials first so we don't open a socket we can't use.
	if t.credFn == nil {
		return nil, errors.New("reach/discoverer: TURN has no credential source")
	}
	cred, err := t.credFn(ctx)
	if err != nil {
		return nil, fmt.Errorf("turn: credentials: %w", err)
	}

	// pion/turn wants a PacketConn — use ListenPacket on an ephemeral UDP port.
	// Resolving serverAddr here validates the format before we touch the socket.
	if _, _, err := net.SplitHostPort(t.serverAddr); err != nil {
		return nil, fmt.Errorf("turn: invalid server addr %q: %w", t.serverAddr, err)
	}
	conn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("turn: listen packet: %w", err)
	}

	client, err := turn.NewClient(&turn.ClientConfig{
		Conn:           conn,
		STUNServerAddr: t.serverAddr,
		TURNServerAddr: t.serverAddr,
		Username:       cred.Username,
		Password:       cred.Password,
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

// BuildTURNPassword derives the TURN REST-API password for a given username.
//
// Pipeline:
//
//	derived = HKDF-SHA256(tenantPSK, salt, info=tenantID)[:32]
//	secret  = hex(derived)
//	pw      = base64(HMAC-SHA1(secret, username))
//
// Exported because the consuming TURN server needs the identical pipeline to
// validate incoming credentials — both sides share this single source of truth.
func BuildTURNPassword(username string, tenantPSK, hkdfSalt []byte, tenantID string) (string, error) {
	if len(tenantPSK) == 0 {
		return "", errors.New("reach: empty tenant PSK")
	}
	r := hkdf.New(sha256.New, tenantPSK, hkdfSalt, []byte(tenantID))
	derived := make([]byte, 32)
	if _, err := io.ReadFull(r, derived); err != nil {
		return "", fmt.Errorf("reach: hkdf derive: %w", err)
	}
	secret := hex.EncodeToString(derived)

	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(username))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}
