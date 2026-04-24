// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"time"

	lad "github.com/bbmumford/ledger"
)

// SchemaVersion is the on-wire version of the ReachRecord payload.
// Bumped only on breaking changes. Additive field changes keep the same version
// since JSON decoders silently ignore unknown fields.
const SchemaVersion uint16 = 1

// ReachRecord extends ledger.ReachRecord with publisher-authored fields.
// It is marshaled as JSON into ledger.Record.Body when published, then
// unmarshaled here when read back. The base ledger schema fields (TenantID,
// NodeID, Seq, Addresses, Region, UpdatedAt, ExpiresAt) are preserved so
// existing consumers of the ledger cache continue to work unchanged.
//
// Publishers populate the richer AddressSet; readers that understand the v2
// schema use AddressSet, while older readers fall back to the flat Addresses
// slice (which is still emitted for compatibility within this repo).
type ReachRecord struct {
	// ── Ledger-compatible base ──────────────────────────────────────
	TenantID      string             `json:"tenant,omitempty"`
	NodeID        string             `json:"node_id"`
	Seq           uint64             `json:"seq"`
	Addresses     []lad.ReachAddress `json:"addrs"`
	Region        string             `json:"region"`
	NATType       string             `json:"nat_type,omitempty"`
	NATObserved   string             `json:"nat_observed,omitempty"`
	LatencyMillis int64              `json:"latency_ms,omitempty"`
	Availability  float64            `json:"availability,omitempty"`
	LoadFactor    float64            `json:"load_factor,omitempty"`
	ExpiresAt     time.Time          `json:"expires_at"`
	UpdatedAt     time.Time          `json:"ts"`

	// ── Reach v1 additions ──────────────────────────────────────────
	SchemaVersion uint16            `json:"v,omitempty"`
	HLC           HLC               `json:"hlc,omitempty"`
	Epoch         uint64            `json:"epoch,omitempty"`
	AddressSet    []Address         `json:"addrs_v1,omitempty"`
	Tombstone     *TombstoneInfo    `json:"tombstone,omitempty"`
	EncryptedOrg  *EncryptedSection `json:"enc_org,omitempty"`
	PubKey        []byte            `json:"pk,omitempty"`
	Signature     []byte            `json:"sig,omitempty"`

	// ── Identity fields (was MemberRecord) ─────────────────────────
	// Folded into ReachRecord so the same signed envelope carries both
	// "how to reach me" and "who I am". Lets consumers drop the separate
	// MemberRecord publish path entirely — one publish, one signature,
	// one HLC, one cache-presence check. Legacy consumers of TopicMember
	// can derive the MemberRecord view via DeriveMember(r).
	ServiceName string   `json:"svc,omitempty"` // e.g. "devices.orbtr.io"
	Roles       []string `json:"roles,omitempty"`

	// ── ICE candidates (RFC 8445) ───────────────────────────────────
	// Populated when at least one ICE-capable discoverer ran. Empty on
	// nodes that only emit flat ReachAddress entries.
	ICECandidates []string `json:"ice,omitempty"` // SDP candidate lines
}

// Address is the enriched per-endpoint reach entry.
// It mirrors ledger.ReachAddress semantically but carries additional
// discovery, health, and routing hints.
type Address struct {
	Host           string           `json:"h"`
	Port           uint16           `json:"p"`
	Proto          string           `json:"pr"`          // udp|quic|wss|tls|grpc
	Scope          Scope            `json:"s"`           // public|private|org|loopback
	Family         Family           `json:"f,omitempty"` // ipv4|ipv6|hostname
	Source         AddressSource    `json:"src"`         // dns|stun|iface|reflection|static|turn|imds
	Confidence     uint8            `json:"c"`           // 0-100
	RTTMicros      uint32           `json:"rtt,omitempty"`
	LossPermille   uint16           `json:"loss,omitempty"`
	MTU            uint16           `json:"mtu,omitempty"`
	LastVerified   time.Time        `json:"ver,omitempty"`
	FirstSeen      time.Time        `json:"fs,omitempty"`
	ExpiresAt      time.Time        `json:"exp"`
	RegionPriority map[string]uint8 `json:"rp,omitempty"` // region → 0-100 preference; "*" = any
	Capabilities   Capabilities     `json:"cap,omitempty"`
	Tags           []string         `json:"t,omitempty"`
}

// Key returns a stable identifier suitable for map keys and digest input.
// Two Address values that should be treated as "the same entry" share a Key.
func (a Address) Key() string {
	return a.Proto + "|" + a.Host + "|" + u16str(a.Port) + "|" + string(a.Scope) + "|" + a.Source.String()
}

// IsPublic reports whether the address is intended to be reachable from
// outside the owning node's private network.
func (a Address) IsPublic() bool { return a.Scope == ScopePublic }

// IsExpired reports whether ExpiresAt is non-zero and before the given time.
func (a Address) IsExpired(now time.Time) bool {
	return !a.ExpiresAt.IsZero() && a.ExpiresAt.Before(now)
}

// Scope describes the reachability scope of an address.
type Scope string

const (
	ScopeUnknown   Scope = ""
	ScopeLoopback  Scope = "loopback"
	ScopePrivate   Scope = "private" // RFC1918 / fdaa: / ULA
	ScopeOrg       Scope = "org"     // same-org mesh (encrypted for non-org peers)
	ScopePublic   Scope = "public"
)

// Family describes the IP family or hostname form of an address.
type Family string

const (
	FamilyUnknown  Family = ""
	FamilyIPv4     Family = "ipv4"
	FamilyIPv6     Family = "ipv6"
	FamilyHostname Family = "hostname"
)

// AddressSource indicates how an address was discovered.
// Source drives default confidence, TTL, and ordering preference.
type AddressSource uint8

const (
	SrcUnknown AddressSource = iota
	SrcStatic                // operator config
	SrcDNS                   // self-DNS resolution of PublicDomain
	SrcPlatformEnv           // FLY_PUBLIC_IP / similar
	SrcIMDS                  // cloud instance metadata (AWS/GCP)
	SrcK8sDownward           // k8s POD_IP / HOST_IP env
	SrcInterface             // net.Interfaces enumeration
	SrcSTUN                  // server-reflexive via STUN
	SrcTURN                  // allocated via TURN
	SrcReflection            // peer-observed (X-VL1-Observed-IP quorum)
	SrcICE                   // ICE candidate pair
	SrcUPnP                  // UPnP/NAT-PMP port mapping
)

// String returns a short stable name for the source.
func (s AddressSource) String() string {
	switch s {
	case SrcStatic:
		return "static"
	case SrcDNS:
		return "dns"
	case SrcPlatformEnv:
		return "env"
	case SrcIMDS:
		return "imds"
	case SrcK8sDownward:
		return "k8s"
	case SrcInterface:
		return "iface"
	case SrcSTUN:
		return "stun"
	case SrcTURN:
		return "turn"
	case SrcReflection:
		return "reflection"
	case SrcICE:
		return "ice"
	case SrcUPnP:
		return "upnp"
	default:
		return "unknown"
	}
}

// Capabilities is a bitfield describing address-level protocol features.
// Orthogonal to aether.Capabilities (which describes session-level features).
type Capabilities uint32

const (
	CapQUICv2       Capabilities = 1 << 0 // RFC 9369
	CapQUIC0RTT     Capabilities = 1 << 1 // session resumption
	CapMASQUE       Capabilities = 1 << 2 // HTTP/3 CONNECT-UDP tunnel
	CapMultipathQUIC Capabilities = 1 << 3
	CapNoiseIK      Capabilities = 1 << 4 // pre-shared identity
	CapPortMapping  Capabilities = 1 << 5 // published port maps differently internally
	CapZeroRTTSafe  Capabilities = 1 << 6 // server willing to process 0-RTT
	CapAnycast      Capabilities = 1 << 7
	CapDedicated    Capabilities = 1 << 8 // dedicated IP (not shared anycast pool)
	CapMTUProbed    Capabilities = 1 << 9
	CapRelay        Capabilities = 1 << 10 // this address is a TURN-allocated relay
	CapAgentNode    Capabilities = 1 << 11 // advertised by a desktop/laptop agent, not a fleet node
	CapEdgeAnchor   Capabilities = 1 << 12 // node also serves LAD anchor snapshots
)

// Has reports whether the bit is set.
func (c Capabilities) Has(bit Capabilities) bool { return c&bit != 0 }

// Set returns c with bit set.
func (c Capabilities) Set(bit Capabilities) Capabilities { return c | bit }

// TombstoneInfo marks a ReachRecord as a graceful-shutdown or demotion signal.
// When present, readers treat the node as offline and should not re-dial it.
type TombstoneInfo struct {
	Reason    string    `json:"r"`           // "shutdown" | "interface_down" | "rekey" | "demote"
	DeadUntil time.Time `json:"u,omitempty"` // absent = indefinite until a newer record arrives
}

// EncryptedSection carries a ChaCha20-Poly1305 sealed payload containing
// additional (private-scope) addresses that only same-org peers should see.
type EncryptedSection struct {
	OrgID      string `json:"org"`
	KeyID      string `json:"kid,omitempty"` // short identifier for the org symmetric key
	Nonce      []byte `json:"n"`             // 12-byte ChaCha20-Poly1305 nonce
	Ciphertext []byte `json:"ct"`
}

// Helpers

func u16str(v uint16) string {
	// stable, allocation-light port-to-string for digest input
	if v == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
