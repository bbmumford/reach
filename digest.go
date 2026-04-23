// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
)

// Digest produces a stable SHA-256 fingerprint over an address set.
// The fingerprint changes iff the set of (proto, host, port, scope, source,
// capabilities, region-priority) changes — volatile fields like LastVerified,
// RTTMicros, and FirstSeen are intentionally excluded so the publisher can
// skip publishing when no structural change has occurred.
//
// Two different publishers that derive the same addresses will produce the
// same digest, so this is also usable as the freshness-gossip identifier.
func Digest(addrs []Address) string {
	// Copy keys and sort so order is deterministic regardless of discoverer order.
	lines := make([]string, len(addrs))
	for i, a := range addrs {
		lines[i] = digestLine(a)
	}
	sort.Strings(lines)

	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{0})
	}
	var sum [32]byte
	sum32 := h.Sum(nil)
	copy(sum[:], sum32)
	return hex.EncodeToString(sum[:])
}

func digestLine(a Address) string {
	// Deterministic form: proto|host|port|scope|source|family|cap|rp
	var rp string
	if len(a.RegionPriority) > 0 {
		keys := make([]string, 0, len(a.RegionPriority))
		for k := range a.RegionPriority {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			rp += k + ":" + strconv.Itoa(int(a.RegionPriority[k])) + ","
		}
	}
	return a.Proto + "|" + a.Host + "|" + strconv.Itoa(int(a.Port)) +
		"|" + string(a.Scope) + "|" + a.Source.String() +
		"|" + string(a.Family) +
		"|" + strconv.FormatUint(uint64(a.Capabilities), 16) +
		"|" + rp
}

// DigestShort returns the first 16 hex chars of Digest — enough for a
// freshness-gossip collision space while keeping the payload tiny.
func DigestShort(addrs []Address) string {
	full := Digest(addrs)
	if len(full) > 16 {
		return full[:16]
	}
	return full
}
