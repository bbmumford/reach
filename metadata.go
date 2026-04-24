// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import "sort"

// Metadata is the identity-plane payload carried by every ReachRecord.
//
// The reach package has ZERO knowledge of what consumers put in here —
// it just signs and carries whatever's in the map. Each consumer picks
// its own key conventions:
//
//   ORBTR agent:
//     {"hostname":      "alice-laptop",
//      "device_id":     "dev-abc123",
//      "os":            "darwin",
//      "os_version":    "14.7.2",
//      "app_version":   "v0.0.6",
//      "tenant_id":     "acme-corp"}
//
//   HSTLES mesh fleet node:
//     {"service_name":  "devices.orbtr.io",
//      "roles":         "anchor,platform.tenant",
//      "region":        "iad",
//      "fly_machine":   "1857b3d2c45d68",
//      "fly_app":       "devices-orbtr-io"}
//
//   Third-party consumer:
//     {"anything":      "they want"}
//
// Metadata flows into the ledger cache verbatim: the cache derives
// lad.MemberRecord views on read (see DirectoryCache.Members) from each
// reach record's Metadata map, keyed by NodeID. Consumers that name their
// keys with MemberRecord conventions (service_name / region / roles) get
// the right behavior for free — no separate Member publish path, no TTL
// drift between Reach and Member.
//
// Metadata is covered by the ReachRecord canonical signature — a peer
// cannot forge metadata on behalf of another NodeID.
type Metadata map[string]string

// Clone returns a deep copy so callers can mutate safely.
func (m Metadata) Clone() Metadata {
	if m == nil {
		return nil
	}
	out := make(Metadata, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// sortedKeys returns the metadata keys in deterministic order. Used by the
// canonical signature so a peer that re-marshals the record cannot produce a
// different signature payload by reordering map iteration.
func (m Metadata) sortedKeys() []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Get is a nil-safe accessor. Returns ("", false) when m is nil or the key
// is absent.
func (m Metadata) Get(key string) (string, bool) {
	if m == nil {
		return "", false
	}
	v, ok := m[key]
	return v, ok
}

// ReachRecord accessor helpers — nil-safe.

// Meta returns the metadata value for a key, handling a nil metadata map.
func (r ReachRecord) Meta(key string) (string, bool) {
	return r.Metadata.Get(key)
}
