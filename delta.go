// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"encoding/json"
	"sort"
	"time"
)

// DeltaOp is the change kind carried in a Delta record.
type DeltaOp string

const (
	DeltaAdd    DeltaOp = "add"
	DeltaRemove DeltaOp = "remove"
	DeltaUpdate DeltaOp = "update"
)

// DeltaEntry describes one change to an address set.
type DeltaEntry struct {
	Op      DeltaOp `json:"op"`
	AddrKey string  `json:"k"`      // Address.Key() of the target
	Addr    *Address `json:"a,omitempty"` // full Address for add/update; nil for remove
}

// DeltaRecord is a compact incremental ReachRecord that applies to a specific
// prior snapshot (identified by BaseDigest). Readers that hold BaseDigest
// apply the Ops in order; readers that don't must request a full snapshot.
//
// Wire format: a Delta is emitted as a normal ledger.Record with Topic=
// TopicReach, but the JSON body unmarshals to DeltaRecord instead of
// ReachRecord. The SchemaVersion field is the discriminator — SchemaVersion
// has bit 15 set (0x8000 | baseVersion) to flag "this is a delta".
type DeltaRecord struct {
	NodeID        string        `json:"node_id"`
	TenantID      string        `json:"tenant,omitempty"`
	SchemaVersion uint16        `json:"v"`
	HLC           HLC           `json:"hlc"`
	Epoch         uint64        `json:"epoch"`
	BaseDigest    string        `json:"base"` // digest of the AddressSet this delta applies to
	Ops           []DeltaEntry  `json:"ops"`
	UpdatedAt     time.Time     `json:"ts"`
	ExpiresAt     time.Time     `json:"exp"`
	PubKey        []byte        `json:"pk,omitempty"`
	Signature     []byte        `json:"sig,omitempty"`
}

// DeltaSchemaFlag marks a record body as a DeltaRecord (vs ReachRecord).
const DeltaSchemaFlag uint16 = 0x8000

// IsDelta reports whether a raw SchemaVersion value denotes a DeltaRecord.
func IsDelta(v uint16) bool { return v&DeltaSchemaFlag != 0 }

// computeDelta returns the ops that transform prev→next, or nil if the sets
// are identical. Keys match by Address.Key() — address identity is
// (proto, host, port, scope, source).
func computeDelta(prev, next []Address) []DeltaEntry {
	prevMap := make(map[string]Address, len(prev))
	for _, a := range prev {
		prevMap[a.Key()] = a
	}
	nextMap := make(map[string]Address, len(next))
	for _, a := range next {
		nextMap[a.Key()] = a
	}
	var ops []DeltaEntry
	// Adds and updates.
	for k, n := range nextMap {
		p, existed := prevMap[k]
		if !existed {
			nn := n
			ops = append(ops, DeltaEntry{Op: DeltaAdd, AddrKey: k, Addr: &nn})
			continue
		}
		if !addressStructurallyEqual(p, n) {
			nn := n
			ops = append(ops, DeltaEntry{Op: DeltaUpdate, AddrKey: k, Addr: &nn})
		}
	}
	// Removes.
	for k := range prevMap {
		if _, ok := nextMap[k]; !ok {
			ops = append(ops, DeltaEntry{Op: DeltaRemove, AddrKey: k})
		}
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].AddrKey < ops[j].AddrKey })
	return ops
}

// addressStructurallyEqual compares the fields a delta needs to care about —
// volatile health fields (RTT, LastVerified) are deliberately excluded so a
// delta isn't emitted for every probe cycle.
func addressStructurallyEqual(a, b Address) bool {
	if a.Scope != b.Scope ||
		a.Family != b.Family ||
		a.Source != b.Source ||
		a.Confidence != b.Confidence ||
		a.Capabilities != b.Capabilities ||
		a.ExpiresAt != b.ExpiresAt {
		return false
	}
	if len(a.Tags) != len(b.Tags) {
		return false
	}
	for i := range a.Tags {
		if a.Tags[i] != b.Tags[i] {
			return false
		}
	}
	if len(a.RegionPriority) != len(b.RegionPriority) {
		return false
	}
	for k, v := range a.RegionPriority {
		if b.RegionPriority[k] != v {
			return false
		}
	}
	return true
}

// ApplyDelta applies a DeltaRecord on top of a base AddressSet, returning
// the new set. The base must have the digest matching delta.BaseDigest;
// otherwise an error is returned and the caller should fetch a fresh snapshot.
func ApplyDelta(base []Address, delta DeltaRecord) ([]Address, error) {
	if Digest(base) != delta.BaseDigest {
		return nil, ErrDeltaBaseMismatch
	}
	keyed := make(map[string]Address, len(base))
	for _, a := range base {
		keyed[a.Key()] = a
	}
	for _, op := range delta.Ops {
		switch op.Op {
		case DeltaAdd, DeltaUpdate:
			if op.Addr == nil {
				continue
			}
			keyed[op.AddrKey] = *op.Addr
		case DeltaRemove:
			delete(keyed, op.AddrKey)
		}
	}
	out := make([]Address, 0, len(keyed))
	for _, a := range keyed {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, nil
}

// ErrDeltaBaseMismatch signals the reader's base doesn't match delta.BaseDigest.
// Callers should then request a full snapshot via the consumer's RPC path.
var ErrDeltaBaseMismatch = deltaErr("reach: delta base digest mismatch — snapshot required")

type deltaErr string

func (e deltaErr) Error() string { return string(e) }

// MarshalDelta produces the JSON body the publisher writes to ledger.Record.Body.
// Writes SchemaVersion with DeltaSchemaFlag set so readers can discriminate.
func MarshalDelta(rec *DeltaRecord) ([]byte, error) {
	if rec.SchemaVersion == 0 {
		rec.SchemaVersion = SchemaVersion | DeltaSchemaFlag
	}
	return json.Marshal(rec)
}

// UnmarshalDelta decodes a body that ShouldBeDelta (per SchemaVersion).
func UnmarshalDelta(body []byte) (*DeltaRecord, error) {
	var d DeltaRecord
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, err
	}
	return &d, nil
}
