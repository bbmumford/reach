// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

package reach

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	lad "github.com/bbmumford/ledger"
)

// ErrDeltaNodeMismatch is returned by LadCacheDeltaApplier for a delta that is
// not by the node of the base it would change: its NodeID, partition or signing
// key differs from the base's.
var ErrDeltaNodeMismatch = errors.New("reach: delta applier: delta is not by its base's node")

// LadCacheDeltaApplier is a cache.ReachDeltaApplier that reconstructs a
// full, lad-cacheable ReachRecord body from the previous full-snapshot
// body and a delta body. Wire it up once at startup:
//
//	ladcache.SetReachDeltaApplier(reach.LadCacheDeltaApplier)
//
// Semantics:
//   - baseBody MUST be a full reach.ReachRecord (SchemaVersion without the
//     delta flag). The cache stores the last full-snapshot body per NodeID
//     and supplies it here.
//   - deltaBody MUST be a reach.DeltaRecord (SchemaVersion with the delta
//     flag).
//   - The returned body is a full reach.ReachRecord with:
//       * AddressSet   = ApplyDelta(base.AddressSet, delta.Ops)
//       * Addresses    = flat projection into lad.ReachAddress (what lad's
//                        ReachRecord sees)
//       * UpdatedAt    = delta.UpdatedAt (delta is the fresher moment)
//       * ExpiresAt    = delta.ExpiresAt
//       * HLC          = delta.HLC (delta is newer in causal time)
//       * Metadata     = base.Metadata (identity payload is immutable across
//                        address churn — it only changes on a new full
//                        snapshot)
//       * Region, NATType, NATObserved, Availability, LoadFactor, PubKey,
//         Epoch, SchemaVersion = base (unchanged)
//       * Signature    = CLEARED. The base's signature is over base.AddressSet;
//                        after applying ops the record no longer matches
//                        that signature. Delta carries its own signature
//                        over (node, base_digest, ops), which is preserved
//                        separately by the cache if needed for auditing.
//                        Consumers that need signature-level trust must
//                        check the base full snapshot, not the reconstructed
//                        derivative.
//
// A delta is applied only when it is its base's node's own: VerifyDelta must
// pass (a signature by the key its NodeID derives from), and its NodeID,
// partition and key must equal the base's, or ErrDeltaNodeMismatch. The base
// digest is public, so without these any key could re-point another node's
// addresses with a delta naming that digest.
//
// If delta.BaseDigest doesn't match Digest(base.AddressSet), ApplyDelta
// returns ErrDeltaBaseMismatch and this function returns the error so the
// cache can skip the apply (the next full snapshot will resync).
func LadCacheDeltaApplier(baseBody, deltaBody []byte) ([]byte, error) {
	if len(baseBody) == 0 {
		return nil, errors.New("reach: delta applier: empty base body")
	}
	if len(deltaBody) == 0 {
		return nil, errors.New("reach: delta applier: empty delta body")
	}

	var base ReachRecord
	if err := json.Unmarshal(baseBody, &base); err != nil {
		return nil, fmt.Errorf("reach: decode base ReachRecord: %w", err)
	}
	if IsDelta(base.SchemaVersion) {
		return nil, errors.New("reach: delta applier: base is itself a delta")
	}

	deltaPtr, err := UnmarshalDelta(deltaBody)
	if err != nil {
		return nil, fmt.Errorf("reach: decode delta: %w", err)
	}
	delta := *deltaPtr
	if err := VerifyDelta(delta); err != nil {
		return nil, fmt.Errorf("reach: delta applier: %w", err)
	}
	if delta.NodeID != base.NodeID || delta.Partition != base.Partition || !bytes.Equal(delta.PubKey, base.PubKey) {
		return nil, ErrDeltaNodeMismatch
	}

	// Skip mismatched deltas — ApplyDelta already enforces, but call it
	// out explicitly for the caller.
	newSet, err := ApplyDelta(base.AddressSet, delta)
	if err != nil {
		return nil, err
	}

	// Rebuild: delta's newer causal state + base's identity payload.
	rebuilt := base
	rebuilt.AddressSet = newSet
	rebuilt.Addresses = flattenToLadAddresses(newSet)
	rebuilt.UpdatedAt = delta.UpdatedAt
	rebuilt.ExpiresAt = delta.ExpiresAt
	rebuilt.HLC = delta.HLC
	rebuilt.Signature = nil // base signature no longer covers new address set

	return json.Marshal(&rebuilt)
}

// flattenToLadAddresses projects a reach.Address slice into the flat
// lad.ReachAddress shape that the ledger cache's ReachRecord uses for
// topology/peer-dial views. Mirrors the projection in Publisher.buildRecord.
func flattenToLadAddresses(set []Address) []lad.ReachAddress {
	out := make([]lad.ReachAddress, 0, len(set))
	for _, a := range set {
		out = append(out, lad.ReachAddress{
			Host:  a.Host,
			Port:  int(a.Port),
			Proto: a.Proto,
			Scope: string(a.Scope),
		})
	}
	return out
}
