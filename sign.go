// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

package reach

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"sort"
	"strconv"

	"github.com/ORBTR/aether"
	lad "github.com/bbmumford/ledger"
)

// ErrSignatureInvalid is returned by Verify when the signature does not match.
var ErrSignatureInvalid = errors.New("reach: invalid signature")

// ErrUnsignedRecord is returned when Verify is called on a record with no
// signature or public key.
var ErrUnsignedRecord = errors.New("reach: record is unsigned")

// ErrNodeIDMismatch is returned by Verify and VerifyDelta when the record's
// NodeID is not the NodeID its signing key derives, so the record claims to
// speak for a node whose key did not sign it.
var ErrNodeIDMismatch = errors.New("reach: record NodeID does not derive from its signing key")

// Sign computes a canonical digest over the semantically-meaningful fields
// of the record and signs it with the given Ed25519 private key. Sets both
// PubKey and Signature on rec.
//
// The canonical form includes NodeID, Partition, SchemaVersion, HLC, Epoch,
// the sorted AddressSet digest, any Tombstone, and any EncryptedGroup fields.
// It intentionally excludes Seq, UpdatedAt, and ExpiresAt — those are ledger
// envelope concerns that can be refreshed without changing the record's
// semantic identity.
func Sign(rec *ReachRecord, key ed25519.PrivateKey) {
	content := canonicalSignatureBytes(rec)
	rec.PubKey = key.Public().(ed25519.PublicKey)
	rec.Signature = ed25519.Sign(key, content)
}

// Verify checks the Ed25519 signature on a ReachRecord and that the record's
// NodeID is the NodeID its PubKey derives.
// Returns nil on success, ErrUnsignedRecord if the record has no signature,
// ErrSignatureInvalid if the signature does not match, or ErrNodeIDMismatch
// if the NodeID is not the signing key's.
func Verify(rec ReachRecord) error {
	_, err := verifiedNodeID(&rec)
	return err
}

// verifiedNodeID runs Verify's checks on rec and returns the NodeID its key
// proves, the identity CacheApplyHook charges rate and replay state to.
func verifiedNodeID(rec *ReachRecord) (string, error) {
	if len(rec.PubKey) == 0 || len(rec.Signature) == 0 {
		return "", ErrUnsignedRecord
	}
	if len(rec.PubKey) != ed25519.PublicKeySize {
		return "", ErrSignatureInvalid
	}
	if len(rec.Signature) != ed25519.SignatureSize {
		return "", ErrSignatureInvalid
	}
	id, err := keyNodeID(rec.NodeID, rec.PubKey)
	if err != nil {
		return "", err
	}
	content := canonicalSignatureBytes(rec)
	if !ed25519.Verify(rec.PubKey, content, rec.Signature) {
		return "", ErrSignatureInvalid
	}
	return id, nil
}

// keyNodeID returns the NodeID pub derives under aether.NewNodeID, the scheme
// mesh NodeIDs are made by, or ErrNodeIDMismatch when claimed is not exactly
// that NodeID. The comparison is exact because the signed bytes carry the
// NodeID as the publisher wrote it, and the publisher writes its Config.NodeID
// unchanged. It runs before the signature check, so a record naming another
// node's NodeID is refused without an Ed25519 verification.
func keyNodeID(claimed string, pub []byte) (string, error) {
	derived, err := aether.NewNodeID(ed25519.PublicKey(pub))
	if err != nil {
		return "", ErrSignatureInvalid
	}
	if string(derived) != claimed {
		return "", ErrNodeIDMismatch
	}
	return string(derived), nil
}

// canonicalSignatureBytes produces the stable byte sequence that is signed.
// Field order is fixed. Every field is length-prefixed (big-endian uint32)
// so malleability is structurally impossible.
func canonicalSignatureBytes(rec *ReachRecord) []byte {
	var buf []byte
	buf = appendLenPrefixed(buf, []byte("reach:v1"))
	buf = appendLenPrefixed(buf, []byte(rec.NodeID))
	buf = appendLenPrefixed(buf, []byte(rec.Partition))

	// SchemaVersion
	var v [2]byte
	binary.BigEndian.PutUint16(v[:], rec.SchemaVersion)
	buf = appendLenPrefixed(buf, v[:])

	// HLC
	buf = appendLenPrefixed(buf, []byte(rec.HLC.String()))

	// Epoch
	var ep [8]byte
	binary.BigEndian.PutUint64(ep[:], rec.Epoch)
	buf = appendLenPrefixed(buf, ep[:])

	// Region
	buf = appendLenPrefixed(buf, []byte(rec.Region))

	// Identity metadata — consumer-defined KV, signed so peers can't forge
	// on behalf of this NodeID. Keys sorted + each (k, v) length-prefixed
	// independently so the map's iteration order doesn't affect the digest.
	for _, k := range rec.Metadata.sortedKeys() {
		buf = appendLenPrefixed(buf, []byte(k))
		buf = appendLenPrefixed(buf, []byte(rec.Metadata[k]))
	}

	// AddressSet digest (stable hash of enriched addresses)
	buf = appendLenPrefixed(buf, []byte(Digest(rec.AddressSet)))

	// Flat Addresses (legacy) — hashed too so a publisher can't desync them
	buf = appendLenPrefixed(buf, []byte(flatAddrDigest(rec.Addresses)))

	// Tombstone
	if rec.Tombstone != nil {
		buf = appendLenPrefixed(buf, []byte(rec.Tombstone.Reason))
		if !rec.Tombstone.DeadUntil.IsZero() {
			var du [8]byte
			binary.BigEndian.PutUint64(du[:], uint64(rec.Tombstone.DeadUntil.UnixMicro()))
			buf = appendLenPrefixed(buf, du[:])
		} else {
			buf = appendLenPrefixed(buf, nil)
		}
	} else {
		buf = appendLenPrefixed(buf, nil)
		buf = appendLenPrefixed(buf, nil)
	}

	// Encrypted section
	if rec.EncryptedGroup != nil {
		buf = appendLenPrefixed(buf, []byte(rec.EncryptedGroup.GroupID))
		buf = appendLenPrefixed(buf, []byte(rec.EncryptedGroup.KeyID))
		buf = appendLenPrefixed(buf, rec.EncryptedGroup.Nonce)
		buf = appendLenPrefixed(buf, rec.EncryptedGroup.Ciphertext)
	} else {
		buf = appendLenPrefixed(buf, nil)
		buf = appendLenPrefixed(buf, nil)
		buf = appendLenPrefixed(buf, nil)
		buf = appendLenPrefixed(buf, nil)
	}

	// ICE candidates (sorted)
	cands := append([]string(nil), rec.ICECandidates...)
	sort.Strings(cands)
	for _, c := range cands {
		buf = appendLenPrefixed(buf, []byte(c))
	}
	return buf
}

// flatAddrDigest produces a stable hash-input string for legacy ReachAddress
// entries. Used to bind the legacy Addresses slice into the signature so a
// downstream node can't re-serialise a record with different legacy content.
func flatAddrDigest(addrs []lad.ReachAddress) string {
	keys := make([]string, 0, len(addrs))
	for _, a := range addrs {
		keys = append(keys, a.Proto+"|"+a.Host+"|"+strconv.Itoa(a.Port)+"|"+a.Scope)
	}
	sort.Strings(keys)
	var out []byte
	for _, k := range keys {
		out = append(out, k...)
		out = append(out, 0)
	}
	return string(out)
}

func appendLenPrefixed(dst, data []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(data)))
	dst = append(dst, l[:]...)
	dst = append(dst, data...)
	return dst
}

// signDelta signs a DeltaRecord with the given Ed25519 key. The canonical
// form covers all fields a reader would use to decide accept/reject so a
// delta can't be replayed, re-parented, or truncated.
func signDelta(d *DeltaRecord, key ed25519.PrivateKey) {
	content := canonicalDeltaBytes(d)
	d.PubKey = key.Public().(ed25519.PublicKey)
	d.Signature = ed25519.Sign(key, content)
}

// VerifyDelta checks the Ed25519 signature on a DeltaRecord and that its
// NodeID is the signing key's. Same errors as Verify.
func VerifyDelta(d DeltaRecord) error {
	_, err := verifiedDeltaNodeID(&d)
	return err
}

// verifiedDeltaNodeID runs VerifyDelta's checks on d and returns the NodeID
// its key proves.
func verifiedDeltaNodeID(d *DeltaRecord) (string, error) {
	if len(d.PubKey) == 0 || len(d.Signature) == 0 {
		return "", ErrUnsignedRecord
	}
	if len(d.PubKey) != ed25519.PublicKeySize || len(d.Signature) != ed25519.SignatureSize {
		return "", ErrSignatureInvalid
	}
	id, err := keyNodeID(d.NodeID, d.PubKey)
	if err != nil {
		return "", err
	}
	content := canonicalDeltaBytes(d)
	if !ed25519.Verify(d.PubKey, content, d.Signature) {
		return "", ErrSignatureInvalid
	}
	return id, nil
}

func canonicalDeltaBytes(d *DeltaRecord) []byte {
	var buf []byte
	buf = appendLenPrefixed(buf, []byte("reach-delta:v1"))
	buf = appendLenPrefixed(buf, []byte(d.NodeID))
	buf = appendLenPrefixed(buf, []byte(d.Partition))

	var v [2]byte
	binary.BigEndian.PutUint16(v[:], d.SchemaVersion)
	buf = appendLenPrefixed(buf, v[:])

	buf = appendLenPrefixed(buf, []byte(d.HLC.String()))

	var ep [8]byte
	binary.BigEndian.PutUint64(ep[:], d.Epoch)
	buf = appendLenPrefixed(buf, ep[:])

	buf = appendLenPrefixed(buf, []byte(d.BaseDigest))

	// Ops must hash in a deterministic order — already sorted by AddrKey
	// when computeDelta produced them, but defend against caller mutation.
	ops := make([]string, len(d.Ops))
	for i, op := range d.Ops {
		line := string(op.Op) + "|" + op.AddrKey
		if op.Addr != nil {
			line += "|" + op.Addr.Key() + "|" + strconv.FormatUint(uint64(op.Addr.Confidence), 10)
		}
		ops[i] = line
	}
	sort.Strings(ops)
	for _, line := range ops {
		buf = appendLenPrefixed(buf, []byte(line))
	}
	return buf
}
