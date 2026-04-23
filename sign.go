// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"sort"
	"strconv"

	lad "github.com/bbmumford/ledger"
)

// ErrSignatureInvalid is returned by Verify when the signature does not match.
var ErrSignatureInvalid = errors.New("reach: invalid signature")

// ErrUnsignedRecord is returned when Verify is called on a record with no
// signature or public key.
var ErrUnsignedRecord = errors.New("reach: record is unsigned")

// Sign computes a canonical digest over the semantically-meaningful fields
// of the record and signs it with the given Ed25519 private key. Sets both
// PubKey and Signature on rec.
//
// The canonical form includes NodeID, TenantID, SchemaVersion, HLC, Epoch,
// the sorted AddressSet digest, any Tombstone, and any EncryptedOrg fields.
// It intentionally excludes Seq, UpdatedAt, and ExpiresAt — those are ledger
// envelope concerns that can be refreshed without changing the record's
// semantic identity.
func Sign(rec *ReachRecord, key ed25519.PrivateKey) {
	content := canonicalSignatureBytes(rec)
	rec.PubKey = key.Public().(ed25519.PublicKey)
	rec.Signature = ed25519.Sign(key, content)
}

// Verify checks the Ed25519 signature on a ReachRecord.
// Returns nil on success, ErrUnsignedRecord if the record has no signature,
// or ErrSignatureInvalid if the signature does not match.
func Verify(rec ReachRecord) error {
	if len(rec.PubKey) == 0 || len(rec.Signature) == 0 {
		return ErrUnsignedRecord
	}
	if len(rec.PubKey) != ed25519.PublicKeySize {
		return ErrSignatureInvalid
	}
	if len(rec.Signature) != ed25519.SignatureSize {
		return ErrSignatureInvalid
	}
	content := canonicalSignatureBytes(&rec)
	if !ed25519.Verify(rec.PubKey, content, rec.Signature) {
		return ErrSignatureInvalid
	}
	return nil
}

// canonicalSignatureBytes produces the stable byte sequence that is signed.
// Field order is fixed. Every field is length-prefixed (big-endian uint32)
// so malleability is structurally impossible.
func canonicalSignatureBytes(rec *ReachRecord) []byte {
	var buf []byte
	buf = appendLenPrefixed(buf, []byte("reach:v1"))
	buf = appendLenPrefixed(buf, []byte(rec.NodeID))
	buf = appendLenPrefixed(buf, []byte(rec.TenantID))

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
	if rec.EncryptedOrg != nil {
		buf = appendLenPrefixed(buf, []byte(rec.EncryptedOrg.OrgID))
		buf = appendLenPrefixed(buf, []byte(rec.EncryptedOrg.KeyID))
		buf = appendLenPrefixed(buf, rec.EncryptedOrg.Nonce)
		buf = appendLenPrefixed(buf, rec.EncryptedOrg.Ciphertext)
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
