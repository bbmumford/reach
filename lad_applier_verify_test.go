// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

package reach

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// signedBaseAndDelta is a signed full snapshot of the node a key signs for and a
// delta against it adding one address, unsigned.
func signedBaseAndDelta(t *testing.T, authorPub ed25519.PublicKey, authorPriv ed25519.PrivateKey) ([]byte, DeltaRecord) {
	t.Helper()
	addrs := []Address{{Host: "1.1.1.1", Port: 9000, Proto: "udp", Scope: ScopePublic, Source: SrcSTUN, ExpiresAt: time.Now().Add(time.Hour)}}
	base := ReachRecord{NodeID: meshNodeID(authorPub), Partition: "p1", AddressSet: addrs, SchemaVersion: SchemaVersion}
	Sign(&base, authorPriv)
	body, err := json.Marshal(&base)
	if err != nil {
		t.Fatal(err)
	}
	evil := Address{Host: "6.6.6.6", Port: 9000, Proto: "udp", Scope: ScopePublic, Source: SrcSTUN, ExpiresAt: time.Now().Add(time.Hour)}
	return body, DeltaRecord{
		NodeID:        base.NodeID,
		Partition:     "p1",
		SchemaVersion: SchemaVersion | DeltaSchemaFlag,
		BaseDigest:    Digest(addrs),
		UpdatedAt:     time.Now(),
		Ops:           []DeltaEntry{{Op: DeltaAdd, AddrKey: evil.Key(), Addr: &evil}},
	}
}

func applyDelta(t *testing.T, base []byte, d DeltaRecord) error {
	t.Helper()
	body, err := MarshalDelta(&d)
	if err != nil {
		t.Fatal(err)
	}
	_, err = LadCacheDeltaApplier(base, body)
	return err
}

// The delta applier changes a node's addresses only with a delta that node
// signed: the base digest it names is public, so an unsigned delta, one signed
// by another key under the node's NodeID, and another node's own delta are all
// refused, and the node's own is applied.
func TestTheDeltaApplierAppliesOnlyTheBaseNodesOwnDelta(t *testing.T) {
	authorPub, authorPriv := seededKey(0x11)
	attackerPub, attackerPriv := seededKey(0x22)
	base, d := signedBaseAndDelta(t, authorPub, authorPriv)

	if err := applyDelta(t, base, d); !errors.Is(err, ErrUnsignedRecord) {
		t.Errorf("an unsigned delta: err = %v, want ErrUnsignedRecord", err)
	}

	forged := d
	signDelta(&forged, attackerPriv)
	if err := applyDelta(t, base, forged); !errors.Is(err, ErrNodeIDMismatch) {
		t.Errorf("a delta signed by another key under the author's NodeID: err = %v, want ErrNodeIDMismatch", err)
	}

	own := d
	own.NodeID = meshNodeID(attackerPub)
	signDelta(&own, attackerPriv)
	if err := applyDelta(t, base, own); !errors.Is(err, ErrDeltaNodeMismatch) {
		t.Errorf("another node's own delta: err = %v, want ErrDeltaNodeMismatch", err)
	}

	// A base the cache holds under one node with another node's key (a body no
	// signature check vetted) takes no delta of the key's node either.
	var mixed ReachRecord
	if err := json.Unmarshal(base, &mixed); err != nil {
		t.Fatal(err)
	}
	mixed.PubKey = attackerPub
	mixedBody, _ := json.Marshal(&mixed)
	if err := applyDelta(t, mixedBody, own); !errors.Is(err, ErrDeltaNodeMismatch) {
		t.Errorf("a delta onto a base of another NodeID carrying its key: err = %v, want ErrDeltaNodeMismatch", err)
	}

	otherPartition := d
	otherPartition.Partition = "p2"
	signDelta(&otherPartition, authorPriv)
	if err := applyDelta(t, base, otherPartition); !errors.Is(err, ErrDeltaNodeMismatch) {
		t.Errorf("the author's delta in another partition: err = %v, want ErrDeltaNodeMismatch", err)
	}

	genuine := d
	signDelta(&genuine, authorPriv)
	if err := applyDelta(t, base, genuine); err != nil {
		t.Errorf("the author's own delta was refused: %v", err)
	}
}
