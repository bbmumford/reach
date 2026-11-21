// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"strings"
	"testing"
	"time"
)

// meshNodeID is the aether NodeID of pub, computed here from its definition
// (vl1_ + lowercase unpadded base32 of the first 16 bytes of SHA-256(pub)) so
// the test does not read the derivation it checks.
func meshNodeID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "vl1_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:16]))
}

func seededKey(b byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = b
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

// A record that names the victim's NodeID but is signed by another key has a
// valid signature over its own bytes; Verify must still refuse it, because the
// NodeID is not the one that key derives.
func TestVerifyRefusesARecordSignedByAKeyThatIsNotItsNodeIDs(t *testing.T) {
	victimPub, victimPriv := seededKey(1)
	_, attackerPriv := seededKey(2)
	victim := meshNodeID(victimPub)

	genuine := ReachRecord{NodeID: victim, SchemaVersion: 1, HLC: HLC{Wall: 1}, Epoch: 5, UpdatedAt: time.Now()}
	Sign(&genuine, victimPriv)
	if err := Verify(genuine); err != nil {
		t.Fatalf("a record signed by its own NodeID's key must verify: %v", err)
	}

	forged := ReachRecord{NodeID: victim, SchemaVersion: 1, HLC: HLC{Wall: 2}, Epoch: 1 << 40, UpdatedAt: time.Now()}
	Sign(&forged, attackerPriv)
	if err := Verify(forged); !errors.Is(err, ErrNodeIDMismatch) {
		t.Fatalf("a record naming %s signed by another key: Verify = %v, want ErrNodeIDMismatch", victim, err)
	}
}

func TestVerifyDeltaRefusesADeltaSignedByAKeyThatIsNotItsNodeIDs(t *testing.T) {
	victimPub, victimPriv := seededKey(3)
	_, attackerPriv := seededKey(4)
	victim := meshNodeID(victimPub)

	genuine := DeltaRecord{NodeID: victim, SchemaVersion: SchemaVersion | DeltaSchemaFlag, HLC: HLC{Wall: 1}, Epoch: 5, BaseDigest: "b"}
	signDelta(&genuine, victimPriv)
	if err := VerifyDelta(genuine); err != nil {
		t.Fatalf("a delta signed by its own NodeID's key must verify: %v", err)
	}

	forged := DeltaRecord{NodeID: victim, SchemaVersion: SchemaVersion | DeltaSchemaFlag, HLC: HLC{Wall: 2}, Epoch: 1 << 40, BaseDigest: "b"}
	signDelta(&forged, attackerPriv)
	if err := VerifyDelta(forged); !errors.Is(err, ErrNodeIDMismatch) {
		t.Fatalf("a delta naming %s signed by another key: VerifyDelta = %v, want ErrNodeIDMismatch", victim, err)
	}
}
