// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"testing"
	"time"
)

// A hook built from the zero config verifies every record: an unsigned record,
// a tampered one and one signed by a key that is not its NodeID's are all
// refused, and a record its own NodeID's key signed is applied.
func TestCacheHookZeroConfigRefusesUnverifiedRecords(t *testing.T) {
	ownerPub, ownerPriv := seededKey(20)
	_, otherPriv := seededKey(21)
	owner := meshNodeID(ownerPub)
	hook := NewCacheApplyHook(CacheHookConfig{})

	unsigned := ReachRecord{NodeID: owner, SchemaVersion: 1, HLC: HLC{Wall: 1}, Epoch: 5, UpdatedAt: time.Now()}
	if err := hook.Check(reachLedgerRecord(t, unsigned)); err == nil {
		t.Fatal("the zero config applied an unsigned record")
	}

	tampered := ReachRecord{NodeID: owner, SchemaVersion: 1, HLC: HLC{Wall: 2}, Epoch: 5, Region: "iad", UpdatedAt: time.Now()}
	Sign(&tampered, ownerPriv)
	tampered.Region = "syd"
	if err := hook.Check(reachLedgerRecord(t, tampered)); err == nil {
		t.Fatal("the zero config applied a record altered after signing")
	}

	foreign := ReachRecord{NodeID: owner, SchemaVersion: 1, HLC: HLC{Wall: 3}, Epoch: 5, UpdatedAt: time.Now()}
	Sign(&foreign, otherPriv)
	if err := hook.Check(reachLedgerRecord(t, foreign)); err == nil {
		t.Fatal("the zero config applied a record signed by a key that is not its NodeID's")
	}

	genuine := ReachRecord{NodeID: owner, SchemaVersion: 1, HLC: HLC{Wall: 4}, Epoch: 5, UpdatedAt: time.Now()}
	Sign(&genuine, ownerPriv)
	if err := hook.Check(reachLedgerRecord(t, genuine)); err != nil {
		t.Fatalf("the zero config refused a record its own NodeID's key signed: %v", err)
	}
}

// The zero config verifies deltas the same way.
func TestCacheHookZeroConfigRefusesAnUnsignedDelta(t *testing.T) {
	ownerPub, ownerPriv := seededKey(22)
	owner := meshNodeID(ownerPub)
	hook := NewCacheApplyHook(CacheHookConfig{})

	unsigned := DeltaRecord{NodeID: owner, SchemaVersion: SchemaVersion | DeltaSchemaFlag, HLC: HLC{Wall: 1}, Epoch: 5, BaseDigest: "b"}
	if err := hook.Check(deltaLedgerRecord(t, unsigned)); err == nil {
		t.Fatal("the zero config applied an unsigned delta")
	}

	genuine := DeltaRecord{NodeID: owner, SchemaVersion: SchemaVersion | DeltaSchemaFlag, HLC: HLC{Wall: 2}, Epoch: 5, BaseDigest: "b"}
	signDelta(&genuine, ownerPriv)
	if err := hook.Check(deltaLedgerRecord(t, genuine)); err != nil {
		t.Fatalf("the zero config refused a delta its own NodeID's key signed: %v", err)
	}
}
