// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"encoding/json"
	"testing"
	"time"

	lad "github.com/bbmumford/ledger"
)

func reachLedgerRecord(t *testing.T, rec ReachRecord) lad.Record {
	t.Helper()
	body, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return lad.Record{Topic: lad.TopicReach, NodeID: rec.NodeID, Body: body}
}

func deltaLedgerRecord(t *testing.T, d DeltaRecord) lad.Record {
	t.Helper()
	body, err := MarshalDelta(&d)
	if err != nil {
		t.Fatal(err)
	}
	return lad.Record{Topic: lad.TopicReach, NodeID: d.NodeID, Body: body}
}

// Records that name the victim's NodeID but are signed by another key are
// refused, and they must not spend the victim's rate budget: the victim's own
// record, arriving after as many forgeries as the budget holds, is applied.
func TestCacheHookForgedRecordsDoNotSpendTheVictimsRateBudget(t *testing.T) {
	victimPub, victimPriv := seededKey(10)
	_, attackerPriv := seededKey(11)
	victim := meshNodeID(victimPub)
	hook := NewCacheApplyHook(CacheHookConfig{RequireValidSig: true, RatePerMin: 3})

	for i := 0; i < 3; i++ {
		forged := ReachRecord{NodeID: victim, SchemaVersion: 1, HLC: HLC{Wall: int64(100 + i)}, Epoch: 9, UpdatedAt: time.Now()}
		Sign(&forged, attackerPriv)
		if err := hook.Check(reachLedgerRecord(t, forged)); err == nil {
			t.Fatalf("forged record %d naming the victim was applied", i)
		}
	}

	genuine := ReachRecord{NodeID: victim, SchemaVersion: 1, HLC: HLC{Wall: 1}, Epoch: 5, UpdatedAt: time.Now()}
	Sign(&genuine, victimPriv)
	if err := hook.Check(reachLedgerRecord(t, genuine)); err != nil {
		t.Fatalf("the victim's own record after 3 forgeries: %v", err)
	}
}

// The same holds for deltas: forged deltas naming the victim leave its budget
// whole.
func TestCacheHookForgedDeltasDoNotSpendTheVictimsRateBudget(t *testing.T) {
	victimPub, victimPriv := seededKey(12)
	_, attackerPriv := seededKey(13)
	victim := meshNodeID(victimPub)
	hook := NewCacheApplyHook(CacheHookConfig{RequireValidSig: true, RatePerMin: 2})

	for i := 0; i < 2; i++ {
		forged := DeltaRecord{NodeID: victim, SchemaVersion: SchemaVersion | DeltaSchemaFlag, HLC: HLC{Wall: int64(100 + i)}, Epoch: 9, BaseDigest: "b"}
		signDelta(&forged, attackerPriv)
		if err := hook.Check(deltaLedgerRecord(t, forged)); err == nil {
			t.Fatalf("forged delta %d naming the victim was applied", i)
		}
	}

	genuine := DeltaRecord{NodeID: victim, SchemaVersion: SchemaVersion | DeltaSchemaFlag, HLC: HLC{Wall: 1}, Epoch: 5, BaseDigest: "b"}
	signDelta(&genuine, victimPriv)
	if err := hook.Check(deltaLedgerRecord(t, genuine)); err != nil {
		t.Fatalf("the victim's own delta after 2 forgeries: %v", err)
	}
}

// With signature checks switched off, an unverified record is still applied,
// but its replay state is kept apart from every verified identity: a forged
// record naming the victim with a far-future Epoch does not make the victim's
// own later record read as a replay.
func TestCacheHookUnverifiedRecordsDoNotAdvanceAVerifiedNodesReplayState(t *testing.T) {
	victimPub, victimPriv := seededKey(14)
	_, attackerPriv := seededKey(15)
	victim := meshNodeID(victimPub)
	hook := NewCacheApplyHook(CacheHookConfig{RequireValidSig: false})

	forged := ReachRecord{NodeID: victim, SchemaVersion: 1, HLC: HLC{Wall: 1 << 50}, Epoch: 1 << 40, UpdatedAt: time.Now()}
	Sign(&forged, attackerPriv)
	if err := hook.Check(reachLedgerRecord(t, forged)); err != nil {
		t.Fatalf("with signature checks off an unverified record is applied: %v", err)
	}

	genuine := ReachRecord{NodeID: victim, SchemaVersion: 1, HLC: HLC{Wall: 1}, Epoch: 5, UpdatedAt: time.Now()}
	Sign(&genuine, victimPriv)
	if err := hook.Check(reachLedgerRecord(t, genuine)); err != nil {
		t.Fatalf("the victim's own record after a forged far-future one: %v", err)
	}

	replayed := genuine
	if err := hook.Check(reachLedgerRecord(t, replayed)); err == nil {
		t.Fatal("a replay of the victim's own record was applied")
	}
}
