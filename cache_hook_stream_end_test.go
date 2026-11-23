// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

package reach

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	lad "github.com/bbmumford/ledger"
	"github.com/bbmumford/ledger/storage"
)

// drainUntilClosed receives from out until it closes, failing the test when
// it stays open past five seconds, and reports how many records arrived.
func drainUntilClosed(t *testing.T, out <-chan lad.Record) int {
	t.Helper()
	timeout := time.After(5 * time.Second)
	n := 0
	for {
		select {
		case _, open := <-out:
			if !open {
				return n
			}
			n++
		case <-timeout:
			t.Fatal("the stream stayed open")
		}
	}
}

// A ledger that a CacheApplyHook wraps is still the ledger a consumer streams
// from (loom's gossip.Synchronizer.Sync reads the end through
// lad.EndReportingLedger and stops only at ErrLedgerClosed), so the wrapper
// must report the inner ledger's stream end, or the consumer restarts on the
// ledger's close until its own context ends.
func TestHookedLedgerReportsTheInnerLedgersClose(t *testing.T) {
	inner := storage.NewMemoryLedger(storage.MemoryLedgerConfig{})
	wrapped := NewCacheApplyHook(CacheHookConfig{}).Wrap(inner)
	er, ok := wrapped.(lad.EndReportingLedger)
	if !ok {
		t.Fatal("the hooked ledger does not report why its streams end")
	}
	out, end, err := er.StreamWithEnd(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("StreamWithEnd: %v", err)
	}
	_ = inner.Close()
	drainUntilClosed(t, out)
	if why := end.Err(); !errors.Is(why, lad.ErrLedgerClosed) {
		t.Fatalf("the stream ended with %v, want ErrLedgerClosed", why)
	}
}

// An overflow is the end a consumer restarts after; through the wrapper it
// must read as ErrStreamOverflow, not as a close or as no reason.
func TestHookedLedgerReportsTheInnerLedgersOverflow(t *testing.T) {
	inner := storage.NewMemoryLedger(storage.MemoryLedgerConfig{})
	defer inner.Close()
	er, ok := NewCacheApplyHook(CacheHookConfig{}).Wrap(inner).(lad.EndReportingLedger)
	if !ok {
		t.Fatal("the hooked ledger does not report why its streams end")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, end, err := er.StreamWithEnd(ctx, nil, []lad.Topic{lad.TopicMember})
	if err != nil {
		t.Fatalf("StreamWithEnd: %v", err)
	}
	// Nothing reads out while the appends run, so the live queue fills and
	// the ledger ends the stream; the appends go to the inner ledger, whose
	// member records the reach hook would pass unchecked in any case.
	for i := 0; i < 4096 && end.Err() == nil; i++ {
		rec := lad.Record{
			Topic:     lad.TopicMember,
			NodeID:    fmt.Sprintf("node-%d", i),
			Timestamp: time.Unix(int64(1_700_000_000+i), 0).UTC(),
		}
		if err := inner.Append(ctx, rec); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	drainUntilClosed(t, out)
	if why := end.Err(); !errors.Is(why, lad.ErrStreamOverflow) {
		t.Fatalf("the stream ended with %v, want ErrStreamOverflow", why)
	}
}

// plainLedger hides StreamWithEnd, standing for an inner ledger that does
// not report its stream ends.
type plainLedger struct{ lad.Ledger }

// An inner ledger that reports nothing gives a StreamEnd that is never set,
// so the consumer sees an end with no reason, the same as streaming the
// inner ledger directly.
func TestHookedLedgerOverAPlainLedgerReportsNoReason(t *testing.T) {
	inner := storage.NewMemoryLedger(storage.MemoryLedgerConfig{})
	er, ok := NewCacheApplyHook(CacheHookConfig{}).Wrap(plainLedger{inner}).(lad.EndReportingLedger)
	if !ok {
		t.Fatal("the hooked ledger does not report why its streams end")
	}
	out, end, err := er.StreamWithEnd(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("StreamWithEnd: %v", err)
	}
	if end == nil {
		t.Fatal("StreamWithEnd gave no StreamEnd")
	}
	_ = inner.Close()
	drainUntilClosed(t, out)
	if why := end.Err(); why != nil {
		t.Fatalf("the stream ended with %v, want no reason from a ledger that reports none", why)
	}
}

// The wrapper hands the inner ledger the caller's context and topics: a
// cancel ends the stream with the context's error, and only the asked
// topic's records arrive.
func TestHookedLedgerStreamWithEndKeepsTheCallersContextAndTopics(t *testing.T) {
	inner := storage.NewMemoryLedger(storage.MemoryLedgerConfig{})
	defer inner.Close()
	er, ok := NewCacheApplyHook(CacheHookConfig{}).Wrap(inner).(lad.EndReportingLedger)
	if !ok {
		t.Fatal("the hooked ledger does not report why its streams end")
	}
	ctx, cancel := context.WithCancel(context.Background())
	out, end, err := er.StreamWithEnd(ctx, nil, []lad.Topic{lad.TopicRole})
	if err != nil {
		t.Fatalf("StreamWithEnd: %v", err)
	}
	// One BatchAppend broadcasts its records in order, so a member record the
	// stream let through would arrive before the role record.
	batch := []lad.Record{{Topic: lad.TopicMember, NodeID: "node-a"}, {Topic: lad.TopicRole, NodeID: "node-a"}}
	if err := inner.BatchAppend(context.Background(), batch); err != nil {
		t.Fatalf("BatchAppend: %v", err)
	}
	select {
	case rec := <-out:
		if rec.Topic != lad.TopicRole {
			t.Fatalf("received a %s record from a stream asked for roles", rec.Topic)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the role record never arrived")
	}
	cancel()
	if n := drainUntilClosed(t, out); n != 0 {
		t.Fatalf("%d more records arrived after the role record", n)
	}
	if why := end.Err(); !errors.Is(why, context.Canceled) {
		t.Fatalf("the stream ended with %v, want context.Canceled", why)
	}
}
