// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

package reach

import (
	"testing"
	"time"
)

// The hook's replay guard keeps per-node state for the window its config states.
func TestCacheApplyHookUsesItsReplayWindow(t *testing.T) {
	if got := NewCacheApplyHook(CacheHookConfig{ReplayWindow: 90}).replay.window; got != 90*time.Second {
		t.Fatalf("replay window = %v, want 90s", got)
	}
	if got := NewCacheApplyHook(CacheHookConfig{}).replay.window; got != 0 {
		t.Fatalf("replay window with none set = %v, want 0 (forever)", got)
	}
}
