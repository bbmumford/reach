// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

//go:build darwin
// +build darwin

package events

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// DarwinPowerSource polls `pmset -g batt` and `ioreg` for wake events.
// A full IOKit subscription requires CGo (IORegisterForSystemPower); the
// polling variant avoids cgo and is good enough to notice a 10s gap in
// clock time that indicates the machine slept.
//
// The detection works by comparing the wall clock delta between ticks —
// if the last tick was more than 90 seconds ago (we poll every 30s), the
// gap implies a sleep/resume cycle.
type DarwinPowerSource struct {
	PollInterval time.Duration
}

// NewDarwinPowerSource returns a power-event source for macOS that fires a
// SourceWake event when it detects a clock-time gap larger than 3x the poll
// interval — a reliable proxy for system sleep/resume.
func NewDarwinPowerSource() *DarwinPowerSource {
	return &DarwinPowerSource{PollInterval: 30 * time.Second}
}

// Start runs the detection loop until ctx is cancelled.
func (s *DarwinPowerSource) Start(ctx context.Context, bus *Bus) error {
	interval := s.PollInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	last := time.Now()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			gap := now.Sub(last)
			if gap > 3*interval {
				// Too long since last tick — machine slept.
				bus.Publish(Event{
					Source: SourceWake,
					Detail: "gap_ms=" + itoa(int(gap.Milliseconds())),
				})
			}
			last = now
		}
	}
}

// Close is a no-op; ctx cancel is the lifecycle signal.
func (s *DarwinPowerSource) Close() error { return nil }

// pmsetBattery is retained for callers that want the current AC/battery
// state — not used by the event loop itself.
func pmsetBattery() string {
	out, err := exec.Command("pmset", "-g", "batt").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
