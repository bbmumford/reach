// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

//go:build linux
// +build linux

package events

import (
	"context"
	"time"
)

// LinuxPowerSource detects sleep/wake via the same clock-gap heuristic as
// Darwin/Windows. A proper logind D-Bus subscription would be more precise
// but requires a dbus dep — the gap detector is good enough for the
// "did we sleep?" signal the publisher needs.
type LinuxPowerSource struct {
	PollInterval time.Duration
}

// NewLinuxPowerSource returns a power-event source for Linux.
func NewLinuxPowerSource() *LinuxPowerSource {
	return &LinuxPowerSource{PollInterval: 30 * time.Second}
}

// Start runs the detection loop until ctx is cancelled.
func (s *LinuxPowerSource) Start(ctx context.Context, bus *Bus) error {
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
				bus.Publish(Event{
					Source: SourceWake,
					Detail: "gap_ms=" + linItoa(int(gap.Milliseconds())),
				})
			}
			last = now
		}
	}
}

// Close is a no-op; ctx cancel is the lifecycle signal.
func (s *LinuxPowerSource) Close() error { return nil }

func linItoa(n int) string {
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
