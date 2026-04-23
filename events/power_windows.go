// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

//go:build windows
// +build windows

package events

import (
	"context"
	"time"
)

// WindowsPowerSource uses the same clock-gap detection as Darwin. A full
// WM_POWERBROADCAST subscription requires a message-only hidden window and
// pumping the message loop — too much infrastructure for the marginal
// benefit. The clock-gap heuristic catches both laptop sleep and server
// hibernation without any OS-specific coupling.
type WindowsPowerSource struct {
	PollInterval time.Duration
}

// NewWindowsPowerSource returns a power-event source for Windows.
func NewWindowsPowerSource() *WindowsPowerSource {
	return &WindowsPowerSource{PollInterval: 30 * time.Second}
}

// Start runs the detection loop until ctx is cancelled.
func (s *WindowsPowerSource) Start(ctx context.Context, bus *Bus) error {
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
					Detail: "gap_ms=" + winItoa(int(gap.Milliseconds())),
				})
			}
			last = now
		}
	}
}

// Close is a no-op; ctx cancel is the lifecycle signal.
func (s *WindowsPowerSource) Close() error { return nil }

func winItoa(n int) string {
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
