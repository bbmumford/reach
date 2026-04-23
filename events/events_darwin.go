// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

//go:build darwin
// +build darwin

package events

import (
	"context"

	"golang.org/x/sys/unix"
)

// PFRouteSource subscribes to macOS PF_ROUTE socket for kernel routing-table
// and interface-state changes. Any message on the socket is treated as an
// event and forwarded to the bus — the publisher treats all events equally
// and re-runs discovery.
type PFRouteSource struct {
	fd int
}

// NewPFRouteSource opens a raw routing socket.
func NewPFRouteSource() (*PFRouteSource, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	return &PFRouteSource{fd: fd}, nil
}

// Start reads from the routing socket and publishes an event for each message.
func (s *PFRouteSource) Start(ctx context.Context, bus *Bus) error {
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	buf := make([]byte, 4096)
	for {
		n, err := unix.Read(s.fd, buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		if n > 0 {
			bus.Publish(Event{Source: SourceRouteChange, Detail: "pf_route"})
		}
	}
}

// Close releases the socket.
func (s *PFRouteSource) Close() error {
	if s.fd > 0 {
		return unix.Close(s.fd)
	}
	return nil
}

// PlatformSource returns the Darwin PF_ROUTE source if available, else a Poller.
func PlatformSource() EventSource {
	if src, err := NewPFRouteSource(); err == nil {
		return src
	}
	return NewDefaultPoller()
}

// platformPowerSource returns the Darwin sleep/wake detector.
func platformPowerSource() EventSource {
	return NewDarwinPowerSource()
}
