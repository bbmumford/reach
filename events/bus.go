// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

// Package events provides network-change notifications for reach.Publisher.
// Platform-specific implementations hook into netlink (linux), PF_ROUTE (darwin),
// and NotifyUnicastIpAddressChange (windows). On unsupported platforms, the
// bus falls back to a polling strategy.
package events

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Source describes why an event fired.
type Source string

const (
	SourceInterfaceUp     Source = "interface.up"
	SourceInterfaceDown   Source = "interface.down"
	SourceAddressAdd      Source = "address.add"
	SourceAddressRemove   Source = "address.remove"
	SourceRouteChange     Source = "route.change"
	SourceDHCPRenew       Source = "dhcp.renew"
	SourceSleep           Source = "power.sleep"
	SourceWake            Source = "power.wake"
	SourceWiFiChange      Source = "wifi.change"
	SourceSIGHUP          Source = "signal.hup"
	SourceEpochBump       Source = "epoch.bump"
	SourcePoll            Source = "poll"
)

// Event is a single network-state-change notification.
type Event struct {
	Source Source
	Detail string
	At     time.Time
}

// Bus is a fan-out pub/sub for network-change events.
// Subscribers are called synchronously from the firing goroutine — handlers
// should be non-blocking (publish to a channel, return quickly).
type Bus struct {
	mu          sync.RWMutex
	subscribers []func(Event)
}

// NewBus creates an empty event bus.
func NewBus() *Bus {
	return &Bus{}
}

// Subscribe registers a handler to receive all future events.
func (b *Bus) Subscribe(h func(Event)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribers = append(b.subscribers, h)
}

// Publish fans out an event to all subscribers.
func (b *Bus) Publish(ev Event) {
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	b.mu.RLock()
	subs := make([]func(Event), len(b.subscribers))
	copy(subs, b.subscribers)
	b.mu.RUnlock()
	for _, h := range subs {
		h(ev)
	}
}

// Source is the contract for a platform-specific event producer.
// Call Start(ctx, bus) once; it runs until ctx is cancelled.
type EventSource interface {
	Start(ctx context.Context, bus *Bus) error
	Close() error
}

// PowerSource returns a platform-specific sleep/wake event source. The
// returned source fires a SourceWake event whenever the clock gap between
// polls suggests the host just resumed. Lives in power_<OS>.go.
func PowerSource() EventSource {
	return platformPowerSource()
}

// Poller is a cross-platform fallback event source that polls interface state
// every Interval and emits AddressAdd/AddressRemove events when it changes.
// Suitable when platform-specific hooks aren't available.
type Poller struct {
	Interval time.Duration
	Snapshot func() (string, error) // opaque fingerprint of current interface state
}

// NewDefaultPoller returns a poller with a 30-second cadence that fingerprints
// the current net.Interfaces + addresses.
func NewDefaultPoller() *Poller {
	return &Poller{
		Interval: 30 * time.Second,
		Snapshot: snapshotInterfaces,
	}
}

// Start runs the poller until ctx is cancelled.
func (p *Poller) Start(ctx context.Context, bus *Bus) error {
	interval := p.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var prev string
	if p.Snapshot != nil {
		prev, _ = p.Snapshot()
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if p.Snapshot == nil {
				continue
			}
			curr, err := p.Snapshot()
			if err != nil {
				continue
			}
			if curr != prev {
				bus.Publish(Event{
					Source: SourcePoll,
					Detail: fmt.Sprintf("interface-state-fingerprint=%s", short(curr)),
				})
				prev = curr
			}
		}
	}
}

// Close is a no-op; ctx cancellation is the lifecycle signal.
func (p *Poller) Close() error { return nil }

func short(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}
