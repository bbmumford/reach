// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

//go:build linux
// +build linux

package events

import (
	"context"

	"golang.org/x/sys/unix"
)

// NetlinkSource subscribes to Linux netlink (RTMGRP_IPV4_IFADDR / IPV6_IFADDR /
// LINK / ROUTE) for instant network-change notifications.
//
// This is a minimal implementation: it opens a netlink socket with the right
// multicast groups, then pushes a generic event whenever any message arrives.
// We do NOT parse the payload — any netlink traffic is a signal to re-discover.
// Keeps the code small and portable across kernel versions.
type NetlinkSource struct {
	fd int
}

// NewNetlinkSource creates a Linux event source. Returns an error if the
// caller lacks CAP_NET_ADMIN / appropriate capabilities; callers should fall
// back to Poller in that case.
func NewNetlinkSource() (*NetlinkSource, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	sa := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: rtmGroups(),
	}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &NetlinkSource{fd: fd}, nil
}

func rtmGroups() uint32 {
	return 1<<(unix.RTNLGRP_LINK-1) |
		1<<(unix.RTNLGRP_IPV4_IFADDR-1) |
		1<<(unix.RTNLGRP_IPV6_IFADDR-1) |
		1<<(unix.RTNLGRP_IPV4_ROUTE-1) |
		1<<(unix.RTNLGRP_IPV6_ROUTE-1)
}

// Start reads from the netlink socket and publishes an event for each message.
func (s *NetlinkSource) Start(ctx context.Context, bus *Bus) error {
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	buf := make([]byte, 65536)
	for {
		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// transient errors: log via the bus poll fallback route
			continue
		}
		if n > 0 {
			// We don't parse the payload — any change triggers re-discovery.
			bus.Publish(Event{
				Source: SourceAddressAdd, // generic; publisher treats them all the same
				Detail: "netlink",
			})
		}
	}
}

// Close releases the netlink socket.
func (s *NetlinkSource) Close() error {
	if s.fd > 0 {
		return unix.Close(s.fd)
	}
	return nil
}

// PlatformSource returns the Linux netlink source if available, else a Poller.
func PlatformSource() EventSource {
	if src, err := NewNetlinkSource(); err == nil {
		return src
	}
	return NewDefaultPoller()
}
