// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

//go:build !linux && !darwin && !windows
// +build !linux,!darwin,!windows

package events

// PlatformSource returns the cross-platform polling fallback.
func PlatformSource() EventSource {
	return NewDefaultPoller()
}
