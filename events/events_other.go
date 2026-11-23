// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

//go:build !linux && !darwin && !windows
// +build !linux,!darwin,!windows

package events

// PlatformSource returns the cross-platform polling fallback.
func PlatformSource() EventSource {
	return NewDefaultPoller()
}

// platformPowerSource returns a no-op for unsupported platforms.
func platformPowerSource() EventSource {
	return NewDefaultPoller()
}
