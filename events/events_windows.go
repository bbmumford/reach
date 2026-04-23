// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

//go:build windows
// +build windows

package events

import (
	"context"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi                   = windows.NewLazySystemDLL("iphlpapi.dll")
	procNotifyUnicastIpAddressChange = modIphlpapi.NewProc("NotifyUnicastIpAddressChange")
	procCancelMibChangeNotify2    = modIphlpapi.NewProc("CancelMibChangeNotify2")
)

// NotifyAddressSource subscribes to Windows IP Helper's NotifyUnicastIpAddressChange
// for kernel-level address-change events. Pure-Go implementation using
// syscall.NewCallback for the kernel callback and a registry to route events
// back to the right Bus.
type NotifyAddressSource struct {
	handle windows.Handle
	bus    *Bus
}

// Single global registry keeps the callback pure (no closures).
// Maps handle → Bus so multiple NotifyAddressSource instances are safe.
var (
	notifyRegistryMu sync.Mutex
	notifyRegistry    = map[uintptr]*NotifyAddressSource{}
	notifyCallbackOnce sync.Once
	notifyCallbackAddr uintptr
)

func ensureNotifyCallback() uintptr {
	notifyCallbackOnce.Do(func() {
		notifyCallbackAddr = syscall.NewCallback(notifyAddressCallback)
	})
	return notifyCallbackAddr
}

// notifyAddressCallback is invoked by the Windows IP Helper API whenever a
// unicast IP address is added, deleted, or changed. Signature (per MIB
// NotifyUnicastIpAddressChange docs):
//
//   void NETIOAPI_API_ callback(PVOID caller, PMIB_UNICASTIPADDRESS_ROW row,
//                               MIB_NOTIFICATION_TYPE notificationType)
//
// The caller pointer is the value we registered. We use it as a key into the
// registry to find the right Bus.
func notifyAddressCallback(caller uintptr, row uintptr, notificationType uint32) uintptr {
	_ = row

	notifyRegistryMu.Lock()
	src := notifyRegistry[caller]
	notifyRegistryMu.Unlock()
	if src == nil || src.bus == nil {
		return 0
	}

	var detail string
	switch notificationType {
	case 1: // MibParameterNotification
		detail = "addr_param_change"
	case 2: // MibAddInstance
		detail = "addr_added"
	case 3: // MibDeleteInstance
		detail = "addr_deleted"
	default:
		detail = "addr_changed"
	}
	src.bus.Publish(Event{Source: SourceAddressAdd, Detail: detail})
	return 0
}

// NewNotifyAddressSource creates a Windows source ready for registration.
// The bus is only populated once Start is called.
func NewNotifyAddressSource() *NotifyAddressSource {
	return &NotifyAddressSource{}
}

// Start registers the source with Windows and runs until ctx is cancelled.
func (s *NotifyAddressSource) Start(ctx context.Context, bus *Bus) error {
	s.bus = bus

	// Register ourselves in the global registry before installing the callback
	// so the callback can find us.
	key := uintptr(unsafe.Pointer(s))
	notifyRegistryMu.Lock()
	notifyRegistry[key] = s
	notifyRegistryMu.Unlock()

	cb := ensureNotifyCallback()

	var handle windows.Handle
	r1, _, err := procNotifyUnicastIpAddressChange.Call(
		uintptr(windows.AF_UNSPEC),
		cb,
		key,   // Caller context
		0,     // InitialNotification = FALSE; we don't need an initial synthetic event
		uintptr(unsafe.Pointer(&handle)),
	)
	if r1 != 0 {
		notifyRegistryMu.Lock()
		delete(notifyRegistry, key)
		notifyRegistryMu.Unlock()
		if err != nil && err != windows.Errno(0) {
			return err
		}
		return windows.Errno(r1)
	}
	s.handle = handle

	// Wait for context cancel; events arrive on the callback goroutine.
	<-ctx.Done()
	return s.Close()
}

// Close cancels the IP Helper registration.
func (s *NotifyAddressSource) Close() error {
	if s.handle == 0 {
		return nil
	}
	r1, _, _ := procCancelMibChangeNotify2.Call(uintptr(s.handle))
	s.handle = 0
	notifyRegistryMu.Lock()
	for k, v := range notifyRegistry {
		if v == s {
			delete(notifyRegistry, k)
		}
	}
	notifyRegistryMu.Unlock()
	if r1 != 0 {
		return windows.Errno(r1)
	}
	return nil
}

// PlatformSource returns the Windows kernel-callback source.
// Falls back to the polling source only if the DLL is missing (very rare).
func PlatformSource() EventSource {
	if modIphlpapi.Load() == nil {
		return NewNotifyAddressSource()
	}
	return NewDefaultPoller()
}
