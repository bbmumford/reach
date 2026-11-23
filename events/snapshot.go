// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

package events

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
)

// snapshotInterfaces produces an opaque, stable fingerprint of the current
// interface + address state. Change in fingerprint ⇒ address set changed.
// Used by the polling fallback event source.
func snapshotInterfaces() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var lines []string
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			lines = append(lines, iface.Name+"|"+a.String())
		}
		if iface.Flags&net.FlagUp != 0 {
			lines = append(lines, iface.Name+"|up")
		}
	}
	sort.Strings(lines)

	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
