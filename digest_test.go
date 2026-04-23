// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import "testing"

func TestDigestStableUnderReorder(t *testing.T) {
	a := []Address{
		{Proto: "udp", Host: "1.2.3.4", Port: 41641, Scope: ScopePublic, Source: SrcDNS},
		{Proto: "wss", Host: "node.example", Port: 443, Scope: ScopePublic, Source: SrcDNS},
	}
	b := []Address{
		{Proto: "wss", Host: "node.example", Port: 443, Scope: ScopePublic, Source: SrcDNS},
		{Proto: "udp", Host: "1.2.3.4", Port: 41641, Scope: ScopePublic, Source: SrcDNS},
	}
	if Digest(a) != Digest(b) {
		t.Fatalf("Digest not stable under reorder")
	}
}

func TestDigestChangesOnFieldChange(t *testing.T) {
	base := []Address{{Proto: "udp", Host: "1.2.3.4", Port: 41641, Scope: ScopePublic, Source: SrcDNS}}
	mutant := []Address{{Proto: "udp", Host: "1.2.3.5", Port: 41641, Scope: ScopePublic, Source: SrcDNS}}
	if Digest(base) == Digest(mutant) {
		t.Fatalf("Digest did not change when Host changed")
	}
}

func TestDigestIgnoresVolatileFields(t *testing.T) {
	now := nowForTest()
	a := Address{Proto: "udp", Host: "1.2.3.4", Port: 41641, Scope: ScopePublic, Source: SrcDNS,
		RTTMicros: 100, LastVerified: now, FirstSeen: now}
	b := Address{Proto: "udp", Host: "1.2.3.4", Port: 41641, Scope: ScopePublic, Source: SrcDNS,
		RTTMicros: 9999, LastVerified: now.Add(-10), FirstSeen: now.Add(-100)}
	if Digest([]Address{a}) != Digest([]Address{b}) {
		t.Fatalf("Digest should ignore volatile fields (RTT / LastVerified / FirstSeen)")
	}
}
