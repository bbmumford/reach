// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"crypto/rand"
	"errors"
	"testing"
)

func TestOrgSealRoundTrip(t *testing.T) {
	key := OrgKey{ID: "key-1", Key: make([]byte, 32)}
	if _, err := rand.Read(key.Key); err != nil {
		t.Fatal(err)
	}
	addrs := []Address{
		{Host: "fdaa:0:1::2", Port: 41641, Proto: "udp", Scope: ScopePrivate, Source: SrcInterface},
		{Host: "10.0.0.5", Port: 41641, Proto: "udp", Scope: ScopePrivate, Source: SrcInterface},
	}
	section, err := SealOrg(addrs, key)
	if err != nil {
		t.Fatal(err)
	}

	opened, err := OpenOrg(section, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened) != len(addrs) {
		t.Fatalf("open: got %d addrs, want %d", len(opened), len(addrs))
	}
	for i, a := range opened {
		if a.Host != addrs[i].Host || a.Port != addrs[i].Port {
			t.Fatalf("open[%d]: %+v != %+v", i, a, addrs[i])
		}
	}
}

func TestOrgSealWrongKeyRejected(t *testing.T) {
	key1 := OrgKey{ID: "k1", Key: make([]byte, 32)}
	_, _ = rand.Read(key1.Key)
	key2 := OrgKey{ID: "k1", Key: make([]byte, 32)}
	_, _ = rand.Read(key2.Key)

	addrs := []Address{{Host: "1.2.3.4", Port: 41641, Proto: "udp", Scope: ScopePrivate, Source: SrcInterface}}
	section, err := SealOrg(addrs, key1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenOrg(section, key2)
	if !errors.Is(err, ErrOrgKeyMismatch) {
		t.Fatalf("expected ErrOrgKeyMismatch, got %v", err)
	}
}
