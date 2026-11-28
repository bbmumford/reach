// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

package reach

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pion/ice/v4"
)

// TestBuildICECandidatesWritesOneLinePerUDPAddress pins the lines a
// ReachRecord's ICECandidates carries: the candidate type each source maps
// to, the foundation counted per type, the RFC 8445 priority, and the
// addresses left out. The relay line's priority carries the UDP relay
// preference because the TURN discoverer allocates over UDP.
func TestBuildICECandidatesWritesOneLinePerUDPAddress(t *testing.T) {
	addrs := []Address{
		{Host: "10.0.0.5", Port: 4242, Proto: "udp", Scope: ScopePrivate, Source: SrcInterface},
		{Host: "203.0.113.7", Port: 5000, Proto: "quic", Scope: ScopePublic, Source: SrcSTUN},
		{Host: "198.51.100.9", Port: 3478, Proto: "udp", Scope: ScopePublic, Source: SrcTURN},
		{Host: "2001:db8::1", Port: 9000, Proto: "udp", Scope: ScopePublic, Source: SrcStatic},
		{Host: "192.0.2.10", Port: 7000, Proto: "udp", Scope: ScopePublic, Source: SrcReflection},
		// Left out: no port, no host, a transport ICE does not carry, a
		// source with no candidate type, and a name that is not an IP.
		{Host: "10.0.0.6", Port: 0, Proto: "udp", Source: SrcInterface},
		{Host: "", Port: 4243, Proto: "udp", Source: SrcInterface},
		{Host: "10.0.0.7", Port: 443, Proto: "wss", Source: SrcInterface},
		{Host: "10.0.0.8", Port: 4244, Proto: "udp", Source: SrcUPnP},
		{Host: "node.example.com", Port: 4245, Proto: "udp", Source: SrcDNS},
	}
	want := []string{
		"h1 1 udp 2130706431 10.0.0.5 4242 typ host",
		"s1 1 udp 1694498815 203.0.113.7 5000 typ srflx",
		"r1 1 udp 1023 198.51.100.9 3478 typ relay",
		"h2 1 udp 2130706431 2001:db8::1 9000 typ host",
		"s2 1 udp 1694498815 192.0.2.10 7000 typ srflx",
	}

	got := BuildICECandidates(addrs)
	if len(got) != len(want) {
		t.Fatalf("BuildICECandidates wrote %d lines, want %d:\n got %q\nwant %q", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestICEAgentsConnectOverLoopbackOnBuiltCandidates proves a peer's ICE agent
// can use the lines BuildICECandidates writes. Two agents gather host
// candidates on loopback; each side learns the other's candidates only as
// reach Addresses turned into lines and parsed back, then the pair connects
// and carries a datagram.
func TestICEAgentsConnectOverLoopbackOnBuiltCandidates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	controlling := newLoopbackAgent(t)
	controlled := newLoopbackAgent(t)
	controllingAddrs := gatherAsAddresses(t, controlling)
	controlledAddrs := gatherAsAddresses(t, controlled)
	addRemoteThroughLines(t, controlled, controllingAddrs)
	addRemoteThroughLines(t, controlling, controlledAddrs)

	controllingUfrag, controllingPwd, err := controlling.GetLocalUserCredentials()
	if err != nil {
		t.Fatalf("controlling credentials: %v", err)
	}
	controlledUfrag, controlledPwd, err := controlled.GetLocalUserCredentials()
	if err != nil {
		t.Fatalf("controlled credentials: %v", err)
	}

	type accepted struct {
		conn *ice.Conn
		err  error
	}
	acceptDone := make(chan accepted, 1)
	go func() {
		conn, err := controlled.Accept(ctx, controllingUfrag, controllingPwd)
		acceptDone <- accepted{conn, err}
	}()
	dialed, err := controlling.Dial(ctx, controlledUfrag, controlledPwd)
	if err != nil {
		t.Fatalf("dial over the built candidates: %v", err)
	}
	acc := <-acceptDone
	if acc.err != nil {
		t.Fatalf("accept over the built candidates: %v", acc.err)
	}

	payload := []byte("reach")
	if _, err := dialed.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	type read struct {
		data []byte
		err  error
	}
	readDone := make(chan read, 1)
	go func() {
		buf := make([]byte, 64)
		n, err := acc.conn.Read(buf)
		readDone <- read{buf[:n], err}
	}()
	select {
	case r := <-readDone:
		if r.err != nil {
			t.Fatalf("read: %v", r.err)
		}
		if string(r.data) != string(payload) {
			t.Fatalf("read %q, want %q", r.data, payload)
		}
	case <-ctx.Done():
		t.Fatal("no datagram arrived over the connected pair")
	}
}

// newLoopbackAgent returns an ICE agent that gathers only UDP host candidates
// on loopback addresses, with mDNS off, closed when the test ends.
func newLoopbackAgent(t *testing.T) *ice.Agent {
	t.Helper()
	agent, err := ice.NewAgentWithOptions(
		ice.WithNetworkTypes([]ice.NetworkType{ice.NetworkTypeUDP4}),
		ice.WithCandidateTypes([]ice.CandidateType{ice.CandidateTypeHost}),
		ice.WithIncludeLoopback(),
		ice.WithIPFilter(func(ip net.IP) bool { return ip.IsLoopback() }),
		ice.WithMulticastDNSMode(ice.MulticastDNSModeDisabled),
	)
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	t.Cleanup(func() {
		if err := agent.Close(); err != nil {
			t.Errorf("close agent: %v", err)
		}
	})
	return agent
}

// gatherAsAddresses gathers the agent's candidates and returns each as the
// reach Address an interface discoverer would publish for it.
func gatherAsAddresses(t *testing.T, agent *ice.Agent) []Address {
	t.Helper()
	var addrs []Address
	done := make(chan struct{})
	if err := agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			close(done)
			return
		}
		addrs = append(addrs, Address{
			Host:   c.Address(),
			Port:   uint16(c.Port()),
			Proto:  "udp",
			Scope:  ScopeLoopback,
			Source: SrcInterface,
		})
	}); err != nil {
		t.Fatalf("candidate handler: %v", err)
	}
	if err := agent.GatherCandidates(); err != nil {
		t.Fatalf("gather: %v", err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("candidate gathering did not finish")
	}
	if len(addrs) == 0 {
		t.Fatal("no loopback host candidate was gathered")
	}
	return addrs
}

// addRemoteThroughLines hands the agent the given addresses the way a peer
// reading a ReachRecord does: as BuildICECandidates lines, parsed back.
func addRemoteThroughLines(t *testing.T, agent *ice.Agent, addrs []Address) {
	t.Helper()
	lines := BuildICECandidates(addrs)
	if len(lines) != len(addrs) {
		t.Fatalf("%d addresses gave %d candidate lines: %q", len(addrs), len(lines), lines)
	}
	for _, line := range lines {
		cand, err := ice.UnmarshalCandidate(line)
		if err != nil {
			t.Fatalf("parse candidate line %q: %v", line, err)
		}
		if err := agent.AddRemoteCandidate(cand); err != nil {
			t.Fatalf("add remote candidate %q: %v", line, err)
		}
	}
}
