// Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.

package reach

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

// maxVerifyBodyBytes bounds a VerifyRequest a handler reads and a
// VerifyResponse a transport reads: each is a nonce, an address and a few
// fields, so no honest one comes near it.
const maxVerifyBodyBytes = 4 << 10

// NoOpVerifyTransport is a transport that never sends a request.
// Useful for tests, dev scenarios, or nodes that don't support probing peers.
// All Ask calls return ErrNoProbeTransport.
type NoOpVerifyTransport struct{}

// ErrNoProbeTransport is returned by NoOpVerifyTransport.Ask.
var ErrNoProbeTransport = errors.New("reach: no verify transport configured")

// Ask returns ErrNoProbeTransport unconditionally.
func (NoOpVerifyTransport) Ask(context.Context, string, VerifyRequest) (VerifyResponse, error) {
	return VerifyResponse{}, ErrNoProbeTransport
}

// HTTPVerifyTransport is a reference implementation of VerifyTransport that
// POSTs a VerifyRequest to an endpoint on each peer and parses a JSON response.
// The consumer supplies a PeerURLFunc that maps NodeID → URL (typically by
// reading peer.Endpoints from LAD and picking an https:// entry).
//
// Each peer is dialed with a 4-second default timeout. The consumer also
// supplies a LocalRegion — the peer returns it in VerifyResponse.ObserverRegion
// so the prober can discard responses from peers in the same region (RFC quorum
// requires distinct-region observers for a "verified" result).
type HTTPVerifyTransport struct {
	PeerURL  func(nodeID string) (string, bool) // returns "", false when peer is unknown
	Client   *http.Client
	Headers  map[string]string // optional auth headers (e.g. tenant token)
	Deadline time.Duration
}

// NewHTTPVerifyTransport constructs the default HTTP verify transport.
// Call ers customize by setting Headers, Client, Deadline.
func NewHTTPVerifyTransport(peerURL func(nodeID string) (string, bool)) *HTTPVerifyTransport {
	return &HTTPVerifyTransport{
		PeerURL: peerURL,
		Client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
				DisableKeepAlives: true, // each probe is one-shot
			},
		},
		Deadline: 4 * time.Second,
	}
}

// Ask POSTs the request to /reach/verify on the peer and decodes the response.
func (t *HTTPVerifyTransport) Ask(ctx context.Context, nodeID string, req VerifyRequest) (VerifyResponse, error) {
	if t.PeerURL == nil {
		return VerifyResponse{}, ErrNoProbeTransport
	}
	url, ok := t.PeerURL(nodeID)
	if !ok || url == "" {
		return VerifyResponse{}, fmt.Errorf("reach: no URL for peer %s", nodeID)
	}

	deadline := t.Deadline
	if deadline == 0 {
		deadline = 4 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	payload, err := json.Marshal(req)
	if err != nil {
		return VerifyResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return VerifyResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range t.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := t.Client.Do(httpReq)
	if err != nil {
		return VerifyResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return VerifyResponse{}, fmt.Errorf("reach: verify HTTP %d from %s", resp.StatusCode, nodeID)
	}

	var out VerifyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxVerifyBodyBytes)).Decode(&out); err != nil {
		return VerifyResponse{}, err
	}
	return out, nil
}

// ServeVerifyHTTP is a reference handler for the other side of HTTPVerifyTransport.
// Consumers (HSTLES nodes, ORBTR agent) mount this on their HTTP mux at
// /reach/verify. Given the ReachVerifier (which probes the target address
// and returns a VerifyResponse), it unmarshals the request, calls the
// verifier, and writes the response.
//
// The handler is protocol-agnostic — a consumer running aether instead of
// HTTP would implement their own handler with the same verifier semantics.
type ReachVerifier interface {
	Verify(ctx context.Context, req VerifyRequest, observerRegion, observerNode string) VerifyResponse
}

// ServeVerifyHTTP returns an http.Handler that wires an incoming probe to v.
// Every request must pass authorize, the mount's proof that the caller is a
// mesh peer it serves: a verifier dials what a request names, so a handler open
// to any caller would probe the observer's network for anyone. A nil authorize
// admits no request. A request body past maxVerifyBodyBytes is refused unread.
func ServeVerifyHTTP(v ReachVerifier, observerRegion, observerNode string, authorize func(*http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if authorize == nil || authorize(r) != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req VerifyRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxVerifyBodyBytes)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		rsp := v.Verify(r.Context(), req, observerRegion, observerNode)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rsp)
	})
}

// DefaultVerifier is a ReachVerifier that dials the requested target address
// over UDP or TCP and reports whether the dial succeeded. Sufficient for basic
// reachability probing; the consumer can implement a richer verifier that
// does a real handshake or NAT-type detection.
//
// It dials only a target probeTarget admits, a public unicast IP literal on a
// UDP or TCP port, and its answer carries no dial error text, so a request can
// make it reach neither the observer's own host, its private network nor a
// cloud metadata address, nor learn more than reachable or not.
type DefaultVerifier struct {
	Timeout time.Duration
}

// Reasons DefaultVerifier gives for a target it does not reach.
const (
	VerifyReasonRefusedTarget = "refused target"
	VerifyReasonUnreachable   = "unreachable"
)

// probeTarget returns the dial network and address for a, or false when a is
// not a target DefaultVerifier dials: the protocol must be udp or tcp, the host
// an IP literal (a name could resolve anywhere), the port in 1-65535, and the
// address public unicast, so not loopback, link-local (169.254.169.254 among
// them), private, multicast or unspecified.
func probeTarget(a Address) (network, addr string, ok bool) {
	if a.Proto != "udp" && a.Proto != "tcp" {
		return "", "", false
	}
	ip, err := netip.ParseAddr(a.Host)
	if err != nil || ip.Zone() != "" {
		return "", "", false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return "", "", false
	}
	if a.Port == 0 {
		return "", "", false
	}
	return a.Proto, net.JoinHostPort(ip.String(), strconv.Itoa(int(a.Port))), true
}

// Verify performs the dial-probe and returns the result.
func (v DefaultVerifier) Verify(ctx context.Context, req VerifyRequest, observerRegion, observerNode string) VerifyResponse {
	timeout := v.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	network, addr, ok := probeTarget(req.TargetAddr)
	if !ok {
		return VerifyResponse{
			Nonce:          req.Nonce,
			ObserverNode:   observerNode,
			ObserverRegion: observerRegion,
			Reason:         VerifyReasonRefusedTarget,
		}
	}
	start := time.Now()
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	rtt := time.Since(start)

	if err != nil {
		return VerifyResponse{
			Nonce:          req.Nonce,
			Reachable:      false,
			ObserverNode:   observerNode,
			ObserverRegion: observerRegion,
			Reason:         VerifyReasonUnreachable,
		}
	}
	_ = conn.Close()
	return VerifyResponse{
		Nonce:          req.Nonce,
		Reachable:      true,
		RTT:            rtt,
		ObserverNode:   observerNode,
		ObserverRegion: observerRegion,
	}
}
