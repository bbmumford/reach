// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

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
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
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
func ServeVerifyHTTP(v ReachVerifier, observerRegion, observerNode string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		rsp := v.Verify(r.Context(), req, observerRegion, observerNode)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rsp)
	})
}

// DefaultVerifier is a ReachVerifier that dials the requested target address
// over UDP and reports whether the dial succeeded. Sufficient for basic
// reachability probing; the consumer can implement a richer verifier that
// does a real handshake or NAT-type detection.
type DefaultVerifier struct {
	Timeout time.Duration
}

// Verify performs the dial-probe and returns the result.
func (v DefaultVerifier) Verify(ctx context.Context, req VerifyRequest, observerRegion, observerNode string) VerifyResponse {
	timeout := v.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(req.TargetAddr.Host, fmt.Sprintf("%d", req.TargetAddr.Port))
	start := time.Now()
	var d net.Dialer
	conn, err := d.DialContext(ctx, req.TargetAddr.Proto, addr)
	rtt := time.Since(start)

	if err != nil {
		return VerifyResponse{
			Nonce:          req.Nonce,
			Reachable:      false,
			ObserverNode:   observerNode,
			ObserverRegion: observerRegion,
			Reason:         err.Error(),
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
