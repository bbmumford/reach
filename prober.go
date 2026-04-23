// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// VerifyTransport is the contract a consumer provides to let the prober talk
// to remote peers over the mesh. Intentionally minimal — the package does not
// care whether the underlying channel is an aether stream, an HTTP endpoint,
// or an in-memory test harness.
type VerifyTransport interface {
	// Ask sends a VerifyRequest to peerNodeID and returns the peer's reply.
	// The implementation is responsible for timeouts, retries, and choosing
	// which session / stream to use.
	Ask(ctx context.Context, peerNodeID string, req VerifyRequest) (VerifyResponse, error)
}

// VerifyRequest asks a remote peer to dial an advertised address of OURS and
// report the result. The peer verifies with a one-shot probe over UDP (a STUN-
// style bind) so the request is cheap and stateless on their end.
type VerifyRequest struct {
	Nonce     []byte  `json:"n"`
	TargetAddr Address `json:"target"` // our advertised address we want verified
	DeadlineMicros int64 `json:"dl"`
}

// VerifyResponse is the peer's reply. RTT is their measured round-trip to our
// advertised address. Confidence is informational — the requesting publisher
// decides how to combine multiple responses.
type VerifyResponse struct {
	Nonce         []byte        `json:"n"`
	Reachable     bool          `json:"ok"`
	RTT           time.Duration `json:"rtt,omitempty"`
	ObserverNode  string        `json:"from"`
	ObserverRegion string       `json:"region"`
	Reason        string        `json:"reason,omitempty"`
}

// Prober runs peer-echo verification of advertised addresses to produce
// confidence scores. Consumers pick the quorum of peers to ask (typically
// 2 peers in distinct regions) and pass them to Verify().
type Prober struct {
	transport VerifyTransport
	metrics   Metrics
	rttTracker *RegionRTTTracker

	// minRegionsForVerified is the number of distinct observer regions whose
	// Reachable=true response is required to graduate an address from
	// ConfidenceUnverified to ConfidenceVerified.
	minRegionsForVerified int
}

// ProberConfig bundles prober tunables.
type ProberConfig struct {
	Metrics               Metrics
	RTTTracker            *RegionRTTTracker
	MinRegionsForVerified int // default 2
}

// NewProber constructs a prober.
func NewProber(transport VerifyTransport, cfg ProberConfig) *Prober {
	if cfg.MinRegionsForVerified <= 0 {
		cfg.MinRegionsForVerified = 2
	}
	if cfg.Metrics == nil {
		cfg.Metrics = NullMetrics{}
	}
	return &Prober{
		transport:             transport,
		metrics:               cfg.Metrics,
		rttTracker:            cfg.RTTTracker,
		minRegionsForVerified: cfg.MinRegionsForVerified,
	}
}

// Verify runs verification for a single advertised address against the given
// set of peers. Returns the updated Address with Confidence adjusted based on
// the quorum result. Never returns an error — verification failures are
// represented as Confidence=0 plus a Tag explaining why.
func (p *Prober) Verify(ctx context.Context, addr Address, peers []PeerInfo) Address {
	if p.transport == nil || len(peers) == 0 {
		return addr
	}

	req := VerifyRequest{
		Nonce:          freshNonce(),
		TargetAddr:     addr,
		DeadlineMicros: time.Now().Add(3 * time.Second).UnixMicro(),
	}

	type result struct {
		rsp VerifyResponse
		err error
	}
	resCh := make(chan result, len(peers))
	probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	for _, peer := range peers {
		go func(peer PeerInfo) {
			rsp, err := p.transport.Ask(probeCtx, peer.NodeID, req)
			resCh <- result{rsp, err}
		}(peer)
	}

	// Collect responses.
	var (
		reachableRegions = map[string]struct{}{}
		rttByRegion      = map[string]time.Duration{}
		observed         int
	)
	for i := 0; i < len(peers); i++ {
		select {
		case r := <-resCh:
			if r.err != nil {
				continue
			}
			if !bytesEq(r.rsp.Nonce, req.Nonce) {
				continue
			}
			observed++
			if r.rsp.Reachable {
				reachableRegions[r.rsp.ObserverRegion] = struct{}{}
				if r.rsp.RTT > 0 {
					rttByRegion[r.rsp.ObserverRegion] = r.rsp.RTT
				}
			}
		case <-probeCtx.Done():
			break
		}
	}

	// Push RTT samples into the region tracker so adaptive priority computes.
	if p.rttTracker != nil {
		for region, rtt := range rttByRegion {
			p.rttTracker.Record(addr.Key(), region, rtt)
		}
	}

	// Grade the address.
	out := addr
	out.LastVerified = time.Now()
	if len(reachableRegions) >= p.minRegionsForVerified {
		out.Confidence = 70
		p.metrics.AddressVerified(addr.Source, addr.Family)
	} else if observed == 0 {
		// No responses at all — not a failure, just uninformative.
		out.Confidence = addr.Confidence
	} else {
		out.Confidence = 10
		p.metrics.AddressVerifyFailed(addr.Source, addr.Family)
		out.Tags = append(out.Tags, "unverified")
	}
	return out
}

// PeerInfo is the minimum info the Prober needs about a peer to ask it to verify.
type PeerInfo struct {
	NodeID string
	Region string
}

// ErrVerifyCanceled is returned when the probe context is canceled.
var ErrVerifyCanceled = errors.New("reach: verify canceled")

func freshNonce() []byte {
	var b [16]byte
	// time-based fallback if crypto/rand is unavailable.
	_ = json.Unmarshal([]byte(time.Now().UTC().Format(time.RFC3339Nano)), &b)
	// crypto/rand.Read is the preferred source.
	randFill(b[:])
	return b[:]
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
