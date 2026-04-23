// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package events

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CaptivePortalSource periodically probes a known "generate_204" URL to detect
// captive portals that intercept plaintext HTTP. The probe:
//
//   - HTTP 204 with empty body  → no portal
//   - HTTP 200 with non-empty   → portal present (redirected to login page)
//   - HTTP 3xx / network error  → treat as portal/unknown
//
// When the portal state flips (present ↔ clear) an event fires on the bus.
// Intended primarily for agent / roaming-laptop nodes.
type CaptivePortalSource struct {
	URL           string
	Interval      time.Duration
	ExpectBody    string        // empty = any body treated as "portal"
	Client        *http.Client

	mu    sync.Mutex
	state captiveState
}

type captiveState int

const (
	captiveUnknown captiveState = iota
	captiveClear
	captivePresent
)

// NewCaptivePortalSource returns a source that probes the given URL. The URL
// must return HTTP 204 No Content (or HTTP 200 with empty body) on clear
// networks; any other response is treated as a captive portal.
//
// Well-known generate_204 endpoints a consumer may choose from:
//
//   http://connectivitycheck.gstatic.com/generate_204    (Google / Android)
//   http://clients3.google.com/generate_204              (Chrome OS)
//   http://www.msftconnecttest.com/connecttest.txt       (Microsoft — body="Microsoft Connect Test")
//   http://captive.apple.com/hotspot-detect.html         (Apple — body contains "<HTML>" on portals)
//   http://detectportal.firefox.com/success.txt          (Mozilla — body="success")
//
// Consumers that run their own mesh infrastructure can host an endpoint
// themselves that returns 204 No Content, which keeps the probe under their
// own availability SLO. If url is empty, Start returns an error.
func NewCaptivePortalSource(url string) *CaptivePortalSource {
	return &CaptivePortalSource{
		URL:      url,
		Interval: 2 * time.Minute,
		Client:   &http.Client{Timeout: 3 * time.Second},
	}
}

// Start runs the probe loop until ctx is cancelled. Returns an error
// immediately if the source was constructed without a URL.
func (s *CaptivePortalSource) Start(ctx context.Context, bus *Bus) error {
	if s.URL == "" {
		return errCaptivePortalNoURL
	}
	// Initial probe.
	s.probe(ctx, bus)

	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.probe(ctx, bus)
		}
	}
}

var errCaptivePortalNoURL = errNoURL{}

type errNoURL struct{}

func (errNoURL) Error() string { return "reach/events: captive portal source requires a URL" }

// Close is a no-op; ctx cancellation is the lifecycle signal.
func (s *CaptivePortalSource) Close() error { return nil }

func (s *CaptivePortalSource) probe(ctx context.Context, bus *Bus) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		s.transition(bus, captivePresent, "network_error: "+err.Error())
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	switch {
	case resp.StatusCode == http.StatusNoContent:
		s.transition(bus, captiveClear, "http_204")
	case resp.StatusCode == http.StatusOK && len(strings.TrimSpace(string(body))) == 0:
		s.transition(bus, captiveClear, "http_200_empty")
	default:
		s.transition(bus, captivePresent, "http_other")
	}
}

func (s *CaptivePortalSource) transition(bus *Bus, new captiveState, detail string) {
	s.mu.Lock()
	prev := s.state
	s.state = new
	s.mu.Unlock()
	if prev == new {
		return
	}
	switch new {
	case captiveClear:
		bus.Publish(Event{Source: SourceRouteChange, Detail: "captive_portal_clear:" + detail})
	case captivePresent:
		bus.Publish(Event{Source: SourceRouteChange, Detail: "captive_portal_present:" + detail})
	}
}
