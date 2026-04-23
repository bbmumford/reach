// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"sync"
	"time"
)

// RegionRTTTracker aggregates prober RTT samples by (address, observer-region)
// so the publisher can compute adaptive RegionPriority maps on every tick.
//
// The tracker is strictly passive accounting — consumers call Record() from
// their prober layer on every successful REACH_VERIFY response.
type RegionRTTTracker struct {
	mu      sync.Mutex
	samples map[string]map[string]*rttWindow // addrKey -> region -> window
	window  time.Duration                    // retention
}

type rttWindow struct {
	Samples    []rttSample
	LastPruned time.Time
}

type rttSample struct {
	RTT time.Duration
	At  time.Time
}

// NewRegionRTTTracker creates a tracker with the given retention window.
// Pass 0 for a 10-minute default.
func NewRegionRTTTracker(window time.Duration) *RegionRTTTracker {
	if window <= 0 {
		window = 10 * time.Minute
	}
	return &RegionRTTTracker{
		samples: make(map[string]map[string]*rttWindow),
		window:  window,
	}
}

// Record ingests a single RTT observation.
// addrKey is typically Address.Key(); observerRegion is the caller's Region()
// at the time of measurement.
func (t *RegionRTTTracker) Record(addrKey, observerRegion string, rtt time.Duration) {
	if rtt <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	regionMap := t.samples[addrKey]
	if regionMap == nil {
		regionMap = make(map[string]*rttWindow)
		t.samples[addrKey] = regionMap
	}
	w := regionMap[observerRegion]
	if w == nil {
		w = &rttWindow{}
		regionMap[observerRegion] = w
	}
	w.Samples = append(w.Samples, rttSample{RTT: rtt, At: time.Now()})
	t.pruneLocked(w)
}

// PriorityFor returns an adaptive RegionPriority map for addrKey.
// Regions with lower median RTT get higher preference (max 100).
// Unknown regions default to 50.
func (t *RegionRTTTracker) PriorityFor(addrKey string) map[string]uint8 {
	t.mu.Lock()
	defer t.mu.Unlock()

	regionMap := t.samples[addrKey]
	if len(regionMap) == 0 {
		return nil
	}

	// Compute median per region.
	medians := make(map[string]time.Duration, len(regionMap))
	var minRTT, maxRTT time.Duration
	for region, w := range regionMap {
		t.pruneLocked(w)
		if len(w.Samples) == 0 {
			continue
		}
		m := medianRTT(w.Samples)
		medians[region] = m
		if minRTT == 0 || m < minRTT {
			minRTT = m
		}
		if m > maxRTT {
			maxRTT = m
		}
	}
	if len(medians) == 0 {
		return nil
	}

	// Normalize: best region = 100, worst = 30.
	priorities := make(map[string]uint8, len(medians)+1)
	for region, m := range medians {
		if maxRTT == minRTT {
			priorities[region] = 100
			continue
		}
		// Linear interpolation in [30, 100], inverted so low RTT → high priority.
		pct := float64(m-minRTT) / float64(maxRTT-minRTT)
		score := uint8(100 - pct*70)
		priorities[region] = score
	}
	priorities["*"] = 50
	return priorities
}

func (t *RegionRTTTracker) pruneLocked(w *rttWindow) {
	now := time.Now()
	cutoff := now.Add(-t.window)
	kept := w.Samples[:0]
	for _, s := range w.Samples {
		if s.At.After(cutoff) {
			kept = append(kept, s)
		}
	}
	w.Samples = kept
	w.LastPruned = now
}

// medianRTT returns the median of a sample list.
func medianRTT(samples []rttSample) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	vals := make([]time.Duration, len(samples))
	for i, s := range samples {
		vals[i] = s.RTT
	}
	// Small n — insertion sort.
	for i := 1; i < len(vals); i++ {
		for j := i; j > 0 && vals[j-1] > vals[j]; j-- {
			vals[j-1], vals[j] = vals[j], vals[j-1]
		}
	}
	mid := len(vals) / 2
	if len(vals)%2 == 1 {
		return vals[mid]
	}
	return (vals[mid-1] + vals[mid]) / 2
}
