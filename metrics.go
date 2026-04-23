// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import "time"

// Metrics is the observability surface for the publisher. Consumers plug in
// Prometheus (or any other backend) by implementing this interface. The
// package ships NullMetrics for callers that don't care.
type Metrics interface {
	PublishAttempt(reason PublishReason)
	PublishSkipped(reason SkipReason)
	PublishSucceeded(bytes int)
	PublishFailed(err error)

	DiscovererRun(name string, duration time.Duration, addrs int, err error)

	AddressVerified(source AddressSource, family Family)
	AddressVerifyFailed(source AddressSource, family Family)
	AddressExpired(source AddressSource)
	AddressRTT(source AddressSource, family Family, region string, rtt time.Duration)

	SignatureInvalid()
	RateLimited(nodeID string)
	TombstonePublished(reason string)
	FreshnessDigestMismatch(peer string)
	HLCSkewMicros(deltaMicros int64)
	ReflectionQuorum(observed int, required int)
	DeltaPublished(opsCount int)
	DeltaSnapshotForced(reason string)
}

// PublishReason describes why a publish was attempted.
type PublishReason string

const (
	PublishReasonTimer     PublishReason = "timer"
	PublishReasonChange    PublishReason = "change"
	PublishReasonEvent     PublishReason = "event"
	PublishReasonEpoch     PublishReason = "epoch"
	PublishReasonTombstone PublishReason = "tombstone"
	PublishReasonBootstrap PublishReason = "bootstrap"
)

// SkipReason describes why a publish was skipped.
type SkipReason string

const (
	SkipDigestMatch    SkipReason = "digest_match"
	SkipRateLimit      SkipReason = "rate_limit"
	SkipNoPublicAddr   SkipReason = "no_public_addr"
	SkipEmptyAddrSet   SkipReason = "empty_addrs"
	SkipShutdownMode   SkipReason = "shutting_down"
)

// NullMetrics is a no-op implementation for callers that don't care.
type NullMetrics struct{}

func (NullMetrics) PublishAttempt(PublishReason)                       {}
func (NullMetrics) PublishSkipped(SkipReason)                          {}
func (NullMetrics) PublishSucceeded(int)                               {}
func (NullMetrics) PublishFailed(error)                                {}
func (NullMetrics) DiscovererRun(string, time.Duration, int, error)    {}
func (NullMetrics) AddressVerified(AddressSource, Family)              {}
func (NullMetrics) AddressVerifyFailed(AddressSource, Family)          {}
func (NullMetrics) AddressExpired(AddressSource)                       {}
func (NullMetrics) AddressRTT(AddressSource, Family, string, time.Duration) {}
func (NullMetrics) SignatureInvalid()                                  {}
func (NullMetrics) RateLimited(string)                                 {}
func (NullMetrics) TombstonePublished(string)                          {}
func (NullMetrics) FreshnessDigestMismatch(string)                     {}
func (NullMetrics) HLCSkewMicros(int64)                                {}
func (NullMetrics) ReflectionQuorum(int, int)                          {}
func (NullMetrics) DeltaPublished(int)                                 {}
func (NullMetrics) DeltaSnapshotForced(string)                         {}
