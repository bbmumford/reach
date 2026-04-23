// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

// Package reach implements the self-reach publisher for peer-to-peer meshes.
//
// Every node runs a Publisher that gathers its own reachable addresses from
// a pluggable set of Discoverers (DNS, STUN, TURN, cloud metadata, interface
// enumeration, peer reflection), signs the result with Ed25519, and writes a
// ReachRecord to the distributed ledger. Peers learn how to dial each other
// without any central directory.
//
// The publisher is self-healing: it skips publishes when the canonical digest
// of the address set has not changed, adapts its cadence to churn, and reacts
// to platform network-change events immediately rather than waiting for the
// next tick.
package reach
