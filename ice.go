// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package reach

import (
	"github.com/pion/ice/v3"
)

// BuildICECandidates converts a slice of reach.Address values into RFC 8445
// ICE candidate lines, ready to include in ReachRecord.ICECandidates.
//
// The mapping is:
//
//   Scope=private, Source=interface | k8s-pod  → host candidate
//   Scope=public,  Source=stun                 → server-reflexive
//   Scope=public,  Source=turn                 → relay
//   Scope=public,  Source=dns | env | imds     → host candidate (dedicated IP)
//
// Unmappable entries are skipped silently. Returns marshaled SDP candidate
// strings (empty slice when nothing maps — which is fine for non-ICE peers).
func BuildICECandidates(addrs []Address) []string {
	var out []string
	foundations := map[string]string{} // per-type foundation counters

	for _, a := range addrs {
		if a.Port == 0 || a.Host == "" {
			continue
		}
		network := "udp"
		if a.Proto != "udp" && a.Proto != "quic" {
			// ICE spec traditionally works over UDP; skip non-UDP for now.
			continue
		}

		cType := classifyCandidate(a)
		if cType == "" {
			continue
		}

		foundation := foundations[cType]
		if foundation == "" {
			foundation = cType[:1] + "1"
		}
		foundations[cType] = bumpFoundation(foundation)

		var cand ice.Candidate
		var err error

		switch cType {
		case "host":
			cand, err = ice.NewCandidateHost(&ice.CandidateHostConfig{
				Network:    network,
				Address:    a.Host,
				Port:       int(a.Port),
				Component:  1,
				Foundation: foundation,
			})
		case "srflx":
			cand, err = ice.NewCandidateServerReflexive(&ice.CandidateServerReflexiveConfig{
				Network:    network,
				Address:    a.Host,
				Port:       int(a.Port),
				Component:  1,
				Foundation: foundation,
			})
		case "relay":
			cand, err = ice.NewCandidateRelay(&ice.CandidateRelayConfig{
				Network:    network,
				Address:    a.Host,
				Port:       int(a.Port),
				Component:  1,
				Foundation: foundation,
				RelAddr:    "0.0.0.0",
				RelPort:    0,
			})
		}
		if err != nil || cand == nil {
			continue
		}
		out = append(out, cand.Marshal())
	}
	return out
}

// classifyCandidate maps a reach.Address to an ICE candidate type string.
func classifyCandidate(a Address) string {
	switch a.Source {
	case SrcSTUN, SrcReflection:
		return "srflx"
	case SrcTURN:
		return "relay"
	case SrcInterface, SrcStatic, SrcDNS, SrcPlatformEnv, SrcIMDS, SrcK8sDownward:
		return "host"
	}
	return ""
}

// bumpFoundation increments the numeric suffix of "H1" → "H2" etc.
// Best effort — on overflow just returns the input unchanged.
func bumpFoundation(f string) string {
	if len(f) < 2 {
		return f
	}
	prefix := f[:1]
	var n int
	for _, c := range f[1:] {
		if c < '0' || c > '9' {
			return f
		}
		n = n*10 + int(c-'0')
	}
	n++
	return prefix + itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
