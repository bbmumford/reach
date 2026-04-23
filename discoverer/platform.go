// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package discoverer

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/bbmumford/reach"
)

// Platform produces addresses derived from platform-specific sources:
//
//   - Fly.io   : $FLY_PUBLIC_IP directly (authoritative, skip DNS)
//   - AWS      : IMDSv2 at http://169.254.169.254/latest/meta-data/public-ipv4
//   - GCP      : metadata.google.internal at /computeMetadata/v1/instance/.../external-ip
//   - k8s      : downward API env vars ($POD_IP, $HOST_IP)
//   - dev      : nothing (no-op)
type Platform struct {
	Base
	provider string
	udpPort  uint16
	client   *http.Client
}

// NewPlatform constructs a platform-aware discoverer. provider must match
// host.PlatformInfo.Provider() — "fly", "aws", "gcp", "k8s", or "".
func NewPlatform(provider string, udpPort uint16) *Platform {
	return &Platform{
		Base: Base{
			NameValue:     "platform:" + provider,
			SourceValue:   platformSource(provider),
			IntervalValue: 30 * time.Minute,
			EnabledValue:  AllProviders,
		},
		provider: provider,
		udpPort:  udpPort,
		client:   &http.Client{Timeout: 2 * time.Second},
	}
}

func platformSource(provider string) reach.AddressSource {
	switch provider {
	case "fly":
		return reach.SrcPlatformEnv
	case "aws", "gcp":
		return reach.SrcIMDS
	case "k8s":
		return reach.SrcK8sDownward
	default:
		return reach.SrcPlatformEnv
	}
}

// Discover routes to the per-provider implementation.
func (p *Platform) Discover(ctx context.Context) ([]reach.Address, error) {
	switch p.provider {
	case "fly":
		return p.discoverFly(), nil
	case "aws":
		return p.discoverAWS(ctx), nil
	case "gcp":
		return p.discoverGCP(ctx), nil
	case "k8s":
		return p.discoverK8s(), nil
	default:
		return nil, nil
	}
}

func (p *Platform) discoverFly() []reach.Address {
	// Fly surfaces the anycast public IP via env. The hostname is resolved
	// by the DNS discoverer if configured; we just emit the direct IP here
	// so peers have an address even before DNS lookup completes.
	ip := os.Getenv("FLY_PUBLIC_IP")
	if ip == "" {
		return nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}
	family := reach.FamilyIPv6
	if parsed.To4() != nil {
		family = reach.FamilyIPv4
	}
	now := time.Now()

	tags := []string{"fly"}
	if app := os.Getenv("FLY_APP_NAME"); app != "" {
		tags = append(tags, "fly:app="+app)
	}
	if machine := os.Getenv("FLY_MACHINE_ID"); machine != "" {
		tags = append(tags, "fly:machine="+machine)
	}
	return []reach.Address{{
		Host:         ip,
		Port:         p.udpPort,
		Proto:        "udp",
		Scope:        reach.ScopePublic,
		Family:       family,
		Source:       reach.SrcPlatformEnv,
		Confidence:   90,
		FirstSeen:    now,
		Capabilities: reach.CapDedicated,
		Tags:         tags,
	}}
}

func (p *Platform) discoverAWS(ctx context.Context) []reach.Address {
	// IMDSv2 requires a token-driven exchange.
	token, err := p.awsIMDSToken(ctx)
	if err != nil || token == "" {
		return nil
	}
	ipv4, _ := p.imdsGet(ctx, "http://169.254.169.254/latest/meta-data/public-ipv4", map[string]string{
		"X-aws-ec2-metadata-token": token,
	})
	if ipv4 == "" {
		return nil
	}
	parsed := net.ParseIP(ipv4)
	if parsed == nil {
		return nil
	}
	return []reach.Address{{
		Host:       ipv4,
		Port:       p.udpPort,
		Proto:      "udp",
		Scope:      reach.ScopePublic,
		Family:     reach.FamilyIPv4,
		Source:     reach.SrcIMDS,
		Confidence: 85,
		FirstSeen:  time.Now(),
		Tags:       []string{"aws"},
	}}
}

func (p *Platform) awsIMDSToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		"http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (p *Platform) discoverGCP(ctx context.Context) []reach.Address {
	ip, _ := p.imdsGet(ctx,
		"http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip",
		map[string]string{"Metadata-Flavor": "Google"})
	if ip == "" {
		return nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}
	return []reach.Address{{
		Host:       ip,
		Port:       p.udpPort,
		Proto:      "udp",
		Scope:      reach.ScopePublic,
		Family:     reach.FamilyIPv4,
		Source:     reach.SrcIMDS,
		Confidence: 85,
		FirstSeen:  time.Now(),
		Tags:       []string{"gcp"},
	}}
}

func (p *Platform) discoverK8s() []reach.Address {
	podIP := os.Getenv("POD_IP")
	hostIP := os.Getenv("HOST_IP")
	now := time.Now()
	var out []reach.Address

	if podIP != "" {
		if parsed := net.ParseIP(podIP); parsed != nil {
			family := reach.FamilyIPv6
			if parsed.To4() != nil {
				family = reach.FamilyIPv4
			}
			out = append(out, reach.Address{
				Host:       podIP,
				Port:       p.udpPort,
				Proto:      "udp",
				Scope:      reach.ScopeOrg, // cluster-internal
				Family:     family,
				Source:     reach.SrcK8sDownward,
				Confidence: 85,
				FirstSeen:  now,
				Tags:       []string{"k8s:pod"},
			})
		}
	}
	if hostIP != "" {
		if parsed := net.ParseIP(hostIP); parsed != nil {
			family := reach.FamilyIPv6
			if parsed.To4() != nil {
				family = reach.FamilyIPv4
			}
			out = append(out, reach.Address{
				Host:       hostIP,
				Port:       p.udpPort,
				Proto:      "udp",
				Scope:      reach.ScopePublic, // host network often routable
				Family:     family,
				Source:     reach.SrcK8sDownward,
				Confidence: 75,
				FirstSeen:  now,
				Tags:       []string{"k8s:host"},
			})
		}
	}
	return out
}

func (p *Platform) imdsGet(ctx context.Context, url string, headers map[string]string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
