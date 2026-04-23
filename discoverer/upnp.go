// Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. Licensed under MIT.

package discoverer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/bbmumford/reach"
)

// UPnP discovers the node's external IP via an IGDv1 / IGDv2 router using
// SSDP + the WANIPConnection:1 SOAP action GetExternalIPAddress. Also
// attempts a port-mapping via AddPortMapping so the mesh UDP port is
// reachable from the public internet.
//
// Intended for home / small-office networks where no fleet STUN server is
// available but the local router speaks UPnP. No-op on enterprise networks
// (SSDP blocked) and on cloud providers (no router).
type UPnP struct {
	Base
	udpPort         uint16
	portMapTTL      time.Duration
	discoverTimeout time.Duration
}

// NewUPnP constructs a UPnP discoverer for the given UDP port.
func NewUPnP(udpPort uint16) *UPnP {
	return &UPnP{
		Base: Base{
			NameValue:     "upnp",
			SourceValue:   reach.SrcUPnP,
			IntervalValue: 15 * time.Minute,
			EnabledValue:  Only("dev", ""), // home/dev only; no-op on cloud
		},
		udpPort:         udpPort,
		portMapTTL:      1 * time.Hour,
		discoverTimeout: 2 * time.Second,
	}
}

// Discover performs an SSDP M-SEARCH for the IGD service and, if found,
// queries the control URL for GetExternalIPAddress and attempts an
// AddPortMapping for our UDP port.
func (u *UPnP) Discover(ctx context.Context) ([]reach.Address, error) {
	controlURL, err := u.discoverIGDControlURL(ctx)
	if err != nil || controlURL == "" {
		return nil, nil
	}
	externalIP, err := u.getExternalIP(ctx, controlURL)
	if err != nil || externalIP == "" {
		return nil, nil
	}

	// Port-map attempt is best-effort — a router that doesn't allow it
	// still gives us the external IP for reflexive purposes.
	_ = u.addPortMapping(ctx, controlURL, u.udpPort)

	family := reach.FamilyIPv6
	if parsed := net.ParseIP(externalIP); parsed != nil && parsed.To4() != nil {
		family = reach.FamilyIPv4
	}
	return []reach.Address{{
		Host:         externalIP,
		Port:         u.udpPort,
		Proto:        "udp",
		Scope:        reach.ScopePublic,
		Family:       family,
		Source:       reach.SrcUPnP,
		Confidence:   50, // router said so; still unverified by peer probe
		FirstSeen:    time.Now(),
		Capabilities: reach.CapPortMapping,
		Tags:         []string{"upnp:" + controlURL},
	}}, nil
}

// discoverIGDControlURL sends an SSDP M-SEARCH for InternetGatewayDevice:1
// and parses the LOCATION header to find the device description URL, then
// follows it to find the WANIPConnection service's controlURL.
func (u *UPnP) discoverIGDControlURL(ctx context.Context) (string, error) {
	ssdpAddr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	if err != nil {
		return "", err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return "", err
	}
	defer conn.Close()

	msearch := strings.Join([]string{
		"M-SEARCH * HTTP/1.1",
		"HOST: 239.255.255.250:1900",
		"MAN: \"ssdp:discover\"",
		"MX: 2",
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		"", "",
	}, "\r\n")
	if _, err := conn.WriteTo([]byte(msearch), ssdpAddr); err != nil {
		return "", err
	}

	deadline, _ := ctx.Deadline()
	if deadline.IsZero() {
		deadline = time.Now().Add(u.discoverTimeout)
	}
	_ = conn.SetReadDeadline(deadline)

	buf := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return "", err
		}
		if desc := parseSSDPLocation(buf[:n]); desc != "" {
			return u.findWANIPConnectionControlURL(ctx, desc)
		}
	}
}

var locationRE = regexp.MustCompile(`(?i)LOCATION:\s*([^\r\n]+)`)

func parseSSDPLocation(data []byte) string {
	m := locationRE.FindSubmatch(data)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

// findWANIPConnectionControlURL fetches the device description and returns
// the WANIPConnection:1 controlURL. XML parsing is done with regexp to
// avoid pulling in encoding/xml for a simple one-shot use.
var (
	serviceBlockRE  = regexp.MustCompile(`(?is)<service>(.*?)</service>`)
	serviceTypeRE   = regexp.MustCompile(`(?is)<serviceType>([^<]+)</serviceType>`)
	controlURLRE    = regexp.MustCompile(`(?is)<controlURL>([^<]+)</controlURL>`)
	wanIPServiceType = "urn:schemas-upnp-org:service:WANIPConnection:1"
)

func (u *UPnP) findWANIPConnectionControlURL(ctx context.Context, descURL string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, u.discoverTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, descURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Find the <service> block whose <serviceType> is WANIPConnection:1.
	for _, svc := range serviceBlockRE.FindAllSubmatch(body, -1) {
		if len(svc) < 2 {
			continue
		}
		tm := serviceTypeRE.FindSubmatch(svc[1])
		if len(tm) < 2 {
			continue
		}
		if strings.TrimSpace(string(tm[1])) != wanIPServiceType {
			continue
		}
		cm := controlURLRE.FindSubmatch(svc[1])
		if len(cm) < 2 {
			return "", nil
		}
		control := strings.TrimSpace(string(cm[1]))
		// Control URL may be relative — resolve against the description URL.
		if strings.HasPrefix(control, "/") {
			if i := strings.Index(descURL, "://"); i >= 0 {
				rest := descURL[i+3:]
				if j := strings.Index(rest, "/"); j >= 0 {
					return descURL[:i+3] + rest[:j] + control, nil
				}
			}
		}
		return control, nil
	}
	return "", nil
}

// getExternalIP issues a SOAP GetExternalIPAddress request against the
// control URL.
func (u *UPnP) getExternalIP(ctx context.Context, controlURL string) (string, error) {
	envelope := `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
  s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
 <s:Body>
  <u:GetExternalIPAddress xmlns:u="` + wanIPServiceType + `" />
 </s:Body>
</s:Envelope>`
	reqCtx, cancel := context.WithTimeout(ctx, u.discoverTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, controlURL,
		bytes.NewBufferString(envelope))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s#GetExternalIPAddress"`, wanIPServiceType))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	m := regexp.MustCompile(`(?is)<NewExternalIPAddress>([^<]+)</NewExternalIPAddress>`).FindSubmatch(body)
	if len(m) < 2 {
		return "", nil
	}
	return strings.TrimSpace(string(m[1])), nil
}

// addPortMapping installs a UDP port-forward from the router's external port
// to our UDP port for `u.portMapTTL`. Best-effort — many consumer routers
// require manual approval or silently ignore the request.
func (u *UPnP) addPortMapping(ctx context.Context, controlURL string, port uint16) error {
	envelope := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
  s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
 <s:Body>
  <u:AddPortMapping xmlns:u="%s">
    <NewRemoteHost></NewRemoteHost>
    <NewExternalPort>%d</NewExternalPort>
    <NewProtocol>UDP</NewProtocol>
    <NewInternalPort>%d</NewInternalPort>
    <NewInternalClient>%s</NewInternalClient>
    <NewEnabled>1</NewEnabled>
    <NewPortMappingDescription>reach</NewPortMappingDescription>
    <NewLeaseDuration>%d</NewLeaseDuration>
  </u:AddPortMapping>
 </s:Body>
</s:Envelope>`, wanIPServiceType, port, port, u.localIPv4(), int(u.portMapTTL.Seconds()))

	reqCtx, cancel := context.WithTimeout(ctx, u.discoverTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, controlURL,
		bytes.NewBufferString(envelope))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s#AddPortMapping"`, wanIPServiceType))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// localIPv4 returns the node's first non-loopback IPv4 address — the
// UPnP router wants an address within its LAN to forward to.
func (u *UPnP) localIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
					return ip4.String()
				}
			}
		}
	}
	return "127.0.0.1"
}
