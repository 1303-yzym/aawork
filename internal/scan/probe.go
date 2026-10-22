package scan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/1303-yzym/mdns-go/internal/model"
)

// ProbeAsset dials one target, negotiates TLS when the service speaks it, and
// records the banner plus protocol details on the asset.
func ProbeAsset(ctx context.Context, asset *model.Asset, timeout time.Duration) {
	address := net.JoinHostPort(asset.IP, strconv.Itoa(asset.Port))
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		asset.Probe = &model.ProbeResult{Protocol: ProtocolFor(asset.Port, asset.Service), Status: probeStatus(err)}
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	protocol := ProtocolFor(asset.Port, asset.Service)
	result := &model.ProbeResult{Protocol: protocol, Status: "open"}
	// ProtocolFor reports "https", so both names must be accepted here; the
	// original "tls" check never matched and left HTTPS probed as plaintext.
	if protocol == "https" || protocol == "tls" {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: tlsServerName(asset)})
		if err := tlsConn.Handshake(); err != nil {
			result.Status = probeStatus(err)
			asset.Probe = result
			return
		}
		conn = tlsConn
		state := tlsConn.ConnectionState()
		result.TLS = &model.TLSInfo{
			Version:    tls.VersionName(state.Version),
			Cipher:     tls.CipherSuiteName(state.CipherSuite),
			Negotiated: state.NegotiatedProtocol,
		}
		if len(state.PeerCertificates) > 0 {
			leaf := state.PeerCertificates[0]
			result.TLS.Subject = leaf.Subject.String()
			result.TLS.Issuer = leaf.Issuer.String()
			result.TLS.DNSNames = leaf.DNSNames
			result.TLS.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
		}
	}
	if protocol == "http" || protocol == "https" {
		host := asset.Hostname
		if host == "" {
			host = asset.IP
		}
		_, _ = fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	}
	if protocol == "smb" {
		if _, err := conn.Write(smbNegotiateRequest()); err != nil {
			result.Status = probeStatus(err)
			asset.Probe = result
			return
		}
	}
	buffer := make([]byte, 4096)
	n, _ := conn.Read(buffer)
	if n == 0 {
		result.Success = true
		asset.Probe = result
		return
	}
	result.Success = true
	result.Banner = strings.TrimSpace(string(buffer[:n]))
	asset.Banner = result.Banner
	if protocol == "http" || protocol == "https" {
		result.Headers = ParseHTTPHeaders(result.Banner)
	}
	asset.Probe = result
}

// tlsServerName returns SNI only for real DNS names; dialing an IP literal as
// ServerName breaks verification and SNI for some servers.
func tlsServerName(asset *model.Asset) string {
	name := asset.Hostname
	if name == "" {
		name = asset.Host
	}
	if name == "" {
		name = asset.IP
	}
	if net.ParseIP(name) != nil {
		return ""
	}
	return strings.TrimSuffix(name, ".")
}

func probeStatus(err error) string {
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "timeout"
	}
	return "closed"
}
