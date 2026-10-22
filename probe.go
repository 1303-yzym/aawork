package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

func probeAssets(ctx context.Context, assets []Asset, timeout time.Duration) []Asset {
	workers := 128
	if len(assets) < workers {
		workers = len(assets)
	}
	if workers == 0 {
		return nil
	}
	jobs := make(chan *Asset)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for asset := range jobs {
				probeAsset(ctx, asset, timeout)
			}
		}()
	}
send:
	for i := range assets {
		select {
		case jobs <- &assets[i]:
		case <-ctx.Done():
			break send
		}
	}
	close(jobs)
	wg.Wait()
	open := assets[:0]
	for _, asset := range assets {
		if asset.Discovered {
			open = append(open, asset)
		} else if asset.Probe != nil && asset.Probe.Success {
			open = append(open, asset)
		}
	}
	return open
}

func probeAsset(ctx context.Context, asset *Asset, timeout time.Duration) {
	address := net.JoinHostPort(asset.IP, strconv.Itoa(asset.Port))
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		asset.Probe = &ProbeResult{Protocol: protocolFor(asset.Port, asset.Service), Status: probeStatus(err)}
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	protocol := protocolFor(asset.Port, asset.Service)
	result := &ProbeResult{Protocol: protocol, Status: "open"}
	// protocolFor reports "https", so both names must be accepted here; the
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
		result.TLS = &TLSInfo{
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
		_, _ = fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", firstNonEmpty(asset.Hostname, asset.IP))
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
		result.Headers = parseHTTPHeaders(result.Banner)
	}
	asset.Probe = result
}

// tlsServerName returns SNI only for real DNS names; dialing an IP literal as
// ServerName breaks verification and SNI for some servers.
func tlsServerName(asset *Asset) string {
	name := firstNonEmpty(asset.Hostname, asset.Host, asset.IP)
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

func smbNegotiateRequest() []byte {
	// NetBIOS session packet + SMB2 NEGOTIATE request (dialects 2.0.2,
	// 2.1, 3.0, 3.0.2 and 3.1.1).
	p := make([]byte, 4+64+46)
	copy(p[4:], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(p[68:70], 36)
	binary.LittleEndian.PutUint16(p[70:72], 5)
	copy(p[4+64+36:], []byte{0x02, 0x02, 0x10, 0x02, 0x22, 0x02, 0x24, 0x02, 0x02, 0x03})
	length := uint32(len(p) - 4)
	p[1] = byte(length >> 16)
	p[2] = byte(length >> 8)
	p[3] = byte(length)
	return p
}

func protocolFor(port int, service string) string {
	s := strings.ToLower(service)
	switch {
	case strings.Contains(s, "https") || port == 443 || port == 8443:
		return "https"
	case strings.Contains(s, "qdiscover"):
		return "qdiscover"
	case strings.Contains(s, "afpovertcp") || port == 548:
		return "afp"
	case strings.Contains(s, "http") || port == 80 || port == 8080 || port == 5000:
		return "http"
	case strings.Contains(s, "ssh") || port == 22:
		return "ssh"
	case strings.Contains(s, "ftp") || port == 21:
		return "ftp"
	case strings.Contains(s, "smb") || port == 139 || port == 445:
		return "smb"
	default:
		return "tcp"
	}
}

func serviceForPort(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 80, 8080:
		return "http"
	case 139, 445:
		return "smb"
	case 548:
		return "afp"
	case 443, 8443:
		return "https"
	default:
		return "tcp"
	}
}

func parseHTTPHeaders(banner string) map[string]string {
	headers := map[string]string{}
	lines := strings.Split(banner, "\n")
	for _, line := range lines[1:] {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok {
			headers[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return headers
}
