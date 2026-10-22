package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProbeAssetsOmitsClosedPorts(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			conn.Close()
		}
	}()
	assets := probeAssets(context.Background(), []Asset{
		{IP: "127.0.0.1", Host: "127.0.0.1", Port: port},
		{IP: "127.0.0.1", Host: "127.0.0.1", Port: 1},
	}, 200*time.Millisecond)
	if len(assets) != 1 || assets[0].Port != port {
		t.Fatalf("got probed assets %#v", assets)
	}
}

func TestParseHTTPHeaders(t *testing.T) {
	headers := parseHTTPHeaders("HTTP/1.0 200 OK\r\nServer: example\r\nContent-Length: 0\r\n")
	if headers["Server"] != "example" || headers["Content-Length"] != "0" {
		t.Fatalf("unexpected headers: %#v", headers)
	}
}

func TestProtocolForExampleServices(t *testing.T) {
	for _, test := range []struct {
		service string
		port    int
		want    string
	}{
		{"qdiscover", 5000, "qdiscover"},
		{"afpovertcp", 548, "afp"},
		{"smb", 445, "smb"},
	} {
		if got := protocolFor(test.port, test.service); got != test.want {
			t.Errorf("protocolFor(%q, %d) = %q, want %q", test.service, test.port, got, test.want)
		}
	}
}

func TestHTTPSProbeNegotiatesTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "proof-tls")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	addr := server.Listener.Addr().(*net.TCPAddr)
	asset := Asset{IP: addr.IP.String(), Host: "127.0.0.1", Port: addr.Port, Service: "https"}
	assets := probeAssets(context.Background(), []Asset{asset}, 2*time.Second)
	if len(assets) != 1 {
		t.Fatal("HTTPS asset was dropped")
	}
	probe := assets[0].Probe
	// A plaintext HEAD against a TLS port yields the server's 400 diagnostic;
	// receiving a real 200 response proves the TLS branch executed.
	if strings.Contains(probe.Banner, "Client sent an HTTP request to an HTTPS server") {
		t.Fatalf("probe spoke plaintext HTTP to a TLS port: %q", probe.Banner)
	}
	if !strings.Contains(probe.Banner, "200") {
		t.Fatalf("unexpected HTTPS banner: %q", probe.Banner)
	}
	if probe.TLS == nil || probe.TLS.Version == "" {
		t.Fatalf("TLS details missing: %#v", probe.TLS)
	}
	if probe.Headers["Server"] != "proof-tls" {
		t.Fatalf("HTTP header not parsed: %#v", probe.Headers)
	}
}

func TestTLSServerNameSkipsIPLiterals(t *testing.T) {
	if got := tlsServerName(&Asset{IP: "192.168.1.10"}); got != "" {
		t.Errorf("IP literal used as SNI: %q", got)
	}
	if got := tlsServerName(&Asset{IP: "192.168.1.10", Hostname: "nas.local"}); got != "nas.local" {
		t.Errorf("hostname SNI = %q", got)
	}
}

func TestSMBNegotiateRequestShape(t *testing.T) {
	packet := smbNegotiateRequest()
	if len(packet) != 114 || string(packet[4:8]) != "\xfeSMB" {
		t.Fatalf("invalid SMB negotiate packet length/signature: %d %x", len(packet), packet[:8])
	}
	got := uint32(packet[1])<<16 | uint32(packet[2])<<8 | uint32(packet[3])
	if got != 110 {
		t.Fatalf("invalid NetBIOS length: %d", got)
	}
}
