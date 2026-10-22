package discovery

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/1303-yzym/mdns-go/internal/model"
	"github.com/1303-yzym/mdns-go/internal/scan"
)

// /24 x 1-10000 is 2,540,000 targets and must be streamed, not rejected.
func TestScanNetworkAcceptsLargeHostPortProduct(t *testing.T) {
	// RFC 5737 TEST-NET-1: routable nowhere, so nothing should answer.
	_, network, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	ports := make([]int, 0, 10000)
	for port := 1; port <= 10000; port++ {
		ports = append(ports, port)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	// The environment may funnel TCP through a transparent gateway, so only
	// the rejection behaviour is asserted here.
	if _, err := scanNetwork(ctx, nil, network, ports, 20*time.Millisecond); err != nil {
		t.Fatalf("large scan was rejected: %v", err)
	}
}

func TestProbeContextIsIndependentOfMDNSWindow(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			conn.Close()
		}
	}()

	options := Options{Timeout: 300 * time.Millisecond}
	ctx, cancel := probeContext(context.Background(), options)
	defer cancel()
	assets := scan.ProbeAssets(ctx, []model.Asset{{IP: "127.0.0.1", Host: "127.0.0.1", Port: port}}, options.Timeout)
	if len(assets) != 1 {
		t.Fatalf("open port %d was dropped, got %d assets", port, len(assets))
	}
}

func TestProbeContextHonoursOptionalScanBudget(t *testing.T) {
	options := Options{Timeout: 50 * time.Millisecond, ScanTimeout: 20 * time.Millisecond}
	ctx, cancel := probeContext(context.Background(), options)
	defer cancel()
	time.Sleep(40 * time.Millisecond)
	if ctx.Err() == nil {
		t.Fatal("expected -scan-timeout budget to expire")
	}
}

func TestScanNetworkStopsOnCancelledContext(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.0.2.0/24")
	ports := make([]int, 0, 2000)
	for port := 1; port <= 2000; port++ {
		ports = append(ports, port)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = scanNetwork(ctx, nil, network, ports, 10*time.Millisecond)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("scanNetwork did not stop after cancellation")
	}
}

// Portless entries (device-info) bypass probing but still reach the output.
func TestScanNetworkKeepsPortlessAssets(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.0.2.0/30")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	assets, err := scanNetwork(ctx, []model.Asset{{IP: "192.0.2.1", Service: "device-info", Name: "nas", Port: 0}}, network, []int{9}, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, asset := range assets {
		if asset.Service == "device-info" {
			found = true
		}
	}
	if !found {
		t.Fatalf("device-info asset dropped: %#v", assets)
	}
}
