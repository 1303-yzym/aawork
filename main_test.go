package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	ports, err := parsePorts("80,443,5000-5002,443")
	if err != nil {
		t.Fatalf("parsePorts returned error: %v", err)
	}
	want := []int{80, 443, 5000, 5001, 5002}
	if len(ports) != len(want) {
		t.Fatalf("got %v, want %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("got %v, want %v", ports, want)
		}
	}
}

func TestParsePortsRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{"0", "65536", "5-4", "abc", ""} {
		if _, err := parsePorts(input); err == nil {
			t.Errorf("parsePorts(%q) accepted invalid input", input)
		}
	}
}

func TestBuildQueryContainsPTRQuestions(t *testing.T) {
	packet := buildQuery([]string{"_http._tcp.local"}, false)
	records, err := parseDNSMessage(append(packet, 0, 0, 0, 0, 0, 0))
	if err != nil {
		t.Fatalf("parseDNSMessage returned error: %v", err)
	}

	if len(records) != 0 {
		t.Fatalf("query should not contain records: %v", records)
	}
	if !bytes.Contains(packet, []byte("_http")) {
		t.Fatalf("query does not contain service name: %x", packet)
	}
}

func TestParseDNSMessagePreservesRecordValues(t *testing.T) {
	packet := []byte{
		0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0,
		4, 'h', 'o', 's', 't', 5, 'l', 'o', 'c', 'a', 'l', 0,
		0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 192, 168, 1, 10,
		0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 10, 0, 16,
		0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 10, 0, 12,
		4, 'h', 'o', 's', 't', 5, 'l', 'o', 'c', 'a', 'l', 0,
		0xc0, 0x0c, 0, 33, 0, 1, 0, 0, 0, 10, 0, 8,
		0, 0, 0, 0, 0, 80, 0xc0, 0x0c,
	}
	records, err := parseDNSMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 4 {
		t.Fatalf("got %d records, want 4", len(records))
	}
	want := []struct {
		kind  uint16
		value string
		port  int
	}{
		{1, "192.168.1.10", 0},
		{28, "fe80::1", 0},
		{12, "host.local", 0},
		{33, "host.local", 80},
	}
	for i, expected := range want {
		if records[i].Type != expected.kind || records[i].Value != expected.value || records[i].Port != expected.port {
			t.Errorf("record %d = %#v, want type=%d value=%q port=%d", i, records[i], expected.kind, expected.value, expected.port)
		}
	}
}

func TestBuildQueryUnicastResponseBit(t *testing.T) {
	multicast := buildQuery([]string{"_http._tcp.local"}, false)
	unicast := buildQuery([]string{"_http._tcp.local"}, true)
	multicastClass := multicast[len(multicast)-4:]
	unicastClass := unicast[len(unicast)-4:]
	if multicastClass[2] != 0x00 || multicastClass[3] != 0x01 {
		t.Fatalf("multicast class = %x, want 0001", multicastClass[2:])
	}
	if unicastClass[2] != 0x80 || unicastClass[3] != 0x01 {
		t.Fatalf("unicast class = %x, want 8001", unicastClass[2:])
	}
}

// When 5353 is already owned the socket must fall back to an ephemeral port
// instead of losing mDNS discovery.
func TestOpenMDNSSocketFallsBackWhenPortBusy(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var iface *net.Interface
	for i := range interfaces {
		if interfaces[i].Flags&net.FlagUp != 0 {
			iface = &interfaces[i]
			break
		}
	}
	if iface == nil || interfaceIP(iface, false) == nil {
		t.Skip("no IPv4 interface available")
	}
	_, network, _ := net.ParseCIDR("192.168.1.0/24")

	blocker, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	busyPort := blocker.LocalAddr().(*net.UDPAddr).Port

	socket, err := openMDNSSocket(iface, network, busyPort)
	if err != nil {
		t.Fatalf("fallback failed: %v", err)
	}
	defer socket.conn.Close()
	if !socket.unicast {
		t.Fatal("expected unicast fallback when the mDNS port is occupied")
	}
	if socket.conn.LocalAddr().(*net.UDPAddr).Port == busyPort {
		t.Fatal("fallback reused the busy port")
	}
}

func TestInstanceName(t *testing.T) {
	got := instanceName("slw-nas._qdiscover._tcp.local", "qdiscover")
	if got != "slw-nas" {
		t.Fatalf("got %q, want %q", got, "slw-nas")
	}
}

func TestRenderTextIncludesDeepFields(t *testing.T) {
	var output strings.Builder
	err := renderText(&output, []Asset{{
		IP: "192.168.1.10", Port: 5000, Service: "qdiscover",
		Name: "slw-nas", Hostname: "slw-nas.local", TTL: 10,
		TXT: map[string]string{"model": "TS-464C"},
	}}, []string{"_qdiscover._tcp.local"}, true)
	if err != nil {
		t.Fatalf("renderText returned error: %v", err)
	}

	for _, expected := range []string{"5000/tcp qdiscover:", "IP=192.168.1.10", "Hostname=slw-nas.local", "model=TS-464C"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("output does not contain %q:\n%s", expected, output.String())
		}
	}
}

func TestJSONIncludesStableAssetFields(t *testing.T) {
	data, err := json.Marshal(ScanOutput{Services: []Asset{{
		IP: "127.0.0.1", Host: "example.local", Hostname: "example.local",
		Port: 443, Service: "https", Banner: "HTTP/1.1 200 OK",
	}}})
	if err != nil {
		t.Fatal(err)
	}

	text := string(data)
	for _, field := range []string{`"ip":"127.0.0.1"`, `"port":443`, `"host":"example.local"`, `"hostname":"example.local"`, `"service":"https"`, `"banner":"HTTP/1.1 200 OK"`} {
		if !strings.Contains(text, field) {
			t.Errorf("JSON missing %s: %s", field, text)
		}
	}
}

func TestFindIPv4ForName(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.1.0/24")
	records := []dnsRecord{{Name: "host.local", Type: 1, Value: "192.168.1.10"}}
	if got := findIPv4ForName(records, "host.local", network); got != "192.168.1.10" {
		t.Fatalf("got %q", got)
	}
}

func TestEnumerateHostsSkipsIPv4NetworkAndBroadcast(t *testing.T) {
	_, network, err := net.ParseCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	got := enumerateHosts(network)
	want := []string{"192.168.1.1", "192.168.1.2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestScanHostsCoversEveryHost(t *testing.T) {
	_, network, err := net.ParseCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := scanHosts(network)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(hosts, ",") != "192.168.1.1,192.168.1.2" {
		t.Fatalf("unexpected hosts: %v", hosts)
	}
}

func TestScanHostsRejectsHugeCIDR(t *testing.T) {
	_, network, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scanHosts(network); err == nil {
		t.Fatal("expected huge CIDR to be rejected")
	}
}

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
	assets := probeAssets(ctx, []Asset{{IP: "127.0.0.1", Host: "127.0.0.1", Port: port}}, options.Timeout)
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

func TestOfflineMDNSFixtureAssociatesServicesAndTXT(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.10.0/24")
	records := []dnsRecord{
		{Name: "_services._dns-sd._udp.local", Type: 12, Value: "_afpovertcp._tcp.local"},
		{Name: "nas.local", Type: 1, Value: "192.168.10.5", TTL: 120},
		{Name: "nas.local", Type: 28, Value: "fe80::1", TTL: 120},
		{Name: "NAS._afpovertcp._tcp.local", Type: 33, Value: "nas.local", Port: 548},
		{Name: "NAS._afpovertcp._tcp.local", Type: 16, TXT: map[string]string{"device": "NAS", "mac": "24:5e:be:69:a3:13"}},
		{Name: "NAS._qdiscover._tcp.local", Type: 16, TXT: map[string]string{"model": "TS-464C", "firmware": "1.0"}},
		{Name: "_device-info._tcp.local", Type: 12, Value: "NAS(AFP)._device-info._tcp.local"},
	}
	assets := buildAssets([]mdnsResult{{Records: records}}, network, []int{548})
	var afp Asset
	for _, asset := range assets {
		if asset.Service == "afpovertcp" {
			afp = asset
		}
	}
	if afp.Service == "" {
		t.Fatalf("unexpected AFP assets: %#v", assets)
	}
	if afp.TXT["device"] != "NAS" || afp.MAC != "24:5e:be:69:a3:13" {
		t.Fatalf("AFP TXT was not merged: %#v", afp.TXT)
	}
	if _, leaked := afp.TXT["model"]; leaked {
		t.Fatalf("qdiscover TXT leaked into AFP: %#v", afp.TXT)
	}
	if len(afp.IPv4) != 1 || len(afp.IPv6) != 1 || afp.Name != "NAS(AFP)" {
		t.Fatalf("identity was not aggregated: %#v", afp)
	}
	var out strings.Builder
	if err := renderText(&out, assets, []string{"_afpovertcp._tcp.local"}, true); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"548/tcp afpovertcp:", "IP=192.168.10.5", "device=NAS"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("golden output missing %q:\n%s", want, out.String())
		}
	}
}

func TestBuildAssetsKeepsMultipleServicesAndDeviceInfo(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.10.0/24")
	records := []dnsRecord{
		{Name: "nas.local", Type: 1, Value: "192.168.10.5"},
		{Name: "NAS._http._tcp.local", Type: 33, Value: "nas.local", Port: 5000},
		{Name: "NAS._qdiscover._tcp.local", Type: 33, Value: "nas.local", Port: 5000},
		{Name: "_device-info._tcp.local", Type: 12, Value: "NAS(AFP)._device-info._tcp.local"},
		{Name: "NAS(AFP)._device-info._tcp.local", Type: 16, TXT: map[string]string{"model": "Xserve"}},
	}
	assets := buildAssets([]mdnsResult{{Records: records}}, network, []int{5000})
	seen := map[string]bool{}
	for _, asset := range assets {
		seen[asset.Service+":"+strconv.Itoa(asset.Port)] = true
	}
	for _, key := range []string{"http:5000", "qdiscover:5000", "device-info:0"} {
		if !seen[key] {
			t.Errorf("missing service %s in %#v", key, assets)
		}
	}
}

func TestWorkstationNameIncludesMAC(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.10.0/24")
	records := []dnsRecord{
		{Name: "nas.local", Type: 1, Value: "192.168.10.5"},
		{Name: "NAS._workstation._tcp.local", Type: 33, Value: "nas.local", Port: 9},
		{Name: "NAS._workstation._tcp.local", Type: 16, TXT: map[string]string{"mac": "24-5e-be-69-a3-13"}},
	}
	assets := buildAssets([]mdnsResult{{Records: records}}, network, []int{9})
	if len(assets) != 1 || assets[0].Name != "NAS [24:5e:be:69:a3:13]" {
		t.Fatalf("unexpected workstation identity: %#v", assets)
	}
}

func TestRenderTextGroupsPTRAnswers(t *testing.T) {
	var output strings.Builder
	if err := renderText(&output, nil, []string{"_http._tcp.local", "_smb._tcp.local"}, false); err != nil {
		t.Fatal(err)
	}
	want := "answers:\nPTR:\n_http._tcp.local\n_smb._tcp.local\n"
	if !strings.Contains(output.String(), want) {
		t.Fatalf("unexpected answers output:\n%s", output.String())
	}
}

func loadReferenceRecords(t *testing.T) []dnsRecord {
	t.Helper()
	records, err := loadFixture("testdata/reference-mdns.hex")
	if err != nil {
		t.Fatalf("loadFixture: %v", err)
	}
	return records
}

func referenceNetwork(t *testing.T) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	return network
}

func TestReferenceFixtureGolden(t *testing.T) {
	expected, err := os.ReadFile("testdata/reference-expected.txt")
	if err != nil {
		t.Fatal(err)
	}
	result, err := replayFixture("testdata/reference-mdns.hex", referenceNetwork(t), []int{9, 445, 548, 5000})
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := renderText(&out, result.Services, result.Answers, false); err != nil {
		t.Fatal(err)
	}
	got := strings.ReplaceAll(out.String(), "\r\n", "\n")
	want := strings.ReplaceAll(string(expected), "\r\n", "\n")
	if got != want {
		t.Fatalf("fixture output mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestReferenceFixtureParsesWireRecords(t *testing.T) {
	records := loadReferenceRecords(t)
	counts := map[uint16]int{}
	for _, record := range records {
		counts[record.Type]++
	}
	for _, kind := range []uint16{12, 33, 16, 1, 28} {
		if counts[kind] == 0 {
			t.Errorf("fixture is missing record type %d", kind)
		}
	}
	// Instance label case must survive parsing.
	found := false
	for _, record := range records {
		if strings.EqualFold(record.Name, "slw-nas(AFP)._afpovertcp._tcp.local") {
			found = true
			if record.Name != "slw-nas(AFP)._afpovertcp._tcp.local" {
				t.Errorf("instance case lost: %q", record.Name)
			}
		}
	}
	if !found {
		t.Error("AFP SRV record missing from fixture")
	}
}

func TestReferenceFixtureIgnoresUnknownFile(t *testing.T) {
	if _, err := loadFixture("testdata/does-not-exist.hex"); err == nil {
		t.Fatal("expected error for missing fixture")
	}
}

func TestReferenceDatasetBlockOutput(t *testing.T) {
	responses := []mdnsResult{{Records: loadReferenceRecords(t)}}
	assets := buildAssets(responses, referenceNetwork(t), []int{9, 445, 548, 5000})
	var out strings.Builder
	if err := renderText(&out, assets, collectAnswers(responses), false); err != nil {
		t.Fatal(err)
	}
	got := out.String()

	host := "IPv4=192.168.1.10\nIPv6=fe80::265e:beff:fe69:a313\nHostname=slw-nas.local\nTTL=10\n"
	for _, want := range []string{
		"services:\n",
		"9/tcp workstation:\nName=slw-nas [24:5e:be:69:a3:13]\n" + host,
		"5000/tcp http:\nName=slw-nas\n" + host + "path=/\n",
		"445/tcp smb:\nName=slw-nas\n" + host,
		"5000/tcp qdiscover:\nName=slw-nas\n" + host + "accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214\n",
		"device-info:\nName=slw-nas(AFP)\n" + host + "model=Xserve\n",
		"548/tcp afpovertcp:\nName=slw-nas(AFP)\n" + host,
		"answers:\nPTR:\n_workstation._tcp.local\n_http._tcp.local\n_smb._tcp.local\n_qdiscover._tcp.local\n_device-info._tcp.local\n_afpovertcp._tcp.local\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing block:\n%s\n--- full output ---\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"\n0/tcp ", "IP=", "Host=", "probe=", "mac=24:5e", "slw-nas._", "_services._dns-sd"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("output must not contain %q:\n%s", unwanted, got)
		}
	}
}

func TestCollectAnswersExcludesInstanceNames(t *testing.T) {
	responses := []mdnsResult{{Records: []dnsRecord{
		{Name: "_services._dns-sd._udp.local", Type: 12, Value: "_http._tcp.local"},
		{Name: "_services._dns-sd._udp.local", Type: 12, Value: "_services._dns-sd._udp.local"},
		{Name: "_http._tcp.local", Type: 12, Value: "slw-nas._http._tcp.local"},
		{Name: "_smb._tcp.local", Type: 12, Value: "slw-nas._smb._tcp.local"},
		{Name: "_ipp._tcp.local", Type: 12, Value: "printer._ipp._tcp.local"},
	}}}
	got := strings.Join(collectAnswers(responses), ",")
	want := "_http._tcp.local"
	if got != want {
		t.Fatalf("collectAnswers = %q, want %q", got, want)
	}
}

func TestVisibleTXTHidesEveryMACKeyVariant(t *testing.T) {
	const mac = "24:5e:be:69:a3:13"
	asset := Asset{
		Name: "slw-nas [" + mac + "]",
		MAC:  mac,
		TXT: map[string]string{
			"mac":        mac,
			"mac_addr":   mac,
			"macaddr":    mac,
			"address":    mac,
			"MACAddress": mac,
			"hwaddr":     mac,
			"model":      "TS-464C",
		},
	}
	keys, _ := visibleTXT(asset)
	if strings.Join(keys, ",") != "model" {
		t.Fatalf("visible TXT keys = %v, want [model]", keys)
	}
}

func TestMACKeyPredicateMatchesExtraction(t *testing.T) {
	// Any key macFromTXT can read a MAC from must also be filtered by
	// visibleTXT, otherwise the MAC is printed twice.
	for _, key := range []string{"mac", "mac_addr", "macaddr", "MACAddress", "address", "hwaddr"} {
		if !isMACKey(key) {
			t.Errorf("isMACKey(%q) = false", key)
		}
		asset := Asset{MAC: "24:5e:be:69:a3:13", TXT: map[string]string{key: "24:5e:be:69:a3:13"}}
		if keys, _ := visibleTXT(asset); len(keys) != 0 {
			t.Errorf("key %q still visible: %v", key, keys)
		}
	}
	for _, key := range []string{"model", "path", "accessType", "device"} {
		if isMACKey(key) {
			t.Errorf("isMACKey(%q) = true", key)
		}
	}
}

func TestTXTDoesNotLeakAcrossServices(t *testing.T) {
	assets := buildAssets([]mdnsResult{{Records: loadReferenceRecords(t)}}, referenceNetwork(t), []int{9, 445, 548, 5000})
	for _, asset := range assets {
		if asset.Service == "qdiscover" {
			continue
		}
		for key := range asset.TXT {
			switch strings.ToLower(key) {
			case "accesstype", "accessport", "displaymodel", "fwver", "fwbuildnum":
				t.Errorf("service %s leaked qdiscover TXT %s", asset.Service, key)
			}
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
