package main

import (
	"net"
	"os"
	"strings"
	"testing"
)

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
	if err := renderText(&out, assets, []string{"_afpovertcp._tcp.local"}, true, nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"548/tcp afpovertcp:", "IP=192.168.10.5", "device=NAS"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("golden output missing %q:\n%s", want, out.String())
		}
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
	if err := renderText(&out, result.Services, result.Answers, false, nil); err != nil {
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
	if err := renderText(&out, assets, collectAnswers(responses), false, nil); err != nil {
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
