package model

import (
	"encoding/json"
	"strings"
	"testing"
)

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

func TestSortAssetsUsesReferenceServiceOrder(t *testing.T) {
	assets := []Asset{
		{IP: "192.168.1.10", Port: 548, Service: "afpovertcp", Name: "nas"},
		{IP: "192.168.1.10", Port: 0, Service: "device-info", Name: "nas"},
		{IP: "192.168.1.10", Port: 9, Service: "workstation", Name: "nas"},
		{IP: "192.168.1.10", Port: 445, Service: "smb", Name: "nas"},
	}
	SortAssets(assets)
	got := make([]string, 0, len(assets))
	for _, asset := range assets {
		got = append(got, asset.Service)
	}
	want := "workstation,smb,device-info,afpovertcp"
	if strings.Join(got, ",") != want {
		t.Fatalf("order = %v, want %s", got, want)
	}
}

func TestMACFromTXTNormalizesSeparators(t *testing.T) {
	for _, value := range []string{"24-5e-be-69-a3-13", "24:5E:BE:69:A3:13", "24.5e.be.69.a3.13"} {
		if got := MACFromTXT(map[string]string{"mac": value}); got != "24:5e:be:69:a3:13" {
			t.Errorf("MACFromTXT(%q) = %q", value, got)
		}
	}
	if got := MACFromTXT(map[string]string{"model": "TS-464C"}); got != "" {
		t.Errorf("MACFromTXT read a model as MAC: %q", got)
	}
}
