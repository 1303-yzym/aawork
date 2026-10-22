package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderTextIncludesDeepFields(t *testing.T) {
	var output strings.Builder
	err := renderText(&output, []Asset{{
		IP: "192.168.1.10", Port: 5000, Service: "qdiscover",
		Name: "slw-nas", Hostname: "slw-nas.local", TTL: 10,
		TXT: map[string]string{"model": "TS-464C"},
	}}, []string{"_qdiscover._tcp.local"}, true, nil)
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

func TestRenderTextGroupsPTRAnswers(t *testing.T) {
	var output strings.Builder
	if err := renderText(&output, nil, []string{"_http._tcp.local", "_smb._tcp.local"}, false, nil); err != nil {
		t.Fatal(err)
	}
	want := "answers:\nPTR:\n_http._tcp.local\n_smb._tcp.local\n"
	if !strings.Contains(output.String(), want) {
		t.Fatalf("unexpected answers output:\n%s", output.String())
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
