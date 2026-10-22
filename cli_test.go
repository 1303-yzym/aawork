package main

import (
	"errors"
	"flag"
	"io"
	"strings"
	"testing"
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

func TestParseOptionsReturnsValidatedScope(t *testing.T) {
	options, network, ports, err := parseOptions([]string{"-cidr", "192.168.1.0/24", "-ports", "9,445"}, io.Discard)
	if err != nil {
		t.Fatalf("parseOptions returned error: %v", err)
	}
	if network.String() != "192.168.1.0/24" {
		t.Errorf("network = %v, want 192.168.1.0/24", network)
	}
	if len(ports) != 2 || ports[0] != 9 || ports[1] != 445 {
		t.Errorf("ports = %v, want [9 445]", ports)
	}
	if options.Format != "text" || options.Timeout.Seconds() != 2 {
		t.Errorf("unexpected defaults: %+v", options)
	}
}

func TestParseOptionsRejectsInvalidScope(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want error
		text string
	}{
		{name: "missing cidr", args: nil, want: errMissingCIDR},
		{name: "bad cidr", args: []string{"-cidr", "999.1.1.1/24"}, text: "invalid cidr:"},
		{name: "bad ports", args: []string{"-cidr", "192.168.1.0/24", "-ports", "0"}, text: "invalid ports:"},
		{name: "bad format", args: []string{"-cidr", "192.168.1.0/24", "-format", "xml"}, text: "format must be text or json"},
		{name: "unknown flag", args: []string{"-nope"}, want: errBadUsage},
		{name: "help", args: []string{"-h"}, want: flag.ErrHelp},
	} {
		_, _, _, err := parseOptions(tc.args, io.Discard)
		if tc.want != nil {
			if !errors.Is(err, tc.want) {
				t.Errorf("%s: error = %v, want %v", tc.name, err, tc.want)
			}
			continue
		}
		if err == nil || !strings.HasPrefix(err.Error(), tc.text) {
			t.Errorf("%s: error = %v, want prefix %q", tc.name, err, tc.text)
		}
	}
}
