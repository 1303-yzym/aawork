package main

import (
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
