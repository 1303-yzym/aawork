package main

import (
	"testing"
)

func TestInstanceName(t *testing.T) {
	got := instanceName("slw-nas._qdiscover._tcp.local", "qdiscover")
	if got != "slw-nas" {
		t.Fatalf("got %q, want %q", got, "slw-nas")
	}
}
