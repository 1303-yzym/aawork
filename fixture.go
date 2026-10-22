package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

// loadFixture parses recorded mDNS packets. Each non-empty line holds one
// hex-encoded DNS message.
func loadFixture(path string) ([]dnsRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var records []dnsRecord
	packets := 0
	for lineNumber, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		packet, err := hex.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: invalid hex: %w", path, lineNumber+1, err)
		}
		parsed, err := parseDNSMessage(packet)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNumber+1, err)
		}
		records = append(records, parsed...)
		packets++
	}
	if packets == 0 {
		return nil, fmt.Errorf("%s: no packets found", path)
	}
	return records, nil
}

// replayFixture renders a recorded dataset through the same asset pipeline the
// live scanner uses, so verification does not need real hardware.
func replayFixture(path string, network *net.IPNet, ports []int) (ScanOutput, error) {
	records, err := loadFixture(path)
	if err != nil {
		return ScanOutput{}, err
	}
	responses := []mdnsResult{{Records: records}}
	assets := buildAssets(responses, network, ports)
	sortAssets(assets)
	return ScanOutput{Services: assets, Answers: collectAnswers(responses)}, nil
}
