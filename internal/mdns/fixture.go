package mdns

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// LoadPacketFile parses recorded mDNS packets: one hex-encoded DNS message per
// line, with blank lines and "#" comments ignored.
func LoadPacketFile(path string) ([]Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var records []Record
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
		parsed, err := parseMessage(packet)
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
