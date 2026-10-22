package main

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

// buildQuery encodes PTR questions. When unicast is set the QU bit
// (0x8000 of the class field) asks responders to answer directly to the
// querying socket, which is required when 5353 could not be bound.
func buildQuery(services []string, unicast bool) []byte {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[4:], uint16(len(services)))
	class := []byte{0, 1}
	if unicast {
		class = []byte{0x80, 0x01}
	}
	for _, service := range services {
		packet = append(packet, encodeName(service)...)
		packet = append(packet, 0, 12)
		packet = append(packet, class...)
	}
	return packet
}

func parseDNSMessage(packet []byte) ([]dnsRecord, error) {
	if len(packet) < 12 {
		return nil, errors.New("short dns packet")
	}
	questions := int(binary.BigEndian.Uint16(packet[4:6]))
	answers := int(binary.BigEndian.Uint16(packet[6:8]))
	authorities := int(binary.BigEndian.Uint16(packet[8:10]))
	additionals := int(binary.BigEndian.Uint16(packet[10:12]))
	offset := 12
	for i := 0; i < questions; i++ {
		var err error
		_, offset, err = readName(packet, offset)
		if err != nil || offset+4 > len(packet) {
			return nil, errors.New("invalid dns question")
		}
		offset += 4
	}
	count := answers + authorities + additionals
	records := make([]dnsRecord, 0, count)
	for i := 0; i < count; i++ {
		name, next, err := readName(packet, offset)
		if err != nil || next+10 > len(packet) {
			return nil, errors.New("invalid dns record")
		}
		offset = next
		kind := binary.BigEndian.Uint16(packet[offset:])
		ttl := binary.BigEndian.Uint32(packet[offset+4:])
		size := int(binary.BigEndian.Uint16(packet[offset+8:]))
		offset += 10
		if offset+size > len(packet) {
			return nil, errors.New("invalid dns record length")
		}
		// Keep the on-wire case: DNS matching is case-insensitive, but the
		// instance label is user-visible (e.g. "slw-nas(AFP)").
		record := dnsRecord{Name: name, Type: kind, TTL: ttl}
		switch kind {
		case 1:
			if size == 4 {
				record.Value = net.IP(packet[offset : offset+4]).String()
			}
		case 28:
			if size == 16 {
				record.Value = net.IP(packet[offset : offset+16]).String()
			}
		case 12:
			record.Value, _, err = readName(packet, offset)
		case 33:
			if size >= 6 {
				record.Port = int(binary.BigEndian.Uint16(packet[offset+4:]))
				record.Value, _, err = readName(packet, offset+6)
			}
		case 16:
			record.TXT = parseTXT(packet[offset : offset+size])
		}
		if err != nil {
			return nil, err
		}
		if kind == 16 && record.TXT == nil {
			record.TXT = map[string]string{}
		}
		if kind == 16 || kind == 1 || kind == 28 || kind == 12 || kind == 33 {
			records = append(records, record)
		}
		offset += size
	}
	return records, nil
}

func readName(packet []byte, offset int) (string, int, error) {
	if offset >= len(packet) {
		return "", offset, errors.New("name out of bounds")
	}
	labels := []string{}
	original := offset
	jumped := false
	jumps := 0
	for {
		if offset >= len(packet) {
			return "", offset, errors.New("name out of bounds")
		}
		length := int(packet[offset])
		if length == 0 {
			offset++
			break
		}
		if length&0xc0 == 0xc0 {
			jumps++
			if jumps > len(packet) {
				return "", offset, errors.New("compression pointer loop")
			}
			if offset+1 >= len(packet) {
				return "", offset, errors.New("invalid compression pointer")
			}
			pointer := int(binary.BigEndian.Uint16(packet[offset:offset+2]) & 0x3fff)
			if !jumped {
				original = offset + 2
			}
			offset = pointer
			jumped = true
			continue
		}
		offset++
		if length > 63 || offset+length > len(packet) {
			return "", offset, errors.New("invalid name label")
		}
		labels = append(labels, string(packet[offset:offset+length]))
		offset += length
	}
	if jumped {
		offset = original
	}
	return strings.Join(labels, "."), offset, nil
}

func encodeName(name string) []byte {
	var encoded []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, label...)
	}
	return append(encoded, 0)
}

func parseTXT(data []byte) map[string]string {
	result := map[string]string{}
	for len(data) > 0 {
		size := int(data[0])
		data = data[1:]
		if size > len(data) {
			break
		}
		item := string(data[:size])
		data = data[size:]
		key, value, ok := strings.Cut(item, "=")
		if ok {
			result[key] = value
		} else {
			result[item] = ""
		}
	}
	return result
}
