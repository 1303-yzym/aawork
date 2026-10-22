package main

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Options struct {
	CIDR        string
	Ports       string
	Timeout     time.Duration
	Interfaces  string
	Format      string
	Verbose     bool
	ScanTimeout time.Duration
	Fixture     string
}

func parsePorts(value string) ([]int, error) {
	seen := map[int]bool{}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid range %q", part)
		}
		start, err := strconv.Atoi(bounds[0])
		if err != nil || start < 1 || start > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		end := start
		if len(bounds) == 2 {
			end, err = strconv.Atoi(bounds[1])
			if err != nil || end < start || end > 65535 {
				return nil, fmt.Errorf("invalid range %q", part)
			}
		}
		for port := start; port <= end; port++ {
			seen[port] = true
		}
	}
	ports := make([]int, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	if len(ports) == 0 {
		return nil, errors.New("no ports specified")
	}
	return ports, nil
}
