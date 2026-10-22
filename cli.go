package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
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

var (
	// errMissingCIDR reports a missing scan scope; the caller prints usage and
	// exits with the conventional "bad invocation" status.
	errMissingCIDR = errors.New("missing -cidr")
	// errBadUsage reports a flag parse failure whose message the flag set has
	// already printed.
	errBadUsage = errors.New("bad usage")
)

// parseOptions parses the command line, validates it and returns the scan
// scope. Flag usage is written to out; validation errors are returned with the
// same wording the CLI has always printed.
func parseOptions(args []string, out io.Writer) (Options, *net.IPNet, []int, error) {
	var options Options
	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flags.SetOutput(out)
	flags.StringVar(&options.CIDR, "cidr", "", "IPv4 network to discover, for example 192.168.1.0/24")
	flags.StringVar(&options.Ports, "ports", "1-1024", "TCP port or range, for example 80,443,5000-5010")
	flags.DurationVar(&options.Timeout, "timeout", 2*time.Second, "mDNS and TCP timeout")
	flags.StringVar(&options.Interfaces, "interface", "", "interface name (default: all multicast-capable interfaces)")
	flags.StringVar(&options.Format, "format", "text", "output format: text or json")
	flags.BoolVar(&options.Verbose, "verbose", false, "add scan diagnostics (IP/Host/probe lines) to text output")
	flags.DurationVar(&options.ScanTimeout, "scan-timeout", 0, "optional whole-scan budget for TCP probing (0 = bounded only by per-connection timeout)")
	flags.StringVar(&options.Fixture, "fixture", "", "replay a recorded mDNS packet file (hex, one packet per line) instead of using the network")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return Options{}, nil, nil, err
		}
		return Options{}, nil, nil, errBadUsage
	}
	if options.CIDR == "" {
		flags.Usage()
		return Options{}, nil, nil, errMissingCIDR
	}
	_, network, err := net.ParseCIDR(options.CIDR)
	if err != nil {
		return Options{}, nil, nil, fmt.Errorf("invalid cidr: %w", err)
	}
	ports, err := parsePorts(options.Ports)
	if err != nil {
		return Options{}, nil, nil, fmt.Errorf("invalid ports: %w", err)
	}
	if options.Format != "text" && options.Format != "json" {
		return Options{}, nil, nil, errors.New("format must be text or json")
	}
	return options, network, ports, nil
}

// exitOptionsError maps a parse failure to the documented exit status: 0 for
// help, 2 for a bad invocation, 1 for invalid values.
func exitOptionsError(err error) {
	switch {
	case errors.Is(err, flag.ErrHelp):
		os.Exit(0)
	case errors.Is(err, errMissingCIDR), errors.Is(err, errBadUsage):
		os.Exit(2)
	default:
		exitError("%v", err)
	}
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
