// Package cli parses and validates the command line.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// Options is the validated command line.
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
	// ErrMissingCIDR reports a missing scan scope; the caller prints usage and
	// exits with the conventional "bad invocation" status.
	ErrMissingCIDR = errors.New("missing -cidr")
	// ErrBadUsage reports a flag parse failure whose message the flag set has
	// already printed.
	ErrBadUsage = errors.New("bad usage")
)

// Parse parses the command line, validates it and returns the scan scope. Flag
// usage is written to out; validation errors are returned with the same
// wording the CLI has always printed.
func Parse(args []string, out io.Writer) (Options, *net.IPNet, []int, error) {
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
		return Options{}, nil, nil, ErrBadUsage
	}
	if options.CIDR == "" {
		flags.Usage()
		return Options{}, nil, nil, ErrMissingCIDR
	}
	_, network, err := net.ParseCIDR(options.CIDR)
	if err != nil {
		return Options{}, nil, nil, fmt.Errorf("invalid cidr: %w", err)
	}
	ports, err := ParsePorts(options.Ports)
	if err != nil {
		return Options{}, nil, nil, fmt.Errorf("invalid ports: %w", err)
	}
	if options.Format != "text" && options.Format != "json" {
		return Options{}, nil, nil, errors.New("format must be text or json")
	}
	return options, network, ports, nil
}

// ExitCode maps a Parse error to the documented exit status: 0 for help, 2 for
// a bad invocation and 1 for invalid values. Only the exit-1 errors still need
// to be printed, because the flag set already reported usage failures.
func ExitCode(err error) int {
	switch {
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, ErrMissingCIDR), errors.Is(err, ErrBadUsage):
		return 2
	default:
		return 1
	}
}
