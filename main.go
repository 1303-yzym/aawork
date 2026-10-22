package main

import (
	"context"
	"encoding/json"
	"flag"
	"net"
	"os"
	"os/signal"
	"time"
)

func main() {
	var options Options
	flag.StringVar(&options.CIDR, "cidr", "", "IPv4 network to discover, for example 192.168.1.0/24")
	flag.StringVar(&options.Ports, "ports", "1-1024", "TCP port or range, for example 80,443,5000-5010")
	flag.DurationVar(&options.Timeout, "timeout", 2*time.Second, "mDNS and TCP timeout")
	flag.StringVar(&options.Interfaces, "interface", "", "interface name (default: all multicast-capable interfaces)")
	flag.StringVar(&options.Format, "format", "text", "output format: text or json")
	flag.BoolVar(&options.Verbose, "verbose", false, "add scan diagnostics (IP/Host/probe lines) to text output")
	flag.DurationVar(&options.ScanTimeout, "scan-timeout", 0, "optional whole-scan budget for TCP probing (0 = bounded only by per-connection timeout)")
	flag.StringVar(&options.Fixture, "fixture", "", "replay a recorded mDNS packet file (hex, one packet per line) instead of using the network")
	flag.Parse()

	if options.CIDR == "" {
		flag.Usage()
		os.Exit(2)
	}
	_, network, err := net.ParseCIDR(options.CIDR)
	if err != nil {
		exitError("invalid cidr: %v", err)
	}
	ports, err := parsePorts(options.Ports)
	if err != nil {
		exitError("invalid ports: %v", err)
	}
	if options.Format != "text" && options.Format != "json" {
		exitError("format must be text or json")
	}

	var result ScanOutput
	if options.Fixture != "" {
		result, err = replayFixture(options.Fixture, network, ports)
	} else {
		// A global deadline would cancel port probing as soon as the mDNS
		// window closes, so only interrupt signals cancel the whole run.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		result, err = discover(ctx, network, ports, options)
	}
	if err != nil {
		exitError("discovery failed: %v", err)
	}
	if options.Format == "json" {
		err = json.NewEncoder(os.Stdout).Encode(result)
	} else {
		err = renderText(os.Stdout, result.Services, result.Answers, options.Verbose, result.Errors)
	}
	if err != nil {
		exitError("render failed: %v", err)
	}
}
