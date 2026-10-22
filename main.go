package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
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

var preferredTXTOrder = []string{
	"path", "accessType", "accessPort", "model", "displayModel",
	"fwVer", "fwBuildNum", "device",
}

// visibleTXT drops values already surfaced elsewhere (the MAC in Name) and
// returns keys in the stable order used by the reference output.
func visibleTXT(asset Asset) ([]string, map[string]string) {
	values := map[string]string{}
	for key, value := range asset.TXT {
		// Hide any key that carries a MAC once the address is promoted to
		// Name/MAC, including when it disagrees with the canonical value.
		if asset.MAC != "" && isMACKey(key) && normalizeMAC(value) != "" {
			continue
		}
		values[key] = value
	}
	var keys []string
	seen := map[string]bool{}
	for _, key := range preferredTXTOrder {
		for existing := range values {
			if strings.EqualFold(existing, key) {
				keys = append(keys, existing)
				seen[existing] = true
			}
		}
	}
	for _, key := range sortedKeys(values) {
		if !seen[key] {
			keys = append(keys, key)
		}
	}
	return keys, values
}

func renderText(output interface{ Write([]byte) (int, error) }, assets []Asset, answers []string, verbose bool, scanErrors ...[]string) error {
	if _, err := fmt.Fprintln(output, "services:"); err != nil {
		return err
	}
	for _, asset := range assets {
		if asset.Port == 0 {
			if _, err := fmt.Fprintf(output, "%s:\n", firstNonEmpty(asset.Service, "tcp")); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintf(output, "%d/tcp %s:\n", asset.Port, firstNonEmpty(asset.Service, "tcp")); err != nil {
			return err
		}
		if verbose {
			fmt.Fprintf(output, "IP=%s\n", asset.IP)
			fmt.Fprintf(output, "Host=%s\n", firstNonEmpty(asset.Host, asset.Hostname, asset.IP))
		}
		fmt.Fprintf(output, "Name=%s\n", asset.Name)
		fmt.Fprintf(output, "IPv4=%s\n", strings.Join(asset.IPv4, ","))
		fmt.Fprintf(output, "IPv6=%s\n", strings.Join(asset.IPv6, ","))
		fmt.Fprintf(output, "Hostname=%s\n", asset.Hostname)
		fmt.Fprintf(output, "TTL=%d\n", asset.TTL)
		keys, values := visibleTXT(asset)
		if verbose {
			for _, key := range keys {
				fmt.Fprintf(output, "%s=%s\n", key, values[key])
			}
		} else if len(keys) > 0 {
			parts := make([]string, 0, len(keys))
			for _, key := range keys {
				parts = append(parts, key+"="+values[key])
			}
			fmt.Fprintln(output, strings.Join(parts, ","))
		}
		if asset.Banner != "" {
			fmt.Fprintf(output, "banner=%q\n", asset.Banner)
		}
		if verbose {
			if asset.Probe != nil {
				fmt.Fprintf(output, "probe=%s status=%s success=%t\n", asset.Probe.Protocol, asset.Probe.Status, asset.Probe.Success)
				for _, key := range sortedKeys(asset.Probe.Headers) {
					fmt.Fprintf(output, "header.%s=%s\n", key, asset.Probe.Headers[key])
				}
				if asset.Probe.TLS != nil {
					fmt.Fprintf(output, "tls.version=%s\n", asset.Probe.TLS.Version)
					fmt.Fprintf(output, "tls.cipher=%s\n", asset.Probe.TLS.Cipher)
					fmt.Fprintf(output, "tls.issuer=%s\n", asset.Probe.TLS.Issuer)
				}
			}
		}
	}
	fmt.Fprintln(output, "answers:")
	if len(answers) > 0 {
		fmt.Fprintln(output, "PTR:")
		for _, answer := range answers {
			fmt.Fprintln(output, answer)
		}
	}
	if len(scanErrors) > 0 {
		for _, scanError := range scanErrors[0] {
			fmt.Fprintln(output, "error:", scanError)
		}
	}
	return nil
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
