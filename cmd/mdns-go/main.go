// Command mdns-go discovers mDNS services and open TCP ports on a network.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/1303-yzym/mdns-go/internal/cli"
	"github.com/1303-yzym/mdns-go/internal/discovery"
	"github.com/1303-yzym/mdns-go/internal/model"
	"github.com/1303-yzym/mdns-go/internal/render"
)

func main() {
	options, network, ports, err := cli.Parse(os.Args[1:], os.Stderr)
	if err != nil {
		code := cli.ExitCode(err)
		if code == 1 {
			// Usage failures were already written by the flag set.
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(code)
	}
	if err := run(options, network, ports); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// run performs one scan - live discovery or fixture replay - and writes the
// rendered result to stdout.
func run(options cli.Options, network *net.IPNet, ports []int) error {
	var result model.ScanOutput
	var err error
	if options.Fixture != "" {
		result, err = discovery.Replay(options.Fixture, ports)
	} else {
		// A global deadline would cancel port probing as soon as the mDNS
		// window closes, so only interrupt signals cancel the whole run.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		result, err = discovery.Discover(ctx, network, ports, discovery.Options{
			Interfaces:  options.Interfaces,
			Timeout:     options.Timeout,
			ScanTimeout: options.ScanTimeout,
		})
	}
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}
	if options.Format == "json" {
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return fmt.Errorf("render failed: %w", err)
		}
		return nil
	}
	if err := render.Text(os.Stdout, result.Services, result.Answers, options.Verbose, result.Errors); err != nil {
		return fmt.Errorf("render failed: %w", err)
	}
	return nil
}
