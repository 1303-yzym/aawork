package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
)

func main() {
	options, network, ports, err := parseOptions(os.Args[1:], os.Stderr)
	if err != nil {
		exitOptionsError(err)
	}
	if err := run(options, network, ports); err != nil {
		exitError("%v", err)
	}
}

// run performs one scan - live discovery or fixture replay - and writes the
// rendered result to stdout.
func run(options Options, network *net.IPNet, ports []int) error {
	var result ScanOutput
	var err error
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
		return fmt.Errorf("discovery failed: %w", err)
	}
	if options.Format == "json" {
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return fmt.Errorf("render failed: %w", err)
		}
		return nil
	}
	if err := renderText(os.Stdout, result.Services, result.Answers, options.Verbose, result.Errors); err != nil {
		return fmt.Errorf("render failed: %w", err)
	}
	return nil
}
