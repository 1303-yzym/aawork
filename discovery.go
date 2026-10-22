package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

func discover(ctx context.Context, network *net.IPNet, ports []int, options Options) (ScanOutput, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ScanOutput{}, err
	}
	var selected []*net.Interface
	var candidates []string
	for i := range interfaces {
		if interfaces[i].Flags&net.FlagUp != 0 && interfaces[i].Flags&net.FlagMulticast != 0 {
			candidates = append(candidates, interfaces[i].Name)
		}
		if options.Interfaces != "" && interfaces[i].Name != options.Interfaces {
			continue
		}
		if interfaces[i].Flags&net.FlagUp != 0 && interfaces[i].Flags&net.FlagMulticast != 0 {
			selected = append(selected, &interfaces[i])
		}
	}
	if len(selected) == 0 {
		if options.Interfaces != "" {
			return ScanOutput{}, fmt.Errorf("interface %q is not an active multicast interface (candidates: %s)", options.Interfaces, strings.Join(candidates, ", "))
		}
		// TCP scanning remains useful on systems without multicast (and for
		// IPv6-only interfaces where mDNS is unavailable).
		return scanWithoutMDNS(ctx, network, ports, options)
	}

	// The mDNS collection window is scoped to this phase only; TCP probing
	// keeps its own per-connection timeout.
	mdnsCtx, cancelMDNS := context.WithTimeout(ctx, options.Timeout)
	defer cancelMDNS()

	results := make(chan mdnsResult, len(selected))
	var wg sync.WaitGroup
	for _, iface := range selected {
		wg.Add(1)
		go func(iface *net.Interface) {
			defer wg.Done()
			if result, err := queryInterface(mdnsCtx, iface, network, options.Timeout); err == nil {
				results <- result
			} else if ctx.Err() == nil {
				results <- mdnsResult{SourceIP: iface.Name, Records: nil, Err: err}
			}
		}(iface)
	}
	wg.Wait()
	close(results)

	var responses []mdnsResult
	for result := range results {
		responses = append(responses, result)
	}
	var mdnsErrors []string
	for _, response := range responses {
		if response.Err != nil {
			mdnsErrors = append(mdnsErrors, response.SourceIP+": "+response.Err.Error())
		}
	}
	discovered := buildAssets(responses, network, ports)
	probeCtx, cancelProbe := probeContext(ctx, options)
	defer cancelProbe()
	assets, err := scanNetwork(probeCtx, discovered, network, ports, options.Timeout)
	if err != nil {
		return ScanOutput{}, err
	}
	sortAssets(assets)
	return ScanOutput{Services: assets, Answers: collectAnswers(responses), Errors: mdnsErrors}, nil
}

// collectAnswers keeps only service-type PTRs. mDNS also answers PTRs for
// individual instances (e.g. slw-nas._http._tcp.local); those must not be
// reported as service types.
func collectAnswers(responses []mdnsResult) []string {
	answers := map[string]bool{}
	for _, response := range responses {
		for _, record := range response.Records {
			if record.Type != 12 || !isServiceType(record.Value) {
				continue
			}
			answers[record.Value] = true
		}
	}
	answerList := make([]string, 0, len(answers))
	for answer := range answers {
		answerList = append(answerList, answer)
	}
	sort.Slice(answerList, func(i, j int) bool {
		ri, rj := serviceRank(serviceType(answerList[i])), serviceRank(serviceType(answerList[j]))
		if ri != rj {
			return ri < rj
		}
		return answerList[i] < answerList[j]
	})
	return answerList
}

// probeContext applies the optional whole-scan budget. Zero means no global
// deadline: each connection is still bounded by the per-dial timeout.
func probeContext(ctx context.Context, options Options) (context.Context, context.CancelFunc) {
	if options.ScanTimeout > 0 {
		return context.WithTimeout(ctx, options.ScanTimeout)
	}
	return context.WithCancel(ctx)
}

func scanWithoutMDNS(ctx context.Context, network *net.IPNet, ports []int, options Options) (ScanOutput, error) {
	probeCtx, cancel := probeContext(ctx, options)
	defer cancel()
	assets, err := scanNetwork(probeCtx, nil, network, ports, options.Timeout)
	if err != nil {
		return ScanOutput{}, err
	}
	sortAssets(assets)
	return ScanOutput{Services: assets}, nil
}
