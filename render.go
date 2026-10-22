package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

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

func renderText(output io.Writer, assets []Asset, answers []string, verbose bool, scanErrors []string) error {
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
		for _, scanError := range scanErrors {
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
