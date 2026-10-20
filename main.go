package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
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
	"sync"
	"time"
)

const mdnsGroup = "224.0.0.251:5353"
const maxScanHosts = uint64(65536)

var commonServices = []string{
	"_services._dns-sd._udp.local",
	"_workstation._tcp.local", "_http._tcp.local", "_https._tcp.local",
	"_smb._tcp.local", "_afpovertcp._tcp.local", "_device-info._tcp.local",
	"_qdiscover._tcp.local", "_ssh._tcp.local", "_printer._tcp.local",
}

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

type Asset struct {
	IP         string            `json:"ip"`
	Port       int               `json:"port"`
	Host       string            `json:"host"`
	Service    string            `json:"service,omitempty"`
	Name       string            `json:"name,omitempty"`
	MAC        string            `json:"mac,omitempty"`
	Hostname   string            `json:"hostname,omitempty"`
	IPv4       []string          `json:"ipv4,omitempty"`
	IPv6       []string          `json:"ipv6,omitempty"`
	TTL        uint32            `json:"ttl,omitempty"`
	Banner     string            `json:"banner,omitempty"`
	Probe      *ProbeResult      `json:"probe,omitempty"`
	TXT        map[string]string `json:"txt,omitempty"`
	Discovered bool              `json:"discovered,omitempty"`
}

type ProbeResult struct {
	Protocol string            `json:"protocol"`
	Status   string            `json:"status"`
	Success  bool              `json:"success"`
	Banner   string            `json:"banner,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	TLS      *TLSInfo          `json:"tls,omitempty"`
}

type TLSInfo struct {
	Version    string   `json:"version,omitempty"`
	Cipher     string   `json:"cipher,omitempty"`
	Negotiated string   `json:"negotiated_protocol,omitempty"`
	Subject    string   `json:"subject,omitempty"`
	Issuer     string   `json:"issuer,omitempty"`
	DNSNames   []string `json:"dns_names,omitempty"`
	NotAfter   string   `json:"not_after,omitempty"`
}

type ScanOutput struct {
	Services []Asset  `json:"services"`
	Answers  []string `json:"answers,omitempty"`
	Errors   []string `json:"errors,omitempty"`
}

type dnsRecord struct {
	Name, Value string
	Type        uint16
	TTL         uint32
	Port        int
	TXT         map[string]string
}

type hostData struct {
	hostname   string
	ipv4, ipv6 []string
	ttl        uint32
}

type mdnsResult struct {
	SourceIP string
	Records  []dnsRecord
	Err      error
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
// loadFixture parses recorded mDNS packets. Each non-empty line holds one
// hex-encoded DNS message.
func loadFixture(path string) ([]dnsRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var records []dnsRecord
	packets := 0
	for lineNumber, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		packet, err := hex.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: invalid hex: %w", path, lineNumber+1, err)
		}
		parsed, err := parseDNSMessage(packet)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNumber+1, err)
		}
		records = append(records, parsed...)
		packets++
	}
	if packets == 0 {
		return nil, fmt.Errorf("%s: no packets found", path)
	}
	return records, nil
}

// replayFixture renders a recorded dataset through the same asset pipeline the
// live scanner uses, so verification does not need real hardware.
func replayFixture(path string, network *net.IPNet, ports []int) (ScanOutput, error) {
	records, err := loadFixture(path)
	if err != nil {
		return ScanOutput{}, err
	}
	responses := []mdnsResult{{Records: records}}
	assets := buildAssets(responses, network, ports)
	sortAssets(assets)
	return ScanOutput{Services: assets, Answers: collectAnswers(responses)}, nil
}

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

// isServiceType reports whether name has the shape _service._tcp.local /
// _service._udp.local. Instance names and the _services enumeration pseudo
// type are rejected.
func isServiceType(name string) bool {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(name), "."), ".")
	if len(labels) != 3 {
		return false
	}
	if !strings.HasPrefix(labels[0], "_") || len(labels[0]) < 2 {
		return false
	}
	if labels[1] != "_tcp" && labels[1] != "_udp" {
		return false
	}
	return labels[2] == "local"
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

// mdnsSocket is an interface-scoped mDNS query socket. unicast is set when
// the well-known port 5353 could not be claimed, in which case queries carry
// the QU (unicast-response) bit and replies arrive on an ephemeral port.
type mdnsSocket struct {
	conn        *net.UDPConn
	destination *net.UDPAddr
	unicast     bool
}

func queryInterface(ctx context.Context, iface *net.Interface, network *net.IPNet, timeout time.Duration) (mdnsResult, error) {
	socket, err := openMDNSSocket(iface, network, 5353)
	if err != nil {
		return mdnsResult{}, err
	}
	defer socket.conn.Close()
	return socket.run(ctx, timeout)
}

// openMDNSSocket prefers a multicast listener on mdnsPort. System mDNS
// daemons (Bonjour, Avahi, Windows Dnscache) commonly own 5353 exclusively,
// so binding failure falls back to an ephemeral port with QU queries instead
// of losing discovery entirely.
func openMDNSSocket(iface *net.Interface, network *net.IPNet, mdnsPort int) (*mdnsSocket, error) {
	networkIsV6 := network.IP.To4() == nil
	networkType, group, wildcard := "udp4", mdnsGroup, net.IPv4zero
	if networkIsV6 {
		networkType, group, wildcard = "udp6", "[ff02::fb]:5353", net.IPv6unspecified
	}
	listenIP := wildcard
	if addr := interfaceIP(iface, networkIsV6); addr != nil {
		listenIP = addr
	}
	destination, err := mustResolveUDPForNetwork(group, networkIsV6, iface)
	if err != nil {
		return nil, err
	}

	conn, multicastErr := net.ListenMulticastUDP(networkType, iface, &net.UDPAddr{IP: listenIP, Port: mdnsPort})
	if multicastErr == nil {
		return &mdnsSocket{conn: conn, destination: destination}, nil
	}

	local := &net.UDPAddr{Port: 0}
	if listenIP != nil && !listenIP.IsUnspecified() {
		local.IP = listenIP
	}
	fallback, err := net.ListenUDP(networkType, local)
	if err != nil {
		return nil, fmt.Errorf("bind udp port %d failed: %w; ephemeral fallback failed: %v", mdnsPort, multicastErr, err)
	}
	return &mdnsSocket{conn: fallback, destination: destination, unicast: true}, nil
}

func (q *mdnsSocket) send(services []string) error {
	_, err := q.conn.WriteToUDP(buildQuery(services, q.unicast), q.destination)
	return err
}

func (q *mdnsSocket) run(ctx context.Context, timeout time.Duration) (mdnsResult, error) {
	if err := q.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return mdnsResult{}, err
	}
	if err := q.send(commonServices); err != nil {
		return mdnsResult{}, err
	}

	var all []dnsRecord
	buffer := make([]byte, 65535)
	queried := map[string]bool{}
	for _, service := range commonServices {
		queried[strings.ToLower(service)] = true
	}
	queryServices := func(records []dnsRecord) error {
		var extra []string
		for _, record := range records {
			if record.Type == 12 && strings.HasPrefix(record.Value, "_") {
				service := strings.ToLower(record.Value)
				if !queried[service] {
					queried[service] = true
					extra = append(extra, service)
				}
			}
		}
		if len(extra) == 0 {
			return nil
		}
		return q.send(extra)
	}
	for {
		select {
		case <-ctx.Done():
			return mdnsResult{}, ctx.Err()
		default:
		}
		count, _, err := q.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			return mdnsResult{}, err
		}
		// Filter addresses from records below, not the packet source. mDNS
		// responders commonly reply from a link-local address while the
		// requested CIDR contains a global or private address.
		records, err := parseDNSMessage(buffer[:count])
		if err == nil {
			all = append(all, records...)
			if err := queryServices(records); err != nil {
				return mdnsResult{}, err
			}
		}
	}
	if len(all) == 0 {
		return mdnsResult{}, errors.New("no matching mDNS response")
	}
	return mdnsResult{SourceIP: "", Records: all}, nil
}

func buildAssets(results []mdnsResult, network *net.IPNet, ports []int) []Asset {
	hosts := map[string]*hostData{}
	var records []dnsRecord
	var assets []Asset
	for _, result := range results {
		records = append(records, result.Records...)
	}
	for _, record := range records {
		if record.Type != 1 && record.Type != 28 {
			continue
		}
		key := strings.ToLower(strings.TrimSuffix(record.Name, "."))
		host := hosts[key]
		if host == nil {
			host = &hostData{hostname: key}
			hosts[key] = host
		}
		host.ttl = record.TTL
		if record.Type == 1 {
			host.ipv4 = appendUnique(host.ipv4, record.Value)
		} else {
			host.ipv6 = appendUnique(host.ipv6, record.Value)
		}
	}
	for _, record := range records {
		if record.Type != 33 || len(record.Value) == 0 {
			continue
		}
		target := strings.ToLower(strings.TrimSuffix(record.Value, "."))
		host := hosts[target]
		if host == nil {
			continue
		}
		ip := firstNonEmpty(host.ipv4...)
		if ip == "" {
			ip = firstNonEmpty(host.ipv6...)
		}
		if ip == "" {
			continue
		}
		if !containsInt(ports, record.Port) {
			continue
		}
		service := serviceType(record.Name)
		name := instanceName(record.Name, service)
		txt := mergeTXTForInstance(records, record.Name, target)
		mac := macFromTXT(txt)
		if service == "afpovertcp" && !strings.HasSuffix(name, "(AFP)") {
			name += "(AFP)"
		}
		if mac != "" && service == "workstation" {
			name += " [" + mac + "]"
		}
		asset := Asset{
			IP: ip, Host: host.hostname, Port: record.Port, Service: service, Name: name,
			MAC: mac, Discovered: true,
			Hostname: host.hostname, IPv4: append([]string(nil), host.ipv4...),
			IPv6: append([]string(nil), host.ipv6...), TTL: host.ttl, TXT: txt,
		}
		assets = appendUniqueAsset(assets, asset)
	}
	for _, record := range records {
		if record.Type != 12 || !strings.Contains(strings.ToLower(record.Name), "_device-info.") {
			continue
		}
		serviceName := strings.TrimSuffix(record.Value, ".")
		name := instanceName(serviceName, "device-info")
		host := findHostByInstance(hosts, name)
		if host == nil {
			continue
		}
		txt := mergeTXTForInstance(records, serviceName, host.hostname)
		assets = appendUniqueAsset(assets, Asset{
			IP:   firstNonEmpty(append(append([]string{}, host.ipv4...), host.ipv6...)...),
			Host: host.hostname, Port: 0, Service: "device-info", Name: name,
			MAC: macFromTXT(txt), Discovered: true, Hostname: host.hostname,
			IPv4: append([]string(nil), host.ipv4...), IPv6: append([]string(nil), host.ipv6...),
			TTL: host.ttl, TXT: txt,
		})
	}
	sort.SliceStable(assets, func(i, j int) bool {
		if assets[i].IP != assets[j].IP {
			return assets[i].IP < assets[j].IP
		}
		ri, rj := serviceRank(assets[i].Service), serviceRank(assets[j].Service)
		if ri != rj {
			return ri < rj
		}
		if assets[i].Port != assets[j].Port {
			return assets[i].Port < assets[j].Port
		}
		return assets[i].Name < assets[j].Name
	})
	return assets
}

// referenceServiceOrder keeps text output stable and matches the documented
// example ordering: workstation, http, smb, qdiscover, device-info, afp.
var referenceServiceOrder = []string{
	"workstation", "http", "smb", "qdiscover", "device-info", "afpovertcp",
}

func serviceRank(service string) int {
	for i, known := range referenceServiceOrder {
		if strings.EqualFold(service, known) {
			return i
		}
	}
	return len(referenceServiceOrder)
}

func appendUniqueAsset(assets []Asset, asset Asset) []Asset {
	for i := range assets {
		if assets[i].IP == asset.IP && assets[i].Port == asset.Port && assets[i].Service == asset.Service && assets[i].Name == asset.Name {
			assets[i].TXT = mergeMaps(assets[i].TXT, asset.TXT)
			return assets
		}
	}
	return append(assets, asset)
}

func mergeTXTForInstance(records []dnsRecord, instance, target string) map[string]string {
	result := map[string]string{}
	ownerLower := strings.ToLower(strings.TrimSuffix(instance, "."))
	service := serviceType(instance)
	base := strings.ToLower(strings.TrimSuffix(instanceName(instance, service), "."))
	for _, record := range records {
		if record.Type != 16 {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(record.Name, "."))
		if name == ownerLower {
			result = mergeMaps(result, record.TXT)
			continue
		}
		// Responders such as QNAP publish one instance's attributes under a
		// sibling service name. Merge only inside that service family so TXT
		// never leaks into unrelated services.
		if service != "qdiscover" || !strings.Contains(name, "_qdiscover.") {
			continue
		}
		if strings.ToLower(strings.TrimSuffix(instanceName(name, "qdiscover"), ".")) == base {
			result = mergeMaps(result, record.TXT)
		}
	}
	return result
}

// isMACKey is the single source of truth for "this TXT key may carry a MAC
// address". macFromTXT and visibleTXT must agree, otherwise the same MAC is
// emitted both inside Name and as a duplicate TXT line.
func isMACKey(key string) bool {
	lower := strings.ToLower(key)
	return strings.Contains(lower, "mac") ||
		strings.Contains(lower, "hwaddr") ||
		lower == "address"
}

func macFromTXT(values map[string]string) string {
	for key, value := range values {
		if !isMACKey(key) {
			continue
		}
		if normalized := normalizeMAC(value); normalized != "" {
			return normalized
		}
	}
	return ""
}

func normalizeMAC(value string) string {
	value = strings.NewReplacer("-", ":", ".", ":", " ", "").Replace(strings.TrimSpace(value))
	parts := strings.Split(value, ":")
	if len(parts) != 6 {
		return ""
	}
	for i := range parts {
		if len(parts[i]) != 2 {
			return ""
		}
	}
	return strings.ToLower(strings.Join(parts, ":"))
}

func findHostByInstance(hosts map[string]*hostData, instance string) *hostData {
	base := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(instance, "(AFP)"), "."))
	for key, host := range hosts {
		if strings.HasPrefix(key, base) || strings.HasPrefix(base, strings.TrimSuffix(key, ".local")) {
			return host
		}
	}
	return nil
}

func mergeMaps(dst, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = map[string]string{}
	}
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func scanHosts(network *net.IPNet) ([]string, error) {
	hostCount, err := networkHostCount(network)
	if err != nil {
		return nil, err
	}
	if hostCount > maxScanHosts {
		return nil, fmt.Errorf("CIDR contains %d scannable hosts; maximum is %d (split the range)", hostCount, maxScanHosts)
	}
	return enumerateHosts(network), nil
}

// scanNetwork streams host/port targets into a bounded worker pool instead of
// materialising every pair, so /24 x 1-10000 does not exhaust memory. mDNS
// assets only enrich a target; they never gate the scan.
func scanNetwork(ctx context.Context, discovered []Asset, network *net.IPNet, ports []int, timeout time.Duration) ([]Asset, error) {
	hosts, err := scanHosts(network)
	if err != nil {
		return nil, err
	}
	discoveredByTarget := map[string][]Asset{}
	passthrough := make([]Asset, 0, 4)
	for _, asset := range discovered {
		if asset.Port == 0 {
			passthrough = appendUniqueAsset(passthrough, asset)
			continue
		}
		key := targetKey(asset.IP, asset.Port)
		discoveredByTarget[key] = appendUniqueAsset(discoveredByTarget[key], asset)
	}

	workers := 128
	jobs := make(chan Asset)
	results := make(chan Asset)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for asset := range jobs {
				probeAsset(ctx, &asset, timeout)
				if !asset.Discovered && (asset.Probe == nil || !asset.Probe.Success) {
					continue
				}
				select {
				case results <- asset:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, host := range hosts {
			for _, port := range ports {
				if ctx.Err() != nil {
					return
				}
				var targets []Asset
				if known, ok := discoveredByTarget[targetKey(host, port)]; ok {
					targets = known
				} else {
					targets = []Asset{{IP: host, Host: host, Port: port, Service: serviceForPort(port)}}
				}
				for _, asset := range targets {
					// Never block forever if every worker already returned
					// after cancellation.
					select {
					case jobs <- asset:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	assets := passthrough
	for asset := range results {
		assets = append(assets, asset)
	}
	return assets, nil
}

func targetKey(ip string, port int) string {
	return net.JoinHostPort(ip, strconv.Itoa(port))
}

func networkHostCount(network *net.IPNet) (uint64, error) {
	ones, bits := network.Mask.Size()
	if ones < 0 {
		return 0, errors.New("invalid CIDR mask")
	}
	hostBits := bits - ones
	if hostBits >= 63 {
		return maxScanHosts + 1, nil
	}
	count := uint64(1) << uint(hostBits)
	if bits == 32 && hostBits > 1 {
		count -= 2
	}
	return count, nil
}

func enumerateHosts(network *net.IPNet) []string {
	var hosts []string
	ip := append(net.IP(nil), network.IP...)
	ones, bits := network.Mask.Size()
	for network.Contains(ip) {
		isNetwork := len(ip) == net.IPv4len && ip.Equal(network.IP)
		next := incIP(ip)
		isBroadcast := false
		if len(ip) == net.IPv4len {
			last := append(net.IP(nil), network.IP...)
			for i := range last {
				last[i] |= ^network.Mask[i]
			}
			isBroadcast = ip.Equal(last)
		}
		pointToPoint := bits == 32 && ones >= 31
		if !(isNetwork || isBroadcast) || pointToPoint {
			hosts = append(hosts, ip.String())
		}
		ip = next
	}
	return hosts
}

func incIP(ip net.IP) net.IP {
	next := append(net.IP(nil), ip...)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

func probeAssets(ctx context.Context, assets []Asset, timeout time.Duration) []Asset {
	workers := 128
	if len(assets) < workers {
		workers = len(assets)
	}
	if workers == 0 {
		return nil
	}
	jobs := make(chan *Asset)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for asset := range jobs {
				probeAsset(ctx, asset, timeout)
			}
		}()
	}
send:
	for i := range assets {
		select {
		case jobs <- &assets[i]:
		case <-ctx.Done():
			break send
		}
	}
	close(jobs)
	wg.Wait()
	open := assets[:0]
	for _, asset := range assets {
		if asset.Discovered {
			open = append(open, asset)
		} else if asset.Probe != nil && asset.Probe.Success {
			open = append(open, asset)
		}
	}
	return open
}

func probeAsset(ctx context.Context, asset *Asset, timeout time.Duration) {
	address := net.JoinHostPort(asset.IP, strconv.Itoa(asset.Port))
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		asset.Probe = &ProbeResult{Protocol: protocolFor(asset.Port, asset.Service), Status: probeStatus(err)}
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	protocol := protocolFor(asset.Port, asset.Service)
	result := &ProbeResult{Protocol: protocol, Status: "open"}
	// protocolFor reports "https", so both names must be accepted here; the
	// original "tls" check never matched and left HTTPS probed as plaintext.
	if protocol == "https" || protocol == "tls" {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: tlsServerName(asset)})
		if err := tlsConn.Handshake(); err != nil {
			result.Status = probeStatus(err)
			asset.Probe = result
			return
		}
		conn = tlsConn
		state := tlsConn.ConnectionState()
		result.TLS = &TLSInfo{
			Version:    tls.VersionName(state.Version),
			Cipher:     tls.CipherSuiteName(state.CipherSuite),
			Negotiated: state.NegotiatedProtocol,
		}
		if len(state.PeerCertificates) > 0 {
			leaf := state.PeerCertificates[0]
			result.TLS.Subject = leaf.Subject.String()
			result.TLS.Issuer = leaf.Issuer.String()
			result.TLS.DNSNames = leaf.DNSNames
			result.TLS.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
		}
	}
	if protocol == "http" || protocol == "https" {
		_, _ = fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", firstNonEmpty(asset.Hostname, asset.IP))
	}
	if protocol == "smb" {
		if _, err := conn.Write(smbNegotiateRequest()); err != nil {
			result.Status = probeStatus(err)
			asset.Probe = result
			return
		}
	}
	buffer := make([]byte, 4096)
	n, _ := conn.Read(buffer)
	if n == 0 {
		result.Success = true
		asset.Probe = result
		return
	}
	result.Success = true
	result.Banner = strings.TrimSpace(string(buffer[:n]))
	asset.Banner = result.Banner
	if protocol == "http" || protocol == "https" {
		result.Headers = parseHTTPHeaders(result.Banner)
	}
	asset.Probe = result
}

// tlsServerName returns SNI only for real DNS names; dialing an IP literal as
// ServerName breaks verification and SNI for some servers.
func tlsServerName(asset *Asset) string {
	name := firstNonEmpty(asset.Hostname, asset.Host, asset.IP)
	if net.ParseIP(name) != nil {
		return ""
	}
	return strings.TrimSuffix(name, ".")
}

func probeStatus(err error) string {
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "timeout"
	}
	return "closed"
}

func smbNegotiateRequest() []byte {
	// NetBIOS session packet + SMB2 NEGOTIATE request (dialects 2.0.2,
	// 2.1, 3.0, 3.0.2 and 3.1.1).
	p := make([]byte, 4+64+46)
	copy(p[4:], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(p[68:70], 36)
	binary.LittleEndian.PutUint16(p[70:72], 5)
	copy(p[4+64+36:], []byte{0x02, 0x02, 0x10, 0x02, 0x22, 0x02, 0x24, 0x02, 0x02, 0x03})
	length := uint32(len(p) - 4)
	p[1] = byte(length >> 16)
	p[2] = byte(length >> 8)
	p[3] = byte(length)
	return p
}

func protocolFor(port int, service string) string {
	s := strings.ToLower(service)
	switch {
	case strings.Contains(s, "https") || port == 443 || port == 8443:
		return "https"
	case strings.Contains(s, "qdiscover"):
		return "qdiscover"
	case strings.Contains(s, "afpovertcp") || port == 548:
		return "afp"
	case strings.Contains(s, "http") || port == 80 || port == 8080 || port == 5000:
		return "http"
	case strings.Contains(s, "ssh") || port == 22:
		return "ssh"
	case strings.Contains(s, "ftp") || port == 21:
		return "ftp"
	case strings.Contains(s, "smb") || port == 139 || port == 445:
		return "smb"
	default:
		return "tcp"
	}
}

func serviceForPort(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 80, 8080:
		return "http"
	case 139, 445:
		return "smb"
	case 548:
		return "afp"
	case 443, 8443:
		return "https"
	default:
		return "tcp"
	}
}

func parseHTTPHeaders(banner string) map[string]string {
	headers := map[string]string{}
	lines := strings.Split(banner, "\n")
	for _, line := range lines[1:] {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok {
			headers[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return headers
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
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

func findIPForName(records []dnsRecord, name string, network *net.IPNet) string {
	for _, record := range records {
		if (record.Type == 1 || record.Type == 28) && strings.EqualFold(record.Name, name) && network.Contains(net.ParseIP(record.Value)) {
			return record.Value
		}
	}
	return ""
}

func findIPv4ForName(records []dnsRecord, name string, network *net.IPNet) string {
	for _, record := range records {
		if record.Type == 1 && strings.EqualFold(record.Name, name) && network.Contains(net.ParseIP(record.Value)) {
			return record.Value
		}
	}
	return ""
}

func findTXT(records []dnsRecord, name string) map[string]string {
	for _, record := range records {
		if record.Type == 16 && strings.EqualFold(record.Name, name) {
			return record.TXT
		}
	}
	return nil
}

func serviceType(name string) string {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i, label := range labels {
		if strings.EqualFold(label, "_tcp") || strings.EqualFold(label, "_udp") {
			if i > 0 {
				return strings.TrimPrefix(labels[i-1], "_")
			}
		}
	}
	return "unknown"
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

func instanceName(name, service string) string {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i, label := range labels {
		isProto := strings.EqualFold(label, "_tcp") || strings.EqualFold(label, "_udp")
		if isProto && i > 0 {
			if i > 1 && strings.EqualFold(strings.TrimPrefix(labels[i-1], "_"), service) {
				return strings.Join(labels[:i-1], ".")
			}
			return strings.Join(labels[:i], ".")
		}
	}
	return strings.TrimSuffix(name, ".")
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func containsInt(values []int, wanted int) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func interfaceIP(iface *net.Interface, wantV6 bool) net.IP {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
			continue
		}
		if (ipNet.IP.To4() == nil) == wantV6 {
			return ipNet.IP
		}
	}
	return nil
}

func mustResolveUDP(address string) (*net.UDPAddr, error) {
	resolved, err := net.ResolveUDPAddr("udp4", address)
	if err != nil || resolved == nil {
		if err == nil {
			err = errors.New("resolved UDP address is nil")
		}
		return nil, fmt.Errorf("resolve UDP address %q: %w", address, err)
	}
	return resolved, nil
}

func mustResolveUDPForNetwork(address string, ipv6 bool, iface *net.Interface) (*net.UDPAddr, error) {
	if !ipv6 {
		return mustResolveUDP(address)
	}
	resolved, err := net.ResolveUDPAddr("udp6", address)
	if err != nil || resolved == nil {
		if err == nil {
			err = errors.New("resolved UDP address is nil")
		}
		return nil, fmt.Errorf("resolve UDP address %q: %w", address, err)
	}
	resolved.Zone = iface.Name
	return resolved, nil
}

// sortAssets keeps the documented reference ordering: by address, then by
// service rank (workstation, http, smb, qdiscover, device-info, afp), then
// port. A plain port sort would move the portless device-info entry to the
// top and break the reference output.
func sortAssets(assets []Asset) {
	sort.SliceStable(assets, func(i, j int) bool {
		if assets[i].IP != assets[j].IP {
			return assets[i].IP < assets[j].IP
		}
		ri, rj := serviceRank(assets[i].Service), serviceRank(assets[j].Service)
		if ri != rj {
			return ri < rj
		}
		if assets[i].Port != assets[j].Port {
			return assets[i].Port < assets[j].Port
		}
		return assets[i].Name < assets[j].Name
	})
}

func exitError(format string, values ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
