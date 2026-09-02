package internal

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ==================== IPv6 Pool ====================

type RouteCheckInfo struct {
	Success   bool   `json:"success"`
	Output    string `json:"output"`
	Interface string `json:"interface"`
}

type StageInfo struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

type IPv6Addr struct {
	IP           string         `json:"ip"`
	Subnet       string         `json:"subnet"`
	Interface    string         `json:"interface"`
	Status       string         `json:"status"`
	LastCheck    time.Time      `json:"last_check"`
	AddedAt      time.Time      `json:"added_at"`
	AddressAdded bool           `json:"address_added"`
	RouteCheck   RouteCheckInfo  `json:"route_check"`
	PolicyRouted bool           `json:"policy_routed"`
	Bind         bool           `json:"bind"`
	TCP          StageInfo      `json:"tcp"`
	TLS          StageInfo      `json:"tls"`
	HTTPS        StageInfo      `json:"https"`
	PublicIP     string         `json:"public_ip"`
	FailureStage string         `json:"failure_stage"`

	// SLAAC source-mode bookkeeping
	SourceMode          string     `json:"source_mode"`
	Prefix              string     `json:"prefix"`
	Configured          bool       `json:"configured"`
	RealRequestCount    int        `json:"real_request_count"`
	SuccessCount        int        `json:"success_count"`
	FailureCount        int        `json:"failure_count"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LastSuccess         *time.Time `json:"last_success"`
	LastFailure         *time.Time `json:"last_failure"`
	LastRecheck         time.Time  `json:"last_recheck"`
	State               string     `json:"state"`
}

type IPv6Pool struct {
	mu          sync.RWMutex
	addrs       map[string]*IPv6Addr
	prefix      *net.IPNet
	dummyIface  string
	sourceIface string
	wanIface    string
	wanGateway  string
	tableID     int
	rulePrio    int
	selectionMode string
	sourceMode  string
	dnsServer   string
	testTarget  string
	// dnsServerRaw/testTargetRaw hold the original configured values, which may
	// be a domain. When they are domains, dnsServer/testTarget carry the
	// resolved AAAA and are periodically refreshed (see startInfraDNSRefresh).
	dnsServerRaw string
	testTargetRaw string
	// hosts maps a hostname to either a literal IPv6 or an alias domain. When
	// the value is a domain, it is resolved (AAAA) at request time — see
	// resolveHost. Keys are normalized (lowercased, :port stripped).
	hosts       map[string]string
	rrIndex     int
	dummyCreated bool

	// dnsCache caches AAAA resolutions for client target domains (and is
	// consulted by resolveHost) so successful resolutions are reused.
	dnsCache *dnsCache
	cfgMu    sync.RWMutex

	// In "manual" selection mode the proxy does not rotate automatically; it
	// keeps using pinnedIP until SwitchToNext/SetPinnedIP changes it (via API).
	pinMu    sync.RWMutex
	pinnedIP string

	// SLAAC source-mode state
	slaacPrefix            *net.IPNet
	slaacWANIP            net.IP
	failureThreshold      int
	recheckFailedInterval time.Duration
	slaacPoolSize         int

	// OCI source-mode state
	ociClient       *OciClient
	ociCompartment  string
	ociVnicID       string
	ociPrefixLength int
}

func NewIPv6Pool(prefixStr, wanIface, dummyIface, selectionMode, dnsServer, testTarget string, createDummy bool) (*IPv6Pool, error) {
	_, prefix, err := net.ParseCIDR(prefixStr)
	if err != nil {
		return nil, fmt.Errorf("parse prefix %s: %w", prefixStr, err)
	}
	var created bool
	var srcIface string
	if createDummy {
		created, err = ensureDummyInterface(dummyIface)
		if err != nil {
			return nil, fmt.Errorf("create dummy %s: %w", dummyIface, err)
		}
		srcIface = dummyIface
	} else {
		// SLAAC source mode adds the pool addresses directly onto the WAN
		// interface (the native /64 routes cleanly; the PD does not), so no
		// dummy device is created.
		srcIface = wanIface
	}
	gw := detectGateway(wanIface)
	log.Printf("IPv6 pool ready (dummyCreated=%v, sourceInterface=%s), WAN=%s gateway=%q", created, srcIface, wanIface, gw)

	// Allow dns_server / test_target to be configured as domains: resolve them
	// to AAAA at startup and cache the result. The raw value is retained so a
	// background refresh can re-resolve if the AAAA changes.
	cache := newDNSCache()
	resolvedDNS := dnsServer
	if !isIPv6Literal(dnsServer) {
		if ip, err := resolveAAAA(context.Background(), dnsServer, ""); err == nil {
			resolvedDNS = ip.String()
			log.Printf("[DNS] resolved dns_server %q -> %s", dnsServer, resolvedDNS)
		} else {
			log.Printf("[DNS] dns_server %q is not a literal IPv6 and initial resolve failed: %v (will retry in background)", dnsServer, err)
		}
	}
	resolvedTgt := testTarget
	if !isIPv6Literal(testTarget) {
		if ip, err := resolveAAAA(context.Background(), testTarget, resolvedDNS); err == nil {
			resolvedTgt = ip.String()
			log.Printf("[DNS] resolved test_target %q -> %s", testTarget, resolvedTgt)
		} else {
			log.Printf("[DNS] test_target %q is not a literal IPv6 and initial resolve failed: %v (will retry in background)", testTarget, err)
		}
	}

	return &IPv6Pool{
		addrs:         make(map[string]*IPv6Addr),
		prefix:        prefix,
		dummyIface:    dummyIface,
		sourceIface:   srcIface,
		wanIface:      wanIface,
		wanGateway:    gw,
		tableID:       100,
		rulePrio:      1000,
		selectionMode: selectionMode,
		dnsServer:     resolvedDNS,
		testTarget:    resolvedTgt,
		dnsServerRaw:  dnsServer,
		testTargetRaw: testTarget,
		hosts:         make(map[string]string),
		dummyCreated:  created,
		dnsCache:      cache,
	}, nil
}

// dnsServerResolved returns the current (possibly refreshed) resolved IPv6 for
// the configured DNS server, safe for concurrent use.
func (p *IPv6Pool) dnsServerResolved() string {
	p.cfgMu.RLock()
	defer p.cfgMu.RUnlock()
	return p.dnsServer
}

// testTargetResolved returns the current (possibly refreshed) resolved IPv6 for
// the configured test target, safe for concurrent use.
func (p *IPv6Pool) testTargetResolved() string {
	p.cfgMu.RLock()
	defer p.cfgMu.RUnlock()
	return p.testTarget
}

// startInfraDNSRefresh periodically re-resolves any domain-valued dns_server /
// test_target config and updates the cached AAAA. It is a no-op for literal
// IPv6 configs. This keeps the cached AAAA fresh and recovers from transient
// resolution failures at startup.
func (p *IPv6Pool) startInfraDNSRefresh(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.refreshInfraDNS()
			}
		}
	}()
}

func (p *IPv6Pool) refreshInfraDNS() {
	resolveOne := func(raw, current, dnsSrv string) string {
		if isIPv6Literal(raw) {
			return current
		}
		if ip, err := resolveAAAA(context.Background(), raw, dnsSrv); err == nil {
			if ip.String() != current {
				log.Printf("[DNS] refreshed %q -> %s", raw, ip.String())
			}
			return ip.String()
		}
		log.Printf("[DNS] refresh of %q failed, keeping %s", raw, current)
		return current
	}

	p.cfgMu.Lock()
	defer p.cfgMu.Unlock()
	if !isIPv6Literal(p.dnsServerRaw) {
		p.dnsServer = resolveOne(p.dnsServerRaw, p.dnsServer, "")
	}
	if !isIPv6Literal(p.testTargetRaw) {
		p.testTarget = resolveOne(p.testTargetRaw, p.testTarget, p.dnsServer)
	}
}

func subnetOf(ip net.IP) string {
	ip16 := ip.To16()
	subnet := make(net.IP, 16)
	copy(subnet, ip16)
	for i := 8; i < 16; i++ {
		subnet[i] = 0
	}
	return fmt.Sprintf("%s/64", subnet.String())
}

func (p *IPv6Pool) GenerateAddresses(count int) []net.IP {
	var ips []net.IP

	prefixLen, _ := p.prefix.Mask.Size()

	subnetCount := count
	if subnetCount > 16 {
		subnetCount = 16
	}
	if subnetCount < 1 {
		subnetCount = 1
	}

	for i := 0; i < subnetCount; i++ {
		ip := make(net.IP, 16)
		copy(ip, p.prefix.IP.To16())
		if prefixLen < 128 {
			// Treat prefix as a PD. The /64 boundary sits after byte 7;
			// within a /60 PD the /64 subnet index is the low nibble of
			// byte 7 (bits 60-63), so we enumerate d600/d601/d602/...
			ip[7] = (ip[7] & 0xF0) | byte(i&0x0F)
			// random host portion (bytes 8..15)
			var buf [8]byte
			rand.Read(buf[:])
			copy(ip[8:16], buf[:])
		} else {
			ip[15] = byte(i + 1)
		}
		ips = append(ips, ip)
	}
	return ips
}

// randomIPInPrefix returns a random /128 within the given prefix. For a /60 PD
// this spans all 16 /64 subnets (low nibble of byte 7) plus a random host.
func randomIPInPrefix(prefix *net.IPNet) net.IP {
	ip := make(net.IP, 16)
	copy(ip, prefix.IP.To16())
	prefixLen, _ := prefix.Mask.Size()
	if prefixLen < 0 || prefixLen > 128 {
		prefixLen = 128
	}
	for i := prefixLen; i < 128; i++ {
		byteIdx := i / 8
		bitIdx := uint(7 - (i % 8))
		if rand.Intn(2) == 1 {
			ip[byteIdx] |= 1 << bitIdx
		} else {
			ip[byteIdx] &^= 1 << bitIdx
		}
	}
	if ip.Equal(net.IPv6zero) {
		ip[15] = 1
	}
	return ip
}

func (p *IPv6Pool) AddAddress(ip net.IP, subnet string) error {
	ipStr := ip.String()
	p.mu.Lock()
	if _, exists := p.addrs[ipStr]; exists {
		p.mu.Unlock()
		return fmt.Errorf("address %s already in pool", ipStr)
	}
	p.mu.Unlock()

	cmd := exec.Command("ip", "-6", "addr", "add", ipStr+"/128", "dev", p.sourceIface)
	addrAdded := true
	if out, err := cmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "File exists") {
			addrAdded = false
		p.mu.Lock()
		p.addrs[ipStr] = &IPv6Addr{
			IP:           ip.String(),
			Subnet:       subnet,
			Interface:    p.sourceIface,
			Status:       "dead",
			AddedAt:      time.Now(),
			AddressAdded: false,
			FailureStage: "address_add_failed",
			SourceMode:   p.sourceMode,
			Prefix:       p.prefix.String(),
			Configured:   true,
		}
			p.mu.Unlock()
			return fmt.Errorf("ip addr add failed: %s: %w", strings.TrimSpace(string(out)), err)
		}
		log.Printf("[POOL] %s already exists on %s, taking ownership", ipStr, p.sourceIface)
	}

	p.mu.Lock()
	p.addrs[ipStr] = &IPv6Addr{
		IP:           ip.String(),
		Subnet:       subnet,
		Interface:    p.sourceIface,
		Status:       "checking",
		AddedAt:      time.Now(),
		AddressAdded: addrAdded,
		SourceMode:   p.sourceMode,
		Prefix:       p.prefix.String(),
		Configured:   true,
	}
	p.mu.Unlock()

	log.Printf("[POOL] Added %s on %s (subnet %s)", ipStr, p.sourceIface, subnet)
	return nil
}

func (p *IPv6Pool) RemoveAddress(ipStr string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	addr, exists := p.addrs[ipStr]
	if !exists {
		return fmt.Errorf("address %s not in pool", ipStr)
	}

	exec.Command("ip", "-6", "addr", "del", ipStr+"/128", "dev", p.sourceIface).Run()
	if addr.PolicyRouted {
		exec.Command("ip", "-6", "rule", "del", "from", ipStr+"/128", "table", strconv.Itoa(p.tableID)).Run()
	}
	delete(p.addrs, ipStr)
	log.Printf("[POOL] Removed %s from %s", ipStr, p.sourceIface)
	return nil
}

// acquireEphemeral allocates a fresh, never-before-used IPv6 inside the PD and
// adds it to the dummy interface. This is the workaround for ISPs that only
// permit the *first* outbound connection from a given source IPv6: by using a
// brand-new address per connection, every dial lands on the allowed attempt.
func (p *IPv6Pool) acquireEphemeral() (string, error) {
	for i := 0; i < 32; i++ {
		ip := randomIPInPrefix(p.prefix)
		ipStr := ip.String()
		p.mu.RLock()
		_, exists := p.addrs[ipStr]
		p.mu.RUnlock()
		if exists {
			continue
		}
		if err := p.AddAddress(ip, subnetOf(ip)); err != nil {
			continue
		}
		return ipStr, nil
	}
	return "", fmt.Errorf("failed to acquire ephemeral source IP")
}

// releaseEphemeral removes a previously acquired ephemeral address so the
// dummy interface does not accumulate stale /128 entries.
func (p *IPv6Pool) releaseEphemeral(ipStr string) {
	p.RemoveAddress(ipStr)
}

func (p *IPv6Pool) SelectIPv6(clientHint string) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if clientHint != "" {
		if addr, ok := p.addrs[clientHint]; ok && addr.Status != "failed" && addr.Status != "dead" {
			return clientHint, nil
		}
		return "", fmt.Errorf("requested IPv6 %s not available", clientHint)
	}

	var selectable []string
	for ip, addr := range p.addrs {
		// "failed" (SLAAC consecutive failures) and "dead" (PD health-check
		// failure) addresses are excluded from selection.
		if addr.Status == "failed" || addr.Status == "dead" {
			continue
		}
		selectable = append(selectable, ip)
	}
	if len(selectable) == 0 {
		return "", fmt.Errorf("no available IPv6 addresses in pool")
	}

	switch p.selectionMode {
	case "random":
		return selectable[rand.Intn(len(selectable))], nil
	case "manual":
		// No automatic rotation: keep the pinned IP until the API switches it.
		return p.manualSelect(selectable)
	default:
		idx := p.rrIndex % len(selectable)
		p.rrIndex++
		return selectable[idx], nil
	}
}

// manualSelect returns the currently pinned IP (no advance). If nothing is
// pinned yet, it pins and returns the first selectable address.
func (p *IPv6Pool) manualSelect(selectable []string) (string, error) {
	p.pinMu.Lock()
	defer p.pinMu.Unlock()
	if len(selectable) == 0 {
		return "", fmt.Errorf("no available IPv6 addresses in pool")
	}
	valid := false
	for _, ip := range selectable {
		if ip == p.pinnedIP {
			valid = true
			break
		}
	}
	if !valid {
		p.pinnedIP = selectable[0]
	}
	return p.pinnedIP, nil
}

// SwitchToNext advances the pinned IP to the next alive address (wrapping
// around) and returns the new pinned IP. Used by the "manual" mode API.
func (p *IPv6Pool) SwitchToNext() (string, error) {
	p.mu.RLock()
	var sel []string
	for ip, a := range p.addrs {
		if a.Status != "failed" && a.Status != "dead" {
			sel = append(sel, ip)
		}
	}
	p.mu.RUnlock()
	if len(sel) == 0 {
		return "", fmt.Errorf("no available IPv6 addresses in pool")
	}
	sort.Strings(sel)

	p.pinMu.Lock()
	defer p.pinMu.Unlock()
	idx := -1
	for i, ip := range sel {
		if ip == p.pinnedIP {
			idx = i
			break
		}
	}
	nxt := sel[(idx+1)%len(sel)]
	p.pinnedIP = nxt
	return nxt, nil
}

// SetPinnedIP pins a specific address (must already be in the pool).
func (p *IPv6Pool) SetPinnedIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IPv6 address %q", ip)
	}
	p.mu.RLock()
	_, ok := p.addrs[ip]
	p.mu.RUnlock()
	if !ok {
		return fmt.Errorf("IPv6 %q not in pool", ip)
	}
	p.pinMu.Lock()
	p.pinnedIP = ip
	p.pinMu.Unlock()
	return nil
}

// GetPinnedIP returns the currently pinned IP (may be empty).
func (p *IPv6Pool) GetPinnedIP() string {
	p.pinMu.RLock()
	defer p.pinMu.RUnlock()
	return p.pinnedIP
}

// SetSelectionMode changes the selection algorithm at runtime (via API).
func (p *IPv6Pool) SetSelectionMode(mode string) error {
	switch mode {
	case "round-robin", "random", "manual":
		p.cfgMu.Lock()
		p.selectionMode = mode
		p.cfgMu.Unlock()
		return nil
	default:
		return fmt.Errorf("invalid selection_mode %q (want round-robin|random|manual)", mode)
	}
}

func (p *IPv6Pool) ListAddresses() map[string]*IPv6Addr {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make(map[string]*IPv6Addr, len(p.addrs))
	for k, v := range p.addrs {
		cp := *v
		result[k] = &cp
	}
	return result
}

// checkRouteAndBind verifies the kernel can route traffic from localIP out the
// WAN and that the address can be bound. On a route failure it attempts a
// minimal-impact policy route before giving up. It mutates addr's route/bind
// diagnostics and returns whether the address is usable for outbound traffic.
// Shared by the full TestAddress probe and the lighter SLAAC probe.
func (p *IPv6Pool) checkRouteAndBind(localIP net.IP, addr *IPv6Addr) bool {
	iface, _, routeOK, routeOut := checkRoute(localIP.String(), p.testTargetResolved(), p.wanIface)
	addr.RouteCheck = RouteCheckInfo{Success: routeOK, Output: strings.TrimSpace(routeOut), Interface: iface}
	if !routeOK {
		if err := p.setupPolicyRoute(localIP.String()); err == nil {
			addr.PolicyRouted = true
			iface, _, routeOK, routeOut = checkRoute(localIP.String(), p.testTargetResolved(), p.wanIface)
			addr.RouteCheck = RouteCheckInfo{Success: routeOK, Output: strings.TrimSpace(routeOut), Interface: iface}
		}
	}
	if !routeOK {
		addr.FailureStage = "route_failed"
		addr.Status = "dead"
		return false
	}
	bindErr := testBind(localIP)
	addr.Bind = bindErr == nil
	if bindErr != nil {
		addr.FailureStage = "bind_failed"
		addr.Status = "dead"
		return false
	}
	return true
}

func (p *IPv6Pool) TestAddress(ipStr string, timeout time.Duration) error {
	localIP := net.ParseIP(ipStr)
	if localIP == nil {
		return fmt.Errorf("invalid IP: %s", ipStr)
	}

	p.mu.Lock()
	addr, ok := p.addrs[ipStr]
	if !ok {
		p.mu.Unlock()
		return fmt.Errorf("address %s not in pool", ipStr)
	}
	p.mu.Unlock()
	addr.LastCheck = time.Now()

	// C. route check + B. bind test (shared by the SLAAC probe).
	if !p.checkRouteAndBind(localIP, addr) {
		return fmt.Errorf("route/bind check failed: %s", addr.RouteCheck.Output)
	}

	// D. TCP connect — this is what defines "usable": outbound works.
	tcpErr := testTCP(localIP, p.testTargetResolved(), timeout)
	addr.TCP = StageInfo{Success: tcpErr == nil, Error: errStr(tcpErr)}
	if tcpErr != nil {
		if strings.Contains(tcpErr.Error(), "timeout") {
			addr.FailureStage = "tcp_timeout"
		} else {
			addr.FailureStage = "tcp_failed"
		}
		addr.Status = "dead"
		return tcpErr
	}
	// Outbound works => usable. Higher-layer blocks (TLS/HTTPS, common with
	// stateful ISP filtering) no longer mark the address dead.
	addr.Status = "alive"
	addr.FailureStage = "success"

	// E. TLS handshake (diagnostic only)
	tlsErr := testTLS(localIP, p.testTargetResolved(), timeout)
	addr.TLS = StageInfo{Success: tlsErr == nil, Error: errStr(tlsErr)}
	if tlsErr != nil {
		addr.FailureStage = "tls_failed"
	}

	// F. HTTPS request + G. public IP match (diagnostic only)
	publicIP, httpsErr := testHTTPS(localIP, timeout, p.dnsServerResolved())
	addr.HTTPS = StageInfo{Success: httpsErr == nil, Error: errStr(httpsErr)}
	addr.PublicIP = publicIP
	if httpsErr != nil {
		addr.FailureStage = "https_failed"
	} else if publicIP != ipStr {
		addr.FailureStage = "public_ip_mismatch"
	}
	// Status stays "alive" because outbound (TCP) succeeded.
	return nil
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// checkRoute runs `ip -6 route get TARGET from TEST_IP` and verifies a route
// exists that egresses on the real WAN. The kernel auto-selects a source on
// the egress interface, so we don't require src==testIP here: an explicit
// bind() in the later TCP/TLS/HTTPS stages still forces testIP as source.
func checkRoute(testIP, targetIP, wanIface string) (iface, src string, ok bool, output string) {
	out, err := exec.Command("ip", "-6", "route", "get", targetIP, "from", testIP).CombinedOutput()
	if err != nil {
		return "", "", false, string(out)
	}
	s := string(out)
	fields := strings.Fields(s)
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			iface = fields[i+1]
		}
		if f == "src" && i+1 < len(fields) {
			src = fields[i+1]
		}
	}
	ok = iface != "" && (wanIface == "" || iface == wanIface)
	return iface, src, ok, s
}

func (p *IPv6Pool) setupPolicyRoute(testIP string) error {
	prio := p.rulePrio
	p.rulePrio++
	ruleCmd := exec.Command("ip", "-6", "rule", "add", "from", testIP+"/128",
		"table", strconv.Itoa(p.tableID), "priority", strconv.Itoa(prio))
	if out, err := ruleCmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "File exists") {
			return fmt.Errorf("rule add: %s: %w", strings.TrimSpace(string(out)), err)
		}
	}
	var routeCmd *exec.Cmd
	if p.wanGateway != "" {
		routeCmd = exec.Command("ip", "-6", "route", "add", "default", "via", p.wanGateway,
			"dev", p.wanIface, "table", strconv.Itoa(p.tableID))
	} else {
		routeCmd = exec.Command("ip", "-6", "route", "add", "default", "dev", p.wanIface,
			"table", strconv.Itoa(p.tableID))
	}
	if out, err := routeCmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "File exists") {
			return fmt.Errorf("route add: %s: %w", strings.TrimSpace(string(out)), err)
		}
	}
	log.Printf("[ROUTE] policy route for %s -> table %d (gw=%q)", testIP, p.tableID, p.wanGateway)
	return nil
}

func testBind(localIP net.IP) error {
	addr := &net.UDPAddr{IP: localIP, Port: 0}
	conn, err := net.ListenUDP("udp6", addr)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func testTCP(localIP net.IP, target string, timeout time.Duration) error {
	dialer := &net.Dialer{
		Timeout:   timeout,
		LocalAddr: &net.TCPAddr{IP: localIP},
	}
	conn, err := dialer.DialContext(context.Background(), "tcp6", "["+target+"]:80")
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func testTLS(localIP net.IP, target string, timeout time.Duration) error {
	dialer := &net.Dialer{
		Timeout:   timeout,
		LocalAddr: &net.TCPAddr{IP: localIP},
	}
	conn, err := tls.DialWithDialer(dialer, "tcp6", "["+target+"]:443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// testHTTPS resolves api64.ipify.org via the given DNS server (bound to the
// test source address) and verifies the returned public IPv6 equals testIP.
func testHTTPS(localIP net.IP, timeout time.Duration, dnsServer string) (string, error) {
	resolver := &net.Resolver{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := &net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: localIP}}
			return d.DialContext(ctx, "tcp6", "["+dnsServer+"]:53")
		},
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := resolver.LookupIPAddr(ctx, host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("dns lookup %s: %w", host, err)
			}
			d := &net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: localIP}}
			return d.DialContext(ctx, "tcp6", net.JoinHostPort(ips[0].IP.String(), port))
		},
	}
	client := &http.Client{Transport: tr, Timeout: timeout + 5*time.Second}
	resp, err := client.Get("https://api64.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	publicIP := strings.TrimSpace(string(body))
	if net.ParseIP(publicIP) == nil {
		return "", fmt.Errorf("unexpected response: %q", publicIP)
	}
	return publicIP, nil
}

func ensureDummyInterface(name string) (bool, error) {
	if out, err := exec.Command("ip", "link", "show", "dev", name).Output(); err == nil && len(out) > 0 {
		typ, e := exec.Command("ip", "-d", "link", "show", "dev", name).Output()
		if e == nil && !strings.Contains(string(typ), "dummy") {
			return false, fmt.Errorf("interface %s exists but is not a dummy interface", name)
		}
		exec.Command("ip", "link", "set", name, "up").Run()
		log.Printf("[DUMMY] reusing existing dummy interface %s", name)
		return false, nil
	}
	if out, err := exec.Command("ip", "link", "add", name, "type", "dummy").CombinedOutput(); err != nil {
		return false, fmt.Errorf("ip link add dummy failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	exec.Command("ip", "link", "set", name, "up").Run()
	log.Printf("[DUMMY] created dummy interface %s", name)
	return true, nil
}

func removeDummyInterface(name string) error {
	out, err := exec.Command("ip", "link", "del", "dev", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip link del failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func detectGateway(iface string) string {
	out, err := exec.Command("ip", "-6", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		for i, f := range fields {
			if f == "dev" && i+1 < len(fields) && fields[i+1] == iface {
				for j := 0; j < i; j++ {
					if fields[j] == "via" && j+1 < len(fields) {
						return fields[j+1]
					}
				}
			}
		}
	}
	return ""
}

func (p *IPv6Pool) HealthCheck(timeout time.Duration) {
	p.mu.Lock()
	addresses := make([]string, 0, len(p.addrs))
	for ip := range p.addrs {
		addresses = append(addresses, ip)
	}
	p.mu.Unlock()

	for _, ipStr := range addresses {
		err := p.TestAddress(ipStr, timeout)
		p.mu.Lock()
		if addr, ok := p.addrs[ipStr]; ok {
			addr.LastCheck = time.Now()
			if err != nil {
				addr.Status = "dead"
				log.Printf("[HEALTH] %s is DEAD: %v", ipStr, err)
			} else {
				addr.Status = "alive"
				log.Printf("[HEALTH] %s is alive", ipStr)
			}
		}
		p.mu.Unlock()
	}
}

// recordRequest records the outcome of a real outbound connection (or a periodic
// health probe) for the given source IP. In SLAAC source mode a transient
// failure must not immediately evict an address, so an address is only marked
// "failed" after failureThreshold consecutive failures; a single success resets
// the counter.
func (p *IPv6Pool) recordRequest(ipStr string, success bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	addr, ok := p.addrs[ipStr]
	if !ok {
		return
	}
	addr.RealRequestCount++
	if success {
		addr.SuccessCount++
		addr.ConsecutiveFailures = 0
		now := time.Now()
		addr.LastSuccess = &now
		addr.Status = "alive"
		addr.State = "healthy"
	} else {
		addr.FailureCount++
		addr.ConsecutiveFailures++
		now := time.Now()
		addr.LastFailure = &now
		if p.failureThreshold > 0 && addr.ConsecutiveFailures >= p.failureThreshold {
			addr.Status = "failed"
			addr.State = "failed"
			log.Printf("[SLAAC] %s marked FAILED after %d consecutive failures", ipStr, addr.ConsecutiveFailures)
		} else {
			// Tolerate transient failure: keep the address selectable.
			addr.Status = "alive"
			addr.State = "degraded"
		}
	}
}

func (p *IPv6Pool) addrStatus(ipStr string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if a, ok := p.addrs[ipStr]; ok {
		return a.Status
	}
	return ""
}

func (p *IPv6Pool) slaacPrefixString() string {
	if p.slaacPrefix == nil {
		return ""
	}
	return p.slaacPrefix.String()
}

func (p *IPv6Pool) slaacWANIPString() string {
	if p.slaacWANIP == nil {
		return ""
	}
	return p.slaacWANIP.String()
}

// healthCheckSLAAC runs the staged test on every address in the SLAAC pool and
// feeds the result into recordRequest. Failed (previously evicted) addresses
// are only re-probed every recheckFailedInterval to avoid wasted probes.
func (p *IPv6Pool) healthCheckSLAAC(timeout time.Duration) {
	p.mu.Lock()
	healthy, failed := []string{}, []string{}
	for ip, a := range p.addrs {
		if a.Status == "failed" {
			failed = append(failed, ip)
		} else {
			healthy = append(healthy, ip)
		}
	}
	p.mu.Unlock()

	now := time.Now()
	for _, ipStr := range healthy {
		p.recordRequest(ipStr, p.probeSLAAC(ipStr, timeout))
	}
	for _, ipStr := range failed {
		p.mu.RLock()
		lr := p.addrs[ipStr].LastRecheck
		p.mu.RUnlock()
		if now.Sub(lr) < p.recheckFailedInterval {
			continue
		}
		p.recordRequest(ipStr, p.probeSLAAC(ipStr, timeout))
		p.mu.Lock()
		if a, ok := p.addrs[ipStr]; ok {
			a.LastRecheck = now
		}
		p.mu.Unlock()
	}
}

// probeSLAAC performs a lightweight liveness check for a SLAAC source address:
// it verifies the kernel can route traffic from that source out the WAN and
// that the address can be bound. A full TCP/TLS/HTTPS probe to the (optional)
// test_target is intentionally skipped — the test target is often unreachable
// from the WAN, and reaching it is not required for the address to be usable.
func (p *IPv6Pool) probeSLAAC(ipStr string, timeout time.Duration) bool {
	localIP := net.ParseIP(ipStr)
	if localIP == nil {
		return false
	}
	p.mu.Lock()
	addr, ok := p.addrs[ipStr]
	if !ok {
		p.mu.Unlock()
		return false
	}
	p.mu.Unlock()
	addr.LastCheck = time.Now()

	if !p.checkRouteAndBind(localIP, addr) {
		return false
	}
	addr.FailureStage = "success"
	addr.Status = "alive"
	return true
}

func (p *IPv6Pool) CleanupAddedAddresses() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for ipStr, addr := range p.addrs {
		exec.Command("ip", "-6", "addr", "del", ipStr+"/128", "dev", p.sourceIface).Run()
		if addr.PolicyRouted {
			exec.Command("ip", "-6", "rule", "del", "from", ipStr+"/128",
				"table", strconv.Itoa(p.tableID)).Run()
		}
		log.Printf("[CLEANUP] Removed %s from %s", ipStr, p.sourceIface)
		delete(p.addrs, ipStr)
	}
	exec.Command("ip", "-6", "route", "flush", "table", strconv.Itoa(p.tableID)).Run()
	if p.dummyCreated {
		if err := removeDummyInterface(p.dummyIface); err != nil {
			log.Printf("[CLEANUP] failed to remove dummy %s: %v", p.dummyIface, err)
		} else {
			log.Printf("[CLEANUP] removed dummy interface %s", p.dummyIface)
		}
	}
}
// SubnetOf is exported wrapper for subnetOf.
func SubnetOf(ip net.IP) string { return subnetOf(ip) }

// Exported helpers for main to configure pool without accessing unexported fields.
func (p *IPv6Pool) SetSourceMode(m string) { p.sourceMode = m }
func (p *IPv6Pool) GetSourceMode() string { p.mu.RLock(); defer p.mu.RUnlock(); return p.sourceMode }
func (p *IPv6Pool) AddHost(k, v string) { p.mu.Lock(); defer p.mu.Unlock(); p.hosts[k] = v }
func (p *IPv6Pool) HostCount() int { p.mu.RLock(); defer p.mu.RUnlock(); return len(p.hosts) }
func (p *IPv6Pool) SetSlaacInfo(wanIP net.IP, prefix *net.IPNet) {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.slaacWANIP = wanIP
    p.slaacPrefix = prefix
    p.prefix = prefix
}
func (p *IPv6Pool) SetFailureThreshold(v int) { p.failureThreshold = v }
func (p *IPv6Pool) SetRecheckFailedInterval(d time.Duration) { p.recheckFailedInterval = d }
func (p *IPv6Pool) SetSlaacPoolSize(n int) { p.slaacPoolSize = n }

func (p *IPv6Pool) StartInfraDNSRefresh(ctx context.Context, interval time.Duration) { p.startInfraDNSRefresh(ctx, interval) }

func (p *IPv6Pool) HealthCheckSLAAC(timeout time.Duration) { p.healthCheckSLAAC(timeout) }

func (p *IPv6Pool) ReconcileSLAAC() { p.reconcileSLAAC() }

func (p *IPv6Pool) GetSlaacPoolSize() int { return p.slaacPoolSize }

