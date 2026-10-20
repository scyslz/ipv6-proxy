package internal

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ipv6-proxy/internal/web"
)

// ==================== API Server ====================

type APIServer struct {
	addr string
	rt   *Runtime
	// proxy is used only to report/verify the address the proxy is actually
	// listening on. It may be nil in tests.
	proxy *ProxyServer

	// cfgMu guards file, the persisted copy of the config that the web console
	// edits. The runtime copy is kept in rt and is replaced on every reload.
	cfgMu   sync.Mutex
	file    *Config
	tokenMu sync.RWMutex
	token   string

	hcRunning int32
	reloadMu  sync.Mutex
}

func NewAPIServer(addr string, pool *IPv6Pool, cfg *Config) *APIServer {
	return NewAPIServerWithRuntime(addr, NewRuntime(pool, cfg))
}

func NewAPIServerWithRuntime(addr string, rt *Runtime) *APIServer {
	cfg := rt.Config()
	return &APIServer{addr: addr, rt: rt, file: cloneConfig(cfg), token: cfg.APIToken}
}

func (s *APIServer) pool() *IPv6Pool { return s.rt.Pool() }
func (s *APIServer) cfg() *Config    { return s.rt.Config() }

// SetProxyServer lets the API report the actual proxy listener address and use
// it for the server-side egress check.
func (s *APIServer) SetProxyServer(p *ProxyServer) { s.proxy = p }

func cloneConfig(cfg *Config) *Config {
	cp := *cfg
	cp.Hosts = make(map[string]string, len(cfg.Hosts))
	for k, v := range cfg.Hosts {
		cp.Hosts[k] = v
	}
	return &cp
}

func (s *APIServer) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/ips", s.handleIPs)
	mux.HandleFunc("/api/generate", s.handleGenerate)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/select", s.handleSelect)
	mux.HandleFunc("/api/egress-check", s.handleEgressCheck)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/hosts", s.handleHosts)
	mux.HandleFunc("/api/addresses", s.handleAddresses)
	mux.HandleFunc("/api/addresses/test", s.handleAddressTest)
	mux.HandleFunc("/api/healthcheck", s.handleHealthCheck)
	mux.HandleFunc("/api/cleanup", s.handleCleanup)
	mux.HandleFunc("/api/oci/prefix", s.handleOCIPrefix)
	mux.HandleFunc("/api/host-egress", s.handleHostEgress)
	mux.HandleFunc("/", s.handleIndex)

	handler := s.withAuth(mux)
	srv := &http.Server{Addr: s.addr, Handler: handler}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	if s.token != "" {
		log.Printf("[API] Listening on %s (token auth enabled)", s.addr)
	} else {
		log.Printf("[API] Listening on %s (no token: set api_token to protect it)", s.addr)
	}
	return srv.ListenAndServe()
}

// withAuth protects /api/* when api_token is configured. The token may be sent
// as X-API-Token, as a Bearer token, or as ?token= (useful for curl). The web
// console itself is served without auth so it can display the token prompt.
func (s *APIServer) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		s.tokenMu.RLock()
		want := s.token
		s.tokenMu.RUnlock()
		if want == "" {
			next.ServeHTTP(w, r)
			return
		}
		got := r.Header.Get("X-API-Token")
		if got == "" {
			if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
				got = strings.TrimSpace(strings.TrimPrefix(a, "Bearer "))
			}
		}
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			jsonErr(w, "unauthorized: provide a valid API token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *APIServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	io.WriteString(w, web.Index)
}

func (s *APIServer) handleIPs(w http.ResponseWriter, r *http.Request) {
	addrs := s.pool().ListAddresses()
	list := make([]*IPv6Addr, 0, len(addrs))
	for _, a := range addrs {
		if a.State == "" {
			a.State = a.Status
		}
		list = append(list, a)
	}
	jsonOut(w, list)
}

// handleGenerate creates `count` random IPv6 source addresses inside the PD
// prefix, adds them to the pool and runs the full staged test on each
// concurrently. It returns the generated addresses with their diagnosed
// usability (status / failure_stage), so the caller can pick the alive ones.
func (s *APIServer) handleGenerate(w http.ResponseWriter, r *http.Request) {
	pool := s.pool()
	cfg := s.cfg()
	count := 5
	if c := r.URL.Query().Get("count"); c != "" {
		if n, err := strconv.Atoi(c); err == nil && n > 0 {
			if n > 50 {
				n = 50
			}
			count = n
		}
	}

	pool.mu.RLock()
	prefix := pool.prefix
	pool.mu.RUnlock()
	generated := make([]string, 0, count)
	for i := 0; i < count; i++ {
		ip := randomIPInPrefix(prefix)
		ipStr := ip.String()
		pool.mu.RLock()
		_, exists := pool.addrs[ipStr]
		pool.mu.RUnlock()
		if exists {
			continue
		}
		if err := pool.AddAddress(ip, subnetOf(ip)); err != nil {
			continue
		}
		generated = append(generated, ipStr)
	}

	// Test each generated address concurrently, then report results.
	var wg sync.WaitGroup
	for _, ipStr := range generated {
		wg.Add(1)
		go func(ipStr string) {
			defer wg.Done()
			pool.TestAddress(ipStr, time.Duration(cfg.ConnectTimeout)*time.Second)
		}(ipStr)
	}
	wg.Wait()

	list := make([]*IPv6Addr, 0, len(generated))
	alive := 0
	for _, ipStr := range generated {
		pool.mu.RLock()
		addr := pool.addrs[ipStr]
		pool.mu.RUnlock()
		if addr != nil {
			if addr.Status == "alive" {
				alive++
			}
			cp := *addr
			list = append(list, &cp)
		}
	}

	prefixStr := ""
	if prefix != nil {
		prefixStr = prefix.String()
	}
	jsonOut(w, map[string]interface{}{
		"count":     len(generated),
		"alive":     alive,
		"prefix":    prefixStr,
		"addresses": list,
	})
}

func (s *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	pool := s.pool()
	cfg := s.cfg()
	pool.mu.RLock()
	total, alive, dead := 0, 0, 0
	for _, a := range pool.addrs {
		total++
		if a.Status == "alive" {
			alive++
		} else if a.Status == "dead" {
			dead++
		}
	}
	prefix := ""
	if pool.prefix != nil {
		prefix = pool.prefix.String()
	}
	sourceMode := pool.sourceMode
	selectionMode := pool.selectionMode
	wanIface := pool.wanIface
	dummyIface := pool.dummyIface
	tableID := pool.tableID
	ociPrefixID := pool.ociPrefixID
	ociPrefixLength := pool.ociPrefixLength
	// In OCI prefix mode the pool prefix is the delegated segment (e.g. /84),
	// which lives inside the VNIC's own /64 subnet. Report both so the console
	// does not look like pool addresses fall outside "the subnet".
	vnicSubnet := ""
	if pool.prefix != nil && sourceMode == "oci" {
		vnicSubnet = subnetOf(pool.prefix.IP.To16())
	}
	pool.mu.RUnlock()

	proxyAddr := cfg.ProxyAddr
	if s.proxy != nil {
		proxyAddr = s.proxy.Addr()
	}
	jsonOut(w, map[string]interface{}{
		"wan_interface":        wanIface,
		"dummy_interface":      dummyIface,
		"prefix":               prefix,
		"vnic_subnet":          vnicSubnet,
		"total":                total,
		"alive":                alive,
		"dead":                 dead,
		"selection_mode":       selectionMode,
		"source_mode":          sourceMode,
		"pinned":               pool.GetPinnedIP(),
		"proxy_addr":           proxyAddr,
		"api_addr":             s.addr,
		"dns_server":           pool.dnsServerResolved(),
		"test_target":          pool.testTargetResolved(),
		"policy_table":         tableID,
		"oci_prefix_id":        ociPrefixID,
		"oci_prefix_length":    ociPrefixLength,
		"slaac_prefix":         pool.slaacPrefixString(),
		"slaac_wan_ip":         pool.slaacWANIPString(),
		"subnet_count":         cfg.SubnetCount,
		"slaac_pool_size":      cfg.SLAACPoolSize,
		"health_interval":      cfg.HealthInterval,
		"connect_timeout":      cfg.ConnectTimeout,
		"max_retries":          cfg.MaxRetries,
		"hosts":                pool.ListHosts(),
		"health_check_running": s.healthCheckRunning(),
	})
}

// handleSelect manages the "manual" selection mode: view the current pinned
// IP, set it explicitly (?ip=...), switch to the next alive address (?next),
// or change the selection algorithm (?mode=...). With no query params it just
// reports the current state.
func (s *APIServer) handleSelect(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	mode := q.Get("mode")
	ip := q.Get("ip")
	_, next := q["next"] // presence of the key triggers a switch, e.g. ?next or ?next=1
	pool := s.pool()

	if mode != "" {
		if err := pool.SetSelectionMode(mode); err != nil {
			jsonErr(w, errStr(err), 400)
			return
		}
	}
	if ip != "" {
		if err := pool.SetPinnedIP(ip); err != nil {
			jsonErr(w, errStr(err), 400)
			return
		}
	}
	switchedTo := ""
	if next {
		nxt, err := pool.SwitchToNext()
		if err != nil {
			jsonErr(w, errStr(err), 400)
			return
		}
		switchedTo = nxt
	}
	// In "follow proxy" mode the host's own IPv6 source must track the pin
	// immediately; otherwise the system keeps egressing from the old address
	// until the next restart or VNIC switch.
	if cfg := s.cfg(); NormalizeHostEgressMode(cfg.HostEgressMode) == "proxy" {
		if err := ApplyHostEgress(cfg, pool); err != nil {
			log.Printf("[HOST] follow-proxy update after select failed: %v", err)
		}
	}
	jsonOut(w, map[string]string{
		"selection_mode": pool.GetSelectionMode(),
		"pinned":         pool.GetPinnedIP(),
		"switched_to":    switchedTo,
	})
}

// handleEgressCheck asks the local proxy to fetch https://api64.ipify.org and
// returns the exit IPv6 it actually used. When ?ip= is given (or an address is
// currently pinned) the request is sent through the proxy with X-Source-IPv6,
// so the result reflects that address. This is the console's "curl through the
// proxy" check after switching.
func (s *APIServer) handleEgressCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requested := strings.TrimSpace(r.URL.Query().Get("ip"))
	expected := requested
	if expected == "" {
		expected = s.pool().GetPinnedIP()
	}
	proxyAddr := s.cfg().ProxyAddr
	if s.proxy != nil {
		proxyAddr = s.proxy.Addr()
	}
	proxyAddr = proxyLoopbackAddr(proxyAddr)
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		jsonErr(w, "invalid proxy address: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tr := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://api64.ipify.org", nil)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("User-Agent", "ipv6-proxy-console/egress-check")
	if expected != "" {
		req.Header.Set("X-Source-IPv6", expected)
	}
	started := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(started)
	if err != nil {
		jsonErr(w, "通过代理检测失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	publicIP := strings.TrimSpace(string(body))
	if resp.StatusCode != http.StatusOK {
		jsonErr(w, fmt.Sprintf("api64.ipify.org 返回 %d: %s", resp.StatusCode, publicIP), http.StatusBadGateway)
		return
	}
	parsed := net.ParseIP(publicIP)
	if parsed == nil || parsed.To4() != nil {
		jsonErr(w, fmt.Sprintf("代理返回了非 IPv6 结果: %q", publicIP), http.StatusBadGateway)
		return
	}
	out := map[string]interface{}{
		"ok":         true,
		"ip":         publicIP,
		"via":        "proxy",
		"proxy":      proxyAddr,
		"target":     "https://api64.ipify.org",
		"elapsed_ms": elapsed.Milliseconds(),
	}
	if expected != "" {
		out["expected"] = expected
		out["match"] = publicIP == expected
	}
	log.Printf("[API] egress check via %s: %s (expected %q, %d ms)", proxyAddr, publicIP, expected, elapsed.Milliseconds())
	jsonOut(w, out)
}

// proxyLoopbackAddr turns a wildcard listen address into an address the API
// server can dial locally. Specific hosts are kept as-is.
func proxyLoopbackAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return net.JoinHostPort(host, port)
}

// handleLogs returns the most recent log lines captured in memory. Use ?lines=N
// to limit the number returned (default 200). DELETE clears the buffer.
func (s *APIServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		log.Printf("[API] log buffer cleared")
		LogBuf.Clear()
		jsonOut(w, map[string]interface{}{"cleared": true})
		return
	}
	if r.Method != http.MethodGet {
		jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	n := 200
	if v := r.URL.Query().Get("lines"); v != "" {
		if k, err := strconv.Atoi(v); err == nil && k > 0 {
			n = k
		}
	}
	lines := LogBuf.Tail(n)
	jsonOut(w, map[string]interface{}{"lines": lines, "count": len(lines)})
}

// ==================== Web console API ====================

// editableConfig is the subset of Config the web console may change. Pointer
// fields distinguish "not sent" from an intentional zero value.
type editableConfig struct {
	ProxyAddr        *string `json:"proxy_addr"`
	APIAddr          *string `json:"api_addr"`
	Prefix           *string `json:"prefix"`
	SubnetCount      *int    `json:"subnet_count"`
	SLAACPoolSize    *int    `json:"slaac_pool_size"`
	FailureThreshold *int    `json:"failure_threshold"`
	HealthInterval   *int    `json:"health_interval_sec"`
	ConnectTimeout   *int    `json:"connect_timeout_sec"`
	MaxRetries       *int    `json:"max_retries"`
	SelectionMode    *string `json:"selection_mode"`
	SourceMode       *string `json:"source_mode"`
	DummyIface       *string `json:"dummy_iface"`
	DNSServer        *string `json:"dns_server"`
	TestTarget       *string `json:"test_target"`
	OciCompartment   *string `json:"oci_compartment"`
	OciVnicID        *string `json:"oci_vnic_id"`
	OciPrefixID      *string `json:"oci_prefix_id"`
	OciPrefixLength  *int    `json:"oci_prefix_length"`
	OciConfigPath    *string `json:"oci_config_path"`
	OciNoCreate      *bool   `json:"oci_no_create"`
	OciSourceIface   *string `json:"oci_source_iface"`
	OciWanGateway    *string `json:"oci_wan_gateway"`
	APIToken         *string `json:"api_token"`
	// Hosts replaces the whole static mapping table when provided.
	Hosts *map[string]string `json:"hosts"`
}

func (s *APIServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.cfgMu.Lock()
		out := cloneConfig(s.file)
		s.cfgMu.Unlock()
		if out.APIToken != "" {
			out.APIToken = "***"
		}
		jsonOut(w, map[string]interface{}{
			"config":          out,
			"path":            out.Path,
			"proxy_addr":      out.ProxyAddr,
			"runtime":         s.runtimeSummary(),
			"token_protected": s.hasToken(),
		})
	case http.MethodPost, http.MethodPut:
		s.updateConfig(w, r)
	default:
		jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *APIServer) runtimeSummary() map[string]interface{} {
	pool := s.pool()
	pool.mu.RLock()
	sourceMode := pool.sourceMode
	prefix := ""
	if pool.prefix != nil {
		prefix = pool.prefix.String()
	}
	ociPrefixID := pool.ociPrefixID
	ociPrefixLength := pool.ociPrefixLength
	pool.mu.RUnlock()
	return map[string]interface{}{
		"selection_mode":    pool.GetSelectionMode(),
		"source_mode":       sourceMode,
		"prefix":            prefix,
		"oci_prefix_id":     ociPrefixID,
		"oci_prefix_length": ociPrefixLength,
		"dns_server":        pool.dnsServerResolved(),
		"test_target":       pool.testTargetResolved(),
	}
}

func (s *APIServer) hasToken() bool {
	s.tokenMu.RLock()
	defer s.tokenMu.RUnlock()
	return s.token != ""
}

func (s *APIServer) updateConfig(w http.ResponseWriter, r *http.Request) {
	var in editableConfig
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	s.cfgMu.Lock()
	next := cloneConfig(s.file)
	s.cfgMu.Unlock()

	// Validate every provided field before touching runtime state, so a bad
	// request cannot leave the server half-updated.
	if err := validateEditable(next, &in); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}

	// next already carries every merged field; keep host mappings in sync with
	// the live pool since /api/hosts can change them independently.
	if in.Hosts == nil {
		next.Hosts = s.pool().ListHosts()
	}

	applied, restart, err := s.commitConfig(next, &in)
	if err != nil {
		code := http.StatusInternalServerError
		if strings.HasPrefix(err.Error(), "apply config:") {
			code = http.StatusBadRequest
		}
		jsonErr(w, err.Error(), code)
		return
	}
	log.Printf("[API] config saved to %s (applied: %v, restart: %v)", next.Path, applied, restart)
	if NormalizeHostEgressMode(next.HostEgressMode) == "proxy" {
		if err := ApplyHostEgress(next, s.pool()); err != nil {
			log.Printf("[HOST] follow-proxy update after config save failed: %v", err)
		}
	}

	out := cloneConfig(next)
	if out.APIToken != "" {
		out.APIToken = "***"
	}
	jsonOut(w, map[string]interface{}{
		"ok":               true,
		"path":             next.Path,
		"config":           out,
		"applied":          applied,
		"restart_required": restart,
		"runtime":          s.runtimeSummary(),
	})
}

// commitConfig builds a replacement pool when needed, persists next, then
// publishes it. The caller must hold reloadMu. Validation and pool building
// happen before the file is written, so a bad change leaves both the live
// runtime and the saved config untouched.
func (s *APIServer) commitConfig(next *Config, in *editableConfig) (applied, restart []string, err error) {
	newPool, err := s.buildPoolIfNeeded(next)
	if err != nil {
		return nil, nil, fmt.Errorf("apply config: %w", err)
	}

	s.cfgMu.Lock()
	if err := next.Save(); err != nil {
		s.cfgMu.Unlock()
		if newPool != nil {
			// This replacement was never published, so remove only what it
			// created and leave the live pool's policy table alone.
			newPool.TeardownExcept(nil, false)
		}
		return nil, nil, fmt.Errorf("save config: %w", err)
	}
	s.file = next
	s.cfgMu.Unlock()

	applied, restart = applyEditable(s, next, newPool, in)
	return applied, restart, nil
}

// buildPoolIfNeeded returns a fully built replacement pool when a setting that
// changes the pool topology differs from the live runtime. It returns nil when
// the existing pool can be updated in place.
func (s *APIServer) buildPoolIfNeeded(next *Config) (*IPv6Pool, error) {
	cur := s.cfg()
	if !needsPoolRebuild(cur, next) {
		return nil, nil
	}
	old := s.pool()
	newPool, err := BuildPoolFromConfig(next, old.WANIface())
	if err != nil {
		return nil, err
	}
	if newPool != nil && newPool.tableID == old.tableID {
		newPool.SetPolicyTable(nextTableIDExcept(old.tableID))
		log.Printf("[POOL] replacement pool table %d conflicts with live table; using %d", old.tableID, newPool.tableID)
	}
	return newPool, nil
}

// needsPoolRebuild reports whether next requires rebuilding the source pool.
// Listener, timeout, token, DNS and host changes are applied in place.
func needsPoolRebuild(cur, next *Config) bool {
	if cur == nil {
		return true
	}
	if cur.SourceMode != next.SourceMode || cur.Prefix != next.Prefix || cur.DummyIface != next.DummyIface {
		return true
	}
	switch next.SourceMode {
	case "pool", "ephemeral", "":
		if cur.SubnetCount != next.SubnetCount {
			return true
		}
	case "slaac":
		if cur.SLAACPoolSize != next.SLAACPoolSize {
			return true
		}
	case "oci":
		if cur.SLAACPoolSize != next.SLAACPoolSize ||
			cur.OciCompartment != next.OciCompartment ||
			cur.OciVnicID != next.OciVnicID ||
			cur.OciPrefixID != next.OciPrefixID ||
			cur.OciPrefixLength != next.OciPrefixLength ||
			cur.OciConfigPath != next.OciConfigPath ||
			cur.OciNoCreate != next.OciNoCreate ||
			cur.OciSourceIface != next.OciSourceIface ||
			cur.OciWanGateway != next.OciWanGateway {
			return true
		}
	}
	return false
}

// validateEditable checks the incoming values against the config they will be
// merged into. It mutates next (the merged copy) but never the live pool.
func validateEditable(next *Config, in *editableConfig) error {
	oldPrefix := next.Prefix
	oldOciPrefixLength := next.OciPrefixLength
	oldOciCompartment := next.OciCompartment
	oldOciVnicID := next.OciVnicID
	if in.ProxyAddr != nil {
		if _, _, err := net.SplitHostPort(*in.ProxyAddr); err != nil {
			return fmt.Errorf("proxy_addr must be host:port")
		}
		next.ProxyAddr = *in.ProxyAddr
	}
	if in.APIAddr != nil {
		if _, _, err := net.SplitHostPort(*in.APIAddr); err != nil {
			return fmt.Errorf("api_addr must be host:port")
		}
		next.APIAddr = *in.APIAddr
	}
	if in.Prefix != nil {
		v := strings.TrimSpace(*in.Prefix)
		if v != "" {
			if _, _, err := net.ParseCIDR(v); err != nil {
				return fmt.Errorf("prefix must be a valid IPv6 CIDR")
			}
		}
		next.Prefix = v
	}
	if in.SubnetCount != nil {
		if *in.SubnetCount < 1 || *in.SubnetCount > 16 {
			return fmt.Errorf("subnet_count must be 1-16")
		}
		next.SubnetCount = *in.SubnetCount
	}
	if in.SLAACPoolSize != nil {
		if *in.SLAACPoolSize < 1 || *in.SLAACPoolSize > 32 {
			return fmt.Errorf("slaac_pool_size must be 1-32")
		}
		next.SLAACPoolSize = *in.SLAACPoolSize
	}
	if in.FailureThreshold != nil {
		if *in.FailureThreshold < 1 {
			return fmt.Errorf("failure_threshold must be >= 1")
		}
		next.FailureThreshold = *in.FailureThreshold
	}
	if in.HealthInterval != nil {
		if *in.HealthInterval < 5 {
			return fmt.Errorf("health_interval_sec must be >= 5")
		}
		next.HealthInterval = *in.HealthInterval
	}
	if in.ConnectTimeout != nil {
		if *in.ConnectTimeout < 1 || *in.ConnectTimeout > 120 {
			return fmt.Errorf("connect_timeout_sec must be 1-120")
		}
		next.ConnectTimeout = *in.ConnectTimeout
	}
	if in.MaxRetries != nil {
		if *in.MaxRetries < 1 || *in.MaxRetries > 50 {
			return fmt.Errorf("max_retries must be 1-50")
		}
		next.MaxRetries = *in.MaxRetries
	}
	if in.SelectionMode != nil {
		switch *in.SelectionMode {
		case "round-robin", "random", "manual":
			next.SelectionMode = *in.SelectionMode
		default:
			return fmt.Errorf("invalid selection_mode %q (want round-robin|random|manual)", *in.SelectionMode)
		}
	}
	if in.SourceMode != nil {
		switch *in.SourceMode {
		case "pool", "slaac", "oci", "ephemeral":
			next.SourceMode = *in.SourceMode
		default:
			return fmt.Errorf("source_mode must be pool|slaac|oci|ephemeral")
		}
	}
	if in.DummyIface != nil {
		if strings.TrimSpace(*in.DummyIface) == "" {
			return fmt.Errorf("dummy_iface must not be empty")
		}
		next.DummyIface = *in.DummyIface
	}
	if in.DNSServer != nil || in.TestTarget != nil {
		dns := next.DNSServer
		if in.DNSServer != nil {
			dns = strings.TrimSpace(*in.DNSServer)
		}
		tgt := next.TestTarget
		if in.TestTarget != nil {
			tgt = strings.TrimSpace(*in.TestTarget)
		}
		if dns == "" || tgt == "" {
			return fmt.Errorf("dns_server and test_target must not be empty")
		}
		if !isIPv6Literal(dns) {
			if _, err := resolveAAAA(context.Background(), dns, ""); err != nil {
				return fmt.Errorf("resolve dns_server %q: %w", dns, err)
			}
		}
		if !isIPv6Literal(tgt) {
			if _, err := resolveAAAA(context.Background(), tgt, dns); err != nil {
				return fmt.Errorf("resolve test_target %q: %w", tgt, err)
			}
		}
		next.DNSServer = dns
		next.TestTarget = tgt
	}
	if in.OciCompartment != nil {
		next.OciCompartment = *in.OciCompartment
	}
	if in.OciVnicID != nil {
		next.OciVnicID = *in.OciVnicID
	}
	if in.OciPrefixID != nil {
		next.OciPrefixID = strings.TrimSpace(*in.OciPrefixID)
	}
	if in.OciPrefixLength != nil {
		if *in.OciPrefixLength != 0 && (*in.OciPrefixLength < 80 || *in.OciPrefixLength > 128 || *in.OciPrefixLength%4 != 0) {
			return fmt.Errorf("oci_prefix_length must be 0 or 80-128 divisible by 4")
		}
		next.OciPrefixLength = *in.OciPrefixLength
	}
	if in.OciConfigPath != nil {
		next.OciConfigPath = *in.OciConfigPath
	}
	if in.OciNoCreate != nil {
		next.OciNoCreate = *in.OciNoCreate
	}
	// An explicit VNIC change invalidates the stored host interface/gateway.
	// BuildPoolFromConfig re-resolves both from instance metadata.
	if in.OciVnicID != nil && next.OciVnicID != oldOciVnicID {
		if in.OciSourceIface == nil {
			next.OciSourceIface = ""
		}
		if in.OciWanGateway == nil {
			next.OciWanGateway = ""
		}
	}
	if in.OciSourceIface != nil {
		next.OciSourceIface = strings.TrimSpace(*in.OciSourceIface)
	}
	if in.OciWanGateway != nil {
		v := strings.TrimSpace(*in.OciWanGateway)
		if v != "" {
			if ip := net.ParseIP(v); ip == nil || ip.To4() != nil {
				return fmt.Errorf("oci_wan_gateway must be an IPv6 address")
			}
		}
		next.OciWanGateway = v
	}
	if in.Hosts != nil {
		clean := make(map[string]string, len(*in.Hosts))
		for host, target := range *in.Hosts {
			if NormalizeHost(host) == "" || strings.TrimSpace(target) == "" {
				return fmt.Errorf("hosts entries need a non-empty host and target")
			}
			if ip := net.ParseIP(target); ip != nil && ip.To4() != nil {
				return fmt.Errorf("hosts target must be IPv6 or a domain alias (IPv4 unsupported)")
			}
			clean[NormalizeHost(host)] = strings.TrimSpace(target)
		}
		next.Hosts = clean
	}
	if in.APIToken != nil {
		next.APIToken = strings.TrimSpace(*in.APIToken)
	}
	// oci_prefix_id pins one specific OCI prefix object. A normal form save
	// keeps it (the UI does not submit it), but changing the prefix length,
	// interface, compartment, manual prefix, or no-create mode means the old
	// pin is no longer what the operator asked for. Clear it so the change
	// takes effect instead of silently continuing to use the pinned object.
	if in.OciPrefixID == nil {
		changed := next.Prefix != oldPrefix ||
			next.OciPrefixLength != oldOciPrefixLength ||
			next.OciCompartment != oldOciCompartment ||
			next.OciVnicID != oldOciVnicID
		if changed || next.OciPrefixLength == 0 {
			next.OciPrefixID = ""
		}
	}
	return nil
}

// applyEditable publishes next to the live runtime and reports which fields
// took effect immediately. Listen address changes still require a restart
// because the listeners are bound at process start.
func applyEditable(s *APIServer, next *Config, newPool *IPv6Pool, in *editableConfig) (applied, restart []string) {
	applied = make([]string, 0, 8)
	restart = make([]string, 0, 2)
	// Compare listener fields against the actual bound addresses, not the
	// previous config value: a previous save may already have changed the file
	// while the listeners still run on the old address.
	if in.ProxyAddr != nil {
		actual := s.cfg().ProxyAddr
		if s.proxy != nil {
			actual = s.proxy.Addr()
		}
		if *in.ProxyAddr != actual {
			restart = append(restart, "proxy_addr")
		}
	}
	if in.APIAddr != nil && *in.APIAddr != s.addr {
		restart = append(restart, "api_addr")
	}

	oldPool := s.pool()
	targetPool := oldPool
	if newPool != nil {
		targetPool = newPool
	}

	if in.FailureThreshold != nil {
		targetPool.SetFailureThreshold(*in.FailureThreshold)
		applied = append(applied, "failure_threshold")
	}
	if in.SelectionMode != nil {
		// Validated above, so this cannot fail.
		_ = targetPool.SetSelectionMode(*in.SelectionMode)
		applied = append(applied, "selection_mode")
	}
	if in.DNSServer != nil || in.TestTarget != nil {
		if err := targetPool.SetInfraDNS(next.DNSServer, next.TestTarget); err != nil {
			log.Printf("[API] refresh DNS config: %v", err)
		}
		if in.DNSServer != nil {
			applied = append(applied, "dns_server")
		}
		if in.TestTarget != nil {
			applied = append(applied, "test_target")
		}
	}
	if in.Hosts != nil {
		// validateEditable already normalized the map into next.
		targetPool.SetHosts(next.Hosts)
		applied = append(applied, "hosts")
	}
	if in.APIToken != nil {
		// validateEditable already trimmed it into next.
		s.tokenMu.Lock()
		s.token = next.APIToken
		s.tokenMu.Unlock()
		applied = append(applied, "api_token")
	}
	if in.HealthInterval != nil {
		applied = append(applied, "health_interval_sec")
	}
	if in.ConnectTimeout != nil {
		applied = append(applied, "connect_timeout_sec")
	}
	if in.MaxRetries != nil {
		applied = append(applied, "max_retries")
	}
	if in.Prefix != nil {
		applied = append(applied, "prefix")
	}
	if in.SubnetCount != nil {
		applied = append(applied, "subnet_count")
	}
	if in.SLAACPoolSize != nil {
		applied = append(applied, "slaac_pool_size")
	}
	if in.SourceMode != nil {
		applied = append(applied, "source_mode")
	}
	if in.DummyIface != nil {
		applied = append(applied, "dummy_iface")
	}
	if in.OciCompartment != nil {
		applied = append(applied, "oci_compartment")
	}
	if in.OciVnicID != nil {
		applied = append(applied, "oci_vnic_id")
	}
	if in.OciPrefixID != nil {
		applied = append(applied, "oci_prefix_id")
	}
	if in.OciPrefixLength != nil {
		applied = append(applied, "oci_prefix_length")
	}
	if in.OciConfigPath != nil {
		applied = append(applied, "oci_config_path")
	}
	if in.OciNoCreate != nil {
		applied = append(applied, "oci_no_create")
	}
	if in.OciSourceIface != nil {
		applied = append(applied, "oci_source_iface")
	}
	if in.OciWanGateway != nil {
		applied = append(applied, "oci_wan_gateway")
	}

	if newPool != nil {
		// If the replacement pool reuses the dummy interface this process
		// created, transfer ownership so the final shutdown still removes it.
		if newPool.sourceIface == newPool.dummyIface && newPool.dummyIface != "" &&
			oldPool.dummyCreated && newPool.dummyIface == oldPool.dummyIface {
			newPool.dummyCreated = true
		}
		s.rt.Set(newPool, next)
		newPool.SetHostEgressIP(oldPool.HostEgressIP())
		// Remove the old pool's addresses without touching addresses the new
		// pool uses. Keep the dummy interface if the new pool still uses it.
		keep := newPool.AddressSet()
		keepDummy := newPool.sourceIface != "" && newPool.sourceIface == oldPool.dummyIface
		oldPool.TeardownExcept(keep, keepDummy)
		log.Printf("[API] hot-reloaded pool: mode=%s prefix=%s interface=%s", newPool.GetSourceMode(), newPool.Prefix(), newPool.sourceIface)
		if newPool.GetSourceMode() != "ephemeral" {
			go func() {
				// Give the kernel time to finish duplicate address detection
				// (DAD) before probing the freshly added /128s. Without this
				// the immediate probe can report bind_failed while the
				// address is still "tentative".
				time.Sleep(2 * time.Second)
				timeout := time.Duration(next.ConnectTimeout) * time.Second
				if newPool.GetSourceMode() == "slaac" {
					newPool.HealthCheckSLAAC(timeout)
				} else {
					newPool.HealthCheck(timeout)
				}
			}()
		}
	} else {
		s.rt.SetConfig(next)
	}
	return applied, restart
}

// handleHosts manages the static hostname -> IPv6 mappings.
// GET lists them, POST {host, target} adds/updates, DELETE ?host= removes.
func (s *APIServer) handleHosts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOut(w, map[string]interface{}{"hosts": s.pool().ListHosts()})
	case http.MethodPost, http.MethodPut:
		var in struct {
			Host   string `json:"host"`
			Target string `json:"target"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
			jsonErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		host := NormalizeHost(in.Host)
		target := strings.TrimSpace(in.Target)
		if host == "" || target == "" {
			jsonErr(w, "host and target are required", http.StatusBadRequest)
			return
		}
		if ip := net.ParseIP(target); ip != nil && ip.To4() != nil {
			jsonErr(w, "target must be IPv6 or a domain alias (IPv4 unsupported)", http.StatusBadRequest)
			return
		}
		s.pool().AddHost(host, target)
		if err := s.persistHosts(); err != nil {
			jsonErr(w, "save config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("[API] host mapping %s -> %s saved", host, target)
		jsonOut(w, map[string]interface{}{"ok": true, "hosts": s.pool().ListHosts()})
	case http.MethodDelete:
		host := NormalizeHost(r.URL.Query().Get("host"))
		if host == "" {
			jsonErr(w, "host query parameter required", http.StatusBadRequest)
			return
		}
		if !s.pool().RemoveHost(host) {
			jsonErr(w, "host mapping not found", http.StatusNotFound)
			return
		}
		if err := s.persistHosts(); err != nil {
			jsonErr(w, "save config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOut(w, map[string]interface{}{"ok": true, "hosts": s.pool().ListHosts()})
	default:
		jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *APIServer) persistHosts() error {
	hosts := s.pool().ListHosts()
	s.cfgMu.Lock()
	next := cloneConfig(s.file)
	next.Hosts = hosts
	if err := next.Save(); err != nil {
		s.cfgMu.Unlock()
		return err
	}
	s.file = next
	s.cfgMu.Unlock()
	// Keep the runtime snapshot in sync so a later config save does not treat
	// this host change as a stale value.
	s.rt.SetConfig(cloneConfig(next))
	return nil
}

// handleAddresses adds or removes a single source address at runtime.
// POST {ip:"..."} adds and probes it, DELETE ?ip=... removes it.
func (s *APIServer) handleAddresses(w http.ResponseWriter, r *http.Request) {
	pool := s.pool()
	switch r.Method {
	case http.MethodPost:
		var in struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
			jsonErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		ipStr := strings.TrimSpace(in.IP)
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() != nil {
			jsonErr(w, "ip must be a valid IPv6 address", http.StatusBadRequest)
			return
		}
		pool.mu.RLock()
		prefix := pool.prefix
		pool.mu.RUnlock()
		if prefix == nil || !prefix.Contains(ip) {
			prefixStr := ""
			if prefix != nil {
				prefixStr = prefix.String()
			}
			jsonErr(w, fmt.Sprintf("ip is outside the pool prefix %s", prefixStr), http.StatusBadRequest)
			return
		}
		if err := pool.AddAddress(ip, subnetOf(ip)); err != nil {
			jsonErr(w, err.Error(), http.StatusConflict)
			return
		}
		go pool.TestAddress(ip.String(), time.Duration(s.cfg().ConnectTimeout)*time.Second)
		jsonOut(w, map[string]interface{}{"ok": true, "ip": ip.String(), "note": "added, probe running"})
	case http.MethodDelete:
		ipStr := strings.TrimSpace(r.URL.Query().Get("ip"))
		if ipStr == "" {
			jsonErr(w, "ip query parameter required", http.StatusBadRequest)
			return
		}
		if err := pool.RemoveAddress(ipStr); err != nil {
			jsonErr(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonOut(w, map[string]interface{}{"ok": true, "ip": ipStr})
	default:
		jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAddressTest re-runs the full staged probe for one address.
func (s *APIServer) handleAddressTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		jsonErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	ipStr := strings.TrimSpace(in.IP)
	if ipStr == "" {
		ipStr = strings.TrimSpace(r.URL.Query().Get("ip"))
	}
	if ipStr == "" {
		jsonErr(w, "ip is required", http.StatusBadRequest)
		return
	}
	go s.pool().TestAddress(ipStr, time.Duration(s.cfg().ConnectTimeout)*time.Second)
	jsonOut(w, map[string]interface{}{"ok": true, "ip": ipStr, "note": "probe running"})
}

// handleCleanup inspects or removes leftover networking state. GET returns a
// preview (what would be removed); POST executes the selected steps.
func (s *APIServer) handleCleanup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOut(w, map[string]interface{}{"preview": s.pool().CleanupPreviewInfo()})
	case http.MethodPost:
		var opts CleanupOptions
		if r.Body != nil {
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&opts); err != nil && err != io.EOF {
				jsonErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		if !opts.Stale && !opts.Routes && !opts.Dummy && !opts.Addresses && len(opts.DeleteOCI) == 0 {
			jsonErr(w, "nothing selected: enable at least one of addresses|stale|routes|dummy|delete_oci", http.StatusBadRequest)
			return
		}
		if opts.Keep < 0 {
			jsonErr(w, "keep must be >= 0", http.StatusBadRequest)
			return
		}
		if opts.Keep > 0 && !opts.Addresses {
			jsonErr(w, "keep is only valid together with addresses", http.StatusBadRequest)
			return
		}
		pool := s.pool()
		res := pool.Cleanup(opts)
		if opts.Addresses && opts.Keep > 0 {
			// Remember the reduced size so a restart in oci/slaac mode does
			// not recreate the deleted addresses.
			s.cfgMu.Lock()
			next := cloneConfig(s.file)
			next.SLAACPoolSize = opts.Keep
			if err := next.Save(); err != nil {
				res.Warnings = append(res.Warnings, "保存 slaac_pool_size 失败: "+err.Error())
			} else {
				s.file = next
				s.rt.SetConfig(cloneConfig(next))
				log.Printf("[API] cleanup kept %d address(es), slaac_pool_size saved as %d", opts.Keep, opts.Keep)
			}
			s.cfgMu.Unlock()
		}
		jsonOut(w, map[string]interface{}{
			"ok":      true,
			"result":  res,
			"preview": pool.CleanupPreviewInfo(),
		})
	default:
		jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleHostEgress reads or applies the host-only egress policy. It is kept
// separate from the proxy pool: changing it never rebuilds the pool.
func (s *APIServer) handleHostEgress(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOut(w, HostEgressStatus(s.cfg(), s.pool()))
	case http.MethodPost, http.MethodPut:
		var in struct {
			Mode   string `json:"mode"`
			VnicID string `json:"vnic_id"`
			IP     string `json:"ip"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
			jsonErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		in.Mode = strings.ToLower(strings.TrimSpace(in.Mode))
		in.VnicID = strings.TrimSpace(in.VnicID)
		in.IP = strings.TrimSpace(in.IP)
		if !ValidHostEgressMode(in.Mode) {
			jsonErr(w, "mode must be system, ipv4, ipv6 or proxy", http.StatusBadRequest)
			return
		}
		if in.Mode == "" {
			in.Mode = "system"
		}
		if in.Mode == "ipv6" && in.VnicID == "" {
			jsonErr(w, "vnic_id is required when mode=ipv6", http.StatusBadRequest)
			return
		}
		if in.IP != "" {
			ip := net.ParseIP(in.IP)
			if ip == nil || ip.To4() != nil || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() {
				jsonErr(w, "ip must be a global unicast IPv6 address", http.StatusBadRequest)
				return
			}
			if in.Mode != "ipv6" {
				jsonErr(w, "ip is only supported when mode=ipv6", http.StatusBadRequest)
				return
			}
			in.IP = ip.String()
		}

		s.reloadMu.Lock()
		defer s.reloadMu.Unlock()
		s.cfgMu.Lock()
		next := cloneConfig(s.file)
		s.cfgMu.Unlock()
		previous := cloneConfig(s.cfg())
		if in.Mode == "proxy" && next.SourceMode != "oci" {
			jsonErr(w, "跟随代理模式仅在 source_mode=oci 时可用", http.StatusBadRequest)
			return
		}
		next.HostEgressMode = in.Mode
		next.HostEgressVnic = in.VnicID
		if in.Mode == "ipv6" {
			next.HostEgressIP = in.IP
		} else {
			next.HostEgressIP = ""
		}

		if err := ApplyHostEgress(next, s.pool()); err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.cfgMu.Lock()
		if err := next.Save(); err != nil {
			s.cfgMu.Unlock()
			_ = ApplyHostEgress(previous, s.pool())
			jsonErr(w, "保存配置失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.file = next
		s.cfgMu.Unlock()
		s.rt.SetConfig(cloneConfig(next))
		log.Printf("[API] host egress applied: mode=%s vnic=%s", next.HostEgressMode, next.HostEgressVnic)
		out := HostEgressStatus(next, s.pool())
		out["ok"] = true
		jsonOut(w, out)
	default:
		jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleOCIPrefix lists OCI IPv6 prefix objects and switches the active pool
// to an existing prefix or a newly created one. OCI has no in-place "edit
// prefix": switching means changing which prefix object the pool allocates
// from, then optionally deleting the old object after the hot swap succeeds.
func (s *APIServer) handleOCIPrefix(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listOCIPrefixes(w)
	case http.MethodPost, http.MethodPut:
		s.switchOCIPrefix(w, r)
	default:
		jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *APIServer) listOCIPrefixes(w http.ResponseWriter) {
	pool := s.pool()
	pool.mu.RLock()
	activeID := pool.ociPrefixID
	activeLen := pool.ociPrefixLength
	activeVnicID := pool.ociVnicID
	activePrefix := ""
	if pool.prefix != nil {
		activePrefix = pool.prefix.String()
	}
	compartment := pool.ociCompartment
	client := pool.ociClient
	pool.mu.RUnlock()

	out := map[string]interface{}{
		"source_mode":    pool.GetSourceMode(),
		"prefixes":       []interface{}{},
		"all_prefixes":   []interface{}{},
		"vnics":          []interface{}{},
		"active_id":      activeID,
		"active_vnic_id": activeVnicID,
		"active_prefix":  activePrefix,
		"prefix_length":  activeLen,
	}
	canSwitch := client != nil && activeVnicID != "" && pool.GetSourceMode() == "oci"
	out["can_switch"] = canSwitch
	out["can_rotate"] = canSwitch && !s.cfg().OciNoCreate
	out["can_create_vnic"] = false
	if !canSwitch {
		out["error"] = "OCI 客户端或 VNIC 未初始化（需 source_mode=oci 且地址池已启动）"
	}

	var err error
	if client != nil && activeVnicID != "" {
		if compartment == "" {
			compartment = client.Tenancy
		}
		// OCIObject cleanup still focuses on the active VNIC. The new global
		// view below additionally enumerates every VNIC attached to the
		// instance, so the console can move the pool to another /64.
		var activeObjects []OCIObject
		activeObjects, _, _, err = pool.ociIPv6Objects()
		if err == nil {
			activePrefixes := make([]OCIObject, 0, len(activeObjects))
			for _, o := range activeObjects {
				if o.CidrBits > 0 {
					o.VnicID = activeVnicID
					activePrefixes = append(activePrefixes, o)
				}
			}
			out["prefixes"] = activePrefixes
		}

		if metas, merr := resolvedVnicMetadata(); merr == nil {
			active64 := ""
			if ip := net.ParseIP(strings.Split(activePrefix, "/")[0]); ip != nil {
				active64 = subnetOf(ip)
			}
			all := make([]map[string]interface{}, 0, 8)
			vnicViews := make([]map[string]interface{}, 0, len(metas))
			for _, meta := range metas {
				view := map[string]interface{}{
					"vnic_id":      meta.VnicID,
					"subnet_cidr":  meta.IPv6SubnetCIDR,
					"subnet_cidrs": meta.IPv6SubnetCIDRs,
					"mac":          meta.MacAddr,
					"gateway":      meta.IPv6VirtualRouterIP,
					"active":       meta.VnicID == activeVnicID,
					"prefixes":     []interface{}{},
				}
				if iface, gw, _, ierr := ResolveOCIVnicNetwork(meta.VnicID); ierr == nil {
					view["interface"] = iface
					if gw != "" {
						view["gateway"] = gw
					}
				}
				list, lerr := client.ListIpv6s(compartment, meta.VnicID)
				if lerr != nil {
					view["error"] = lerr.Error()
					vnicViews = append(vnicViews, view)
					continue
				}
				items := make([]map[string]interface{}, 0, len(list))
				for _, o := range list {
					if o.CidrPrefixLength == nil || *o.CidrPrefixLength == 0 {
						continue
					}
					item := map[string]interface{}{
						"id":          o.ID,
						"ip_address":  o.IPAddress,
						"cidr_bits":   *o.CidrPrefixLength,
						"state":       o.LifecycleState,
						"vnic_id":     meta.VnicID,
						"subnet_cidr": meta.IPv6SubnetCIDR,
						"interface":   view["interface"],
						"active":      o.ID == activeID,
						"same_64":     active64 != "" && prefix64Of(o.IPAddress) == active64,
					}
					items = append(items, item)
					all = append(all, item)
				}
				view["prefixes"] = items
				vnicViews = append(vnicViews, view)
			}
			out["all_prefixes"] = all
			out["vnics"] = vnicViews
			out["can_create_vnic"] = canSwitch && !s.cfg().OciNoCreate && len(vnicViews) < 2
		} else if merr != nil {
			out["vnics_error"] = merr.Error()
		}
	}
	if err != nil {
		out["error"] = err.Error()
	}
	jsonOut(w, out)
}

// prefix64Of returns the /64 containing an IPv6 address or CIDR, or "" for
// invalid input. It accepts both forms because callers pass prefix objects
// (with /112 etc.) as well as bare addresses.
func prefix64Of(s string) string {
	s = strings.TrimSpace(s)
	var parsed net.IP
	if strings.Contains(s, "/") {
		ip, _, err := net.ParseCIDR(s)
		if err != nil {
			return ""
		}
		parsed = ip
	} else {
		parsed = net.ParseIP(s)
	}
	if parsed == nil || parsed.To4() != nil {
		return ""
	}
	return subnetOf(parsed)
}

func (s *APIServer) switchOCIPrefix(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action       string `json:"action"` // use | rotate | new64
		ID           string `json:"id"`
		VnicID       string `json:"vnic_id"`
		PrefixLength int    `json:"prefix_length"`
		DeleteOld    bool   `json:"delete_old"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonErr(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	in.Action = strings.ToLower(strings.TrimSpace(in.Action))
	in.ID = strings.TrimSpace(in.ID)
	in.VnicID = strings.TrimSpace(in.VnicID)
	if in.Action != "use" && in.Action != "rotate" && in.Action != "new64" && in.Action != "switch_vnic" && in.Action != "new_vnic" && in.Action != "delete_vnic" {
		jsonErr(w, "action must be use, rotate, new64, switch_vnic, new_vnic or delete_vnic", http.StatusBadRequest)
		return
	}
	if in.Action == "use" && in.ID == "" {
		jsonErr(w, "id is required when action=use", http.StatusBadRequest)
		return
	}
	if (in.Action == "switch_vnic" || in.Action == "delete_vnic") && in.VnicID == "" {
		jsonErr(w, "vnic_id is required when action="+in.Action, http.StatusBadRequest)
		return
	}
	if in.PrefixLength != 0 && (in.PrefixLength < 80 || in.PrefixLength > 128 || in.PrefixLength%4 != 0) {
		jsonErr(w, "prefix_length must be 80-128 divisible by 4", http.StatusBadRequest)
		return
	}

	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	cur := s.cfg()
	if cur.SourceMode != "oci" {
		jsonErr(w, "OCI 前缀切换仅在 source_mode=oci 时可用", http.StatusBadRequest)
		return
	}
	pool := s.pool()
	pool.mu.RLock()
	client := pool.ociClient
	compartment := pool.ociCompartment
	vnic := pool.ociVnicID
	activeID := pool.ociPrefixID
	activeLen := pool.ociPrefixLength
	activePrefix := ""
	if pool.prefix != nil {
		activePrefix = pool.prefix.String()
	}
	oldIface := pool.sourceIface
	oldGateway := pool.wanGateway
	pool.mu.RUnlock()
	if client == nil || vnic == "" {
		jsonErr(w, "OCI 客户端未初始化，请先确认 source_mode=oci 的地址池已启动", http.StatusServiceUnavailable)
		return
	}
	if compartment == "" {
		compartment = client.Tenancy
	}

	// The pool normally records the active prefix object. For pools started
	// before that field existed, derive it from prefix + length.
	oldPrefixID := activeID
	oldPrefixLen := activeLen
	if oldPrefixID == "" && activePrefix != "" && activeLen != 0 {
		if list, err := client.ListIpv6s(compartment, vnic); err == nil {
			if _, n, perr := net.ParseCIDR(activePrefix); perr == nil {
				base := n.IP.String()
				for _, o := range list {
					if o.CidrPrefixLength != nil && *o.CidrPrefixLength == oldPrefixLen {
						if ip := net.ParseIP(o.IPAddress); ip != nil && ip.String() == base {
							oldPrefixID = o.ID
							break
						}
					}
				}
			}
		}
	}

	var (
		next      *Config
		change    editableConfig
		newID     string
		newPrefix string
		newLen    int
		created   *OciIpv6
		plan      *new64Plan
		warnings  = []string{}
	)
	s.cfgMu.Lock()
	next = cloneConfig(s.file)
	s.cfgMu.Unlock()
	// Keep host mappings in sync with the live pool, as /api/hosts can change
	// them independently of the saved config.
	next.Hosts = pool.ListHosts()

	targetVnic := vnic
	targetIface := oldIface
	targetGateway := oldGateway
	targetSubnetCIDR := ""
	resolveTarget := func() error {
		iface, gw, meta, rerr := ResolveOCIVnicNetwork(targetVnic)
		if rerr != nil {
			return rerr
		}
		targetIface = iface
		targetGateway = gw
		if meta.IPv6SubnetCIDR != "" {
			targetSubnetCIDR = meta.IPv6SubnetCIDR
		}
		return nil
	}

	switch in.Action {
	case "use":
		if in.VnicID != "" {
			targetVnic = in.VnicID
		}
		if err := resolveTarget(); err != nil {
			jsonErr(w, "解析目标 OCI 网卡失败: "+err.Error(), http.StatusBadGateway)
			return
		}
		list, err := client.ListIpv6s(compartment, targetVnic)
		if err != nil {
			jsonErr(w, "查询 OCI 前缀失败: "+err.Error(), http.StatusBadGateway)
			return
		}
		var selected *OciIpv6
		for i := range list {
			if list[i].ID == in.ID {
				selected = &list[i]
				break
			}
		}
		if selected == nil {
			jsonErr(w, "所选 OCI 前缀对象不在目标 VNIC 上", http.StatusNotFound)
			return
		}
		if selected.LifecycleState != "" && selected.LifecycleState != "AVAILABLE" {
			jsonErr(w, "所选 OCI 前缀状态为 "+selected.LifecycleState+"，暂不可切换", http.StatusBadRequest)
			return
		}
		if selected.CidrPrefixLength == nil {
			jsonErr(w, "所选对象不是前缀段（/128 请用逐 IP 模式）", http.StatusBadRequest)
			return
		}
		newID = selected.ID
		newLen = *selected.CidrPrefixLength
		if newID == "" || newLen < 80 || newLen > 128 || newLen%4 != 0 {
			jsonErr(w, "所选 OCI 前缀对象无效", http.StatusBadRequest)
			return
		}
		newPrefix = fmt.Sprintf("%s/%d", selected.IPAddress, newLen)
		if _, _, perr := net.ParseCIDR(newPrefix); perr != nil {
			jsonErr(w, "所选 OCI 前缀地址无效: "+perr.Error(), http.StatusBadGateway)
			return
		}
		if targetSubnetCIDR == "" {
			targetSubnetCIDR = prefix64Of(selected.IPAddress)
		}
		if targetSubnetCIDR != "" && prefix64Of(selected.IPAddress) != targetSubnetCIDR {
			jsonErr(w, "所选前缀不属于目标 VNIC 的 /64 子网", http.StatusBadRequest)
			return
		}
		log.Printf("[API] switching OCI pool to existing prefix %s (%s) on vnic %s", newPrefix, newID, targetVnic)
	case "new_vnic":
		p, err := prepareNewVnic(client, vnic, cur.OciNoCreate)
		if err != nil {
			jsonErr(w, "新建 VNIC 失败: "+err.Error(), http.StatusBadGateway)
			return
		}
		log.Printf("[API] created VNIC %s iface=%s subnet=%s", p.VnicID, p.Interface, p.SubnetCIDR)
		jsonOut(w, map[string]interface{}{
			"ok":          true,
			"action":      in.Action,
			"vnic_id":     p.VnicID,
			"interface":   p.Interface,
			"gateway":     p.Gateway,
			"subnet_cidr": p.SubnetCIDR,
		})
		return
	case "delete_vnic":
		if NormalizeHostEgressMode(cur.HostEgressMode) == "ipv6" && cur.HostEgressVnic == in.VnicID {
			jsonErr(w, "该 VNIC 正被「主机出口」使用，请先修改主机出口设置", http.StatusBadRequest)
			return
		}
		warnings, err := deleteVnicByID(client, compartment, in.VnicID, vnic)
		if err != nil {
			jsonErr(w, "删除 VNIC 失败: "+err.Error(), http.StatusBadGateway)
			return
		}
		log.Printf("[API] deleted VNIC %s", in.VnicID)
		jsonOut(w, map[string]interface{}{
			"ok":       true,
			"action":   in.Action,
			"vnic_id":  in.VnicID,
			"warnings": warnings,
		})
		return
	case "switch_vnic":
		targetVnic = in.VnicID
		if err := resolveTarget(); err != nil {
			jsonErr(w, "解析目标 OCI 网卡失败: "+err.Error(), http.StatusBadGateway)
			return
		}
		list, err := client.ListIpv6s(compartment, targetVnic)
		if err != nil {
			jsonErr(w, "查询 OCI 前缀失败: "+err.Error(), http.StatusBadGateway)
			return
		}
		selected := selectVnicPrefix(list, targetSubnetCIDR, in.PrefixLength, activeLen)
		if selected != nil {
			newID = selected.ID
			newLen = *selected.CidrPrefixLength
			newPrefix = fmt.Sprintf("%s/%d", selected.IPAddress, newLen)
			if targetSubnetCIDR == "" {
				targetSubnetCIDR = prefix64Of(selected.IPAddress)
			}
			if targetSubnetCIDR != "" && prefix64Of(selected.IPAddress) != targetSubnetCIDR {
				jsonErr(w, "所选前缀不属于目标 VNIC 的 /64 子网", http.StatusBadRequest)
				return
			}
			log.Printf("[API] switching OCI pool to existing prefix %s (%s) on vnic %s", newPrefix, newID, targetVnic)
			break
		}
		if cur.OciNoCreate {
			jsonErr(w, "目标 VNIC 没有可用前缀，且 oci_no_create=true 禁止新建前缀", http.StatusBadRequest)
			return
		}
		newLen = in.PrefixLength
		if newLen == 0 {
			newLen = activeLen
		}
		if newLen == 0 {
			newLen = cur.OciPrefixLength
		}
		if newLen == 0 {
			newLen = 112
		}
		if newLen < 80 || newLen > 128 || newLen%4 != 0 {
			jsonErr(w, "prefix_length must be 80-128 divisible by 4", http.StatusBadRequest)
			return
		}
		obj, cidr, plen, err := createVnicPrefix(client, compartment, targetVnic, targetSubnetCIDR, newLen)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusBadGateway)
			return
		}
		created = obj
		newID, newPrefix, newLen = obj.ID, cidr, plen
		if targetSubnetCIDR == "" {
			targetSubnetCIDR = prefix64Of(obj.IPAddress)
		}
		log.Printf("[API] created OCI prefix %s (%s) on vnic %s for switch_vnic", newPrefix, newID, targetVnic)
	case "rotate":
		if cur.OciNoCreate {
			jsonErr(w, "oci_no_create=true 禁止新建前缀；请先在配置中取消「只切换不创建网卡段」", http.StatusBadRequest)
			return
		}
		if in.VnicID != "" {
			targetVnic = in.VnicID
		}
		if err := resolveTarget(); err != nil {
			jsonErr(w, "解析目标 OCI 网卡失败: "+err.Error(), http.StatusBadGateway)
			return
		}
		newLen = in.PrefixLength
		if newLen == 0 {
			newLen = activeLen
		}
		if newLen == 0 {
			newLen = cur.OciPrefixLength
		}
		if newLen == 0 {
			newLen = 112
		}
		if newLen < 80 || newLen > 128 || newLen%4 != 0 {
			jsonErr(w, "prefix_length must be 80-128 divisible by 4", http.StatusBadRequest)
			return
		}
		obj, cidr, plen, err := createVnicPrefix(client, compartment, targetVnic, targetSubnetCIDR, newLen)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusBadGateway)
			return
		}
		created = obj
		newID, newPrefix, newLen = obj.ID, cidr, plen
		if targetSubnetCIDR == "" {
			targetSubnetCIDR = prefix64Of(obj.IPAddress)
		}
		log.Printf("[API] created OCI prefix %s (%s) on vnic %s", newPrefix, newID, targetVnic)
	case "new64":
		if cur.OciNoCreate {
			jsonErr(w, "oci_no_create=true 禁止创建新子网/VNIC 或前缀", http.StatusBadRequest)
			return
		}
		desiredLen := in.PrefixLength
		if desiredLen == 0 {
			desiredLen = activeLen
		}
		if desiredLen == 0 {
			desiredLen = cur.OciPrefixLength
		}
		if desiredLen == 0 {
			desiredLen = 112
		}
		p, err := prepareNew64(client, compartment, vnic, desiredLen, cur.OciNoCreate)
		if err != nil {
			jsonErr(w, "新建 /64 失败: "+err.Error(), http.StatusBadGateway)
			return
		}
		plan = p
		targetVnic = plan.VnicID
		targetIface = plan.Interface
		targetGateway = plan.Gateway
		targetSubnetCIDR = plan.SubnetCIDR
		newID = plan.PrefixID
		newPrefix = plan.PrefixCIDR
		newLen = plan.PrefixLen
		log.Printf("[API] new64 plan: vnic=%s iface=%s subnet=%s prefix=%s reused_vnic=%v reused_prefix=%v",
			targetVnic, targetIface, targetSubnetCIDR, newPrefix, plan.ReusedVnic, plan.ReusedPrefix)
	}

	next.SourceMode = "oci"
	next.OciVnicID = targetVnic
	next.OciPrefixID = newID
	next.OciPrefixLength = newLen
	if targetSubnetCIDR != "" {
		next.Prefix = targetSubnetCIDR
	}
	if targetIface != "" {
		next.OciSourceIface = targetIface
	}
	if targetGateway != "" {
		next.OciWanGateway = targetGateway
	}
	idCopy, lenCopy := newID, newLen
	vnicCopy, ifaceCopy, gwCopy, prefixCopy := targetVnic, targetIface, targetGateway, next.Prefix
	change = editableConfig{
		SourceMode:      &next.SourceMode,
		OciVnicID:       &vnicCopy,
		OciPrefixID:     &idCopy,
		OciPrefixLength: &lenCopy,
		OciSourceIface:  &ifaceCopy,
		OciWanGateway:   &gwCopy,
		Prefix:          &prefixCopy,
	}

	applied, restart, err := s.commitConfig(next, &change)
	if err != nil {
		if plan != nil {
			rollbackNew64(client, plan, &warnings)
		} else if created != nil {
			if derr := client.DeleteIpv6(created.ID); derr != nil {
				log.Printf("[OCI] rollback delete of %s failed: %v", created.ID, derr)
				warnings = append(warnings, "回滚新建前缀失败: "+derr.Error())
			}
		}
		code := http.StatusInternalServerError
		if strings.HasPrefix(err.Error(), "apply config:") {
			code = http.StatusBadRequest
		}
		msg := err.Error()
		if len(warnings) > 0 {
			msg += "；" + strings.Join(warnings, "；")
		}
		jsonErr(w, msg, code)
		return
	}

	deletedOld := false
	if in.DeleteOld && oldPrefixID != "" && oldPrefixID != newID {
		// Delete only the prefix object that backed the previous pool. It is
		// safe now that the old addresses have been torn down and the new pool
		// has been published. Refuse if another OCI /128 object still lives
		// inside the old prefix.
		if ok, reason := client.PrefixDeletionSafe(compartment, vnic, oldPrefixID, activePrefix); !ok {
			warnings = append(warnings, reason)
			log.Printf("[OCI] keep old prefix %s: %s", oldPrefixID, reason)
		} else if err := client.DeleteIpv6(oldPrefixID); err != nil {
			warnings = append(warnings, "删除旧前缀对象失败: "+err.Error())
			log.Printf("[OCI] delete old prefix %s failed: %v", oldPrefixID, err)
		} else {
			deletedOld = true
			log.Printf("[OCI] deleted old prefix %s", oldPrefixID)
		}
	} else if in.DeleteOld && oldPrefixID == "" && activePrefix != "" {
		warnings = append(warnings, "未能识别旧前缀对象，已保留，请在 OCI 控制台手动确认")
	}

	// In "follow proxy" mode the host's IPv6 default must move with the new
	// VNIC. Other modes are independent and unchanged by a prefix switch.
	if NormalizeHostEgressMode(next.HostEgressMode) == "proxy" {
		if err := ApplyHostEgress(next, s.pool()); err != nil {
			warnings = append(warnings, "更新主机出口失败: "+err.Error())
			log.Printf("[HOST] follow-proxy update failed: %v", err)
		}
	}

	log.Printf("[API] OCI prefix switch complete: %s -> %s (applied=%v, restart=%v)", activePrefix, newPrefix, applied, restart)
	out := map[string]interface{}{
		"ok":               true,
		"action":           in.Action,
		"prefix":           newPrefix,
		"prefix_id":        newID,
		"prefix_length":    newLen,
		"applied":          applied,
		"restart_required": restart,
		"deleted_old":      deletedOld,
		"old_prefix_id":    oldPrefixID,
		"warnings":         warnings,
		"runtime":          s.runtimeSummary(),
	}
	if created != nil {
		out["created"] = true
	}
	if plan != nil {
		out["vnic_id"] = plan.VnicID
		out["interface"] = plan.Interface
		out["gateway"] = plan.Gateway
		out["subnet_cidr"] = plan.SubnetCIDR
		out["reused_vnic"] = plan.ReusedVnic
		out["reused_prefix"] = plan.ReusedPrefix
	}
	jsonOut(w, out)
}

// handleHealthCheck starts a full health check in the background and returns
// immediately; poll /api/ips or /api/logs for progress.
func (s *APIServer) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !atomic.CompareAndSwapInt32(&s.hcRunning, 0, 1) {
		jsonErr(w, "health check already running", http.StatusConflict)
		return
	}
	go func() {
		defer atomic.StoreInt32(&s.hcRunning, 0)
		pool := s.pool()
		timeout := time.Duration(s.cfg().ConnectTimeout) * time.Second
		switch pool.GetSourceMode() {
		case "slaac":
			pool.HealthCheckSLAAC(timeout)
		default:
			pool.HealthCheck(timeout)
		}
		log.Printf("[API] manual health check finished")
	}()
	log.Printf("[API] manual health check started")
	jsonOut(w, map[string]interface{}{"ok": true, "note": "health check started"})
}

func (s *APIServer) healthCheckRunning() bool { return atomic.LoadInt32(&s.hcRunning) == 1 }

func jsonOut(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ==================== Main ====================

// LogBuffer is an in-memory ring buffer of recent log lines, exposed via the
// /api/logs endpoint. It is safe for concurrent use and preserves partial
// writes until a newline arrives.
type logBuffer struct {
	mu      sync.Mutex
	buf     []string
	pending []byte
	max     int
}

func newLogBuffer(max int) *logBuffer {
	if max <= 0 {
		max = 2000
	}
	return &logBuffer{max: max}
}

var LogBuf = newLogBuffer(2000)

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pending = append(l.pending, p...)
	for {
		idx := bytes.IndexByte(l.pending, '\n')
		if idx < 0 {
			break
		}
		line := string(l.pending[:idx])
		l.pending = l.pending[idx+1:]
		l.buf = append(l.buf, line)
		if len(l.buf) > l.max {
			l.buf = l.buf[len(l.buf)-l.max:]
		}
	}
	return len(p), nil
}

// Tail returns up to the last n log lines (most-recent last).
func (l *logBuffer) Tail(n int) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n >= len(l.buf) {
		out := make([]string, len(l.buf))
		copy(out, l.buf)
		return out
	}
	out := make([]string, n)
	copy(out, l.buf[len(l.buf)-n:])
	return out
}

// Clear drops all buffered log lines, including any partial line.
func (l *logBuffer) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = nil
	l.pending = nil
}
