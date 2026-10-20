package internal

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testServer(t *testing.T, cfg *Config) (*APIServer, string) {
	t.Helper()
	pool := &IPv6Pool{
		addrs:         map[string]*IPv6Addr{},
		prefix:        mustCIDR(t, "2603:c024:4517:a81e::/64"),
		wanIface:      "enp0s6",
		dummyIface:    "v6test0",
		sourceIface:   "enp0s6",
		selectionMode: "manual",
		sourceMode:    "oci",
		dnsServer:     "2606:4700:4700::1111",
		testTarget:    "2606:4700:4700::1111",
		dnsCache:      newDNSCache(),
		hosts:         map[string]string{"a.example": "2606:4700::1"},
	}
	pool.addrs["2603:c024:4517:a81e:1::1"] = &IPv6Addr{IP: "2603:c024:4517:a81e:1::1", Status: "alive", Bind: true, TCP: StageInfo{Success: true}}
	pool.pinnedIP = "2603:c024:4517:a81e:1::1"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	s := NewAPIServer(addr, pool, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.ListenAndServe(ctx) }()
	time.Sleep(150 * time.Millisecond)
	return s, "http://" + addr
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func req(t *testing.T, method, url, token, body string) (int, string) {
	t.Helper()
	var r *http.Request
	var err error
	if body != "" {
		r, err = http.NewRequest(method, url, strings.NewReader(body))
	} else {
		r, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		r.Header.Set("X-API-Token", token)
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func TestWebConsoleAPI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"proxy_addr":"[::]:8180","api_addr":"[::]:9191","prefix":"2603:c024:4517:a81e::/64","source_mode":"oci","selection_mode":"manual","hosts":{"a.example":"2606:4700::1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	s, base := testServer(t, cfg)

	if code, body := req(t, "GET", base+"/", "", ""); code != 200 || !strings.Contains(body, "IPv6 Proxy") {
		t.Fatalf("index: %d %s", code, body[:min(len(body), 200)])
	}

	code, body := req(t, "GET", base+"/api/status", "", "")
	if code != 200 {
		t.Fatalf("status: %d %s", code, body)
	}
	var st map[string]interface{}
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatal(err)
	}
	if st["pinned"] != "2603:c024:4517:a81e:1::1" || st["total"].(float64) != 1 {
		t.Fatalf("unexpected status: %v", st)
	}
	if st["health_check_running"] != false {
		t.Fatalf("health_check_running: %v", st["health_check_running"])
	}

	code, body = req(t, "GET", base+"/api/ips", "", "")
	if code != 200 || !strings.Contains(body, "2603:c024:4517:a81e:1::1") {
		t.Fatalf("ips: %d %s", code, body)
	}

	// host add + delete persisted to config
	code, body = req(t, "POST", base+"/api/hosts", "", `{"host":"b.example:443","target":"2606:4700::2"}`)
	if code != 200 || !strings.Contains(body, "b.example") {
		t.Fatalf("add host: %d %s", code, body)
	}
	saved, _ := os.ReadFile(path)
	if !strings.Contains(string(saved), "b.example") {
		t.Fatalf("host not persisted: %s", saved)
	}
	code, body = req(t, "DELETE", base+"/api/hosts?host=b.example", "", "")
	if code != 200 || strings.Contains(body, "b.example") {
		t.Fatalf("del host: %d %s", code, body)
	}
	code, _ = req(t, "POST", base+"/api/hosts", "", `{"host":"x.example","target":"1.2.3.4"}`)
	if code != 400 {
		t.Fatalf("ipv4 target should be rejected, got %d", code)
	}

	// config read + update
	code, body = req(t, "GET", base+"/api/config", "", "")
	if code != 200 || !strings.Contains(body, "proxy_addr") {
		t.Fatalf("get config: %d %s", code, body)
	}
	code, body = req(t, "POST", base+"/api/config", "", `{"selection_mode":"random","failure_threshold":5,"dns_server":"2606:4700:4700::1001","test_target":"2606:4700:4700::1001","api_token":"s3cret","bogus":1}`)
	if code != 400 {
		t.Fatalf("unknown field should be rejected, got %d %s", code, body)
	}
	code, body = req(t, "POST", base+"/api/config", "", `{"selection_mode":"random","failure_threshold":5,"dns_server":"2606:4700:4700::1001","test_target":"2606:4700:4700::1001","api_token":"s3cret"}`)
	if code != 200 || !strings.Contains(body, `"applied"`) {
		t.Fatalf("post config: %d %s", code, body)
	}
	time.Sleep(50 * time.Millisecond)
	// token now enforced
	code, _ = req(t, "GET", base+"/api/status", "", "")
	if code != 401 {
		t.Fatalf("expected 401 after token set, got %d", code)
	}
	code, body = req(t, "GET", base+"/api/status", "s3cret", "")
	if code != 200 || !strings.Contains(body, "random") {
		t.Fatalf("authorized status: %d %s", code, body)
	}
	// token masked in config output
	code, body = req(t, "GET", base+"/api/config", "s3cret", "")
	if code != 200 || strings.Contains(body, "s3cret") {
		t.Fatalf("token leaked: %s", body)
	}
	saved, _ = os.ReadFile(path)
	if !strings.Contains(string(saved), "s3cret") || !strings.Contains(string(saved), `"random"`) {
		t.Fatalf("config not persisted: %s", saved)
	}

	// logs
	code, body = req(t, "GET", base+"/api/logs?lines=5", "s3cret", "")
	if code != 200 || !strings.Contains(body, "lines") {
		t.Fatalf("logs: %d %s", code, body)
	}
	LogBuf.Write([]byte("test log line\n"))
	code, body = req(t, "DELETE", base+"/api/logs", "s3cret", "")
	if code != 200 || !strings.Contains(body, "cleared") {
		t.Fatalf("clear logs: %d %s", code, body)
	}
	code, body = req(t, "GET", base+"/api/logs", "s3cret", "")
	if code != 200 || strings.Contains(body, "test log line") {
		t.Fatalf("logs not cleared: %d %s", code, body)
	}

	// address validation rejects out-of-prefix / bad IPs before touching the kernel
	code, _ = req(t, "POST", base+"/api/addresses", "s3cret", `{"ip":"2001:db8::1"}`)
	if code != 400 {
		t.Fatalf("out-of-prefix should be 400, got %d", code)
	}
	code, _ = req(t, "POST", base+"/api/addresses", "s3cret", `{"ip":"1.2.3.4"}`)
	if code != 400 {
		t.Fatalf("ipv4 should be 400, got %d", code)
	}
	code, _ = req(t, "DELETE", base+"/api/addresses?ip=2603:c024:4517:a81e:9::9", "s3cret", "")
	if code != 404 {
		t.Fatalf("missing address should be 404, got %d", code)
	}

	// cleanup: preview + input validation. Point the pool at a dummy name that
	// cannot exist so the test never touches real interfaces.
	s.pool().dummyIface = "v6test-does-not-exist"
	code, body = req(t, "GET", base+"/api/cleanup", "s3cret", "")
	if code != 200 || !strings.Contains(body, "dummy") {
		t.Fatalf("cleanup preview: %d %s", code, body)
	}
	code, body = req(t, "POST", base+"/api/cleanup", "s3cret", `{}`)
	if code != 400 {
		t.Fatalf("empty cleanup should be 400, got %d %s", code, body)
	}
	code, body = req(t, "POST", base+"/api/cleanup", "s3cret", `{"stale":true}`)
	if code != 200 || !strings.Contains(body, "result") {
		t.Fatalf("stale cleanup: %d %s", code, body)
	}

	// bulk delete with keep: pinned address survives, rest are removed and the
	// reduced size is persisted so a restart does not recreate them.
	s.pool().sourceIface = "v6test-does-not-exist"
	s.pool().addrs["2603:c024:4517:a81e:2::1"] = &IPv6Addr{IP: "2603:c024:4517:a81e:2::1", Status: "alive"}
	s.pool().addrs["2603:c024:4517:a81e:2::2"] = &IPv6Addr{IP: "2603:c024:4517:a81e:2::2", Status: "dead"}
	code, body = req(t, "POST", base+"/api/cleanup", "s3cret", `{"addresses":true,"keep":1}`)
	if code != 200 {
		t.Fatalf("cleanup keep: %d %s", code, body)
	}
	if !strings.Contains(body, "2603:c024:4517:a81e:1::1") || strings.Contains(body, "2603:c024:4517:a81e:2::1") {
		t.Fatalf("cleanup keep should retain pinned address only: %s", body)
	}
	if got := len(s.pool().ListAddresses()); got != 1 {
		t.Fatalf("pool should have 1 address after keep, got %d", got)
	}
	if s.file.SLAACPoolSize != 1 {
		t.Fatalf("slaac_pool_size should be persisted as 1, got %d", s.file.SLAACPoolSize)
	}
	code, body = req(t, "POST", base+"/api/cleanup", "s3cret", `{"keep":1}`)
	if code != 400 {
		t.Fatalf("keep without addresses should be 400, got %d %s", code, body)
	}

	// selection endpoints
	code, body = req(t, "POST", base+"/api/select?ip=2603:c024:4517:a81e:9::9", "s3cret", "")
	if code != 400 {
		t.Fatalf("pin unknown ip should be 400, got %d %s", code, body)
	}
	code, body = req(t, "POST", base+"/api/select?next", "s3cret", "")
	if code != 200 || !strings.Contains(body, "selection_mode") {
		t.Fatalf("next: %d %s", code, body)
	}
}

func TestUpdateConfigValidationIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"selection_mode":"manual","source_mode":"oci"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	s, base := testServer(t, cfg)
	_ = s

	// Valid field followed by an invalid one: nothing may be applied or saved.
	code, body := req(t, "POST", base+"/api/config", "", `{"selection_mode":"round-robin","subnet_count":99}`)
	if code != 400 {
		t.Fatalf("expected 400, got %d %s", code, body)
	}
	if got := s.pool().selectionMode; got != "manual" {
		t.Fatalf("selection mode applied despite failed validation: %s", got)
	}
	saved, _ := os.ReadFile(path)
	if strings.Contains(string(saved), "round-robin") {
		t.Fatalf("config saved despite failed validation: %s", saved)
	}
}

func TestSelectIPv6UsesRuntimeSelectionMode(t *testing.T) {
	pool := &IPv6Pool{
		addrs: map[string]*IPv6Addr{
			"2603:c024:4517:a81e:1::1": {IP: "2603:c024:4517:a81e:1::1", Status: "alive"},
			"2603:c024:4517:a81e:1::2": {IP: "2603:c024:4517:a81e:1::2", Status: "alive"},
		},
		prefix:        mustCIDR(t, "2603:c024:4517:a81e::/64"),
		selectionMode: "manual",
	}
	// Manual mode pins the first pick and keeps returning it.
	first, err := pool.SelectIPv6("")
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := pool.SelectIPv6(""); again != first {
		t.Fatalf("manual mode rotated: %s -> %s", first, again)
	}
	// Switching the mode at runtime must take effect immediately.
	if err := pool.SetSelectionMode("round-robin"); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		ip, err := pool.SelectIPv6("")
		if err != nil {
			t.Fatal(err)
		}
		seen[ip] = true
	}
	if len(seen) != 2 {
		t.Fatalf("round-robin did not rotate: %v", seen)
	}
}

func TestProxyLoopbackAddr(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0:8180":     "127.0.0.1:8180",
		"[::]:8180":        "[::1]:8180",
		"127.0.0.1:8180":   "127.0.0.1:8180",
		"[::1]:8180":       "[::1]:8180",
		"proxy.local:8180": "proxy.local:8180",
	}
	for in, want := range cases {
		if got := proxyLoopbackAddr(in); got != want {
			t.Errorf("proxyLoopbackAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConfigHotReloadInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"proxy_addr":"[::]:8180","api_addr":"[::]:9191","selection_mode":"manual","source_mode":"oci","health_interval_sec":60,"connect_timeout_sec":10,"max_retries":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	s, base := testServer(t, cfg)
	poolBefore := s.pool()

	code, body := req(t, "POST", base+"/api/config", "", `{"health_interval_sec":7,"connect_timeout_sec":3,"max_retries":2,"selection_mode":"round-robin","failure_threshold":4}`)
	if code != 200 {
		t.Fatalf("post config: %d %s", code, body)
	}
	var resp struct {
		Applied []string `json:"applied"`
		Restart []string `json:"restart_required"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Restart) != 0 {
		t.Fatalf("in-place changes should not require restart: %v", resp.Restart)
	}
	for _, key := range []string{"health_interval_sec", "connect_timeout_sec", "max_retries", "selection_mode", "failure_threshold"} {
		found := false
		for _, a := range resp.Applied {
			if a == key {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s not reported as applied: %v", key, resp.Applied)
		}
	}
	if s.pool() != poolBefore {
		t.Fatal("in-place config change rebuilt the pool unexpectedly")
	}
	live := s.cfg()
	if live.HealthInterval != 7 || live.ConnectTimeout != 3 || live.MaxRetries != 2 {
		t.Fatalf("runtime config not updated: %+v", live)
	}
	if got := s.pool().GetSelectionMode(); got != "round-robin" {
		t.Fatalf("selection mode not applied: %s", got)
	}

	// Listener addresses cannot be rebound in place; they must be reported as
	// restart-required while status keeps reporting the actual listener.
	code, body = req(t, "POST", base+"/api/config", "", `{"proxy_addr":"[::]:18080","api_addr":"[::]:19191"}`)
	if code != 200 {
		t.Fatalf("post listener config: %d %s", code, body)
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range resp.Restart {
		seen[r] = true
	}
	if !seen["proxy_addr"] || !seen["api_addr"] {
		t.Fatalf("listener changes should be restart-required: %v", resp.Restart)
	}
	if s.addr == "[::]:19191" {
		t.Fatal("API listener address was changed without rebinding")
	}
}

func TestNeedsPoolRebuild(t *testing.T) {
	poolBase := &Config{SourceMode: "pool", SubnetCount: 4, SLAACPoolSize: 1, HealthInterval: 60}
	slaacBase := &Config{SourceMode: "slaac", SubnetCount: 4, SLAACPoolSize: 1, HealthInterval: 60}
	ociBase := &Config{SourceMode: "oci", SubnetCount: 4, SLAACPoolSize: 1, HealthInterval: 60}
	cases := []struct {
		name string
		base *Config
		next *Config
		want bool
	}{
		{"unchanged", poolBase, &Config{SourceMode: "pool", SubnetCount: 4, SLAACPoolSize: 1, HealthInterval: 60}, false},
		{"scalar", poolBase, &Config{SourceMode: "pool", SubnetCount: 4, SLAACPoolSize: 1, HealthInterval: 7}, false},
		{"pool size", poolBase, &Config{SourceMode: "pool", SubnetCount: 5, SLAACPoolSize: 1, HealthInterval: 60}, true},
		{"pool ignores slaac size", poolBase, &Config{SourceMode: "pool", SubnetCount: 4, SLAACPoolSize: 9, HealthInterval: 60}, false},
		{"slaac size", slaacBase, &Config{SourceMode: "slaac", SubnetCount: 4, SLAACPoolSize: 2, HealthInterval: 60}, true},
		{"slaac ignores subnet count", slaacBase, &Config{SourceMode: "slaac", SubnetCount: 9, SLAACPoolSize: 1, HealthInterval: 60}, false},
		{"oci prefix length", ociBase, &Config{SourceMode: "oci", SubnetCount: 4, SLAACPoolSize: 1, OciPrefixLength: 112, HealthInterval: 60}, true},
		{"oci prefix id", ociBase, &Config{SourceMode: "oci", SubnetCount: 4, SLAACPoolSize: 1, OciPrefixID: "ocid1.ipv6.oc1..x", OciPrefixLength: 112, HealthInterval: 60}, true},
		{"oci no create", ociBase, &Config{SourceMode: "oci", SubnetCount: 4, SLAACPoolSize: 1, OciNoCreate: true, HealthInterval: 60}, true},
		{"mode change", poolBase, &Config{SourceMode: "slaac", SubnetCount: 4, SLAACPoolSize: 1, HealthInterval: 60}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := needsPoolRebuild(tc.base, tc.next); got != tc.want {
				t.Fatalf("needsPoolRebuild = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidateEditableKeepsOciPrefixID(t *testing.T) {
	base := func() *Config {
		return &Config{
			SourceMode:      "oci",
			Prefix:          "2603:c024:4517:a81e:7d21:1a63:5b61:0/112",
			OciPrefixID:     "ocid1.ipv6.oc1..selected",
			OciPrefixLength: 112,
			OciCompartment:  "ocid1.compartment..x",
			OciVnicID:       "ocid1.vnic..x",
		}
	}
	prefix := "2603:c024:4517:a81e:7d21:1a63:5b61:0/112"
	len112 := 112
	next := base()
	if err := validateEditable(next, &editableConfig{Prefix: &prefix, OciPrefixLength: &len112}); err != nil {
		t.Fatal(err)
	}
	if next.OciPrefixID == "" {
		t.Fatal("saving unchanged prefix fields must keep oci_prefix_id pinned")
	}

	len80 := 80
	next = base()
	if err := validateEditable(next, &editableConfig{OciPrefixLength: &len80}); err != nil {
		t.Fatal(err)
	}
	if next.OciPrefixID != "" {
		t.Fatal("changing oci_prefix_length should clear the old pinned prefix")
	}

	id := "ocid1.ipv6.oc1..new"
	next = base()
	if err := validateEditable(next, &editableConfig{OciPrefixID: &id, OciPrefixLength: &len80}); err != nil {
		t.Fatal(err)
	}
	if next.OciPrefixID != id {
		t.Fatal("explicit oci_prefix_id should win")
	}
}

func TestOCIPrefixEndpointValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"selection_mode":"manual","source_mode":"oci","oci_prefix_length":112}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	s, base := testServer(t, cfg)
	_ = s

	// GET is read-only and must not fail the HTTP request when the OCI client
	// is unavailable; the UI displays the embedded error instead.
	code, body := req(t, "GET", base+"/api/oci/prefix", "", "")
	if code != 200 || !strings.Contains(body, "OCI") || !strings.Contains(body, `"can_switch":false`) {
		t.Fatalf("oci prefix list: %d %s", code, body)
	}
	code, body = req(t, "POST", base+"/api/oci/prefix", "", `{"action":"use"}`)
	if code != 400 || !strings.Contains(body, "id is required") {
		t.Fatalf("use without id: %d %s", code, body)
	}
	code, body = req(t, "POST", base+"/api/oci/prefix", "", `{"action":"rotate","prefix_length":113}`)
	if code != 400 || !strings.Contains(body, "prefix_length") {
		t.Fatalf("bad prefix length: %d %s", code, body)
	}
	code, body = req(t, "POST", base+"/api/oci/prefix", "", `{"action":"use","id":"ocid1.ipv6.oc1..x"}`)
	if code != 503 {
		t.Fatalf("use without OCI client should be 503, got %d %s", code, body)
	}

	// Switching is OCI-only; other source modes must be rejected before any
	// OCI call.
	s.rt.SetConfig(&Config{SourceMode: "pool"})
	code, body = req(t, "POST", base+"/api/oci/prefix", "", `{"action":"rotate","prefix_length":112}`)
	if code != 400 || !strings.Contains(body, "source_mode=oci") {
		t.Fatalf("non-oci switch: %d %s", code, body)
	}
}

func TestApplyEditableSwapsPool(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"selection_mode":"manual","source_mode":"oci","dummy_iface":"v6test0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := testServer(t, cfg)
	oldPool := s.pool()
	oldPool.addrs["2603:c024:4517:a81e:1::1"].AddressAdded = false

	next := cloneConfig(cfg)
	next.SourceMode = "ephemeral"
	next.HealthInterval = 9
	newPool := &IPv6Pool{
		addrs:       map[string]*IPv6Addr{},
		prefix:      mustCIDR(t, "2603:c024:4517:a81e::/64"),
		wanIface:    "enp0s6",
		dummyIface:  "v6test0",
		sourceIface: "v6test0",
		sourceMode:  "ephemeral",
		dnsCache:    newDNSCache(),
		hosts:       map[string]string{},
	}

	applied, restart := applyEditable(s, next, newPool, &editableConfig{SourceMode: &next.SourceMode})
	if len(restart) != 0 {
		t.Fatalf("unexpected restart fields: %v", restart)
	}
	found := false
	for _, a := range applied {
		if a == "source_mode" {
			found = true
		}
	}
	if !found {
		t.Fatalf("source_mode not reported applied: %v", applied)
	}
	if s.pool() != newPool {
		t.Fatal("runtime pool was not swapped")
	}
	if s.cfg() != next || s.cfg().HealthInterval != 9 {
		t.Fatalf("runtime config was not swapped: %+v", s.cfg())
	}
}
