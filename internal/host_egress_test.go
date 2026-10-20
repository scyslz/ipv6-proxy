package internal

import (
	"net"
	"testing"
)

func TestNormalizeHostEgressMode(t *testing.T) {
	cases := map[string]string{
		"":         "system",
		"system":   "system",
		"IPV4":     "ipv4",
		" ipv6 ":   "ipv6",
		"proxy":    "proxy",
		"bogus":    "system",
		"  PROXY ": "proxy",
	}
	for in, want := range cases {
		if got := NormalizeHostEgressMode(in); got != want {
			t.Errorf("NormalizeHostEgressMode(%q) = %q, want %q", in, got, want)
		}
	}
	if !ValidHostEgressMode("") || !ValidHostEgressMode("ipv4") || ValidHostEgressMode("nope") {
		t.Fatal("ValidHostEgressMode returned unexpected result")
	}
}

func TestIPInVnicSubnet(t *testing.T) {
	meta := &VnicMetadata{
		IPv6SubnetCIDR:  "2603:c024:4517:a81e::/64",
		IPv6SubnetCIDRs: []string{"2603:c024:4517:a81f::/64"},
	}
	cases := map[string]bool{
		"2603:c024:4517:a81e::1234": true,
		"2603:c024:4517:a81f:1::9":  true,
		"2603:c024:4517:a820::1":    false,
		"2001:db8::1":               false,
	}
	for ip, want := range cases {
		if got := ipInVnicSubnet(net.ParseIP(ip), meta); got != want {
			t.Errorf("ipInVnicSubnet(%s) = %v, want %v", ip, got, want)
		}
	}
	if ipInVnicSubnet(net.ParseIP("2603:c024:4517:a81e::1"), nil) {
		t.Error("nil metadata must not match any address")
	}
}

func TestProxyPinnedSource(t *testing.T) {
	pool := &IPv6Pool{
		addrs: map[string]*IPv6Addr{
			"2603:c024:4517:a81e:1::1": {IP: "2603:c024:4517:a81e:1::1", Status: "alive"},
		},
		prefix:        mustCIDR(t, "2603:c024:4517:a81e::/64"),
		selectionMode: "round-robin",
	}
	if got := proxyPinnedSource(pool); got != "" {
		t.Errorf("rotating pool must not pin a host source, got %q", got)
	}
	_ = pool.SetSelectionMode("manual")
	// No explicit pin yet: fall back to the address the proxy would select.
	if got := proxyPinnedSource(pool); got != "2603:c024:4517:a81e:1::1" {
		t.Errorf("manual mode should follow the proxy pick, got %q", got)
	}
	pool.pinnedIP = "2603:c024:4517:a81e:1::1"
	if got := proxyPinnedSource(pool); got != "2603:c024:4517:a81e:1::1" {
		t.Errorf("manual pin not followed, got %q", got)
	}
	pool.addrs["2603:c024:4517:a81e:1::1"].Status = "dead"
	if got := proxyPinnedSource(pool); got != "" {
		t.Errorf("dead pin must not be used, got %q", got)
	}
}
