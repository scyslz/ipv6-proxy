package internal

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const (
	hostEgressMetric = 49
	gaiBeginMarker   = "# BEGIN ipv6-proxy host egress"
	gaiEndMarker     = "# END ipv6-proxy host egress"
)

// NormalizeHostEgressMode maps empty/unknown values to the safe default. Only
// applyHostEgress validates unknown values, so a typo cannot silently rewrite
// host routing.
func NormalizeHostEgressMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "ipv4", "ipv6", "proxy":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return "system"
	}
}

func ValidHostEgressMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "system", "ipv4", "ipv6", "proxy":
		return true
	}
	return false
}

// ApplyHostEgress applies the host-only egress policy. It never changes the
// proxy pool's source addresses or per-source policy routes; the proxy keeps
// using its own VNIC even when the host itself prefers another one.
func ApplyHostEgress(cfg *Config, pool *IPv6Pool) error {
	mode := NormalizeHostEgressMode(cfg.HostEgressMode)
	switch mode {
	case "ipv4":
		clearHostIPv6Default()
		if pool != nil {
			pool.SetHostEgressIP("")
		}
		if err := updateGAIBlock("precedence ::ffff:0:0/96 100"); err != nil {
			return fmt.Errorf("write /etc/gai.conf: %w", err)
		}
		log.Printf("[HOST] egress mode: prefer IPv4")
		return nil
	case "ipv6", "proxy":
		// Keep every proxy address pinned to its own table before lowering the
		// main IPv6 default metric, otherwise host egress could steal them.
		if pool != nil {
			if err := pool.EnsurePolicyRoutes(); err != nil {
				log.Printf("[HOST] ensure proxy policy routes: %v", err)
			}
		}
		vnicID := cfg.HostEgressVnic
		if mode == "proxy" {
			vnicID = cfg.OciVnicID
			// The live pool is authoritative if a switch already happened but
			// the caller passed a stale config.
			if pool != nil {
				if active := pool.ActiveVnicID(); active != "" {
					vnicID = active
				}
			}
		}
		iface, gateway, meta, err := ResolveOCIVnicNetwork(vnicID)
		if err != nil {
			return fmt.Errorf("解析主机出口 VNIC 失败: %w", err)
		}
		var source string
		switch {
		case mode == "ipv6" && strings.TrimSpace(cfg.HostEgressIP) != "":
			// Explicit pin: only accept an address that already lives on the
			// interface or belongs to this VNIC's delegated /64.
			pinned, perr := pinHostIPv6Source(cfg.HostEgressIP, iface, vnicID, meta)
			if perr != nil {
				return perr
			}
			source = pinned
		case mode == "proxy":
			// Follow the proxy's current source address, not just its VNIC.
			// "manual" selection pins one address, and users expect the host
			// to egress from that same address.
			source = proxyPinnedSource(pool)
			if source == "" {
				source = ensureHostIPv6Source(cfg, pool, iface, vnicID)
			}
			if source != "" && !hostAddressOnIface(iface, source) {
				// Ephemeral mode or a pin that was never installed: the address
				// must exist locally before it can be a route source.
				if err := addHostIPv6Address(iface, source); err != nil {
					log.Printf("[HOST] add proxy source %s on %s: %v", source, iface, err)
					source = ensureHostIPv6Source(cfg, pool, iface, vnicID)
				} else {
					time.Sleep(1 * time.Second)
				}
			}
		default:
			source = ensureHostIPv6Source(cfg, pool, iface, vnicID)
		}
		if source == "" {
			return fmt.Errorf("VNIC 接口 %s 没有可用的全局 IPv6 地址，请先把代理切换到该 VNIC 生成地址", iface)
		}
		if err := updateGAIBlock(""); err != nil {
			return fmt.Errorf("write /etc/gai.conf: %w", err)
		}
		if err := setHostIPv6Default(iface, gateway, source); err != nil {
			return err
		}
		if pool != nil {
			pool.SetHostEgressIP(source)
		}
		log.Printf("[HOST] egress mode: prefer IPv6 via %s src %s (gw=%q, vnic=%s)", iface, source, gateway, vnicID)
		return nil
	default:
		clearHostIPv6Default()
		if pool != nil {
			pool.SetHostEgressIP("")
		}
		if err := updateGAIBlock(""); err != nil {
			return fmt.Errorf("write /etc/gai.conf: %w", err)
		}
		log.Printf("[HOST] egress mode: system default")
		return nil
	}
}

func setHostIPv6Default(iface, gateway, source string) error {
	if iface == "" {
		return fmt.Errorf("主机出口接口为空")
	}
	if source != "" {
		// The source may have just been added; the kernel rejects a tentative
		// (DAD-running) address with "Invalid source address".
		waitForHostAddress(iface, source)
	}
	// Replace our own metric only; RA/static defaults keep their metrics.
	clearHostIPv6Default()
	args := []string{"-6", "route", "replace", "default"}
	if gateway != "" {
		args = append(args, "via", gateway)
	}
	args = append(args, "dev", iface)
	if source != "" {
		args = append(args, "src", source)
	}
	args = append(args, "metric", fmt.Sprint(hostEgressMetric))
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("设置主机 IPv6 默认路由失败: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// proxyPinnedSource returns the address the proxy is currently pinned to in
// manual selection mode. Empty means the proxy rotates, so the host falls back
// to the VNIC's default source.
func proxyPinnedSource(pool *IPv6Pool) string {
	if pool == nil || pool.GetSelectionMode() != "manual" {
		return ""
	}
	pin := pool.GetPinnedIP()
	if pin == "" {
		// At startup nothing is pinned until the first proxied request. Pin the
		// same address the proxy would pick, so the host default route starts
		// out matching the proxy instead of a stale SLAAC address.
		ip, err := pool.SelectIPv6("")
		if err != nil {
			return ""
		}
		pin = ip
	}
	pool.mu.RLock()
	a := pool.addrs[pin]
	pool.mu.RUnlock()
	if a == nil {
		return ""
	}
	// A stale pin from a previous pool (the address is no longer present) must
	// not keep the host route on an address the proxy no longer uses.
	if a.Status == "dead" || a.Status == "failed" {
		return ""
	}
	return pin
}

// pinHostIPv6Source validates and installs an explicitly chosen host egress
// source. The address must be a global unicast IPv6 that either already exists
// on iface or falls inside the VNIC's delegated /64; anything else would create
// a route whose source the kernel cannot use.
func pinHostIPv6Source(raw, iface, vnicID string, meta *VnicMetadata) (string, error) {
	ipStr := strings.TrimSpace(raw)
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() != nil {
		return "", fmt.Errorf("主机出口 IPv6 地址无效: %q", raw)
	}
	if ip.IsLinkLocalUnicast() || ip.IsLoopback() || ip.IsMulticast() || !ip.IsGlobalUnicast() {
		return "", fmt.Errorf("主机出口 IPv6 必须是全局单播地址: %s", ipStr)
	}
	ipStr = ip.String()
	if hostAddressOnIface(iface, ipStr) {
		return ipStr, nil
	}
	if !ipInVnicSubnet(ip, meta) {
		return "", fmt.Errorf("IPv6 %s 不在 VNIC %s 的 /64 子网内，无法作为主机源地址", ipStr, vnicID)
	}
	if err := addHostIPv6Address(iface, ipStr); err != nil {
		return "", err
	}
	log.Printf("[HOST] added pinned host source %s on %s", ipStr, iface)
	// Give DAD a moment before the address is used as a route source.
	time.Sleep(1 * time.Second)
	return ipStr, nil
}

func addHostIPv6Address(iface, ipStr string) error {
	// nodad skips duplicate-address detection: these are pool-unique /128s and
	// a tentative address cannot be used as a route source yet.
	out, err := exec.Command("ip", "-6", "addr", "add", ipStr+"/128", "dev", iface, "nodad").CombinedOutput()
	if err != nil && !strings.Contains(string(out), "File exists") {
		return fmt.Errorf("添加主机 IPv6 %s 到 %s 失败: %s: %w", ipStr, iface, strings.TrimSpace(string(out)), err)
	}
	waitForHostAddress(iface, ipStr)
	return nil
}

// waitForHostAddress waits until ipStr is no longer tentative on iface so the
// kernel accepts it as the source of a route. The kernel reports "Invalid
// source address" while DAD is still running.
func waitForHostAddress(iface, ipStr string) {
	for i := 0; i < 50; i++ {
		out, err := exec.Command("ip", "-6", "-o", "addr", "show", "dev", iface).Output()
		if err != nil {
			return
		}
		found, tentative := false, false
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.Contains(line, ipStr+"/128") {
				continue
			}
			found = true
			if strings.Contains(line, "tentative") {
				tentative = true
			}
		}
		if found && !tentative {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// hostAddressOnIface reports whether ipStr is already configured on iface.
func hostAddressOnIface(iface, ipStr string) bool {
	for _, ip := range hostIPv6Addresses(iface) {
		if ip == ipStr {
			return true
		}
	}
	return false
}

// hostIPv6Addresses lists the global /128 addresses configured on iface.
func hostIPv6Addresses(iface string) []string {
	out, err := exec.Command("ip", "-6", "-o", "addr", "show", "dev", iface, "scope", "global").Output()
	if err != nil {
		return nil
	}
	var ips []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f != "inet6" || i+1 >= len(fields) {
				continue
			}
			ipStr, bits, ok := strings.Cut(fields[i+1], "/")
			if !ok || bits != "128" {
				continue
			}
			ips = append(ips, ipStr)
		}
	}
	return ips
}

// ipInVnicSubnet reports whether ip falls inside one of the VNIC's /64s as
// reported by the instance metadata service.
func ipInVnicSubnet(ip net.IP, meta *VnicMetadata) bool {
	if meta == nil {
		return false
	}
	cidrs := append([]string{}, meta.IPv6SubnetCIDRs...)
	if meta.IPv6SubnetCIDR != "" {
		cidrs = append(cidrs, meta.IPv6SubnetCIDR)
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ensureHostIPv6Source returns a usable global /128 on iface. If the interface
// has none yet, it asks OCI for a prefix on vnicID and adds a local address
// from that prefix, so host egress can work even before the proxy pool has
// generated addresses on that VNIC.
func ensureHostIPv6Source(cfg *Config, pool *IPv6Pool, iface, vnicID string) string {
	if src := hostIPv6Source(iface, pool); src != "" {
		return src
	}
	if cfg.SourceMode != "oci" || vnicID == "" {
		return ""
	}
	client, err := LoadOciClientFromConfig(cfg.OciConfigPath)
	if err != nil {
		log.Printf("[HOST] load OCI client for host source: %v", err)
		return ""
	}
	compartment := cfg.OciCompartment
	if compartment == "" {
		compartment = client.Tenancy
	}
	prefixLen := cfg.OciPrefixLength
	if prefixLen == 0 {
		prefixLen = 112
	}
	var obj *OciIpv6
	if cfg.OciNoCreate {
		list, err := client.ListIpv6s(compartment, vnicID)
		if err != nil {
			log.Printf("[HOST] list OCI prefixes for host source: %v", err)
			return ""
		}
		for i := range list {
			if list[i].CidrPrefixLength != nil && *list[i].CidrPrefixLength == prefixLen {
				obj = &list[i]
				break
			}
		}
		if obj == nil {
			for i := range list {
				if list[i].CidrPrefixLength != nil && *list[i].CidrPrefixLength >= 80 {
					obj = &list[i]
					break
				}
			}
		}
	} else {
		o, err := client.EnsurePrefix(compartment, vnicID, prefixLen)
		if err != nil {
			log.Printf("[HOST] ensure OCI prefix for host source: %v", err)
			return ""
		}
		obj = o
	}
	if obj == nil || obj.IPAddress == "" {
		return ""
	}
	plen := prefixLen
	if obj.CidrPrefixLength != nil {
		plen = *obj.CidrPrefixLength
	}
	_, prefix, err := net.ParseCIDR(fmt.Sprintf("%s/%d", obj.IPAddress, plen))
	if err != nil {
		log.Printf("[HOST] parse OCI prefix for host source: %v", err)
		return ""
	}
	ip := randomIPInPrefix(prefix)
	if err := addHostIPv6Address(iface, ip.String()); err != nil {
		log.Printf("[HOST] add host IPv6 %s on %s: %v", ip.String(), iface, err)
		return ""
	}
	return ip.String()
}

// hostIPv6Source picks a global /128 on iface for host-originated traffic.
// A dynamic (SLAAC) address is preferred; otherwise the first pool address is
// used, because it is known to belong to that VNIC.
func hostIPv6Source(iface string, pool *IPv6Pool) string {
	if iface == "" {
		return ""
	}
	out, err := exec.Command("ip", "-6", "-o", "addr", "show", "dev", iface, "scope", "global").Output()
	if err != nil {
		return ""
	}
	poolAddrs := map[string]bool{}
	if pool != nil {
		for ip := range pool.ListAddresses() {
			poolAddrs[ip] = true
		}
	}
	fallback := ""
	poolFallback := ""
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f != "inet6" || i+1 >= len(fields) {
				continue
			}
			cidr := fields[i+1]
			ipStr, bits, ok := strings.Cut(cidr, "/")
			if !ok || bits != "128" {
				continue
			}
			if strings.Contains(line, " dynamic ") {
				return ipStr
			}
			if !poolAddrs[ipStr] {
				if fallback == "" {
					fallback = ipStr
				}
			} else if poolFallback == "" {
				poolFallback = ipStr
			}
		}
	}
	if fallback != "" {
		return fallback
	}
	return poolFallback
}

func clearHostIPv6Default() {
	// Ignore "No such process"/"not found": there may be no managed route.
	exec.Command("ip", "-6", "route", "del", "default", "metric", fmt.Sprint(hostEgressMetric)).Run()
}

// ClearHostEgress removes the managed host IPv6 default route. It is called on
// shutdown so the kernel does not keep a default route whose source address is
// about to be removed from the interface.
func ClearHostEgress() {
	clearHostIPv6Default()
}

// SetHostEgressIP records the address currently pinned as the host's IPv6
// source (empty when no managed IPv6 default exists).
func (p *IPv6Pool) SetHostEgressIP(ip string) {
	p.mu.Lock()
	p.hostEgressIP = strings.TrimSpace(ip)
	p.mu.Unlock()
}

// HostEgressIP returns the recorded host egress source address.
func (p *IPv6Pool) HostEgressIP() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.hostEgressIP
}

// updateGAIBlock edits only a marked block in /etc/gai.conf. An empty block
// removes the block and leaves every other line untouched.
func updateGAIBlock(block string) error {
	const path = "/etc/gai.conf"
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if block == "" {
			return nil
		}
		data = nil
	}
	lines := strings.Split(string(data), "\n")
	out := make([]string, 0, len(lines)+4)
	inside := false
	for _, line := range lines {
		switch strings.TrimSpace(line) {
		case gaiBeginMarker:
			inside = true
			continue
		case gaiEndMarker:
			inside = false
			continue
		}
		if !inside {
			out = append(out, line)
		}
	}
	if block != "" {
		// Trim trailing blank lines, then append the managed block.
		for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
			out = out[:len(out)-1]
		}
		out = append(out, "", gaiBeginMarker, block, gaiEndMarker, "")
	}
	newData := strings.Join(out, "\n")
	if newData == string(data) {
		return nil
	}
	return os.WriteFile(path, []byte(newData), 0644)
}

// HostEgressStatus reports both the configured policy and the routes the
// kernel currently uses, for the web console.
func HostEgressStatus(cfg *Config, pool *IPv6Pool) map[string]interface{} {
	mode := NormalizeHostEgressMode(cfg.HostEgressMode)
	out := map[string]interface{}{
		"mode":            mode,
		"vnic_id":         cfg.HostEgressVnic,
		"ip":              cfg.HostEgressIP,
		"ipv4_default":    commandOutput("ip", "-4", "route", "show", "default"),
		"ipv6_default":    commandOutput("ip", "-6", "route", "show", "default"),
		"ipv6_managed":    commandOutput("ip", "-6", "route", "show", "default", "metric", fmt.Sprint(hostEgressMetric)),
		"ipv4_route_get":  commandOutput("ip", "-4", "route", "get", "1.1.1.1"),
		"ipv6_route_get":  commandOutput("ip", "-6", "route", "get", "2001:4860:4860::8888"),
		"gai_ipv4_forced": gaiIPv4Forced(),
		"metric":          hostEgressMetric,
		"source_ipv6":     "",
	}
	if pool != nil {
		out["source_ipv6"] = pool.HostEgressIP()
	}
	vnics := make([]map[string]interface{}, 0, 4)
	poolAddrs := map[string]bool{}
	if pool != nil {
		for ip := range pool.ListAddresses() {
			poolAddrs[ip] = true
		}
	}
	if metas, err := resolvedVnicMetadata(); err == nil {
		for _, meta := range metas {
			view := map[string]interface{}{
				"vnic_id":     meta.VnicID,
				"subnet_cidr": meta.IPv6SubnetCIDR,
				"active":      pool != nil && meta.VnicID == pool.ActiveVnicID(),
			}
			if iface, gw, _, ierr := ResolveOCIVnicNetwork(meta.VnicID); ierr == nil {
				view["interface"] = iface
				view["gateway"] = gw
				if src := hostIPv6Source(iface, pool); src != "" {
					view["source_ipv6"] = src
					view["has_ipv6"] = true
				}
				// Offer every candidate source the UI can pin: the /128s
				// already on the interface plus pool addresses when this VNIC
				// backs the live pool.
				seen := map[string]bool{}
				addrs := make([]string, 0, 8)
				for _, ip := range hostIPv6Addresses(iface) {
					if !seen[ip] {
						seen[ip] = true
						addrs = append(addrs, ip)
					}
				}
				if view["active"] == true {
					for ip := range poolAddrs {
						if !seen[ip] {
							seen[ip] = true
							addrs = append(addrs, ip)
						}
					}
				}
				sort.Strings(addrs)
				view["addresses"] = addrs
			}
			vnics = append(vnics, view)
		}
	}
	out["vnics"] = vnics
	return out
}

func commandOutput(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(out))
	}
	return strings.TrimSpace(string(out))
}

func gaiIPv4Forced() bool {
	data, err := os.ReadFile("/etc/gai.conf")
	if err != nil {
		return false
	}
	inside := false
	for _, line := range strings.Split(string(data), "\n") {
		switch strings.TrimSpace(line) {
		case gaiBeginMarker:
			inside = true
		case gaiEndMarker:
			inside = false
		default:
			if inside && strings.Contains(line, "::ffff:0:0/96") && strings.Contains(line, "100") {
				return true
			}
		}
	}
	return false
}
