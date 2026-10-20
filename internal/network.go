package internal

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

// ==================== WAN Interface Detection ====================

func DetectWANInterface() (string, error) {
	out, err := exec.Command("ip", "-6", "route", "show", "default").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			for i, f := range fields {
				if f == "dev" && i+1 < len(fields) {
					return fields[i+1], nil
				}
			}
		}
	}

	out, err = exec.Command("ip", "-6", "route", "show").Output()
	if err != nil {
		return "", fmt.Errorf("get routes: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "default") || strings.HasPrefix(line, "::/0") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "dev" && i+1 < len(fields) {
					return fields[i+1], nil
				}
			}
		}
	}
	return "", fmt.Errorf("no WAN interface found")
}

func DetectPDPrefix(iface string) (string, error) {
	out, err := exec.Command("ip", "-6", "route", "show", "default").Output()
	if err != nil {
		return "", fmt.Errorf("get routes: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "default from ") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				cidr := fields[2]
				if _, _, err := net.ParseCIDR(cidr); err == nil {
					return cidr, nil
				}
			}
		}
	}
	return "", fmt.Errorf("no PD prefix in default route")
}

func DetectIPv6Prefix(iface string) (string, error) {
	out, err := exec.Command("ip", "-6", "addr", "show", "dev", iface).Output()
	if err != nil {
		return "", fmt.Errorf("get addresses: %w", err)
	}

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet6") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				cidr := fields[1]
				_, ipNet, err := net.ParseCIDR(cidr)
				if err != nil {
					continue
				}
				ones, _ := ipNet.Mask.Size()
				if ones > 64 {
					// Skip /128 host addresses (likely added by us or SLAAC temp)
					continue
				}
				// Real prefix (<= /64): derive clean /64 prefix
				prefix := ipNet.IP.To16()
				prefix[12] = 0
				prefix[13] = 0
				prefix[14] = 0
				prefix[15] = 0
				return fmt.Sprintf("%s/64", prefix.String()), nil
			}
		}
	}
	return "", fmt.Errorf("no IPv6 address found on %s", iface)
}

// ==================== SLAAC Source Mode ====================

// isGlobalUnicast6 reports whether ip is in the 2000::/3 global unicast range,
// which is what we want for SLAAC-pool addresses (the router's own WAN SLAAC
// address lives here and routes cleanly through the ISP).
func isGlobalUnicast6(ip net.IP) bool {
	if ip.To4() != nil {
		return false
	}
	return ip[0]&0xE0 == 0x20
}

// isULA6 reports whether ip is in the fc00::/7 unique-local range, which we do
// not want to use as a SLAAC source pool.
func isULA6(ip net.IP) bool {
	if ip.To4() != nil {
		return false
	}
	return ip[0]&0xFE == 0xFC
}

// detectSLAAC inspects the WAN interface's IPv6 addresses and returns the
// router's global SLAAC address together with its /64 prefix. Link-local,
// loopback, multicast, ULA and temporary addresses are skipped; a global
// 2000::/3 address is preferred.
func detectSLAAC(wanIface string) (net.IP, *net.IPNet, error) {
	out, err := exec.Command("ip", "-6", "addr", "show", "dev", wanIface).Output()
	if err != nil {
		return nil, nil, fmt.Errorf("get addresses: %w", err)
	}
	var chosen net.IP
	var chosenPrefix *net.IPNet
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "inet6") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ipStr := strings.Split(fields[1], "/")[0]
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() != nil {
			continue
		}
		if ip.IsLinkLocalUnicast() || ip.IsLoopback() || ip.IsMulticast() {
			continue
		}
		if isULA6(ip) {
			continue
		}
		// Skip temporary SLAAC addresses so the pool doesn't churn with them.
		if strings.Contains(line, "temporary") {
			continue
		}
		_, ipNet, perr := net.ParseCIDR(fields[1])
		if perr != nil {
			continue
		}
		prefixIP := ipNet.IP.To16()
		for i := 8; i < 16; i++ {
			prefixIP[i] = 0
		}
		_, p64, _ := net.ParseCIDR(fmt.Sprintf("%s/64", prefixIP.String()))
		if chosen == nil || (isGlobalUnicast6(ip) && !isGlobalUnicast6(chosen)) {
			chosen = ip
			chosenPrefix = p64
		}
	}
	if chosen == nil {
		return nil, nil, fmt.Errorf("no suitable SLAAC address on %s", wanIface)
	}
	return chosen, chosenPrefix, nil
}

// GenerateSLAACAddresses returns up to count random /128 addresses within the
// pool's SLAAC /64, excluding the WAN interface's own address and the network
// address. These are fixed for the lifetime of the process.
func (p *IPv6Pool) GenerateSLAACAddresses(count int, exclude net.IP) []net.IP {
	seen := map[string]bool{}
	var ips []net.IP
	for i := 0; i < count*8 && len(ips) < count; i++ {
		ip := randomIPInPrefix(p.prefix)
		if ip.Equal(net.IPv6zero) || (exclude != nil && ip.Equal(exclude)) {
			continue
		}
		s := ip.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		ips = append(ips, ip)
	}
	return ips
}

// addressExistsOnIface reports whether the given /128 is currently configured
// on the named interface.
func addressExistsOnIface(iface, ipStr string) bool {
	out, err := exec.Command("ip", "-6", "addr", "show", "dev", iface).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), ipStr+"/128")
}

// reconcileSLAAC keeps the fixed SLAAC pool in sync with the WAN interface. If
// the WAN's SLAAC /64 changes (e.g. after a reconnect), the whole pool is
// rebuilt. Otherwise it re-adds any configured address that disappeared.
func (p *IPv6Pool) reconcileSLAAC() {
	wanIP, slaacPrefix, err := detectSLAAC(p.wanIface)
	if err != nil {
		log.Printf("[SLAAC] prefix re-detection failed: %v", err)
		return
	}
	p.mu.RLock()
	curPrefix := p.prefix.String()
	p.mu.RUnlock()
	if slaacPrefix.String() != curPrefix {
		log.Printf("[SLAAC] WAN prefix changed %s -> %s; rebuilding pool", curPrefix, slaacPrefix.String())
		p.mu.Lock()
		old := make([]string, 0, len(p.addrs))
		for ip := range p.addrs {
			old = append(old, ip)
		}
		p.mu.Unlock()
		for _, ip := range old {
			p.RemoveAddress(ip)
		}
		p.mu.Lock()
		p.prefix = slaacPrefix
		p.slaacPrefix = slaacPrefix
		p.slaacWANIP = wanIP
		p.mu.Unlock()
		p.cfgMu.RLock()
		poolSize := p.slaacPoolSize
		p.cfgMu.RUnlock()
		ips := p.GenerateSLAACAddresses(poolSize, wanIP)
		for _, ip := range ips {
			if aerr := p.AddAddress(ip, subnetOf(ip)); aerr != nil {
				log.Printf("[SLAAC] re-add %s: %v", ip, aerr)
			}
		}
		log.Printf("[SLAAC] rebuilt pool with %d addresses in %s", len(ips), slaacPrefix.String())
		return
	}

	p.mu.Lock()
	var missing []net.IP
	for ipStr, a := range p.addrs {
		if !a.Configured {
			continue
		}
		if !addressExistsOnIface(p.sourceIface, ipStr) {
			log.Printf("[SLAAC] %s missing from %s; re-adding", ipStr, p.sourceIface)
			missing = append(missing, net.ParseIP(ipStr))
		}
	}
	p.mu.Unlock()
	for _, ip := range missing {
		if aerr := p.AddAddress(ip, subnetOf(ip)); aerr != nil {
			log.Printf("[SLAAC] re-add %s: %v", ip, aerr)
		}
	}
}

// DetectSLAAC is exported wrapper for detectSLAAC (used by main).
func DetectSLAAC(wanIface string) (net.IP, *net.IPNet, error) {
	return detectSLAAC(wanIface)
}
