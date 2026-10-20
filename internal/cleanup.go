package internal

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// ==================== Cleanup (dummy interface / stale state) ====================

// CleanupOptions selects which pieces of state to remove.
type CleanupOptions struct {
	// Stale removes /128 addresses that live inside the pool prefix on the
	// source interface but are not part of the current pool (leftovers from a
	// previous run). Safe: managed/dynamic addresses are skipped.
	Stale bool `json:"stale"`
	// Routes flushes the policy-routing table and deletes its rules.
	Routes bool `json:"routes"`
	// Dummy deletes the configured dummy interface when it exists and is not
	// currently carrying the pool (source_mode=pool). Never touches a
	// non-dummy interface.
	Dummy bool `json:"dummy"`
	// Addresses removes addresses from the pool. With Keep=0 this empties the
	// pool and interrupts proxying until addresses are re-added; with Keep>0
	// it keeps that many (pinned/alive first) and removes the rest.
	Addresses bool `json:"addresses"`
	// Keep is only valid together with Addresses. It is the number of pool
	// addresses to keep, and is persisted as slaac_pool_size so a restart in
	// oci/slaac mode regenerates the same count.
	Keep int `json:"keep"`
	// DeleteOCI removes the listed OCI IPv6 object IDs. Prefix objects that
	// back the active pool and dynamic (provider-managed) /128 are refused.
	DeleteOCI []string `json:"delete_oci"`
}

// InterfaceInfo describes the configured dummy interface.
type InterfaceInfo struct {
	Name    string `json:"name"`
	Exists  bool   `json:"exists"`
	IsDummy bool   `json:"is_dummy"`
	InUse   bool   `json:"in_use"`
}

// CleanupPreview is the read-only view shown in the console before cleaning.
type CleanupPreview struct {
	Dummy           InterfaceInfo `json:"dummy"`
	SourceInterface string        `json:"source_interface"`
	SourceMode      string        `json:"source_mode"`
	StaleInterface  string        `json:"stale_interface"`
	StaleMode       string        `json:"stale_mode"`
	StaleError      string        `json:"stale_error,omitempty"`
	OCIManaged      []string      `json:"oci_managed"`
	OCIObjects      []OCIObject   `json:"oci_objects"`
	PoolPrefix      string        `json:"pool_prefix"`
	PoolAddresses   int           `json:"pool_addresses"`
	StaleAddresses  []string      `json:"stale_addresses"`
	PolicyRules     int           `json:"policy_rules"`
	TableRoutes     int           `json:"table_routes"`
	PolicyTable     int           `json:"policy_table"`
}

// OCIObject is one IPv6 resource assigned to the VNIC in OCI. Prefix objects
// (CidrBits > 0) delegate a whole segment; /128 objects are per-address.
type OCIObject struct {
	ID         string `json:"id"`
	IPAddress  string `json:"ip_address"`
	CidrBits   int    `json:"cidr_bits"`
	State      string `json:"state"`
	InPool     bool   `json:"in_pool"`
	OnKernel   bool   `json:"on_kernel"`
	Dynamic    bool   `json:"dynamic"`
	Active     bool   `json:"active"`
	VnicID     string `json:"vnic_id,omitempty"`
	SubnetCIDR string `json:"subnet_cidr,omitempty"`
}

// CleanupResult reports what an executed cleanup actually removed.
type CleanupResult struct {
	RemovedAddresses int      `json:"removed_addresses"`
	KeptAddresses    []string `json:"kept_addresses"`
	RemovedStale     []string `json:"removed_stale"`
	RemovedOCI       []string `json:"removed_oci"`
	RulesRemoved     int      `json:"rules_removed"`
	RoutesFlushed    bool     `json:"routes_flushed"`
	DummyRemoved     string   `json:"dummy_removed"`
	Warnings         []string `json:"warnings"`
}

func inspectInterface(name string) InterfaceInfo {
	info := InterfaceInfo{Name: name}
	if name == "" {
		return info
	}
	out, err := exec.Command("ip", "link", "show", "dev", name).Output()
	if err != nil || len(out) == 0 {
		return info
	}
	info.Exists = true
	detail, derr := exec.Command("ip", "-d", "link", "show", "dev", name).Output()
	info.IsDummy = derr == nil && strings.Contains(string(detail), "dummy")
	return info
}

// interfaceAddresses parses `ip -6 -o addr show dev <iface>` into a map of
// CIDR -> raw line, so callers can filter by flags (dynamic/temporary/...).
func interfaceAddresses(iface string) map[string]string {
	out := map[string]string{}
	if iface == "" {
		return out
	}
	raw, err := exec.Command("ip", "-6", "-o", "addr", "show", "dev", iface).Output()
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f != "inet6" || i+1 >= len(fields) {
				continue
			}
			out[fields[i+1]] = line
			break
		}
	}
	return out
}

// stalePlan describes the addresses the stale sweep may touch. It is always
// restricted to interfaces/segments this process owns:
//
//   - dummy: the configured dummy interface (source_mode=pool or leftovers).
//   - oci:   the source interface, but only addresses that are neither in the
//     pool, nor OCI-managed objects, nor inside a non-pool OCI prefix. This
//     catches locally-added leftovers without touching provider addresses.
//
// Any other mode leaves the WAN alone, because its addresses cannot be told
// apart from ISP/SLAAC-managed ones.
type stalePlan struct {
	Iface    string
	Mode     string
	Stale    []string
	Managed  []string
	Prefixes []string
	Objects  []OCIObject
	Err      string
}

func (p *IPv6Pool) buildStalePlan() stalePlan {
	p.mu.RLock()
	dummy := p.dummyIface
	wan := p.wanIface
	source := p.sourceIface
	mode := p.sourceMode
	prefix := p.prefix
	wanIP := p.slaacWANIP
	ociPrefixLength := p.ociPrefixLength
	hostEgressIP := p.hostEgressIP
	known := make(map[string]bool, len(p.addrs))
	for ip := range p.addrs {
		known[ip] = true
	}
	p.mu.RUnlock()

	if dummy != "" && dummy != wan && dummy != "lo" {
		info := inspectInterface(dummy)
		if info.Exists && info.IsDummy {
			plan := stalePlan{Iface: dummy, Mode: "dummy"}
			plan.Stale = scanStaleAddresses(dummy, func(ip net.IP, ipStr, lower string) bool {
				if hostEgressIP != "" && ipStr == hostEgressIP {
					return false
				}
				if source == dummy {
					// Dummy is carrying the pool: only remove addresses inside
					// the pool prefix that are no longer tracked.
					if prefix == nil || !prefix.Contains(ip) || known[ipStr] {
						return false
					}
				}
				if wanIP != nil && ip.Equal(wanIP) {
					return false
				}
				return true
			})
			return plan
		}
	}

	if mode != "oci" {
		return stalePlan{}
	}

	plan := stalePlan{Iface: source, Mode: "oci"}
	objects, prefixes, exact, err := p.ociIPv6Objects()
	if err != nil {
		plan.Iface = ""
		plan.Err = err.Error()
		return plan
	}
	for _, o := range objects {
		plan.Managed = append(plan.Managed, formatOCIObject(o))
	}
	plan.Objects = objects
	for _, n := range prefixes {
		plan.Prefixes = append(plan.Prefixes, n.String())
	}
	// In per-IP mode prefix is only informational; do not treat it as owned.
	var poolPrefix *net.IPNet
	if ociPrefixLength != 0 {
		poolPrefix = prefix
	}
	plan.Stale = scanStaleAddresses(source, func(ip net.IP, ipStr, lower string) bool {
		if hostEgressIP != "" && ipStr == hostEgressIP {
			return false
		}
		if wanIP != nil && ip.Equal(wanIP) {
			return false
		}
		if known[ipStr] || exact[ipStr] {
			return false
		}
		if poolPrefix != nil && poolPrefix.Contains(ip) {
			// Inside the pool's own delegation but no longer tracked.
			return true
		}
		for _, n := range prefixes {
			if n.Contains(ip) {
				// Another delegated segment: leave it alone.
				return false
			}
		}
		// Static /128 outside every OCI delegation: local leftover.
		return true
	})
	return plan
}

// scanStaleAddresses lists static global /128 addresses on iface for which
// keep returns true. Dynamic/SLAAC-managed addresses are always skipped.
func scanStaleAddresses(iface string, keep func(net.IP, string, string) bool) []string {
	var stale []string
	for cidr, line := range interfaceAddresses(iface) {
		if !strings.HasSuffix(cidr, "/128") {
			continue
		}
		ipStr := strings.TrimSuffix(cidr, "/128")
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() != nil {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "dynamic") || strings.Contains(lower, "temporary") ||
			strings.Contains(lower, "mngtmpaddr") || strings.Contains(lower, "deprecated") ||
			strings.Contains(lower, "noprefixroute") {
			continue
		}
		if keep(ip, ipStr, lower) {
			stale = append(stale, ipStr)
		}
	}
	sort.Strings(stale)
	return stale
}

func formatOCIObject(o OCIObject) string {
	if o.CidrBits > 0 {
		return fmt.Sprintf("%s/%d", o.IPAddress, o.CidrBits)
	}
	return o.IPAddress
}

// deleteOCIObjects removes per-address OCI IPv6 resources. It refuses objects
// that are provider-managed (dynamic /128 on the kernel, e.g. SLAAC), prefix
// objects (the active pool segment and other delegations), and objects that
// are still tracked in the pool.
func (p *IPv6Pool) deleteOCIObjects(ids []string) (removed, warnings []string) {
	objects, _, _, err := p.ociIPv6Objects()
	if err != nil {
		return nil, []string{err.Error()}
	}
	byID := make(map[string]OCIObject, len(objects))
	for _, o := range objects {
		byID[o.ID] = o
	}
	for _, id := range ids {
		o, ok := byID[id]
		if !ok {
			warnings = append(warnings, fmt.Sprintf("OCI 对象 %s 不在当前 VNIC 上，跳过", id))
			continue
		}
		switch {
		case o.CidrBits > 0:
			warnings = append(warnings, fmt.Sprintf("%s 是前缀段 /%d，不能用此操作删除", o.IPAddress, o.CidrBits))
			continue
		case o.Dynamic:
			warnings = append(warnings, fmt.Sprintf("%s 是系统/提供商管理的地址，拒绝删除", o.IPAddress))
			continue
		case o.InPool:
			warnings = append(warnings, fmt.Sprintf("%s 仍在地址池中，请先删除池内地址", o.IPAddress))
			continue
		}
		if err := p.ociClient.DeleteIpv6(id); err != nil {
			warnings = append(warnings, fmt.Sprintf("删除 OCI 对象 %s: %v", o.IPAddress, err))
			continue
		}
		if o.OnKernel {
			exec.Command("ip", "-6", "addr", "del", o.IPAddress+"/128", "dev", p.sourceIface).Run()
		}
		removed = append(removed, o.IPAddress)
		log.Printf("[CLEANUP] deleted OCI IPv6 object %s (%s)", o.IPAddress, id)
	}
	return removed, warnings
}

// ociIPv6Objects lists the IPv6 resources assigned to the configured VNIC.
// exact contains every assigned literal address (prefix bases included);
// prefixes contains only the delegated CIDRs.
func (p *IPv6Pool) ociIPv6Objects() (objects []OCIObject, prefixes []*net.IPNet, exact map[string]bool, err error) {
	p.mu.RLock()
	client := p.ociClient
	compartment := p.ociCompartment
	vnic := p.ociVnicID
	source := p.sourceIface
	known := make(map[string]bool, len(p.addrs))
	for ip := range p.addrs {
		known[ip] = true
	}
	p.mu.RUnlock()

	if client == nil || vnic == "" {
		return nil, nil, nil, fmt.Errorf("OCI 客户端未初始化")
	}
	list, err := client.ListIpv6s(compartment, vnic)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("查询 OCI IPv6 对象失败: %w", err)
	}
	exact = make(map[string]bool, len(list))
	onKernel := interfaceAddresses(source)
	for _, o := range list {
		obj := OCIObject{
			ID:        o.ID,
			IPAddress: o.IPAddress,
			State:     o.LifecycleState,
			InPool:    known[o.IPAddress],
		}
		if o.CidrPrefixLength != nil {
			obj.CidrBits = *o.CidrPrefixLength
			if _, n, perr := net.ParseCIDR(fmt.Sprintf("%s/%d", o.IPAddress, obj.CidrBits)); perr == nil {
				prefixes = append(prefixes, n)
			}
		}
		if line, ok := onKernel[o.IPAddress+"/128"]; ok {
			obj.OnKernel = true
			lower := strings.ToLower(line)
			obj.Dynamic = strings.Contains(lower, "dynamic") ||
				strings.Contains(lower, "noprefixroute")
		}
		if ip := net.ParseIP(o.IPAddress); ip != nil {
			exact[ip.String()] = true
		}
		objects = append(objects, obj)
	}
	// Mark the object that backs the active pool segment. Prefix objects must
	// never be deleted by this cleanup, but the label makes that visible.
	p.mu.RLock()
	poolPrefix := p.prefix
	poolPrefixLen := 0
	if poolPrefix != nil {
		poolPrefixLen, _ = poolPrefix.Mask.Size()
	}
	activeID := p.ociPrefixID
	p.mu.RUnlock()
	for i := range objects {
		if activeID != "" && objects[i].ID == activeID {
			objects[i].Active = true
			continue
		}
		if poolPrefix != nil && poolPrefixLen != 128 {
			base := poolPrefix.IP.String()
			if objects[i].CidrBits == poolPrefixLen {
				if ip := net.ParseIP(objects[i].IPAddress); ip != nil && ip.String() == base {
					objects[i].Active = true
				}
			}
		}
	}
	sort.Slice(objects, func(i, j int) bool {
		if objects[i].CidrBits != objects[j].CidrBits {
			return objects[i].CidrBits > objects[j].CidrBits
		}
		return objects[i].IPAddress < objects[j].IPAddress
	})
	return objects, prefixes, exact, nil
}

func (p *IPv6Pool) countPolicyRules() int {
	out, err := exec.Command("ip", "-6", "rule", "show").Output()
	if err != nil {
		return 0
	}
	needle := "lookup " + strconv.Itoa(p.tableID)
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, needle) {
			n++
		}
	}
	return n
}

func (p *IPv6Pool) countTableRoutes() int {
	out, err := exec.Command("ip", "-6", "route", "show", "table", strconv.Itoa(p.tableID)).Output()
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// CleanupPreviewInfo gathers the current cleanup state.
func (p *IPv6Pool) CleanupPreviewInfo() CleanupPreview {
	p.mu.RLock()
	iface := p.sourceIface
	dummy := p.dummyIface
	mode := p.sourceMode
	prefix := ""
	if p.prefix != nil {
		prefix = p.prefix.String()
	}
	count := len(p.addrs)
	table := p.tableID
	p.mu.RUnlock()

	info := inspectInterface(dummy)
	info.InUse = iface == dummy && dummy != ""
	plan := p.buildStalePlan()
	stale := plan.Stale
	if stale == nil {
		stale = []string{}
	}
	managed := plan.Managed
	if managed == nil {
		managed = []string{}
	}
	objects := plan.Objects
	if objects == nil {
		objects = []OCIObject{}
	}

	return CleanupPreview{
		Dummy:           info,
		SourceInterface: iface,
		SourceMode:      mode,
		StaleInterface:  plan.Iface,
		StaleMode:       plan.Mode,
		StaleError:      plan.Err,
		OCIManaged:      managed,
		OCIObjects:      objects,
		PoolPrefix:      prefix,
		PoolAddresses:   count,
		StaleAddresses:  stale,
		PolicyRules:     p.countPolicyRules(),
		TableRoutes:     p.countTableRoutes(),
		PolicyTable:     table,
	}
}

// Cleanup removes the selected state. It is safe to call concurrently with the
// proxy: pool bookkeeping is protected by the pool mutex and each kernel
// command is independent.
func (p *IPv6Pool) Cleanup(opts CleanupOptions) CleanupResult {
	var res CleanupResult

	if opts.Addresses {
		p.mu.Lock()
		ips := make([]string, 0, len(p.addrs))
		alive := make(map[string]bool, len(p.addrs))
		for ip, a := range p.addrs {
			ips = append(ips, ip)
			alive[ip] = a.Status == "alive"
		}
		p.mu.Unlock()
		sort.Slice(ips, func(i, j int) bool {
			pi, pj := ips[i] == p.GetPinnedIP(), ips[j] == p.GetPinnedIP()
			if pi != pj {
				return pi
			}
			if alive[ips[i]] != alive[ips[j]] {
				return alive[ips[i]]
			}
			return ips[i] < ips[j]
		})
		keep := opts.Keep
		if keep < 0 {
			keep = 0
		}
		if keep > len(ips) {
			keep = len(ips)
		}
		res.KeptAddresses = append(res.KeptAddresses, ips[:keep]...)
		hostEgressIP := p.HostEgressIP()
		for _, ip := range ips[keep:] {
			if hostEgressIP != "" && ip == hostEgressIP {
				// Removing it would break the host's pinned IPv6 default route.
				res.KeptAddresses = append(res.KeptAddresses, ip)
				res.Warnings = append(res.Warnings, "保留主机出口源地址 "+ip+"（请先在「主机自身出口」切换策略）")
				continue
			}
			if err := p.RemoveAddress(ip); err == nil {
				res.RemovedAddresses++
			} else {
				res.Warnings = append(res.Warnings, err.Error())
			}
		}
		log.Printf("[CLEANUP] removed %d pool address(es), kept %d", res.RemovedAddresses, keep)
	}

	if opts.Stale {
		plan := p.buildStalePlan()
		if plan.Iface == "" {
			if plan.Err != "" {
				res.Warnings = append(res.Warnings, plan.Err)
			} else {
				res.Warnings = append(res.Warnings, "没有可扫描的网卡（dummy 不存在，且当前模式不是 OCI）")
			}
		} else if plan.Err != "" {
			// Never guess when the OCI object list is unavailable: without it
			// provider-managed addresses cannot be excluded safely.
			res.Warnings = append(res.Warnings, plan.Err)
		}
		for _, ip := range plan.Stale {
			cmd := exec.Command("ip", "-6", "addr", "del", ip+"/128", "dev", plan.Iface)
			if out, err := cmd.CombinedOutput(); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("del %s: %s: %v", ip, strings.TrimSpace(string(out)), err))
				continue
			}
			res.RemovedStale = append(res.RemovedStale, ip)
			log.Printf("[CLEANUP] removed stale address %s from %s (%s)", ip, plan.Iface, plan.Mode)
		}
	}

	if opts.Routes {
		p.mu.RLock()
		table := p.tableID
		p.mu.RUnlock()
		for i := 0; i < 256; i++ {
			if _, err := exec.Command("ip", "-6", "rule", "del", "table", strconv.Itoa(table)).CombinedOutput(); err != nil {
				break // no more rules for this table
			}
			res.RulesRemoved++
		}
		if out, err := exec.Command("ip", "-6", "route", "flush", "table", strconv.Itoa(table)).CombinedOutput(); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("flush table %d: %s: %v", table, strings.TrimSpace(string(out)), err))
		} else {
			res.RoutesFlushed = true
		}
		log.Printf("[CLEANUP] policy table %d: removed %d rule(s), routes flushed=%v", table, res.RulesRemoved, res.RoutesFlushed)
	}

	if len(opts.DeleteOCI) > 0 {
		removed, warnings := p.deleteOCIObjects(opts.DeleteOCI)
		res.RemovedOCI = append(res.RemovedOCI, removed...)
		res.Warnings = append(res.Warnings, warnings...)
	}

	if opts.Dummy {
		p.mu.RLock()
		name := p.dummyIface
		inUse := p.sourceIface == p.dummyIface && p.dummyIface != ""
		p.mu.RUnlock()
		switch {
		case name == "":
			res.Warnings = append(res.Warnings, "dummy_iface is empty")
		case inUse && !opts.Addresses:
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("虚拟网卡 %s 正被地址池使用（source_mode=pool）；如要彻底清理，请同时勾选「清空池内地址」", name))
		default:
			info := inspectInterface(name)
			if !info.Exists {
				// Nothing to do; not an error.
			} else if !info.IsDummy {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s 不是 dummy 网卡，拒绝删除", name))
			} else if err := removeDummyInterface(name); err != nil {
				res.Warnings = append(res.Warnings, err.Error())
			} else {
				res.DummyRemoved = name
				p.mu.Lock()
				p.dummyCreated = false
				p.mu.Unlock()
				log.Printf("[CLEANUP] removed dummy interface %s", name)
				if inUse {
					res.Warnings = append(res.Warnings,
						"虚拟网卡与池内地址均已清理；当前实例已无可用源地址，请重启进程或切换模式后重新生成")
				}
			}
		}
	}

	if res.Warnings == nil {
		res.Warnings = []string{}
	}
	if res.RemovedStale == nil {
		res.RemovedStale = []string{}
	}
	if res.RemovedOCI == nil {
		res.RemovedOCI = []string{}
	}
	if res.KeptAddresses == nil {
		res.KeptAddresses = []string{}
	}
	return res
}
