package internal

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// new64Plan describes the target resources for a new-/64 switch. Only fields
// prefixed with Created are owned by this operation and may be rolled back.
type new64Plan struct {
	VnicID          string
	Interface       string
	Gateway         string
	SubnetCIDR      string
	PrefixID        string
	PrefixCIDR      string
	PrefixLen       int
	ReusedVnic      bool
	ReusedPrefix    bool
	CreatedPrefix   bool
	CreatedSubnetID string
	CreatedAttachID string
}

// waitForSubnetDeletion waits briefly for a just-detached VNIC to release its
// subnet. OCI subnet deletion fails while any VNIC is still present.
func waitForSubnetDeletion(client *OciClient, subnetID string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for {
		err := client.DeleteSubnet(subnetID)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			log.Printf("[OCI] delete subnet %s failed: %v", subnetID, err)
			return
		}
		time.Sleep(2 * time.Second)
	}
}

func rollbackNew64(client *OciClient, plan *new64Plan, warnings *[]string) {
	if plan == nil {
		return
	}
	if plan.CreatedPrefix && plan.PrefixID != "" {
		if err := client.DeleteIpv6(plan.PrefixID); err != nil {
			*warnings = append(*warnings, "回滚新建前缀失败: "+err.Error())
		}
	}
	if plan.CreatedAttachID != "" {
		if err := client.DetachVnic(plan.CreatedAttachID); err != nil {
			*warnings = append(*warnings, "回滚分离新 VNIC 失败: "+err.Error())
		}
	}
	if plan.CreatedSubnetID != "" {
		waitForSubnetDeletion(client, plan.CreatedSubnetID, 20*time.Second)
	}
}

// deleteSubnetEventually retries because a just-detached VNIC keeps the
// subnet busy for a few seconds while OCI terminates it.
func deleteSubnetEventually(client *OciClient, subnetID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		if err := client.DeleteSubnet(subnetID); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return lastErr
		}
		time.Sleep(2 * time.Second)
	}
}

// deleteVnicByID detaches a non-active, non-primary secondary VNIC and then
// deletes its subnet. The subnet deletion is best-effort: if another VNIC still
// uses it OCI refuses and the warning is returned instead of failing the whole
// operation. The active VNIC and the primary/default-route VNIC are protected.
func deleteVnicByID(client *OciClient, compartment, vnicID, activeVnic string) ([]string, error) {
	warnings := []string{}
	if vnicID == "" {
		return warnings, fmt.Errorf("vnic_id is required")
	}
	if vnicID == activeVnic {
		return warnings, fmt.Errorf("不能删除当前正在使用的 VNIC，请先切换到其它 VNIC")
	}
	primaryIface, _ := DetectWANInterface()
	iface, _, _, ierr := ResolveOCIVnicNetwork(vnicID)
	if ierr != nil {
		return warnings, fmt.Errorf("无法解析 VNIC 接口，拒绝删除: %w", ierr)
	}
	if primaryIface != "" && iface == primaryIface {
		return warnings, fmt.Errorf("不能删除主 VNIC（默认路由所在网卡）")
	}
	info, err := client.GetVnic(vnicID)
	if err != nil {
		return warnings, fmt.Errorf("查询 VNIC 失败: %w", err)
	}
	instanceID, err := DetectInstanceID()
	if err != nil {
		return warnings, fmt.Errorf("读取实例 OCID 失败: %w", err)
	}
	atts, err := client.ListVnicAttachments(compartment, instanceID)
	if err != nil {
		return warnings, fmt.Errorf("列出 VNIC 附加信息失败: %w", err)
	}
	var attachmentID string
	for _, a := range atts {
		if a.VnicID == vnicID {
			attachmentID = a.ID
			break
		}
	}
	if attachmentID == "" {
		return warnings, fmt.Errorf("未找到 VNIC %s 的附加记录", vnicID)
	}
	if err := client.DetachVnic(attachmentID); err != nil {
		return warnings, fmt.Errorf("分离 VNIC 失败: %w", err)
	}
	log.Printf("[OCI] detached VNIC %s (attachment %s), deleting subnet %s", vnicID, attachmentID, info.SubnetID)
	if info.SubnetID != "" {
		if err := deleteSubnetEventually(client, info.SubnetID, 60*time.Second); err != nil {
			warnings = append(warnings, "VNIC 已分离，但删除子网失败: "+err.Error())
		}
	}
	return warnings, nil
}

// allocateIPv6Subnet picks an unused /64 from the VCN's Oracle-assigned IPv6
// blocks. Subnets in a VCN cannot share a /64, which is why a second /64 needs
// a second subnet and therefore a second VNIC.
func allocateIPv6Subnet(vcn *OciVcn, subnets []OciSubnet) (string, error) {
	used := make([]*net.IPNet, 0, len(subnets))
	for _, s := range subnets {
		for _, c := range append(append([]string{}, s.IPv6CidrBlocks...), s.IPv6CidrBlock) {
			if c == "" {
				continue
			}
			if _, n, err := net.ParseCIDR(c); err == nil {
				used = append(used, n)
			}
		}
	}
	for _, block := range vcn.IPv6CidrBlocks {
		_, parent, err := net.ParseCIDR(strings.TrimSpace(block))
		if err != nil || parent.IP.To4() != nil {
			continue
		}
		ones, bits := parent.Mask.Size()
		if bits != 128 || ones > 64 {
			continue
		}
		limit := 4096
		if shift := 64 - ones; shift < 12 {
			limit = 1 << uint(shift)
		}
		for i := 0; i < limit; i++ {
			ip := subnetCandidate(parent, i, 64)
			cidr := fmt.Sprintf("%s/64", ip)
			if !cidrOverlapsAny(cidr, used) {
				return cidr, nil
			}
		}
	}
	return "", fmt.Errorf("VCN 中没有可用的 IPv6 /64；请确认 VCN 已分配 Oracle IPv6 前缀")
}

// allocateIPv4Subnet picks an unused /24 from the VCN IPv4 CIDR. The subnet
// needs an IPv4 CIDR even though the proxy itself only uses IPv6.
func allocateIPv4Subnet(vcn *OciVcn, subnets []OciSubnet) (string, error) {
	used := make([]*net.IPNet, 0, len(subnets))
	for _, s := range subnets {
		if s.CidrBlock == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(s.CidrBlock); err == nil {
			used = append(used, n)
		}
	}
	for _, block := range vcn.CidrBlocks {
		_, parent, err := net.ParseCIDR(strings.TrimSpace(block))
		if err != nil || parent.IP.To4() == nil {
			continue
		}
		ones, bits := parent.Mask.Size()
		if bits != 32 || ones > 24 {
			continue
		}
		limit := 4096
		if shift := 24 - ones; shift < 12 {
			limit = 1 << uint(shift)
		}
		for i := 0; i < limit; i++ {
			ip := subnetCandidate(parent, i, 24)
			cidr := fmt.Sprintf("%s/24", ip)
			if !cidrOverlapsAny(cidr, used) {
				return cidr, nil
			}
		}
	}
	return "", fmt.Errorf("VCN 中没有可用的 IPv4 /24；请为 VCN 扩容 IPv4 CIDR 或手动创建子网")
}

// subnetCandidate returns the i-th prefixBits-sized network inside parent,
// with all bits outside the new prefix cleared.
func subnetCandidate(parent *net.IPNet, i, prefixBits int) net.IP {
	ones, _ := parent.Mask.Size()
	out := make(net.IP, len(parent.IP))
	copy(out, parent.IP)
	// Zero the host bits first.
	for bit := ones; bit < len(out)*8; bit++ {
		out[bit/8] &^= 1 << uint(7-bit%8)
	}
	// Encode i into bits [ones, prefixBits).
	indexBits := prefixBits - ones
	for b := 0; b < indexBits; b++ {
		if i&(1<<uint(indexBits-1-b)) != 0 {
			bit := ones + b
			out[bit/8] |= 1 << uint(7-bit%8)
		}
	}
	return out
}

func cidrOverlapsAny(cidr string, used []*net.IPNet) bool {
	ip, cand, err := net.ParseCIDR(cidr)
	if err != nil {
		return true
	}
	for _, n := range used {
		if n.Contains(ip) || cand.Contains(n.IP) {
			return true
		}
	}
	return false
}

// prefixInSubnet reports whether cidr is inside subnetCIDR.
func prefixInSubnet(cidr, subnetCIDR string) bool {
	_, sub, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return true
	}
	ip, _, err := net.ParseCIDR(cidr)
	return err == nil && sub.Contains(ip)
}

// selectVnicPrefix picks an existing usable prefix on a VNIC. desiredLen is
// preferred when non-zero, then preferLen (usually the currently active
// length); otherwise the first usable prefix wins.
func selectVnicPrefix(list []OciIpv6, subnetCIDR string, desiredLen, preferLen int) *OciIpv6 {
	var fallback *OciIpv6
	var preferred *OciIpv6
	for i := range list {
		o := &list[i]
		if o.CidrPrefixLength == nil || *o.CidrPrefixLength < 80 || o.IPAddress == "" {
			continue
		}
		if o.LifecycleState != "" && o.LifecycleState != "AVAILABLE" {
			continue
		}
		cidr := fmt.Sprintf("%s/%d", o.IPAddress, *o.CidrPrefixLength)
		if !prefixInSubnet(cidr, subnetCIDR) {
			continue
		}
		if fallback == nil {
			fallback = o
		}
		if desiredLen > 0 && *o.CidrPrefixLength == desiredLen {
			return o
		}
		if preferred == nil && preferLen > 0 && *o.CidrPrefixLength == preferLen {
			preferred = o
		}
	}
	if preferred != nil {
		return preferred
	}
	return fallback
}

// createVnicPrefix creates and validates a prefix object on a VNIC. On any
// validation failure the just-created OCI object is deleted again.
func createVnicPrefix(client *OciClient, compartment, vnic, subnetCIDR string, desiredLen int) (*OciIpv6, string, int, error) {
	obj, err := client.CreateIpv6CidrInSubnet(vnic, subnetCIDR, "", desiredLen)
	if err != nil {
		return nil, "", 0, fmt.Errorf("创建 OCI 前缀失败: %w", err)
	}
	if obj.ID == "" || obj.IPAddress == "" {
		if obj.ID != "" {
			_ = client.DeleteIpv6(obj.ID)
		}
		return nil, "", 0, fmt.Errorf("OCI 创建前缀后未返回对象 ID / 地址")
	}
	if obj.LifecycleState != "" && obj.LifecycleState != "AVAILABLE" {
		ready, werr := client.WaitForPrefixAvailable(compartment, vnic, obj.ID, 30*time.Second)
		if werr != nil {
			_ = client.DeleteIpv6(obj.ID)
			return nil, "", 0, fmt.Errorf("等待 OCI 前缀可用失败: %w", werr)
		}
		obj = ready
	}
	newLen := desiredLen
	if obj.CidrPrefixLength != nil {
		newLen = *obj.CidrPrefixLength
	}
	if newLen < 80 || newLen > 128 || newLen%4 != 0 {
		_ = client.DeleteIpv6(obj.ID)
		return nil, "", 0, fmt.Errorf("OCI 创建前缀后返回了不支持的段长度")
	}
	cidr := fmt.Sprintf("%s/%d", obj.IPAddress, newLen)
	if _, _, perr := net.ParseCIDR(cidr); perr != nil {
		_ = client.DeleteIpv6(obj.ID)
		return nil, "", 0, fmt.Errorf("OCI 创建前缀后返回了无效地址: %w", perr)
	}
	return obj, cidr, newLen, nil
}

// prepareNewVnic always creates a brand-new /64: a new subnet and a new
// secondary VNIC. It does not create or touch any IPv6 prefix; the caller can
// switch to the VNIC and edit IPv6 separately.
func prepareNewVnic(client *OciClient, activeVnic string, noCreate bool) (*new64Plan, error) {
	if noCreate {
		return nil, fmt.Errorf("oci_no_create=true 禁止创建新子网/VNIC")
	}
	metas, err := resolvedVnicMetadata()
	if err != nil {
		return nil, fmt.Errorf("读取实例网卡元数据失败: %w", err)
	}
	if len(metas) >= 2 {
		return nil, fmt.Errorf("实例已使用 %d 个 VNIC（上限通常为 2），无法再新建 VNIC。请先删除旧的非主 VNIC，或使用已有 VNIC", len(metas))
	}
	activeVnicInfo, err := client.GetVnic(activeVnic)
	if err != nil {
		return nil, fmt.Errorf("查询当前 VNIC 失败: %w", err)
	}
	activeSubnet, err := client.GetSubnet(activeVnicInfo.SubnetID)
	if err != nil {
		return nil, fmt.Errorf("查询当前子网失败: %w", err)
	}
	vcn, err := client.GetVcn(activeSubnet.VcnID)
	if err != nil {
		return nil, fmt.Errorf("查询 VCN 失败: %w", err)
	}
	subnets, err := client.ListSubnets(activeSubnet.CompartmentID, vcn.ID)
	if err != nil {
		return nil, fmt.Errorf("列出子网失败: %w", err)
	}
	ipv6CIDR, err := allocateIPv6Subnet(vcn, subnets)
	if err != nil {
		return nil, err
	}
	ipv4CIDR, err := allocateIPv4Subnet(vcn, subnets)
	if err != nil {
		return nil, err
	}
	name := "proxy-egress-" + strings.ReplaceAll(strings.ReplaceAll(ipv6CIDR, ":", ""), "/", "-")
	subnet, err := client.CreateSubnet(activeSubnet.CompartmentID, vcn.ID, name, ipv4CIDR, ipv6CIDR,
		activeSubnet.RouteTableID, activeSubnet.DhcpOptionsID, activeSubnet.SecurityListIDs,
		activeSubnet.ProhibitInternetIngress, activeSubnet.ProhibitPublicIPOnVnic)
	if err != nil {
		return nil, fmt.Errorf("创建子网 %s 失败: %w", ipv6CIDR, err)
	}
	plan := &new64Plan{}
	plan.CreatedSubnetID = subnet.ID
	log.Printf("[OCI] created subnet %s (%s, IPv4 %s)", subnet.ID, ipv6CIDR, ipv4CIDR)
	if subnet.LifecycleState != "" && subnet.LifecycleState != "AVAILABLE" {
		subnet, err = client.WaitForSubnetAvailable(subnet.ID, 90*time.Second)
		if err != nil {
			var warnings []string
			rollbackNew64(client, plan, &warnings)
			return nil, fmt.Errorf("等待新子网可用失败: %w", err)
		}
	}

	instanceID, err := DetectInstanceID()
	if err != nil {
		rollbackNew64(client, plan, &[]string{})
		return nil, fmt.Errorf("读取实例 OCID 失败: %w", err)
	}
	att, err := client.AttachVnic(instanceID, subnet.ID, name)
	if err != nil {
		rollbackNew64(client, plan, &[]string{})
		return nil, fmt.Errorf("创建并附加 VNIC 失败: %w", err)
	}
	plan.CreatedAttachID = att.ID
	ready, err := client.WaitForVnicAttachment(att.ID, 90*time.Second)
	if err != nil {
		var warnings []string
		rollbackNew64(client, plan, &warnings)
		return nil, fmt.Errorf("等待 VNIC 附加失败: %w", err)
	}
	if ready.VnicID == "" {
		var warnings []string
		rollbackNew64(client, plan, &warnings)
		return nil, fmt.Errorf("VNIC 附加成功但未返回 VNIC OCID")
	}
	plan.VnicID = ready.VnicID

	iface, gateway, meta, err := WaitForVnicNetwork(plan.VnicID, 90*time.Second)
	if err != nil {
		var warnings []string
		rollbackNew64(client, plan, &warnings)
		return nil, err
	}
	plan.Interface = iface
	plan.Gateway = gateway
	plan.SubnetCIDR = meta.IPv6SubnetCIDR
	if plan.SubnetCIDR == "" {
		var warnings []string
		rollbackNew64(client, plan, &warnings)
		return nil, fmt.Errorf("VNIC %s 没有 IPv6 子网", plan.VnicID)
	}

	return plan, nil
}

// prepareNew64 is the legacy one-shot flow: create a new VNIC and immediately
// create a pool prefix on it. The console uses new_vnic + switch_vnic instead
// so VNIC management and IPv6 editing stay separate.
func prepareNew64(client *OciClient, compartment, activeVnic string, desiredLen int, noCreate bool) (*new64Plan, error) {
	if desiredLen == 0 {
		desiredLen = 112
	}
	if desiredLen < 80 || desiredLen > 128 || desiredLen%4 != 0 {
		return nil, fmt.Errorf("prefix_length must be 80-128 divisible by 4")
	}
	plan, err := prepareNewVnic(client, activeVnic, noCreate)
	if err != nil {
		return nil, err
	}
	obj, cidr, plen, err := createVnicPrefix(client, compartment, plan.VnicID, plan.SubnetCIDR, desiredLen)
	if err != nil {
		var warnings []string
		rollbackNew64(client, plan, &warnings)
		return nil, err
	}
	plan.CreatedPrefix = true
	plan.PrefixID = obj.ID
	plan.PrefixCIDR = cidr
	plan.PrefixLen = plen
	return plan, nil
}
