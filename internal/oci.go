package internal

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// OciClient handles OCI IAM Signature V1 using API Key (~/.oci/config).
// No external deps. For Instance Principal, use same key via IMDS federation
// or switch to config file auth as demonstrated in oci-ipv6-manager.py.
type OciClient struct {
	Tenancy     string
	User        string
	Fingerprint string
	PrivateKey  *rsa.PrivateKey
	Region      string
	HTTPClient  *http.Client
}

func LoadOciClientFromConfig(path string) (*OciClient, error) {
	if path == "" {
		path = os.ExpandEnv("$HOME/.oci/config")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read oci config: %w", err)
	}
	cfg := map[string]string{}
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			continue
		}
		if section != "DEFAULT" {
			continue
		}
		if idx := strings.Index(line, "="); idx > 0 {
			k := strings.TrimSpace(line[:idx])
			v := strings.TrimSpace(line[idx+1:])
			cfg[k] = v
		}
	}
	tenancy, ok := cfg["tenancy"]
	if !ok {
		return nil, fmt.Errorf("tenancy not in %s", path)
	}
	user := cfg["user"]
	fp := cfg["fingerprint"]
	keyFile := cfg["key_file"]
	region := cfg["region"]
	if region == "" {
		region = "ap-singapore-1"
	}
	pemData, err := os.ReadFile(os.ExpandEnv(keyFile))
	if err != nil {
		return nil, fmt.Errorf("read key_file %s: %w", keyFile, err)
	}
	priv, err := parsePrivateKey(pemData)
	if err != nil {
		return nil, err
	}
	return &OciClient{
		Tenancy:     tenancy,
		User:        user,
		Fingerprint: fp,
		PrivateKey:  priv,
		Region:      region,
		HTTPClient:  &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func parsePrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("pem decode failed")
	}
	// Try PKCS1, PKCS8
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := k.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("not RSA private key")
	}
	return nil, fmt.Errorf("parse private key failed")
}

func (c *OciClient) keyID() string {
	return fmt.Sprintf("%s/%s/%s", c.Tenancy, c.User, c.Fingerprint)
}

func (c *OciClient) host() string {
	return fmt.Sprintf("iaas.%s.oraclecloud.com", c.Region)
}

// sign builds OCI Signature V1 header value.
func (c *OciClient) sign(method, uri string, headers map[string]string) (string, error) {
	// headers order for signing: (request-target) date host [x-content-sha256 content-type content-length]
	keys := []string{"(request-target)", "date", "host"}
	if _, ok := headers["x-content-sha256"]; ok {
		keys = append(keys, "x-content-sha256", "content-type", "content-length")
	}
	var parts []string
	for _, k := range keys {
		var v string
		if k == "(request-target)" {
			v = fmt.Sprintf("(request-target): %s %s", strings.ToLower(method), uri)
		} else {
			v = fmt.Sprintf("%s: %s", k, headers[k])
		}
		parts = append(parts, v)
	}
	signingString := strings.Join(parts, "\n")
	h := sha256.Sum256([]byte(signingString))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.PrivateKey, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	b64 := base64.StdEncoding.EncodeToString(sig)
	hdrs := strings.Join(keys, " ")
	return fmt.Sprintf(`Signature version="1",keyId="%s",algorithm="rsa-sha256",headers="%s",signature="%s"`, c.keyID(), hdrs, b64), nil
}

func (c *OciClient) do(method, path string, body interface{}) (int, []byte, error) {
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
	}
	uri := path // for signing includes query
	host := c.host()
	url := fmt.Sprintf("https://%s%s", host, path)
	date := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	headers := map[string]string{
		"date": date,
		"host": host,
	}
	if data != nil {
		h := sha256.Sum256(data)
		headers["x-content-sha256"] = base64.StdEncoding.EncodeToString(h[:])
		headers["content-type"] = "application/json"
		headers["content-length"] = fmt.Sprintf("%d", len(data))
	}
	auth, err := c.sign(method, uri, headers)
	if err != nil {
		return 0, nil, err
	}
	var reqBody io.Reader
	if data != nil {
		reqBody = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Date", headers["date"])
	req.Header.Set("Host", headers["host"])
	req.Header.Set("Authorization", auth)
	if data != nil {
		req.Header.Set("x-content-sha256", headers["x-content-sha256"])
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

// Ipv6 mirrors OCI Ipv6 resource (subset)
type OciIpv6 struct {
	ID               string `json:"id"`
	IPAddress        string `json:"ipAddress"`
	CidrPrefixLength *int   `json:"cidrPrefixLength"`
	LifecycleState   string `json:"lifecycleState"`
	VnicID           string `json:"vnicId"`
	SubnetID         string `json:"subnetId"`
}

func (c *OciClient) ListIpv6s(compartmentID, vnicID string) ([]OciIpv6, error) {
	path := fmt.Sprintf("/20160918/ipv6?compartmentId=%s&vnicId=%s", compartmentID, vnicID)
	code, body, err := c.do("GET", path, nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("ListIpv6s %d: %s", code, string(body))
	}
	var out []OciIpv6
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// OciVnic mirrors the OCI VNIC resource (subset used for routing and subnet
// discovery).
type OciVnic struct {
	ID             string `json:"id"`
	SubnetID       string `json:"subnetId"`
	CompartmentID  string `json:"compartmentId"`
	MacAddress     string `json:"macAddress"`
	PrivateIP      string `json:"privateIp"`
	PublicIP       string `json:"publicIp"`
	LifecycleState string `json:"lifecycleState"`
	DisplayName    string `json:"displayName"`
}

type OciSubnet struct {
	ID                      string   `json:"id"`
	VcnID                   string   `json:"vcnId"`
	CompartmentID           string   `json:"compartmentId"`
	CidrBlock               string   `json:"cidrBlock"`
	IPv6CidrBlock           string   `json:"ipv6CidrBlock"`
	IPv6CidrBlocks          []string `json:"ipv6CidrBlocks"`
	DisplayName             string   `json:"displayName"`
	RouteTableID            string   `json:"routeTableId"`
	DhcpOptionsID           string   `json:"dhcpOptionsId"`
	SecurityListIDs         []string `json:"securityListIds"`
	ProhibitInternetIngress bool     `json:"prohibitInternetIngress"`
	ProhibitPublicIPOnVnic  bool     `json:"prohibitPublicIpOnVnic"`
	LifecycleState          string   `json:"lifecycleState"`
}

type OciVcn struct {
	ID             string   `json:"id"`
	CompartmentID  string   `json:"compartmentId"`
	CidrBlocks     []string `json:"cidrBlocks"`
	IPv6CidrBlocks []string `json:"ipv6CidrBlocks"`
	LifecycleState string   `json:"lifecycleState"`
}

type OciVnicAttachment struct {
	ID             string `json:"id"`
	InstanceID     string `json:"instanceId"`
	VnicID         string `json:"vnicId"`
	LifecycleState string `json:"lifecycleState"`
	NicIndex       int    `json:"nicIndex"`
	DisplayName    string `json:"displayName"`
}

func (c *OciClient) GetVnic(id string) (*OciVnic, error) {
	code, body, err := c.do("GET", "/20160918/vnics/"+id, nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("GetVnic %d: %s", code, string(body))
	}
	var out OciVnic
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *OciClient) GetSubnet(id string) (*OciSubnet, error) {
	code, body, err := c.do("GET", "/20160918/subnets/"+id, nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("GetSubnet %d: %s", code, string(body))
	}
	var out OciSubnet
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *OciClient) GetVcn(id string) (*OciVcn, error) {
	code, body, err := c.do("GET", "/20160918/vcns/"+id, nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("GetVcn %d: %s", code, string(body))
	}
	var out OciVcn
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *OciClient) ListSubnets(compartmentID, vcnID string) ([]OciSubnet, error) {
	path := fmt.Sprintf("/20160918/subnets?compartmentId=%s&vcnId=%s&limit=1000", compartmentID, vcnID)
	code, body, err := c.do("GET", path, nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("ListSubnets %d: %s", code, string(body))
	}
	var out []OciSubnet
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *OciClient) CreateSubnet(compartmentID, vcnID, displayName, ipv4CIDR, ipv6CIDR, routeTableID, dhcpOptionsID string, securityListIDs []string, prohibitInternetIngress, prohibitPublicIP bool) (*OciSubnet, error) {
	body := map[string]interface{}{
		"compartmentId":           compartmentID,
		"vcnId":                   vcnID,
		"displayName":             displayName,
		"cidrBlock":               ipv4CIDR,
		"ipv6CidrBlocks":          []string{ipv6CIDR},
		"routeTableId":            routeTableID,
		"dhcpOptionsId":           dhcpOptionsID,
		"securityListIds":         securityListIDs,
		"prohibitInternetIngress": prohibitInternetIngress,
		"prohibitPublicIpOnVnic":  prohibitPublicIP,
	}
	code, resp, err := c.do("POST", "/20160918/subnets", body)
	if err != nil {
		return nil, err
	}
	if code != 200 && code != 201 {
		return nil, fmt.Errorf("CreateSubnet %d: %s", code, string(resp))
	}
	var out OciSubnet
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// WaitForSubnetAvailable waits for a newly created subnet to accept VNIC
// attachments. CreateSubnet can return PROVISIONING before the subnet is ready.
func (c *OciClient) WaitForSubnetAvailable(id string, timeout time.Duration) (*OciSubnet, error) {
	deadline := time.Now().Add(timeout)
	for {
		sub, err := c.GetSubnet(id)
		if err == nil {
			switch sub.LifecycleState {
			case "", "AVAILABLE":
				return sub, nil
			case "TERMINATING", "TERMINATED", "FAILED":
				return nil, fmt.Errorf("subnet %s state %s", id, sub.LifecycleState)
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				return nil, fmt.Errorf("timeout waiting for subnet %s: %w", id, err)
			}
			return nil, fmt.Errorf("timeout waiting for subnet %s to become AVAILABLE", id)
		}
		time.Sleep(2 * time.Second)
	}
}

func (c *OciClient) DeleteSubnet(id string) error {
	code, body, err := c.do("DELETE", "/20160918/subnets/"+id, nil)
	if err != nil {
		return err
	}
	if code != 200 && code != 204 {
		return fmt.Errorf("DeleteSubnet %d: %s", code, string(body))
	}
	return nil
}

// AttachVnic creates a secondary VNIC and attaches it to instanceID. OCI
// creates the VNIC as part of the attachment, so there is no separate VNIC
// create call.
func (c *OciClient) AttachVnic(instanceID, subnetID, displayName string) (*OciVnicAttachment, error) {
	body := map[string]interface{}{
		"instanceId":  instanceID,
		"displayName": displayName,
		"createVnicDetails": map[string]interface{}{
			"subnetId":       subnetID,
			"displayName":    displayName,
			"assignPublicIp": false,
			"assignIpv6Ip":   false,
		},
	}
	code, resp, err := c.do("POST", "/20160918/vnicAttachments", body)
	if err != nil {
		return nil, err
	}
	if code != 200 && code != 201 {
		return nil, fmt.Errorf("AttachVnic %d: %s", code, string(resp))
	}
	var out OciVnicAttachment
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *OciClient) GetVnicAttachment(id string) (*OciVnicAttachment, error) {
	code, body, err := c.do("GET", "/20160918/vnicAttachments/"+id, nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("GetVnicAttachment %d: %s", code, string(body))
	}
	var out OciVnicAttachment
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListVnicAttachments lists the VNIC attachments of an instance. Detaching a
// secondary VNIC requires its attachment OCID, which is not exposed in guest
// metadata.
func (c *OciClient) ListVnicAttachments(compartmentID, instanceID string) ([]OciVnicAttachment, error) {
	path := fmt.Sprintf("/20160918/vnicAttachments?compartmentId=%s&instanceId=%s&limit=1000", compartmentID, instanceID)
	code, body, err := c.do("GET", path, nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("ListVnicAttachments %d: %s", code, string(body))
	}
	var out []OciVnicAttachment
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *OciClient) WaitForVnicAttachment(id string, timeout time.Duration) (*OciVnicAttachment, error) {
	deadline := time.Now().Add(timeout)
	for {
		att, err := c.GetVnicAttachment(id)
		if err == nil {
			switch att.LifecycleState {
			case "ATTACHED":
				return att, nil
			case "DETACHING", "DETACHED", "FAILED":
				return nil, fmt.Errorf("VNIC attachment %s state %s", id, att.LifecycleState)
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				return nil, fmt.Errorf("timeout waiting for VNIC attachment %s: %w", id, err)
			}
			return nil, fmt.Errorf("timeout waiting for VNIC attachment %s", id)
		}
		time.Sleep(2 * time.Second)
	}
}

func (c *OciClient) DetachVnic(attachmentID string) error {
	code, body, err := c.do("DELETE", "/20160918/vnicAttachments/"+attachmentID, nil)
	if err != nil {
		return err
	}
	if code != 200 && code != 202 && code != 204 {
		return fmt.Errorf("DetachVnic %d: %s", code, string(body))
	}
	return nil
}

// WaitForVnicNetwork waits until a freshly attached VNIC appears in instance
// metadata and its Linux interface can be resolved. OCI can report the
// attachment as ATTACHED slightly before the guest has the interface.
func WaitForVnicNetwork(vnicID string, timeout time.Duration) (iface, gateway string, meta *VnicMetadata, err error) {
	deadline := time.Now().Add(timeout)
	for {
		iface, gateway, meta, err = ResolveOCIVnicNetwork(vnicID)
		if err == nil {
			return iface, gateway, meta, nil
		}
		if time.Now().After(deadline) {
			return "", "", nil, fmt.Errorf("timeout waiting for VNIC %s network: %w", vnicID, err)
		}
		time.Sleep(2 * time.Second)
	}
}

func (c *OciClient) CreateIpv6(vnicID string) (*OciIpv6, error) {
	return c.CreateIpv6Cidr(vnicID, "", 0)
}

// CreateIpv6Cidr creates an IPv6 on vnic. If ipv6Ip=="" let Oracle pick.
// cidrPrefixLength 0 means single /128, otherwise 80-128 divisible by 4 (e.g. 112,80)
func (c *OciClient) CreateIpv6Cidr(vnicID, ipv6Ip string, cidrPrefixLength int) (*OciIpv6, error) {
	return c.CreateIpv6CidrInSubnet(vnicID, "", ipv6Ip, cidrPrefixLength)
}

// CreateIpv6CidrInSubnet is CreateIpv6Cidr with an explicit subnet CIDR. OCI
// requires ipv6SubnetCidr when the subnet has more than one IPv6 prefix. It is
// also how a second VNIC selects the /64 that belongs to its own subnet.
func (c *OciClient) CreateIpv6CidrInSubnet(vnicID, subnetCIDR, ipv6Ip string, cidrPrefixLength int) (*OciIpv6, error) {
	body := map[string]interface{}{"vnicId": vnicID}
	if subnetCIDR != "" {
		body["ipv6SubnetCidr"] = subnetCIDR
	}
	if ipv6Ip != "" {
		body["ipv6Ip"] = ipv6Ip
	}
	if cidrPrefixLength != 0 {
		body["cidrPrefixLength"] = cidrPrefixLength
	}
	code, resp, err := c.do("POST", "/20160918/ipv6", body)
	if err != nil {
		return nil, err
	}
	if code != 200 && code != 201 {
		return nil, fmt.Errorf("CreateIpv6 %d: %s", code, string(resp))
	}
	var out OciIpv6
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *OciClient) DeleteIpv6(ipv6ID string) error {
	code, body, err := c.do("DELETE", fmt.Sprintf("/20160918/ipv6/%s", ipv6ID), nil)
	if err != nil {
		return err
	}
	if code != 204 && code != 200 {
		return fmt.Errorf("DeleteIpv6 %d: %s", code, string(body))
	}
	return nil
}

// PrefixDeletionSafe reports whether an OCI IPv6 prefix object can be deleted
// without touching any other OCI IPv6 object inside its CIDR. The active pool's
// self-allocated /128s are local kernel addresses, not OCI objects, so they do
// not block deletion; provider-managed /128 objects do.
func (c *OciClient) PrefixDeletionSafe(compartmentID, vnicID, prefixID, prefixCIDR string) (bool, string) {
	_, n, err := net.ParseCIDR(prefixCIDR)
	if err != nil {
		return false, fmt.Sprintf("无法校验旧前缀 %q，已保留: %v", prefixCIDR, err)
	}
	list, err := c.ListIpv6s(compartmentID, vnicID)
	if err != nil {
		return false, "无法校验旧前缀内的 OCI 对象，已保留: " + err.Error()
	}
	found := false
	blocking := 0
	for _, o := range list {
		if o.ID == prefixID {
			found = true
			if o.CidrPrefixLength == nil {
				return false, "旧活动对象不是前缀段，已保留"
			}
			continue
		}
		if ip := net.ParseIP(o.IPAddress); ip != nil && n.Contains(ip) {
			blocking++
		}
	}
	if !found {
		return false, "旧前缀对象已不在 OCI 上"
	}
	if blocking > 0 {
		return false, fmt.Sprintf("旧前缀内仍有 %d 个 OCI IPv6 对象，已保留旧前缀", blocking)
	}
	return true, ""
}

// WaitForPrefixAvailable polls until an OCI IPv6 prefix object is AVAILABLE.
// It is used after creating a prefix so the pool is not switched to a segment
// that OCI has not finished provisioning yet.
func (c *OciClient) WaitForPrefixAvailable(compartmentID, vnicID, id string, timeout time.Duration) (*OciIpv6, error) {
	deadline := time.Now().Add(timeout)
	for {
		list, err := c.ListIpv6s(compartmentID, vnicID)
		if err == nil {
			for i := range list {
				if list[i].ID != id {
					continue
				}
				switch list[i].LifecycleState {
				case "", "AVAILABLE":
					return &list[i], nil
				case "TERMINATING", "TERMINATED", "FAILED":
					return nil, fmt.Errorf("OCI IPv6 %s state %s", id, list[i].LifecycleState)
				}
				break
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				return nil, fmt.Errorf("timeout waiting for OCI IPv6 %s: %w", id, err)
			}
			return nil, fmt.Errorf("timeout waiting for OCI IPv6 %s to become AVAILABLE", id)
		}
		time.Sleep(2 * time.Second)
	}
}

// EnsurePrefix ensures a CIDR prefix is assigned to the VNIC for self-allocation.
// If a matching cidrPrefixLength already exists, reuse it. Otherwise create one.
// Returns the assigned Ipv6 object.
func (c *OciClient) EnsurePrefix(compartmentID, vnicID string, cidrPrefixLength int) (*OciIpv6, error) {
	list, err := c.ListIpv6s(compartmentID, vnicID)
	if err != nil {
		return nil, err
	}
	for _, o := range list {
		if o.CidrPrefixLength != nil && *o.CidrPrefixLength == cidrPrefixLength {
			log.Printf("[OCI] reuse existing /%d %s (%s)", cidrPrefixLength, o.IPAddress, o.ID)
			return &o, nil
		}
	}
	log.Printf("[OCI] creating /%d prefix on %s", cidrPrefixLength, vnicID)
	return c.CreateIpv6Cidr(vnicID, "", cidrPrefixLength)
}

// GetCompartmentID derives compartment from VNIC metadata or fallback to tenancy.
func (c *OciClient) GetCompartmentID() string {
	return c.Tenancy
}

// ==================== Pool integration ====================

// VnicMetadata is the subset of /opc/v2/vnics/ needed to bind a pool to a
// specific VNIC. The metadata service reports every attached VNIC, including
// secondary VNICs, together with the subnet prefix and virtual router address.
type VnicMetadata struct {
	VnicID              string   `json:"vnicId"`
	MacAddr             string   `json:"macAddr"`
	PrivateIP           string   `json:"privateIp"`
	SubnetCIDR          string   `json:"subnetCidrBlock"`
	IPv6SubnetCIDR      string   `json:"ipv6SubnetCidrBlock"`
	IPv6SubnetCIDRs     []string `json:"ipv6SubnetCidrBlocks"`
	IPv6VirtualRouterIP string   `json:"ipv6VirtualRouterIp"`
}

func imdsGet(path string) ([]byte, error) {
	req, err := http.NewRequest("GET", "http://169.254.169.254"+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer Oracle")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("metadata %s: HTTP %d", path, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func listVnicMetadata() ([]VnicMetadata, error) {
	b, err := imdsGet("/opc/v2/vnics/")
	if err != nil {
		return nil, err
	}
	var vnics []VnicMetadata
	if err := json.Unmarshal(b, &vnics); err != nil {
		return nil, err
	}
	return vnics, nil
}

// DetectVnicMetadata finds the metadata entry for vnicID. An empty vnicID
// selects the first VNIC, preserving the original auto-detect behaviour.
func DetectVnicMetadata(vnicID string) (*VnicMetadata, error) {
	vnics, err := listVnicMetadata()
	if err != nil {
		return nil, err
	}
	if len(vnics) == 0 {
		return nil, fmt.Errorf("no vnics in metadata")
	}
	if vnicID == "" {
		return &vnics[0], nil
	}
	for i := range vnics {
		if vnics[i].VnicID == vnicID {
			return &vnics[i], nil
		}
	}
	return nil, fmt.Errorf("VNIC %s is not attached to this instance", vnicID)
}

// resolvedVnicMetadata drops metadata entries whose MAC no longer has a Linux
// interface. After detaching a secondary VNIC, OCI metadata can keep reporting
// the deleted VNIC for a while even though the guest interface is gone.
func resolvedVnicMetadata() ([]VnicMetadata, error) {
	metas, err := listVnicMetadata()
	if err != nil {
		return nil, err
	}
	out := make([]VnicMetadata, 0, len(metas))
	for _, meta := range metas {
		if _, ierr := interfaceForMAC(meta.MacAddr); ierr == nil {
			out = append(out, meta)
		}
	}
	return out, nil
}

func detectVnicID() (string, error) {
	meta, err := DetectVnicMetadata("")
	if err != nil {
		return "", err
	}
	return meta.VnicID, nil
}

func DetectInstanceID() (string, error) {
	b, err := imdsGet("/opc/v2/instance/id")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", fmt.Errorf("empty instance id in metadata")
	}
	return id, nil
}

// interfaceForMAC maps an OCI VNIC MAC address to the Linux interface name.
// Secondary VNICs can be named enp1s0 rather than enp0s7, so name-based
// heuristics are not reliable.
func interfaceForMAC(mac string) (string, error) {
	want := strings.ToLower(strings.TrimSpace(mac))
	if want == "" {
		return "", fmt.Errorf("empty MAC address")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if strings.ToLower(ifc.HardwareAddr.String()) == want {
			return ifc.Name, nil
		}
	}
	return "", fmt.Errorf("no Linux interface with MAC %s", mac)
}

// ResolveOCIVnicNetwork returns the host interface and IPv6 virtual router for
// a VNIC. The router address comes from instance metadata, so it works even
// before Router Advertisement has installed a default route on the interface.
func ResolveOCIVnicNetwork(vnicID string) (iface, gateway string, meta *VnicMetadata, err error) {
	meta, err = DetectVnicMetadata(vnicID)
	if err != nil {
		return "", "", nil, err
	}
	iface, err = interfaceForMAC(meta.MacAddr)
	if err != nil {
		return "", "", nil, err
	}
	// A freshly attached secondary VNIC is initially DOWN. Bringing it up is
	// harmless for an already-configured interface and lets the kernel accept
	// the source addresses we are about to add.
	_ = exec.Command("ip", "link", "set", "dev", iface, "up").Run()
	gateway = strings.TrimSpace(meta.IPv6VirtualRouterIP)
	if gateway == "" {
		gateway = detectGateway(iface)
	}
	return iface, gateway, meta, nil
}

// InitOciPool populates the pool from OCI. If OciPrefixLength !=0 it ensures a
// CIDR prefix (e.g. /80, /112) and generates pool IPs locally within that CIDR
// without per-IP API calls (prefix self-allocation). Otherwise it uses per-IP
// /128 objects from ListIpv6s. Up to 32 objects per VNIC (each CIDR can hold 2^(128-prefix) IPs).
func (p *IPv6Pool) InitOciPool(cfg *Config) error {
	client, err := LoadOciClientFromConfig(cfg.OciConfigPath)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.ociClient = client
	p.mu.Unlock()
	compartment := cfg.OciCompartment
	if compartment == "" {
		compartment = client.Tenancy
	}
	vnicID := cfg.OciVnicID
	if vnicID == "" {
		if v, err := detectVnicID(); err == nil {
			vnicID = v
			log.Printf("[OCI] auto-detected vnic %s", vnicID)
		} else {
			return fmt.Errorf("oci_vnic_id required (auto-detect failed: %v)", err)
		}
	}
	p.mu.Lock()
	p.ociCompartment = compartment
	p.ociVnicID = vnicID
	p.ociPrefixLength = cfg.OciPrefixLength
	p.mu.Unlock()
	threshold := cfg.FailureThreshold
	if threshold == 0 {
		threshold = 3
	}
	p.SetFailureThreshold(threshold)

	// Prefix mode: allocate one CIDR and generate local pool inside it.
	// An explicit oci_prefix_id wins over prefix length / oci_no_create so a
	// prefix selected in the console is stable across restarts even when the
	// VNIC has several prefixes of the same length.
	prefixLen := cfg.OciPrefixLength
	if cfg.OciPrefixID != "" || prefixLen != 0 {
		if prefixLen != 0 && (prefixLen < 80 || prefixLen > 128 || prefixLen%4 != 0) {
			return fmt.Errorf("oci_prefix_length must be 80-128 divisible by 4")
		}
		var obj *OciIpv6
		if cfg.OciPrefixID != "" {
			list, err := client.ListIpv6s(compartment, vnicID)
			if err != nil {
				return err
			}
			for i := range list {
				if list[i].ID == cfg.OciPrefixID {
					obj = &list[i]
					break
				}
			}
			if obj == nil {
				return fmt.Errorf("oci_prefix_id %s not found on vnic %s", cfg.OciPrefixID, vnicID)
			}
			if obj.CidrPrefixLength == nil {
				return fmt.Errorf("OCI object %s is not a prefix", cfg.OciPrefixID)
			}
			prefixLen = *obj.CidrPrefixLength
			if prefixLen < 80 || prefixLen > 128 || prefixLen%4 != 0 {
				return fmt.Errorf("OCI prefix %s has unsupported length /%d", obj.IPAddress, prefixLen)
			}
			log.Printf("[OCI] using selected /%d prefix %s (%s)", prefixLen, obj.IPAddress, obj.ID)
		}

		// Without an explicit OCI object ID, honour an explicitly configured
		// prefix base when it exactly matches an existing prefix object. This
		// keeps the saved operator choice stable when several prefixes of the
		// same length exist.
		if obj == nil && cfg.Prefix != "" {
			if _, n, perr := net.ParseCIDR(cfg.Prefix); perr == nil {
				plen, _ := n.Mask.Size()
				if plen == prefixLen && plen >= 80 && plen <= 128 && plen%4 == 0 {
					if list, err := client.ListIpv6s(compartment, vnicID); err == nil {
						base := n.IP.String()
						for i := range list {
							if list[i].CidrPrefixLength == nil || *list[i].CidrPrefixLength != plen {
								continue
							}
							if ip := net.ParseIP(list[i].IPAddress); ip != nil && ip.String() == base {
								obj = &list[i]
								break
							}
						}
					}
				}
			}
		}

		if obj == nil {
			if cfg.OciNoCreate {
				// 只切换IP：复用已存在同长度 CIDR，不 Create 新段
				list, err := client.ListIpv6s(compartment, vnicID)
				if err != nil {
					return err
				}
				for i := range list {
					if list[i].CidrPrefixLength != nil && *list[i].CidrPrefixLength == prefixLen {
						obj = &list[i]
						break
					}
				}
				if obj == nil {
					return fmt.Errorf("oci_no_create=true but no existing /%d found; set false or create via python manager", prefixLen)
				}
				log.Printf("[OCI] no_create reuse /%d %s", prefixLen, obj.IPAddress)
			} else {
				o, err := client.EnsurePrefix(compartment, vnicID, prefixLen)
				if err != nil {
					return err
				}
				obj = o
				if obj.CidrPrefixLength != nil {
					prefixLen = *obj.CidrPrefixLength
				}
			}
		}
		// Parse the CIDR base
		ip := net.ParseIP(obj.IPAddress)
		if ip == nil {
			return fmt.Errorf("invalid CIDR IP %s", obj.IPAddress)
		}
		// Build CIDR for generation
		_, cidr, err := net.ParseCIDR(fmt.Sprintf("%s/%d", obj.IPAddress, prefixLen))
		if err != nil {
			return err
		}
		n := cfg.SLAACPoolSize
		if n < 1 {
			n = 4
		}
		if n > 32 {
			n = 32
		}
		log.Printf("[OCI] prefix %s/%d -> generating %d local IPs (no per-IP API)", obj.IPAddress, prefixLen, n)
		// Ensure the CIDR base itself is present on interface (kernel needs it)
		p.mu.Lock()
		p.prefix = cidr
		p.ociPrefixID = obj.ID
		p.ociPrefixLength = prefixLen
		p.mu.Unlock()
		// Generate random IPs within CIDR
		if prefixLen == 128 {
			// A /128 prefix object holds exactly one address; avoid the
			// randomIPInPrefix loop, which would never leave the base.
			if err := p.AddAddress(ip, cidr.String()); err != nil {
				log.Printf("[OCI] Add %s: %v", ip, err)
			}
			return nil
		}
		for i := 0; i < n; i++ {
			rip := randomIPInPrefix(cidr)
			// Avoid network address itself
			if rip.Equal(cidr.IP) {
				i--
				continue
			}
			if err := p.AddAddress(rip, cidr.String()); err != nil {
				log.Printf("[OCI] Add %s: %v", rip, err)
			}
		}
		return nil
	}

	// Per-IP mode: list existing /128 objects
	list, err := client.ListIpv6s(compartment, vnicID)
	if err != nil {
		return err
	}
	if len(list) == 0 && !cfg.OciNoCreate {
		log.Printf("[OCI] no IPv6 assigned, creating %d", cfg.SLAACPoolSize)
		n := cfg.SLAACPoolSize
		if n < 1 {
			n = 4
		}
		for i := 0; i < n; i++ {
			obj, err := client.CreateIpv6(vnicID)
			if err != nil {
				log.Printf("[OCI] CreateIpv6: %v", err)
				continue
			}
			list = append(list, *obj)
		}
	}
	log.Printf("[OCI] %d IPv6 objects on %s", len(list), vnicID)
	for _, o := range list {
		ip := net.ParseIP(o.IPAddress)
		if ip == nil {
			continue
		}
		if err := p.AddAddress(ip, subnetOf(ip)); err != nil {
			// Already exists on interface after prior run, still count
			log.Printf("[OCI] Add %s: %v", o.IPAddress, err)
		}
	}
	return nil
}

// ReconcileOci re-syncs with OCI control plane: adds any new assigned IPs that
// appeared (e.g. via console), re-adds missing local Addresses.
func (p *IPv6Pool) ReconcileOci() {
	p.mu.RLock()
	client := p.ociClient
	vnicID := p.ociVnicID
	compartment := p.ociCompartment
	prefixLength := p.ociPrefixLength
	iface := p.sourceIface
	p.mu.RUnlock()
	if client == nil || vnicID == "" {
		return
	}
	list, err := client.ListIpv6s(compartment, vnicID)
	if err != nil {
		log.Printf("[OCI] reconcile list failed: %v", err)
		return
	}
	// In prefix mode, nothing to reconcile per-IP (local pool is within CIDR)
	if prefixLength != 0 {
		return
	}
	for _, o := range list {
		p.mu.RLock()
		_, exists := p.addrs[o.IPAddress]
		p.mu.RUnlock()
		if !exists {
			log.Printf("[OCI] discovered new %s, adding locally", o.IPAddress)
			ip := net.ParseIP(o.IPAddress)
			if ip != nil {
				p.AddAddress(ip, subnetOf(ip))
			}
		}
	}
	type missingAddr struct {
		ip     string
		subnet string
	}
	p.mu.RLock()
	var missing []missingAddr
	for ipStr, a := range p.addrs {
		if !a.Configured {
			continue
		}
		if !addressExistsOnIface(iface, ipStr) {
			missing = append(missing, missingAddr{ip: ipStr, subnet: a.Subnet})
		}
	}
	p.mu.RUnlock()
	for _, m := range missing {
		log.Printf("[OCI] %s missing from %s, re-adding", m.ip, iface)
		p.AddAddress(net.ParseIP(m.ip), m.subnet)
	}
}
