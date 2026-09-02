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

func (c *OciClient) CreateIpv6(vnicID string) (*OciIpv6, error) {
	return c.CreateIpv6Cidr(vnicID, "", 0)
}

// CreateIpv6Cidr creates an IPv6 on vnic. If ipv6Ip=="" let Oracle pick.
// cidrPrefixLength 0 means single /128, otherwise 80-128 divisible by 4 (e.g. 112,80)
func (c *OciClient) CreateIpv6Cidr(vnicID, ipv6Ip string, cidrPrefixLength int) (*OciIpv6, error) {
	body := map[string]interface{}{"vnicId": vnicID}
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

func detectVnicID() (string, error) {
	req, err := http.NewRequest("GET", "http://169.254.169.254/opc/v2/vnics/", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer Oracle")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var vnics []struct {
		VnicID string `json:"vnicId"`
	}
	if err := json.Unmarshal(b, &vnics); err != nil {
		return "", err
	}
	if len(vnics) == 0 {
		return "", fmt.Errorf("no vnics in metadata")
	}
	return vnics[0].VnicID, nil
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
	p.ociClient = client
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
	p.ociCompartment = compartment
	p.ociVnicID = vnicID
	p.ociPrefixLength = cfg.OciPrefixLength
	p.failureThreshold = cfg.FailureThreshold
	if p.failureThreshold == 0 {
		p.failureThreshold = 3
	}

	// Prefix mode: allocate one CIDR and generate local pool inside it
	if cfg.OciPrefixLength != 0 {
		if cfg.OciPrefixLength < 80 || cfg.OciPrefixLength > 128 || cfg.OciPrefixLength%4 != 0 {
			return fmt.Errorf("oci_prefix_length must be 80-128 divisible by 4")
		}
		var obj *OciIpv6
		if cfg.OciNoCreate {
			// 只切换IP：复用已存在同长度 CIDR，不 Create 新段
			list, err := client.ListIpv6s(compartment, vnicID)
			if err != nil {
				return err
			}
			for _, o := range list {
				if o.CidrPrefixLength != nil && *o.CidrPrefixLength == cfg.OciPrefixLength {
					tmp := o
					obj = &tmp
					break
				}
			}
			if obj == nil {
				return fmt.Errorf("oci_no_create=true but no existing /%d found; set false or create via python manager", cfg.OciPrefixLength)
			}
			log.Printf("[OCI] no_create reuse /%d %s", cfg.OciPrefixLength, obj.IPAddress)
		} else {
			o, err := client.EnsurePrefix(compartment, vnicID, cfg.OciPrefixLength)
			if err != nil {
				return err
			}
			obj = o
		}
		// Parse the CIDR base
		ip := net.ParseIP(obj.IPAddress)
		if ip == nil {
			return fmt.Errorf("invalid CIDR IP %s", obj.IPAddress)
		}
		// Build CIDR for generation
		_, cidr, err := net.ParseCIDR(fmt.Sprintf("%s/%d", obj.IPAddress, cfg.OciPrefixLength))
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
		log.Printf("[OCI] prefix %s/%d -> generating %d local IPs (no per-IP API)", obj.IPAddress, cfg.OciPrefixLength, n)
		// Ensure the CIDR base itself is present on interface (kernel needs it)
		p.prefix = cidr
		// Generate random IPs within CIDR
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
	if p.ociClient == nil || p.ociVnicID == "" {
		return
	}
	list, err := p.ociClient.ListIpv6s(p.ociCompartment, p.ociVnicID)
	if err != nil {
		log.Printf("[OCI] reconcile list failed: %v", err)
		return
	}
	// In prefix mode, nothing to reconcile per-IP (local pool is within CIDR)
	if p.ociPrefixLength != 0 {
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
	for ipStr, a := range p.addrs {
		if !a.Configured {
			continue
		}
		if !addressExistsOnIface(p.sourceIface, ipStr) {
			log.Printf("[OCI] %s missing from %s, re-adding", ipStr, p.sourceIface)
			p.AddAddress(net.ParseIP(ipStr), a.Subnet)
		}
	}
}
