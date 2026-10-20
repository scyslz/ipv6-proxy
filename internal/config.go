package internal

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// ==================== Configuration ====================

type Config struct {
	ProxyAddr string `json:"proxy_addr"`
	APIAddr   string `json:"api_addr"`
	// Prefix is the IPv6 prefix (PD or WAN /64) used to generate source
	// addresses. Empty => auto-detect (PD first, then WAN prefix).
	Prefix           string `json:"prefix"`
	SubnetCount      int    `json:"subnet_count"`
	SLAACPoolSize    int    `json:"slaac_pool_size"`
	FailureThreshold int    `json:"failure_threshold"`
	HealthInterval   int    `json:"health_interval_sec"`
	ConnectTimeout   int    `json:"connect_timeout_sec"`
	// MaxRetries only takes effect in source_mode "ephemeral" (each retry mints
	// a fresh source IP). In other modes a single attempt is made per request.
	MaxRetries    int    `json:"max_retries"`
	SelectionMode string `json:"selection_mode"`
	SourceMode    string `json:"source_mode"`
	DummyIface    string `json:"dummy_iface"`
	DNSServer     string `json:"dns_server"`
	TestTarget    string `json:"test_target"`
	// Hosts maps a hostname to a fixed IPv6 address, bypassing DNS. Keys are
	// matched case-insensitively after stripping any :port. Values must be
	// valid IPv6; an IPv4 value is rejected at load time.
	Hosts map[string]string `json:"hosts"`
	// OCI integration (source_mode=oci)
	OciCompartment  string `json:"oci_compartment"`
	OciVnicID       string `json:"oci_vnic_id"`
	OciPrefixID     string `json:"oci_prefix_id,omitempty"` // preferred OCI IPv6 prefix object OCID
	OciPrefixLength int    `json:"oci_prefix_length"`       // 0=per-IP /128 pool, 80/112/120 etc = CIDR prefix for self-allocation
	OciConfigPath   string `json:"oci_config_path"`
	OciNoCreate     bool   `json:"oci_no_create"` // true=只切换IP不操作网卡段（不 EnsurePrefix/不 Create）
	// OciSourceIface / OciWanGateway pin the host interface and link-local
	// router for the selected VNIC. They are normally auto-detected from the
	// instance metadata service, but storing them makes a switch to a second
	// VNIC deterministic across restarts.
	OciSourceIface string `json:"oci_source_iface,omitempty"`
	OciWanGateway  string `json:"oci_wan_gateway,omitempty"`
	// HostEgressMode controls the host's own egress independently from the
	// proxy pool: "system" leaves routing untouched, "ipv4" prefers IPv4,
	// "ipv6" prefers IPv6 via HostEgressVnic, and "proxy" follows the VNIC of
	// the active proxy pool.
	HostEgressMode string `json:"host_egress_mode,omitempty"`
	HostEgressVnic string `json:"host_egress_vnic,omitempty"`
	// HostEgressIP optionally pins the exact IPv6 source address used for the
	// host's own egress (mode=ipv6). Empty means "auto": prefer the VNIC's
	// dynamic/SLAAC address, then any non-pool global /128 on the interface.
	HostEgressIP string `json:"host_egress_ip,omitempty"`
	// APIToken protects the /api/* endpoints (and therefore the web console's
	// write actions). Empty means the API is open — only do that on a trusted
	// network.
	APIToken string `json:"api_token,omitempty"`
	// Path is the file this config was loaded from (not serialized).
	Path string `json:"-"`
}

func DefaultConfig() *Config {
	return &Config{
		ProxyAddr:        "0.0.0.0:8080",
		APIAddr:          "[::]:9191",
		Prefix:           "",
		SubnetCount:      4,
		SLAACPoolSize:    4,
		FailureThreshold: 3,
		HealthInterval:   60,
		ConnectTimeout:   5,
		MaxRetries:       5,
		SelectionMode:    "manual",
		SourceMode:       "pool",
		DummyIface:       "v6test0",
		DNSServer:        "2606:4700:4700::1111",
		TestTarget:       "2606:4700:4700::1111",
	}
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[CONFIG] No config at %s, using defaults", path)
			cfg.Path = path
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if abs, aerr := filepath.Abs(path); aerr == nil {
		cfg.Path = abs
	} else {
		cfg.Path = path
	}
	return cfg, nil
}

// Save writes the config back to its original path as indented JSON. The
// temporary file + rename keeps a crash from leaving a half-written config,
// which would prevent the service from starting again.
func (c *Config) Save() error {
	if c.Path == "" {
		return fmt.Errorf("config path unknown")
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := c.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.Path)
}
