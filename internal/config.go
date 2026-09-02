package internal

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// ==================== Configuration ====================

type Config struct {
	ProxyAddr      string `json:"proxy_addr"`
	APIAddr        string `json:"api_addr"`
	// Prefix is the IPv6 prefix (PD or WAN /64) used to generate source
	// addresses. Empty => auto-detect (PD first, then WAN prefix).
	Prefix         string `json:"prefix"`
	SubnetCount    int    `json:"subnet_count"`
	SLAACPoolSize  int    `json:"slaac_pool_size"`
	FailureThreshold int  `json:"failure_threshold"`
	HealthInterval int    `json:"health_interval_sec"`
	ConnectTimeout int    `json:"connect_timeout_sec"`
	// MaxRetries only takes effect in source_mode "ephemeral" (each retry mints
	// a fresh source IP). In other modes a single attempt is made per request.
	MaxRetries     int    `json:"max_retries"`
	SelectionMode  string `json:"selection_mode"`
	SourceMode     string `json:"source_mode"`
	DummyIface     string `json:"dummy_iface"`
	DNSServer      string `json:"dns_server"`
	TestTarget     string `json:"test_target"`
	// Hosts maps a hostname to a fixed IPv6 address, bypassing DNS. Keys are
	// matched case-insensitively after stripping any :port. Values must be
	// valid IPv6; an IPv4 value is rejected at load time.
	Hosts map[string]string `json:"hosts"`
	// OCI integration (source_mode=oci)
	OciCompartment   string `json:"oci_compartment"`
	OciVnicID        string `json:"oci_vnic_id"`
	OciPrefixLength  int    `json:"oci_prefix_length"` // 0=per-IP /128 pool, 80/112/120 etc = CIDR prefix for self-allocation
	OciConfigPath    string `json:"oci_config_path"`
	OciNoCreate      bool   `json:"oci_no_create"` // true=只切换IP不操作网卡段（不 EnsurePrefix/不 Create）
}

func DefaultConfig() *Config {
	return &Config{
		ProxyAddr:      "0.0.0.0:8080",
		APIAddr:        "[::]:9191",
		Prefix:         "",
		SubnetCount:    4,
		SLAACPoolSize:  4,
		FailureThreshold: 3,
		HealthInterval: 60,
		ConnectTimeout: 5,
		MaxRetries:     5,
		SelectionMode:  "manual",
		SourceMode:     "pool",
		DummyIface:     "v6test0",
		DNSServer:      "2606:4700:4700::1111",
		TestTarget:     "2606:4700:4700::1111",
	}
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[CONFIG] No config at %s, using defaults", path)
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}
