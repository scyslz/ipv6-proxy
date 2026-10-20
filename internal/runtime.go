package internal

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// Runtime holds the live configuration and address pool. Both are replaced
// atomically on a hot reload, so the proxy and API always see a consistent
// snapshot without holding a lock for the lifetime of a request.
type Runtime struct {
	pool    atomic.Pointer[IPv6Pool]
	cfg     atomic.Pointer[Config]
	changed chan struct{}
}

func NewRuntime(pool *IPv6Pool, cfg *Config) *Runtime {
	r := &Runtime{changed: make(chan struct{}, 1)}
	r.pool.Store(pool)
	r.cfg.Store(cfg)
	return r
}

func (r *Runtime) Pool() *IPv6Pool { return r.pool.Load() }
func (r *Runtime) Config() *Config { return r.cfg.Load() }

// Changes is signalled (coalesced) whenever the pool or config is replaced.
// The health loop uses it to recompute its interval immediately.
func (r *Runtime) Changes() <-chan struct{} { return r.changed }

// Set swaps in a fully-built pool and config. The caller owns tearing down the
// previous pool after the swap.
func (r *Runtime) Set(pool *IPv6Pool, cfg *Config) {
	r.pool.Store(pool)
	r.SetConfig(cfg)
}

// SetConfig replaces only the live configuration (used when a setting is
// changed without rebuilding the pool, e.g. hosts or health interval).
func (r *Runtime) SetConfig(cfg *Config) {
	r.cfg.Store(cfg)
	select {
	case r.changed <- struct{}{}:
	default:
	}
}

// BuildPoolFromConfig creates and populates a pool for cfg. It is used both at
// startup and when the web console changes a pool-affecting setting. Errors are
// returned before the new pool is published, so the old runtime stays intact.
func BuildPoolFromConfig(cfg *Config, wanIface string) (*IPv6Pool, error) {
	ociGateway := ""
	if cfg.SourceMode == "oci" {
		// In OCI mode the source addresses must live on the interface that
		// belongs to the configured VNIC. The primary VNIC happens to match the
		// default-route interface, but a secondary VNIC (used to obtain a new
		// /64) can have a different name and a non-default route. Resolve it
		// from instance metadata instead of guessing from the default route.
		if cfg.OciVnicID != "" {
			// Re-resolve on every build. The interface name can change after a
			// reboot (for example enp1s0 -> enp2s0), so a stored name is only a
			// fallback, not the source of truth.
			if iface, gw, _, rerr := ResolveOCIVnicNetwork(cfg.OciVnicID); rerr == nil {
				wanIface = iface
				ociGateway = gw
				if cfg.OciSourceIface != "" && iface != cfg.OciSourceIface {
					log.Printf("[OCI] VNIC %s interface changed: %s -> %s", cfg.OciVnicID, cfg.OciSourceIface, iface)
				}
				log.Printf("[OCI] using interface %s (gateway %s)", iface, gw)
			} else if cfg.OciSourceIface != "" {
				if _, ierr := net.InterfaceByName(cfg.OciSourceIface); ierr != nil {
					return nil, fmt.Errorf("resolve OCI VNIC %s: %w", cfg.OciVnicID, rerr)
				}
				wanIface = cfg.OciSourceIface
				ociGateway = cfg.OciWanGateway
			} else {
				return nil, fmt.Errorf("resolve OCI VNIC %s: %w", cfg.OciVnicID, rerr)
			}
		} else if cfg.OciSourceIface != "" {
			wanIface = cfg.OciSourceIface
			ociGateway = cfg.OciWanGateway
		} else if iface, gw, _, rerr := ResolveOCIVnicNetwork(""); rerr == nil {
			wanIface = iface
			ociGateway = gw
			log.Printf("[OCI] using interface %s (gateway %s)", iface, gw)
		}
		// With an empty oci_vnic_id, metadata auto-detection can fail in
		// unit tests or when running outside OCI. Keep the caller-provided
		// WAN interface as the fallback, matching the old behaviour.
	}

	prefix, createDummy, err := prefixForConfig(cfg, wanIface)
	if err != nil {
		return nil, err
	}

	pool, err := NewIPv6Pool(prefix, wanIface, cfg.DummyIface, cfg.SelectionMode, cfg.DNSServer, cfg.TestTarget, createDummy)
	if err != nil {
		return nil, err
	}
	if cfg.SourceMode == "oci" {
		if ociGateway == "" {
			ociGateway = cfg.OciWanGateway
		}
		if ociGateway != "" {
			pool.SetWanGateway(ociGateway)
		}
	}
	pool.SetSourceMode(cfg.SourceMode)
	pool.SetFailureThreshold(cfg.FailureThreshold)
	pool.SetRecheckFailedInterval(5 * time.Minute)
	pool.SetSlaacPoolSize(cfg.SLAACPoolSize)

	fail := func(err error) (*IPv6Pool, error) {
		// Tear down only what this partially built pool created. Each pool owns
		// a unique policy table, so flushing it cannot affect the live pool.
		// dummyCreated is false when an existing dummy was reused, so
		// keepDummy=false only removes a dummy this build actually created.
		pool.TeardownExcept(nil, false)
		return nil, err
	}

	for k, v := range cfg.Hosts {
		val := strings.TrimSpace(v)
		key := NormalizeHost(k)
		if key == "" || val == "" {
			continue
		}
		if ip := net.ParseIP(val); ip != nil && ip.To4() != nil {
			log.Printf("[CONFIG] skipping invalid IPv6 host mapping %q -> %q (IPv4 not supported)", k, v)
			continue
		}
		pool.AddHost(key, val)
	}

	switch cfg.SourceMode {
	case "ephemeral":
		log.Printf("[CONFIG] ephemeral source mode: skipping static pool")
	case "slaac":
		wanIP, slaacPrefix, serr := DetectSLAAC(wanIface)
		if serr != nil {
			return fail(fmt.Errorf("detect SLAAC prefix: %w", serr))
		}
		pool.SetSlaacInfo(wanIP, slaacPrefix)
		ips := pool.GenerateSLAACAddresses(cfg.SLAACPoolSize, wanIP)
		log.Printf("[CONFIG] generated %d fixed SLAAC IPv6 from %s", len(ips), slaacPrefix.String())
		for _, ip := range ips {
			if aerr := pool.AddAddress(ip, subnetOf(ip)); aerr != nil {
				log.Printf("[CONFIG] add %s: %v", ip, aerr)
			}
		}
	case "oci":
		if err := pool.InitOciPool(cfg); err != nil {
			return fail(err)
		}
	default:
		ips := pool.GenerateAddresses(cfg.SubnetCount)
		log.Printf("[CONFIG] generated %d IPv6 addresses from PD subnets", len(ips))
		for _, ip := range ips {
			if aerr := pool.AddAddress(ip, subnetOf(ip)); aerr != nil {
				log.Printf("[CONFIG] add %s: %v", ip, aerr)
			}
		}
	}
	return pool, nil
}

// prefixForConfig mirrors the startup prefix detection rules.
func prefixForConfig(cfg *Config, wanIface string) (prefix string, createDummy bool, err error) {
	switch cfg.SourceMode {
	case "slaac":
		_, slaacPrefix, derr := DetectSLAAC(wanIface)
		if derr != nil {
			return "", false, fmt.Errorf("detect SLAAC prefix: %w", derr)
		}
		return slaacPrefix.String(), false, nil
	case "oci":
		if cfg.Prefix != "" {
			if _, _, perr := net.ParseCIDR(cfg.Prefix); perr != nil {
				return "", false, fmt.Errorf("parse prefix %s: %w", cfg.Prefix, perr)
			}
			return cfg.Prefix, false, nil
		}
		if _, p, derr := DetectSLAAC(wanIface); derr == nil {
			return p.String(), false, nil
		}
		if p, derr := DetectIPv6Prefix(wanIface); derr == nil {
			return p, false, nil
		}
		return "", false, fmt.Errorf("OCI mode needs prefix: auto-detect failed and prefix is empty")
	default:
		if cfg.Prefix != "" {
			if _, _, perr := net.ParseCIDR(cfg.Prefix); perr != nil {
				return "", false, fmt.Errorf("parse prefix %s: %w", cfg.Prefix, perr)
			}
			return cfg.Prefix, true, nil
		}
		if pd, perr := DetectPDPrefix(wanIface); perr == nil {
			return pd, true, nil
		}
		p, derr := DetectIPv6Prefix(wanIface)
		if derr != nil {
			return "", false, fmt.Errorf("detect prefix: %w", derr)
		}
		return p, true, nil
	}
}
