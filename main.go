package main

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ipv6-proxy/internal"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.SetPrefix("[IPv6Proxy] ")
	log.SetOutput(io.MultiWriter(os.Stdout, internal.LogBuf))

	configPath := "/etc/ipv6-proxy/config.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := internal.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Load config: %v", err)
	}

	wanIface, err := internal.DetectWANInterface()
	if err != nil {
		log.Fatalf("Detect WAN: %v", err)
	}
	log.Printf("WAN interface: %s", wanIface)

	var prefix string
	createDummy := true
	if cfg.SourceMode == "slaac" {
		wanIP, slaacPrefix, serr := internal.DetectSLAAC(wanIface)
		if serr != nil {
			log.Fatalf("Detect SLAAC prefix: %v", serr)
		}
		prefix = slaacPrefix.String()
		createDummy = false
		log.Printf("SLAAC WAN IP: %s, prefix: %s", wanIP.String(), prefix)
	} else if cfg.SourceMode == "oci" {
		if cfg.Prefix != "" {
			prefix = cfg.Prefix
		} else if _, p, err := internal.DetectSLAAC(wanIface); err == nil {
			prefix = p.String()
		} else {
			prefix = "2603:c024:4517:a81e::/64"
		}
		createDummy = false
		log.Printf("OCI mode: prefix=%s vnic=%s", prefix, cfg.OciVnicID)
	} else if cfg.Prefix != "" {
		prefix = cfg.Prefix
	} else {
		pd, perr := internal.DetectPDPrefix(wanIface)
		if perr == nil {
			prefix = pd
			log.Printf("Auto-detected PD prefix: %s", prefix)
		} else {
			prefix, err = internal.DetectIPv6Prefix(wanIface)
			if err != nil {
				log.Fatalf("Detect prefix: %v", err)
			}
			log.Printf("Auto-detected WAN prefix: %s", prefix)
		}
	}
	log.Printf("IPv6 prefix: %s", prefix)

	pool, err := internal.NewIPv6Pool(prefix, wanIface, cfg.DummyIface, cfg.SelectionMode, cfg.DNSServer, cfg.TestTarget, createDummy)
	if err != nil {
		log.Fatalf("Init pool: %v", err)
	}
	pool.SetSourceMode(cfg.SourceMode)
	log.Printf("Source mode: %s", cfg.SourceMode)

	for k, v := range cfg.Hosts {
		val := strings.TrimSpace(v)
		lower := strings.ToLower(k)
		key := internal.NormalizeHost(lower)
		if ip := net.ParseIP(val); ip != nil && ip.To4() != nil {
			log.Printf("skipping invalid IPv6 host mapping %q -> %q (IPv4 not supported)", k, v)
			continue
		}
		pool.AddHost(key, val)
	}
	if pool.HostCount() > 0 {
		log.Printf("loaded %d static host mapping(s)", pool.HostCount())
	}

	switch cfg.SourceMode {
	case "ephemeral":
		log.Printf("Ephemeral source mode: skipping static pool and health check")
	case "slaac":
		wanIP, slaacPrefix, _ := internal.DetectSLAAC(wanIface)
		pool.SetSlaacInfo(wanIP, slaacPrefix)
		pool.SetFailureThreshold(cfg.FailureThreshold)
		pool.SetRecheckFailedInterval(5 * time.Minute)
		pool.SetSlaacPoolSize(cfg.SLAACPoolSize)
		ips := pool.GenerateSLAACAddresses(cfg.SLAACPoolSize, wanIP)
		log.Printf("Generated %d fixed SLAAC IPv6 from %s", len(ips), slaacPrefix.String())
		for _, ip := range ips {
			if aerr := pool.AddAddress(ip, internal.SubnetOf(ip)); aerr != nil {
				log.Printf("Add %s: %v", ip, aerr)
			}
		}
	case "oci":
		if err := pool.InitOciPool(cfg); err != nil {
			log.Fatalf("OCI init: %v", err)
		}
	default:
		ips := pool.GenerateAddresses(cfg.SubnetCount)
		log.Printf("Generated %d IPv6 addresses from PD subnets", len(ips))
		for _, ip := range ips {
			if aerr := pool.AddAddress(ip, internal.SubnetOf(ip)); aerr != nil {
				log.Printf("Add %s: %v", ip, aerr)
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.StartInfraDNSRefresh(ctx, time.Duration(cfg.HealthInterval)*time.Second)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received %s, shutting down...", sig)
		cancel()
	}()

	time.Sleep(2 * time.Second)

	go func() {
		srv := internal.NewProxyServer(cfg.ProxyAddr, pool, cfg)
		if err := srv.ListenAndServe(ctx); err != nil {
			log.Printf("Proxy error: %v", err)
		}
	}()

	go func() {
		srv := internal.NewAPIServer(cfg.APIAddr, pool, cfg)
		if err := srv.ListenAndServe(ctx); err != nil {
			log.Printf("API error: %v", err)
		}
	}()

	if cfg.SourceMode == "ephemeral" {
		log.Printf("Ephemeral source mode: skipping static pool and health check")
	} else {
		time.Sleep(1 * time.Second)
		log.Printf("Running initial health check...")
		if cfg.SourceMode == "slaac" {
			pool.HealthCheckSLAAC(time.Duration(cfg.ConnectTimeout) * time.Second)
		} else if cfg.SourceMode == "oci" {
			pool.HealthCheck(time.Duration(cfg.ConnectTimeout) * time.Second)
		} else {
			pool.HealthCheck(time.Duration(cfg.ConnectTimeout) * time.Second)
		}

		go func() {
			ticker := time.NewTicker(time.Duration(cfg.HealthInterval) * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if cfg.SourceMode == "slaac" {
						pool.ReconcileSLAAC()
						pool.HealthCheckSLAAC(time.Duration(cfg.ConnectTimeout) * time.Second)
					} else if cfg.SourceMode == "oci" {
						pool.ReconcileOci()
						pool.HealthCheck(time.Duration(cfg.ConnectTimeout) * time.Second)
					} else {
						pool.HealthCheck(time.Duration(cfg.ConnectTimeout) * time.Second)
					}
				}
			}
		}()
	}

	<-ctx.Done()
	log.Printf("Cleaning up IPv6 addresses...")
	pool.CleanupAddedAddresses()
	log.Printf("Shutdown complete")
}
