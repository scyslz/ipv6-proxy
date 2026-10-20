package main

import (
	"context"
	"io"
	"log"
	"os"
	"os/signal"
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

	pool, err := internal.BuildPoolFromConfig(cfg, wanIface)
	if err != nil {
		log.Fatalf("Init pool: %v", err)
	}
	log.Printf("Source mode: %s, prefix: %s", cfg.SourceMode, func() string {
		if p := pool.Prefix(); p != "" {
			return p
		}
		return "(none)"
	}())

	rt := internal.NewRuntime(pool, cfg)
	if err := internal.ApplyHostEgress(cfg, pool); err != nil {
		log.Printf("[HOST] apply host egress on startup: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received %s, shutting down...", sig)
		cancel()
	}()

	proxySrv := internal.NewProxyServerWithRuntime(cfg.ProxyAddr, rt)
	apiSrv := internal.NewAPIServerWithRuntime(cfg.APIAddr, rt)
	apiSrv.SetProxyServer(proxySrv)

	go func() {
		if err := proxySrv.ListenAndServe(ctx); err != nil {
			log.Printf("Proxy error: %v", err)
		}
	}()
	go func() {
		if err := apiSrv.ListenAndServe(ctx); err != nil {
			log.Printf("API error: %v", err)
		}
	}()

	// Let the kernel finish duplicate address detection (DAD) on the initial
	// /128s before the first probe, otherwise they can look bind_failed even
	// though they become usable a second later.
	time.Sleep(3 * time.Second)
	go runHealthLoop(ctx, rt)

	<-ctx.Done()
	log.Printf("Cleaning up IPv6 addresses...")
	internal.ClearHostEgress()
	rt.Pool().CleanupAddedAddresses()
	log.Printf("Shutdown complete")
}

// runHealthLoop performs the initial check and then re-reads the live config
// every iteration. A hot reload wakes it immediately so interval changes take
// effect without waiting for the previous (possibly much longer) interval.
func runHealthLoop(ctx context.Context, rt *internal.Runtime) {
	doCheck(rt)

	for {
		cfg := rt.Config()
		interval := time.Duration(cfg.HealthInterval) * time.Second
		if interval < 5*time.Second {
			interval = 5 * time.Second
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-rt.Changes():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			// New pools already kick their own async health check when they
			// are published; just recompute the next interval.
			continue
		case <-timer.C:
			doCheck(rt)
		}
	}
}

func doCheck(rt *internal.Runtime) {
	cfg := rt.Config()
	pool := rt.Pool()
	pool.RefreshInfraDNS()
	mode := pool.GetSourceMode()
	if mode == "ephemeral" {
		return
	}
	timeout := time.Duration(cfg.ConnectTimeout) * time.Second
	switch mode {
	case "slaac":
		pool.ReconcileSLAAC()
		pool.HealthCheckSLAAC(timeout)
	case "oci":
		pool.ReconcileOci()
		pool.HealthCheck(timeout)
	default:
		pool.HealthCheck(timeout)
	}
}
