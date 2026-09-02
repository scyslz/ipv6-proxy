package internal

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// dnsCacheTTL bounds how long a successfully resolved AAAA record is reused
// before it is considered stale and re-resolved. A positive, non-trivial TTL
// keeps the per-request DNS lookups off the hot path while still recovering if
// a target's AAAA set changes.
const dnsCacheTTL = 5 * time.Minute

// dnsCache caches AAAA resolutions keyed by hostname so that repeated outbound
// requests to the same domain do not re-query the DNS server on every dial.
// Entries carry an expiry; lookups past expiry miss and trigger a re-resolve.
// A failed dial can invalidate an entry (see dialOut) so a dead AAAA is not
// reused for the remainder of its TTL window.
type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]dnsCacheEntry
}

type dnsCacheEntry struct {
	ip      net.IP
	expires time.Time
}

func newDNSCache() *dnsCache {
	return &dnsCache{entries: make(map[string]dnsCacheEntry)}
}

func (c *dnsCache) get(host string) (net.IP, bool) {
	c.mu.RLock()
	e, ok := c.entries[host]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e.ip, true
}

func (c *dnsCache) put(host string, ip net.IP) {
	c.mu.Lock()
	c.entries[host] = dnsCacheEntry{ip: ip, expires: time.Now().Add(dnsCacheTTL)}
	c.mu.Unlock()
}

func (c *dnsCache) invalidate(host string) {
	c.mu.Lock()
	delete(c.entries, host)
	c.mu.Unlock()
}

// isIPv6Literal reports whether s is a literal IPv6 address (not a hostname and
// not IPv4). Pure-IPv6 infra values must be IPv6.
func isIPv6Literal(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() == nil
}

// resolveAAAA resolves host to its first AAAA record, reusing lookupAAAA.
// Used for the infra config values (dns_server/test_target), which may be
// domains, so successful resolutions are not cached here (the caller owns the
// refresh logic). Pure-IPv6 infra values must be IPv6.
func resolveAAAA(ctx context.Context, host, dnsSrv string) (net.IP, error) {
	ips, err := lookupAAAA(ctx, host, dnsSrv)
	if err != nil {
		return nil, err
	}
	return ips[0], nil
}

// lookupDNS resolves host using srv. An empty srv uses the system resolver;
// lookupAAAA returns all AAAA records for host. An empty dnsSrv uses the system
// resolver; otherwise dnsSrv is dialed directly on :53. Only IPv6 results are
// returned — a host without AAAA cannot be reached by this pure-IPv6 proxy. The
// transport (UDP first, TCP on truncation) is left to Go so large/truncated
// AAAA responses are not silently dropped. Shared by both target-host
// resolution (resolveHost) and the infra config-domain resolution.
func lookupAAAA(ctx context.Context, host, dnsSrv string) ([]net.IP, error) {
	var resolver *net.Resolver
	if dnsSrv != "" {
		resolver = &net.Resolver{
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := &net.Dialer{Timeout: dnsDialTimeout}
				return d.DialContext(ctx, network, net.JoinHostPort(dnsSrv, "53"))
			},
		}
	} else {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var v6 []net.IP
	for _, a := range ips {
		if a.IP.To4() == nil {
			v6 = append(v6, a.IP)
		}
	}
	if len(v6) == 0 {
		return nil, fmt.Errorf("no AAAA records for %s", host)
	}
	return v6, nil
}
