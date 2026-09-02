package internal

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ==================== Proxy Server ====================

type ProxyServer struct {
	addr string
	pool *IPv6Pool
	cfg  *Config
}

func NewProxyServer(addr string, pool *IPv6Pool, cfg *Config) *ProxyServer {
	return &ProxyServer{addr: addr, pool: pool, cfg: cfg}
}

func (s *ProxyServer) ListenAndServe(ctx context.Context) error {
	host, port, err := net.SplitHostPort(s.addr)
	if err != nil {
		host, port = "0.0.0.0", "8080"
	}

	// Open separate IPv4 (0.0.0.0) and IPv6 (::) sockets so the proxy is
	// reachable on every interface. Using tcp4/tcp6 networks keeps each
	// socket address-family-specific (no v6only clash), which guarantees a
	// visible 0.0.0.0:<port> listener.
	listens := map[string]string{}
	if host == "" || host == "0.0.0.0" || host == "::" {
		listens["tcp4"] = "0.0.0.0:" + port
		listens["tcp6"] = "[::]:" + port
	} else if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		listens["tcp4"] = s.addr
	} else {
		listens["tcp6"] = s.addr
	}

	var listeners []net.Listener
	var addrs []string
	for network, a := range listens {
		ln, e := net.Listen(network, a)
		if e != nil {
			log.Printf("[PROXY] listen %s %s: %v", network, a, e)
			continue
		}
		listeners = append(listeners, ln)
		addrs = append(addrs, a)
	}
	if len(listeners) == 0 {
		return fmt.Errorf("no listener established for %s", s.addr)
	}
	for _, ln := range listeners {
		defer ln.Close()
	}

	log.Printf("[PROXY] Listening on %s", strings.Join(addrs, ", "))

	stop := make(chan struct{})
	go func() {
		<-ctx.Done()
		for _, ln := range listeners {
			ln.Close()
		}
		close(stop)
	}()

	var wg sync.WaitGroup
	for _, ln := range listeners {
		wg.Add(1)
		go func(ln net.Listener) {
			defer wg.Done()
			for {
				conn, e := ln.Accept()
				if e != nil {
					select {
					case <-stop:
						return
					default:
						log.Printf("[PROXY] Accept: %v", e)
						continue
					}
				}
				go s.handleConn(conn)
			}
		}(ln)
	}
	wg.Wait()
	return nil
}

func (s *ProxyServer) handleConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	peek, err := br.Peek(1)
	if err != nil {
		return
	}
	if peek[0] == 0x05 {
		s.handleSOCKS5(conn, br)
	} else {
		s.handleHTTP(conn, br)
	}
}

// ==================== HTTP Proxy ====================

// selectSource picks the source IPv6 for an outbound connection. In
// "ephemeral" source mode it always mints a fresh address (so the ISP's
// first-connection-only allowance applies to the real traffic).
func (s *ProxyServer) selectSource(clientHint string) (ip string, err error) {
	if s.pool.sourceMode == "ephemeral" {
		return s.pool.acquireEphemeral()
	}
	return s.pool.SelectIPv6(clientHint)
}

// dialOut opens an outbound connection bound to a source IPv6 from the pool (or
// a fresh ephemeral address) and retries on failure. In ephemeral source mode
// each retry mints a brand-new source IP, because this ISP only allows some
// fraction of first connections — so repeated fresh attempts raise the odds of
// hitting an allowed one. Failed attempts are released immediately; the single
// successful source IP is returned to the caller, who must release it once the
// connection is closed.
// dnsDialTimeout bounds how long we wait for the configured DNS server before
// giving up and falling back to the system resolver.
const dnsDialTimeout = 5 * time.Second

// defaultDNSServer is used when the configuration does not specify dns_server.
const defaultDNSServer = "2606:4700:4700::1111"

// resolveHost resolves host to an IPv6 (AAAA) address. Resolution order:
//   1. the configured dns_server (or the code default if unset),
//   2. the system resolver (last resort).
// There is no secondary DNS fallback list. Only AAAA records are considered —
// a host with no IPv6 address cannot be reached by this pure-IPv6 proxy, so
// any IPv4 results are discarded rather than dialed.
//
// The query is sent from the default (WAN SLAAC) source — NOT the
// per-connection ephemeral source — so DNS resolution does not burn that
// source's single allowed outbound connection. The transport (UDP first, TCP
// on truncation) is left to Go so large/truncated AAAA responses are not
// silently dropped.
func (s *ProxyServer) resolveHost(ctx context.Context, host, network string) (net.IP, error) {
	return s.resolveHostImpl(ctx, host, network, 0)
}

// resolveHostImpl resolves host to an IPv6 (AAAA) address. A host with a static
// mapping in pool.hosts takes highest priority: a literal IPv6 is returned
// directly, while an alias domain is resolved (AAAA) in turn — allowing
// domain->domain mappings. depth guards against alias loops.
func (s *ProxyServer) resolveHostImpl(ctx context.Context, host, network string, depth int) (net.IP, error) {
	if target, ok := s.pool.hosts[normalizeHost(host)]; ok {
		if ip := net.ParseIP(target); ip != nil && ip.To4() == nil {
			log.Printf("[DNS] %s static mapping -> %s", host, ip)
			return ip, nil
		}
		// Alias domain: resolve it (AAAA) and return its IP directly.
		if depth >= 5 {
			return nil, fmt.Errorf("hosts alias chain too deep for %s", host)
		}
		log.Printf("[DNS] %s host-alias -> %s", host, target)
		return s.resolveHostImpl(ctx, target, network, depth+1)
	}

	// Serve a cached AAAA if it is still fresh, so repeated requests to the
	// same domain skip the DNS query entirely.
	if ip, ok := s.pool.dnsCache.get(host); ok {
		return ip, nil
	}

	primary := s.pool.dnsServerResolved()
	if primary == "" {
		primary = defaultDNSServer
	}
	servers := []string{primary, ""} // "" => system resolver

	var lastErr error
	for _, srv := range servers {
		label := srv
		if label == "" {
			label = "system"
		}
		v6, err := lookupAAAA(ctx, host, srv)
		if err != nil {
			log.Printf("[DNS] %s via %s failed (%v)", host, label, err)
			lastErr = err
			continue
		}
		// Cache the successful AAAA resolution for reuse by subsequent
		// requests (see dnsCacheTTL for the freshness window).
		s.pool.dnsCache.put(host, v6[0])
		return v6[0], nil
	}
	return nil, fmt.Errorf("dns lookup %s: %w", host, lastErr)
}

// normalizeHost strips an optional :port and lowercases the hostname so static
// mappings can be keyed by bare hostname regardless of how the client presents
// the target (e.g. "opencode.ai:443" and "opencode.ai" match the same entry).
func normalizeHost(host string) string {
	h := host
	if hp, _, err := net.SplitHostPort(host); err == nil {
		h = hp
	}
	return strings.ToLower(strings.TrimSpace(h))
}


func (s *ProxyServer) dialOut(network, target, clientHint string) (net.Conn, string, error) {
	retries := s.cfg.MaxRetries
	if retries < 1 {
		retries = 1
	}
	// Ephemeral fresh-source strategy only helps IPv6 destinations (we have no
	// IPv4 source addresses), and only when enabled.
	useEphemeral := s.pool.sourceMode == "ephemeral" && network == "tcp6"
	if !useEphemeral {
		retries = 1
	}

	host, port, herr := net.SplitHostPort(target)
	if herr != nil {
		return nil, "", herr
	}
	literalIP := net.ParseIP(host)

	ctx := context.Background()
	var lastErr error
	for i := 0; i < retries; i++ {
		var ip string
		var err error
		ip, err = s.selectSource(clientHint)
		if err != nil {
			return nil, "", err
		}

		// Resolve the domain (if any) via dns_server, then dial the resolved IP
		// bound to this connection's source address.
		dialTarget := target
		if literalIP == nil {
			resolved, rerr := s.resolveHost(ctx, host, network)
			if rerr != nil {
				log.Printf("[DNS] %s via source %s failed: %v", host, ip, rerr)
				lastErr = rerr
				if useEphemeral {
					s.pool.releaseEphemeral(ip)
				}
				continue
			}
			dialTarget = net.JoinHostPort(resolved.String(), port)
		}

		dialer := &net.Dialer{
			Timeout:   time.Duration(s.cfg.ConnectTimeout) * time.Second,
			LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)},
		}
		conn, derr := dialer.DialContext(ctx, network, dialTarget)
		if derr == nil {
			if s.pool.sourceMode == "slaac" {
				s.pool.recordRequest(ip, true)
			}
			return conn, ip, nil
		}
		lastErr = derr
		log.Printf("[DIAL] %s via %s failed: %v", dialTarget, ip, derr)
		if useEphemeral {
			s.pool.releaseEphemeral(ip)
		}
	}
	// All attempts failed: drop any cached AAAA for this host so the next
	// request re-resolves rather than reusing a possibly-dead address.
	if literalIP == nil {
		s.pool.dnsCache.invalidate(host)
	}
	return nil, "", lastErr
}

func (s *ProxyServer) handleHTTP(conn net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("[HTTP] Read: %v", err)
		return
	}

	srcIPv6 := req.Header.Get("X-Source-IPv6")
	req.Header.Del("X-Source-IPv6")
	req.Header.Del("Proxy-Connection")

	log.Printf("[HTTP] %s %s", req.Method, req.URL)

	if req.Method == http.MethodConnect {
		s.httpConnect(conn, req, srcIPv6)
	} else {
		s.httpForward(conn, req, srcIPv6)
	}
}

func formatDialTarget(host, defaultPort string) string {
	if strings.HasPrefix(host, "[") {
		idx := strings.Index(host, "]")
		if idx < 0 {
			return host
		}
		ip := host[1:idx]
		rest := host[idx+1:]
		if rest == "" || rest == ":" {
			return net.JoinHostPort(ip, defaultPort)
		}
		return host
	}
	if !strings.Contains(host, ":") {
		return net.JoinHostPort(host, defaultPort)
	}
	return host
}

func (s *ProxyServer) httpConnect(conn net.Conn, req *http.Request, srcIPv6 string) {
	target := formatDialTarget(req.Host, "443")

	tgt, srcIP, err := s.dialOut("tcp6", target, srcIPv6)
	if err != nil {
		log.Printf("[HTTP] Connect %s: %v", target, err)
		httpReply(conn, 502, err.Error())
		return
	}
	log.Printf("[HTTP] Connect %s via %s", target, srcIP)
	defer tgt.Close()
	if s.pool.sourceMode == "ephemeral" {
		defer s.pool.releaseEphemeral(srcIP)
	}

	fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	relay(conn, tgt)
}

func (s *ProxyServer) httpForward(conn net.Conn, req *http.Request, srcIPv6 string) {
	host := formatDialTarget(req.Host, "80")

	tgt, srcIP, err := s.dialOut("tcp6", host, srcIPv6)
	if err != nil {
		log.Printf("[HTTP] Connect %s: %v", host, err)
		httpReply(conn, 502, err.Error())
		return
	}
	log.Printf("[HTTP] Forward %s via %s", host, srcIP)
	defer tgt.Close()
	if s.pool.sourceMode == "ephemeral" {
		defer s.pool.releaseEphemeral(srcIP)
	}

	req.RequestURI = ""
	// A forwarded HTTP request is fully written by req.Write (including any
	// body), so we only need to stream the response back. Force the upstream to
	// close afterwards; otherwise a keep-alive server would leave the relay
	// copy blocked forever and the per-connection source IP would never be
	// released (address leak on the dummy interface).
	req.Close = true
	if err := req.Write(tgt); err != nil {
		log.Printf("[HTTP] Write: %v", err)
		httpReply(conn, 502, err.Error())
		return
	}
	// Cap the data phase too: this ISP sometimes lets the SYN through but then
	// blackholes the payload, which would otherwise hang io.Copy (and the
	// per-connection source address) indefinitely.
	dl := time.Now().Add(time.Duration(s.cfg.ConnectTimeout) * time.Second)
	tgt.SetDeadline(dl)
	io.Copy(conn, tgt)
	tgt.Close()
	conn.Close()
}

func httpReply(conn net.Conn, code int, msg string) {
	body := fmt.Sprintf("HTTP/1.1 %d Error\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", code, len(msg), msg)
	conn.Write([]byte(body))
}

func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		if tc, ok := b.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		if tc, ok := a.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	wg.Wait()
}

// ==================== SOCKS5 Proxy ====================

func (s *ProxyServer) handleSOCKS5(conn net.Conn, br *bufio.Reader) {
	// Client greeting
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	nMethods := int(hdr[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	// Check if username auth is in offered methods
	hasUserPass := false
	for _, m := range methods {
		if m == 0x02 {
			hasUserPass = true
			break
		}
	}

	if hasUserPass {
		// Server selects username/password auth
		conn.Write([]byte{0x05, 0x02})
	} else {
		// Server selects no auth
		conn.Write([]byte{0x05, 0x00})
	}

	// If auth selected, read credentials
	srcIPv6 := ""
	if hasUserPass {
		// Read version(1) + ulen(1) + uname(ulen) + plen(1) + passwd(plen)
		authHdr := make([]byte, 2)
		if _, err := io.ReadFull(conn, authHdr); err != nil {
			return
		}
		if authHdr[0] != 0x01 {
			conn.Write([]byte{0x01, 0x01})
			return
		}
		ulen := int(authHdr[1])
		uname := make([]byte, ulen)
		if _, err := io.ReadFull(conn, uname); err != nil {
			return
		}
		plenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, plenByte); err != nil {
			return
		}
		passwd := make([]byte, plenByte[0])
		if _, err := io.ReadFull(conn, passwd); err != nil {
			return
		}

		// Username is the desired source IPv6
		srcIPv6 = string(uname)
		conn.Write([]byte{0x01, 0x00})
	}

	// Read connect request
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		socks5Reply(conn, 0x07, nil, 0)
		return
	}

	var targetHost string
	switch req[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		targetHost = net.IP(addr).String()
	case 0x03: // Domain
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return
		}
		domain := make([]byte, lenByte[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		targetHost = string(domain)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		targetHost = net.IP(addr).String()
	default:
		socks5Reply(conn, 0x08, nil, 0)
		return
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBytes)
	target := net.JoinHostPort(targetHost, strconv.Itoa(int(port)))

	network := "tcp6"
	if ip := net.ParseIP(targetHost); ip != nil && ip.To4() != nil {
		network = "tcp4"
	}

	tgt, srcIP, err := s.dialOut(network, target, srcIPv6)
	if err != nil {
		log.Printf("[SOCKS5] Connect %s: %v", target, err)
		socks5Reply(conn, 0x05, nil, 0)
		return
	}
	defer tgt.Close()
	if s.pool.sourceMode == "ephemeral" && network == "tcp6" {
		defer s.pool.releaseEphemeral(srcIP)
	}

	log.Printf("[SOCKS5] Connect %s via %s", target, srcIP)

	bindAddr := tgt.LocalAddr().(*net.TCPAddr)
	socks5Reply(conn, 0x00, bindAddr.IP, bindAddr.Port)
	relay(conn, tgt)
}

func socks5Reply(conn net.Conn, status byte, bindIP net.IP, bindPort int) {
	if bindIP == nil {
		bindIP = net.IPv4zero
	}
	v4 := bindIP.To4()
	var resp []byte
	if v4 != nil {
		resp = []byte{0x05, status, 0x00, 0x01}
		resp = append(resp, v4...)
	} else {
		resp = []byte{0x05, status, 0x00, 0x04}
		resp = append(resp, bindIP.To16()...)
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(bindPort))
	resp = append(resp, pb...)
	conn.Write(resp)
}
// NormalizeHost is exported wrapper for normalizeHost.
func NormalizeHost(host string) string { return normalizeHost(host) }

