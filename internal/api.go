package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ==================== API Server ====================

type APIServer struct {
	addr string
	pool *IPv6Pool
	cfg  *Config
}

func NewAPIServer(addr string, pool *IPv6Pool, cfg *Config) *APIServer {
	return &APIServer{addr: addr, pool: pool, cfg: cfg}
}

func (s *APIServer) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/ips", s.handleIPs)
	mux.HandleFunc("/api/generate", s.handleGenerate)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/select", s.handleSelect)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/", s.handleIndex)

	srv := &http.Server{Addr: s.addr, Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	log.Printf("[API] Listening on %s", s.addr)
	return srv.ListenAndServe()
}

func (s *APIServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, `<html><head><title>IPv6 Proxy</title>
<style>body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:20px}
h1{color:#0f3460}pre{background:#16213e;padding:15px;border-radius:5px}</style></head><body>
<h1>IPv6 Proxy</h1><pre>
GET /api/ips                  - List IPv6 pool
GET /api/generate?count=5     - Generate N random IPv6, test &amp; return usability
GET /api/select               - Manual selection mode (set/next/mode)
GET /api/status               - Server status + configuration
GET /api/logs?lines=200       - Recent log lines
</pre></body></html>`)
}

func (s *APIServer) handleIPs(w http.ResponseWriter, r *http.Request) {
	addrs := s.pool.ListAddresses()
	list := make([]*IPv6Addr, 0, len(addrs))
	for _, a := range addrs {
		if a.State == "" {
			a.State = a.Status
		}
		list = append(list, a)
	}
	jsonOut(w, list)
}

// handleGenerate creates `count` random IPv6 source addresses inside the PD
// prefix, adds them to the pool and runs the full staged test on each
// concurrently. It returns the generated addresses with their diagnosed
// usability (status / failure_stage), so the caller can pick the alive ones.
func (s *APIServer) handleGenerate(w http.ResponseWriter, r *http.Request) {
	count := 5
	if c := r.URL.Query().Get("count"); c != "" {
		if n, err := strconv.Atoi(c); err == nil && n > 0 {
			if n > 50 {
				n = 50
			}
			count = n
		}
	}

	generated := make([]string, 0, count)
	for i := 0; i < count; i++ {
		ip := randomIPInPrefix(s.pool.prefix)
		ipStr := ip.String()
		if _, exists := s.pool.addrs[ipStr]; exists {
			continue
		}
		if err := s.pool.AddAddress(ip, subnetOf(ip)); err != nil {
			continue
		}
		generated = append(generated, ipStr)
	}

	// Test each generated address concurrently, then report results.
	var wg sync.WaitGroup
	for _, ipStr := range generated {
		wg.Add(1)
		go func(ipStr string) {
			defer wg.Done()
			s.pool.TestAddress(ipStr, time.Duration(s.cfg.ConnectTimeout)*time.Second)
		}(ipStr)
	}
	wg.Wait()

	list := make([]*IPv6Addr, 0, len(generated))
	alive := 0
	for _, ipStr := range generated {
		s.pool.mu.RLock()
		addr := s.pool.addrs[ipStr]
		s.pool.mu.RUnlock()
		if addr != nil {
			if addr.Status == "alive" {
				alive++
			}
			cp := *addr
			list = append(list, &cp)
		}
	}

	jsonOut(w, map[string]interface{}{
		"count":     len(generated),
		"alive":     alive,
		"prefix":    s.pool.prefix.String(),
		"addresses": list,
	})
}

func (s *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.pool.mu.RLock()
	total, alive, dead := 0, 0, 0
	for _, a := range s.pool.addrs {
		total++
		if a.Status == "alive" {
			alive++
		} else if a.Status == "dead" {
			dead++
		}
	}
	s.pool.mu.RUnlock()

	jsonOut(w, map[string]interface{}{
		"wan_interface":   s.pool.wanIface,
		"dummy_interface": s.pool.dummyIface,
		"prefix":          s.pool.prefix.String(),
		"total":           total,
		"alive":           alive,
		"dead":            dead,
		"selection_mode":  s.pool.selectionMode,
		"source_mode":     s.pool.sourceMode,
		"pinned":          s.pool.GetPinnedIP(),
		"proxy_addr":      s.cfg.ProxyAddr,
		"api_addr":        s.cfg.APIAddr,
		"dns_server":      s.pool.dnsServerResolved(),
		"test_target":     s.pool.testTargetResolved(),
		"policy_table":    s.pool.tableID,
		"slaac_prefix":    s.pool.slaacPrefixString(),
		"slaac_wan_ip":    s.pool.slaacWANIPString(),
		"subnet_count":    s.cfg.SubnetCount,
		"slaac_pool_size": s.cfg.SLAACPoolSize,
		"health_interval": s.cfg.HealthInterval,
		"connect_timeout": s.cfg.ConnectTimeout,
		"max_retries":     s.cfg.MaxRetries,
		"hosts":           s.cfg.Hosts,
	})
}

// handleSelect manages the "manual" selection mode: view the current pinned
// IP, set it explicitly (?ip=...), switch to the next alive address (?next),
// or change the selection algorithm (?mode=...). With no query params it just
// reports the current state.
func (s *APIServer) handleSelect(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	mode := q.Get("mode")
	ip := q.Get("ip")
	_, next := q["next"] // presence of the key triggers a switch, e.g. ?next or ?next=1

	if mode != "" {
		if err := s.pool.SetSelectionMode(mode); err != nil {
			jsonErr(w, errStr(err), 400)
			return
		}
	}
	if ip != "" {
		if err := s.pool.SetPinnedIP(ip); err != nil {
			jsonErr(w, errStr(err), 400)
			return
		}
	}
	switchedTo := ""
	if next {
		nxt, err := s.pool.SwitchToNext()
		if err != nil {
			jsonErr(w, errStr(err), 400)
			return
		}
		switchedTo = nxt
	}
	jsonOut(w, map[string]string{
		"selection_mode": s.pool.selectionMode,
		"pinned":         s.pool.GetPinnedIP(),
		"switched_to":    switchedTo,
	})
}

// handleLogs returns the most recent log lines captured in memory. Use ?lines=N
// to limit the number returned (default 200).
func (s *APIServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	n := 200
	if v := r.URL.Query().Get("lines"); v != "" {
		if k, err := strconv.Atoi(v); err == nil && k > 0 {
			n = k
		}
	}
	lines := LogBuf.Tail(n)
	jsonOut(w, map[string]interface{}{"lines": lines, "count": len(lines)})
}

func jsonOut(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ==================== Main ====================

// LogBuffer is an in-memory ring buffer of recent log lines, exposed via the
// /api/logs endpoint. It is safe for concurrent use and preserves partial
// writes until a newline arrives.
type logBuffer struct {
	mu      sync.Mutex
	buf     []string
	pending []byte
	max     int
}

func newLogBuffer(max int) *logBuffer {
	if max <= 0 {
		max = 2000
	}
	return &logBuffer{max: max}
}
var LogBuf = newLogBuffer(2000)


func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pending = append(l.pending, p...)
	for {
		idx := bytes.IndexByte(l.pending, '\n')
		if idx < 0 {
			break
		}
		line := string(l.pending[:idx])
		l.pending = l.pending[idx+1:]
		l.buf = append(l.buf, line)
		if len(l.buf) > l.max {
			l.buf = l.buf[len(l.buf)-l.max:]
		}
	}
	return len(p), nil
}

// Tail returns up to the last n log lines (most-recent last).
func (l *logBuffer) Tail(n int) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n >= len(l.buf) {
		out := make([]string, len(l.buf))
		copy(out, l.buf)
		return out
	}
	out := make([]string, n)
	copy(out, l.buf[len(l.buf)-n:])
	return out
}


