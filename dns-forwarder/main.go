package main

import (
	"bytes"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// --- INTERFACES & ABSTRACTIONS ---

// Upstream defines the interface for different types of DNS servers.
type Upstream interface {
	Query(req *dns.Msg) (*dns.Msg, error)
	Address() string
	Type() string
}

// --- POOLED UPSTREAM (TCP, UDP, DoT) ---

type PooledUpstream struct {
	addr    string
	netType string
	pool    chan *dns.Conn
}

func NewPooledUpstream(addr, netType string, poolSize int) *PooledUpstream {
	return &PooledUpstream{
		addr:    addr,
		netType: netType,
		pool:    make(chan *dns.Conn, poolSize),
	}
}

func (u *PooledUpstream) Address() string { return u.addr }
func (u *PooledUpstream) Type() string    { return strings.ToUpper(u.netType) }

func (u *PooledUpstream) getConn() (*dns.Conn, error) {
	select {
	case conn := <-u.pool:
		return conn, nil
	default:
		conn, err := dns.DialTimeout(u.netType, u.addr, 500*time.Millisecond)
		if err != nil {
			return nil, err
		}
		// Apply keepalive if it's a TCP connection
		if tcpConn, ok := conn.Conn.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(1 * time.Minute)
		}
		return conn, nil
	}
}

func (u *PooledUpstream) putConn(conn *dns.Conn) {
	select {
	case u.pool <- conn:
	default:
		conn.Close()
	}
}

func (u *PooledUpstream) Query(req *dns.Msg) (*dns.Msg, error) {
	var err error
	var resp *dns.Msg

	// Try up to 2 times for pooled connections in case one went stale
	for attempt := 0; attempt < 1; attempt++ {
		conn, err := u.getConn()
		if err != nil {
			continue // Dial failed, try again
		}

		conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if err = conn.WriteMsg(req); err != nil {
			conn.Close()
			continue // Broken conn, loop and get a fresh one
		}

		resp, err = conn.ReadMsg()
		if err != nil {
			conn.Close()
			continue
		}

		u.putConn(conn) // Success, return to pool
		return resp, nil
	}
	return nil, err
}

// --- DoH UPSTREAM (DNS over HTTPS) ---

type DoHUpstream struct {
	url    string
	client *http.Client
}

func NewDoHUpstream(url string) *DoHUpstream {
	return &DoHUpstream{
		url: url,
		client: &http.Client{
			Timeout: 1500 * time.Millisecond,
			Transport: &http.Transport{
				MaxIdleConns:      10,
				IdleConnTimeout:   30 * time.Second,
				DisableKeepAlives: false,
			},
		},
	}
}

func (u *DoHUpstream) Address() string { return u.url }
func (u *DoHUpstream) Type() string    { return "HTTPS" }

func (u *DoHUpstream) Query(req *dns.Msg) (*dns.Msg, error) {
	msgBytes, err := req.Pack()
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", u.url, bytes.NewReader(msgBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	resp, err := u.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned HTTP %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(bodyBytes); err != nil {
		return nil, err
	}

	return dnsResp, nil
}

// --- PROXY & METRICS CORE ---

type ServerStat struct {
	Address   string
	Type      string
	TotalPkts atomic.Int64
	Successes atomic.Int64
	Failures  atomic.Int64

	mu      sync.Mutex
	LenDist map[string]int64
}

type UpstreamServer struct {
	upstream Upstream
	stat     *ServerStat
}

type Proxy struct {
	Servers []*UpstreamServer
}

func categorizeLength(length int) string {
	if length < 50 {
		return "< 50 bytes"
	} else if length <= 100 {
		return "50 - 100 bytes"
	} else if length <= 200 {
		return "101 - 200 bytes"
	}
	return "> 200 bytes"
}

// Parse upstream URI (e.g., tcp://8.8.8.8:53, tls://1.1.1.1:853, https://dns.google/dns-query)
func parseUpstream(uri string, poolSize int) Upstream {
	if strings.HasPrefix(uri, "https://") {
		return NewDoHUpstream(uri)
	}

	var netType, addr string
	if strings.HasPrefix(uri, "tcp://") {
		netType, addr = "tcp", strings.TrimPrefix(uri, "tcp://")
	} else if strings.HasPrefix(uri, "udp://") {
		netType, addr = "udp", strings.TrimPrefix(uri, "udp://")
	} else if strings.HasPrefix(uri, "tls://") {
		netType, addr = "tcp-tls", strings.TrimPrefix(uri, "tls://")
	} else {
		// Default to TCP for backward compatibility
		netType, addr = "tcp", uri
	}

	return NewPooledUpstream(addr, netType, poolSize)
}

func NewProxy(targetURIs []string, poolSize int) *Proxy {
	p := &Proxy{
		Servers: make([]*UpstreamServer, len(targetURIs)),
	}

	for i, uri := range targetURIs {
		upstream := parseUpstream(uri, poolSize)
		p.Servers[i] = &UpstreamServer{
			upstream: upstream,
			stat: &ServerStat{
				Address: upstream.Address(),
				Type:    upstream.Type(),
				LenDist: make(map[string]int64),
			},
		}
	}
	return p
}

func (p *Proxy) queryServer(idx int, r *dns.Msg) (*dns.Msg, error) {
	srv := p.Servers[idx]
	srv.stat.TotalPkts.Add(1)

	// Record query length distribution
	bucket := categorizeLength(r.Len())
	srv.stat.mu.Lock()
	srv.stat.LenDist[bucket]++
	srv.stat.mu.Unlock()

	resp, err := srv.upstream.Query(r)
	if err != nil {
		srv.stat.Failures.Add(1)
		return nil, err
	}

	srv.stat.Successes.Add(1)
	return resp, nil
}

func (p *Proxy) forwardQuery(r *dns.Msg) (*dns.Msg, error) {
	limit := 3
	if len(p.Servers) < 3 {
		limit = len(p.Servers)
	}

	// Phase 1: Try the first 3 servers sequentially
	for i := 0; i < limit; i++ {
		resp, err := p.queryServer(i, r)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			return resp, nil
		}
		log.Printf("[Warning] Server %d (%s) failed: %v", i+1, p.Servers[i].upstream.Address(), err)
	}

	// Phase 2: RACE the remaining servers
	if len(p.Servers) > 3 {
		return p.raceRemainingServers(3, r)
	}

	return nil, fmt.Errorf("all attempted upstream servers failed")
}

func (p *Proxy) raceRemainingServers(startIdx int, r *dns.Msg) (*dns.Msg, error) {
	successChan := make(chan *dns.Msg, 1)
	var wg sync.WaitGroup

	for i := startIdx; i < len(p.Servers); i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			reqCopy := r.Copy() // Prevent concurrent ID mutation
			resp, err := p.queryServer(idx, reqCopy)
			if err == nil && resp != nil {
				select {
				case successChan <- resp:
				default: // Channel full
				}
			}
		}(i)
	}

	go func() {
		wg.Wait()
		close(successChan)
	}()

	resp, ok := <-successChan
	if ok {
		return resp, nil
	}
	return nil, fmt.Errorf("all raced servers failed")
}

func (p *Proxy) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()
	if len(r.Question) == 0 {
		return
	}
	qName := r.Question[0].Name

	resp, err := p.forwardQuery(r)
	if err != nil {
		log.Printf("[Error] Failed to resolve %s: %v", qName, err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	log.Printf("[OK] Resolved %s in %v", qName, time.Since(start))
	resp.Id = r.Id // Restore ID for client
	if err = w.WriteMsg(resp); err != nil {
		log.Printf("[Error] Failed to reply: %v", err)
	}
}

// --- HTTP STATISTICS SERVER ---

type StatSnapshot struct {
	Address   string
	Type      string
	TotalPkts int64
	Successes int64
	Failures  int64
	LenDist   map[string]int64
}

const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
	<title>DNS Proxy Stats</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 40px; background-color: #fcfcfc; }
		h2 { color: #333; }
		table { border-collapse: collapse; width: 100%; box-shadow: 0 2px 10px rgba(0,0,0,0.05); background-color: white; }
		th, td { border: 1px solid #eee; padding: 14px; text-align: left; }
		th { background-color: #2c3e50; color: white; font-weight: 500; }
		tr:hover { background-color: #f9f9f9; }
		.badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; background-color: #3498db; color: white; }
		.badge.udp { background-color: #9b59b6; }
		.badge.tcp { background-color: #e67e22; }
		.badge.tls { background-color: #2ecc71; }
		.badge.https { background-color: #e74c3c; }
	</style>
</head>
<body>
	<h2>DNS Proxy Statistics</h2>
	<table>
		<tr>
			<th>Upstream Server</th>
			<th>Type</th>
			<th>Total Packets</th>
			<th>Successes</th>
			<th>Failures</th>
			<th>Query Length Distribution</th>
		</tr>
		{{range .}}
		<tr>
			<td><b>{{.Address}}</b></td>
			<td><span class="badge {{.Type | lower}}">{{.Type}}</span></td>
			<td>{{.TotalPkts}}</td>
			<td style="color: green;">{{.Successes}}</td>
			<td style="color: red;">{{.Failures}}</td>
			<td>
				<ul style="margin: 0; padding-left: 20px;">
					{{range $bucket, $count := .LenDist}}
						<li>{{$bucket}}: <b>{{$count}}</b></li>
					{{end}}
				</ul>
			</td>
		</tr>
		{{end}}
	</table>
</body>
</html>
`

func (p *Proxy) startHTTPStats(addr string) {
	funcs := template.FuncMap{"lower": strings.ToLower}
	tmpl := template.Must(template.New("stats").Funcs(funcs).Parse(htmlTemplate))

	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		snapshots := make([]StatSnapshot, 0, len(p.Servers))
		for _, srv := range p.Servers {
			srv.stat.mu.Lock()
			distCopy := make(map[string]int64)
			for k, v := range srv.stat.LenDist {
				distCopy[k] = v
			}
			srv.stat.mu.Unlock()

			snapshots = append(snapshots, StatSnapshot{
				Address:   srv.stat.Address,
				Type:      srv.stat.Type,
				TotalPkts: srv.stat.TotalPkts.Load(),
				Successes: srv.stat.Successes.Load(),
				Failures:  srv.stat.Failures.Load(),
				LenDist:   distCopy,
			})
		}
		w.Header().Set("Content-Type", "text/html")
		tmpl.Execute(w, snapshots)
	})

	log.Printf("Starting HTTP statistics server on http://localhost%s/stats", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}

// --- MAIN ENTRY ---

func main() {
	listenAddr := flag.String("listen", ":5353", "Local UDP address to listen on")
	poolSize := flag.Int("pool", 5, "Number of concurrent connections to keep open per server")
	httpAddr := flag.String("http", ":8080", "HTTP Server address for stats")

	defaultTargets := "tcp://8.8.8.8:53;udp://1.1.1.1:53;tls://1.1.1.1:853;https://cloudflare-dns.com/dns-query;tcp://9.9.9.9:53"
	targetAddr := flag.String("target", defaultTargets, "Semicolon separated upstream servers with schemes (udp://, tcp://, tls://, https://)")
	flag.Parse()

	targets := strings.Split(*targetAddr, ";")
	if len(targets) == 0 || targets[0] == "" {
		log.Fatal("No target servers provided.")
	}

	proxy := NewProxy(targets, *poolSize)

	// Start HTTP Stats Server
	go proxy.startHTTPStats(*httpAddr)

	dns.HandleFunc(".", proxy.handleDNSRequest)
	server := &dns.Server{
		Addr: *listenAddr,
		Net:  "udp",
	}

	log.Printf("Starting DNS proxy on UDP %s", *listenAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}
}
