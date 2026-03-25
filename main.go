package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ─── Config ──────────────────────────────────────────────────────────────────

type IPRangeRule struct {
	Domain string `json:"domain"` // e.g. "example.com."  (trailing dot optional)
	CIDR   string `json:"cidr"`   // e.g. "10.0.0.0/8"
	Count  int    `json:"count"`  // how many random IPs to return
	TTL    uint32 `json:"ttl"`    // TTL for synthesised records
}

type Config struct {
	ListenAddr     string        `json:"listen_addr"`     // ":8053"
	TLSCert        string        `json:"tls_cert"`        // path to cert.pem  (empty = HTTP only, rely on nginx)
	TLSKey         string        `json:"tls_key"`         // path to key.pem
	UpstreamDNS    string        `json:"upstream_dns"`    // "8.8.8.8:53"
	AllowedDomains []string      `json:"allowed_domains"` // bare names, trailing dot optional
	CacheTTL       int           `json:"cache_ttl_sec"`   // default cache entry TTL override (0 = use DNS TTL)
	IPRangeRules   []IPRangeRule `json:"ip_range_rules"`
}

// ─── Cache ────────────────────────────────────────────────────────────────────

type cacheKey struct {
	name  string
	qtype dnsmessage.Type
}

type cacheEntry struct {
	msg     []byte
	expires time.Time
}

type Cache struct {
	mu      sync.RWMutex
	entries map[cacheKey]cacheEntry
}

func NewCache() *Cache {
	c := &Cache{entries: make(map[cacheKey]cacheEntry)}
	go c.evict()
	return c
}

func (c *Cache) Get(k cacheKey) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[k]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e.msg, true
}

func (c *Cache) Set(k cacheKey, msg []byte, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[k] = cacheEntry{msg: msg, expires: time.Now().Add(ttl)}
}

func (c *Cache) evict() {
	for range time.Tick(30 * time.Second) {
		now := time.Now()
		c.mu.Lock()
		for k, e := range c.entries {
			if now.After(e.expires) {
				delete(c.entries, k)
			}
		}
		c.mu.Unlock()
	}
}

// ─── IP range helpers ─────────────────────────────────────────────────────────

func randomIPsFromCIDR(cidr string, count int) ([]net.IP, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// Calculate the number of host addresses
	ones, bits := network.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 0 {
		return nil, fmt.Errorf("CIDR %s has no host addresses", cidr)
	}

	// Total number of addresses in the range
	total := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))

	baseIP := network.IP.To4()
	if baseIP == nil {
		baseIP = network.IP.To16()
	}
	baseInt := new(big.Int).SetBytes(baseIP)

	seen := make(map[string]bool)
	var ips []net.IP
	attempts := 0
	maxAttempts := count * 10

	for len(ips) < count && attempts < maxAttempts {
		attempts++
		// random offset in [1, total-2] to skip network and broadcast
		if total.Int64() <= 2 {
			break
		}
		offset := new(big.Int).Rand(rand.New(rand.NewSource(time.Now().UnixNano())), new(big.Int).Sub(total, big.NewInt(2)))
		offset.Add(offset, big.NewInt(1))

		ipInt := new(big.Int).Add(baseInt, offset)
		ipBytes := ipInt.Bytes()

		// pad to correct length
		padLen := len(baseIP)
		for len(ipBytes) < padLen {
			ipBytes = append([]byte{0}, ipBytes...)
		}
		ip := net.IP(ipBytes)
		s := ip.String()
		if !seen[s] {
			seen[s] = true
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

// ─── Server ───────────────────────────────────────────────────────────────────

type Server struct {
	cfg     Config
	cache   *Cache
	allowed map[string]bool        // normalised allowed domains
	ipRules map[string]IPRangeRule // normalised domain -> rule
}

func fqdn(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

func NewServer(cfg Config) *Server {
	allowed := make(map[string]bool)
	for _, d := range cfg.AllowedDomains {
		allowed[fqdn(d)] = true
	}
	ipRules := make(map[string]IPRangeRule)
	for _, r := range cfg.IPRangeRules {
		key := fqdn(r.Domain)
		if r.Count <= 0 {
			r.Count = 1
		}
		if r.TTL == 0 {
			r.TTL = 60
		}
		ipRules[key] = r
		// Ensure the domain is in the allowed list automatically
		allowed[key] = true
	}
	return &Server{cfg: cfg, cache: NewCache(), allowed: allowed, ipRules: ipRules}
}

// isAllowed checks exact match or parent domain match
func (s *Server) isAllowed(name string) bool {
	name = fqdn(name)
	if s.allowed[name] {
		return true
	}
	// Check if it ends with any allowed domain (subdomain support)
	for d := range s.allowed {
		if strings.HasSuffix(name, "."+d) || name == d {
			return true
		}
	}
	return false
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/dns-query" {
		http.NotFound(w, r)
		return
	}

	var rawMsg []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		// RFC 8484: base64url without padding
		import64 := func(s string) ([]byte, error) {
			import64pad := s
			switch len(s) % 4 {
			case 2:
				import64pad += "=="
			case 3:
				import64pad += "="
			}
			import64pad = strings.ReplaceAll(import64pad, "-", "+")
			import64pad = strings.ReplaceAll(import64pad, "_", "/")
			import64 := make([]byte, len(import64pad))
			n, err := decodeBase64(import64pad, import64)
			return import64[:n], err
		}
		rawMsg, err = import64(dnsParam)
		if err != nil {
			http.Error(w, "bad base64", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/dns-message") {
			http.Error(w, "bad content-type", http.StatusUnsupportedMediaType)
			return
		}
		rawMsg, err = io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp, err := s.resolve(rawMsg)
	if err != nil {
		log.Printf("resolve error: %v", err)
		http.Error(w, "resolver error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func (s *Server) resolve(rawMsg []byte) ([]byte, error) {
	var msg dnsmessage.Message
	if err := msg.Unpack(rawMsg); err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}

	if len(msg.Questions) == 0 {
		return refusedResponse(msg.Header.ID), nil
	}

	q := msg.Questions[0]
	name := strings.ToLower(q.Name.String())

	if !s.isAllowed(name) {
		log.Printf("REFUSED %s (not in allowed list)", name)
		return refusedResponse(msg.Header.ID), nil
	}

	// Check IP range rule for A queries
	if q.Type == dnsmessage.TypeA {
		if rule, ok := s.ipRules[name]; ok {
			return s.synthesiseAResponse(msg.Header.ID, q, rule)
		}
	}

	// Cache lookup
	ck := cacheKey{name: name, qtype: q.Type}
	if cached, ok := s.cache.Get(ck); ok {
		// Patch the ID to match the client's query
		if len(cached) >= 2 {
			patchedID := make([]byte, len(cached))
			copy(patchedID, cached)
			binary.BigEndian.PutUint16(patchedID[:2], msg.Header.ID)
			return patchedID, nil
		}
		return cached, nil
	}

	// Forward to upstream
	upstream, err := s.forwardToUpstream(rawMsg)
	if err != nil {
		return nil, fmt.Errorf("upstream: %w", err)
	}

	// Determine TTL for caching
	ttl := s.minTTL(upstream)
	if s.cfg.CacheTTL > 0 {
		ttl = time.Duration(s.cfg.CacheTTL) * time.Second
	}
	if ttl > 0 {
		s.cache.Set(ck, upstream, ttl)
	}

	log.Printf("FORWARD %s %s TTL=%s", q.Type, name, ttl)
	return upstream, nil
}

func (s *Server) synthesiseAResponse(id uint16, q dnsmessage.Question, rule IPRangeRule) ([]byte, error) {
	ips, err := randomIPsFromCIDR(rule.CIDR, rule.Count)
	if err != nil {
		return nil, fmt.Errorf("ip range: %w", err)
	}

	var b dnsmessage.Builder = dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 id,
		Response:           true,
		Authoritative:      true,
		RecursionDesired:   true,
		RecursionAvailable: true,
	})
	b.StartQuestions()
	b.Question(q)
	b.StartAnswers()
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		var a [4]byte
		copy(a[:], ip4)
		b.AResource(dnsmessage.ResourceHeader{
			Name:  q.Name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   rule.TTL,
		}, dnsmessage.AResource{A: a})
	}
	log.Printf("SYNTH A %s → %d IPs from %s", q.Name, len(ips), rule.CIDR)
	return b.Finish()
}

func (s *Server) forwardToUpstream(rawMsg []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", s.cfg.UpstreamDNS, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(rawMsg); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (s *Server) minTTL(rawMsg []byte) time.Duration {
	var msg dnsmessage.Message
	if err := msg.Unpack(rawMsg); err != nil {
		return 0
	}
	var min uint32 = ^uint32(0)
	for _, a := range msg.Answers {
		if a.Header.TTL < min {
			min = a.Header.TTL
		}
	}
	if min == ^uint32(0) || min == 0 {
		return 0
	}
	return time.Duration(min) * time.Second
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func refusedResponse(id uint16) []byte {
	var b dnsmessage.Builder = dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:       id,
		Response: true,
		RCode:    dnsmessage.RCodeRefused,
	})
	out, _ := b.Finish()
	return out
}

// Simple base64 std decoder (avoids importing encoding/base64 name clash)
func decodeBase64(s string, dst []byte) (int, error) {
	import64 := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	table := [256]byte{}
	for i := range table {
		table[i] = 0xFF
	}
	for i, c := range import64 {
		table[c] = byte(i)
	}
	table['='] = 0

	n := 0
	for i := 0; i < len(s); i += 4 {
		if i+3 >= len(s) {
			break
		}
		a, b, c, d := table[s[i]], table[s[i+1]], table[s[i+2]], table[s[i+3]]
		dst[n] = a<<2 | b>>4
		n++
		if s[i+2] != '=' {
			dst[n] = b<<4 | c>>2
			n++
		}
		if s[i+3] != '=' {
			dst[n] = c<<6 | d
			n++
		}
	}
	return n, nil
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	cfgPath := "config.json"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("parse config: %v", err)
	}

	if cfg.UpstreamDNS == "" {
		cfg.UpstreamDNS = "8.8.8.8:53"
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8053"
	}

	srv := NewServer(cfg)

	mux := http.NewServeMux()
	mux.Handle("/dns-query", srv)

	log.Printf("DoH server listening on %s", cfg.ListenAddr)
	log.Printf("Upstream: %s | Allowed domains: %v", cfg.UpstreamDNS, cfg.AllowedDomains)

	httpSrv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		log.Printf("TLS enabled with cert=%s key=%s", cfg.TLSCert, cfg.TLSKey)
		log.Fatal(httpSrv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey))
	} else {
		log.Println("Running in plain HTTP mode (put nginx in front for HTTPS)")
		log.Fatal(httpSrv.ListenAndServe())
	}
}
