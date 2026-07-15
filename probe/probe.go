// Command probe performs a real TLS 1.3 handshake against each host, offering
// the hybrid post-quantum key exchange X25519MLKEM768, and reports the group
// the server actually negotiated in its ServerHello. It emits one JSON object
// per host (JSONL) on stdout. The negotiated group is the only PQC signal we
// trust: nothing is inferred from cipher lists, ALPN, or banners.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"sync"
	"time"
)

// Groups we offer. X25519MLKEM768 first so a capable server picks it; X25519
// as fallback so a non-capable server still completes the handshake and we can
// record what it chose (rather than seeing a handshake failure = unknown).
var offered = []tls.CurveID{tls.X25519MLKEM768, tls.X25519}

func groupName(id tls.CurveID) string {
	// tls.CurveID.String() already knows these; keep the switch honest and
	// explicit for the two ids that carry product meaning.
	switch id {
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	case tls.X25519:
		return "X25519"
	case 0:
		return ""
	default:
		return id.String()
	}
}

type result struct {
	Host       string `json:"host"`
	Group      string `json:"group"`       // negotiated group name, "" on error
	GroupID    uint16 `json:"group_id"`    // negotiated group id, 0 on error
	TLSVersion uint16 `json:"tls_version"` // 0 on error
	Error      string `json:"error,omitempty"`
}

func probe(host string, timeout time.Duration) result {
	r := result{Host: host}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			MinVersion:       tls.VersionTLS13,
			MaxVersion:       tls.VersionTLS13,
			CurvePreferences: offered,
			ServerName:       hostname(host),
			// We measure the negotiated group, chosen in ServerHello before cert
			// validation matters. Skipping verification keeps endpoints with cert
			// issues measurable instead of collapsing them to unknown.
			InsecureSkipVerify: true,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", withPort(host))
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer conn.Close()

	state := conn.(*tls.Conn).ConnectionState()
	r.Group = groupName(state.CurveID)
	r.GroupID = uint16(state.CurveID)
	r.TLSVersion = state.Version
	return r
}

func hostname(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func withPort(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, "443")
}

func main() {
	hosts := os.Args[1:]
	if len(hosts) == 0 {
		os.Exit(0)
	}

	const workers = 16
	const timeout = 10 * time.Second

	jobs := make(chan string)
	results := make(chan result)

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				results <- probe(h, timeout)
			}
		}()
	}
	go func() {
		for _, h := range hosts {
			jobs <- h
		}
		close(jobs)
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	enc := json.NewEncoder(os.Stdout)
	for r := range results {
		enc.Encode(r)
	}
}
