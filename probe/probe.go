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
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// Groups we enable. Go ignores the order of this list and applies its own
// internal preference, so this is a set, not a ranking: the server selects one
// of these from the ClientHello. Enabling X25519 alongside the PQC group lets a
// non-PQC server still complete the handshake, so we observe its choice instead
// of a bare handshake failure.
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

// isPublicIP reports whether ip is a globally routable unicast address. It
// rejects every special-use range that could point the probe at non-public
// infrastructure, including CGNAT (100.64.0.0/10), which Go's IsPrivate misses.
func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return false
	}
	return true
}

type result struct {
	Host       string `json:"host"`
	Group      string `json:"group"`       // negotiated group name, "" on error
	GroupID    uint16 `json:"group_id"`    // negotiated group id, 0 on error
	TLSVersion uint16 `json:"tls_version"` // 0 on error
	PeerIP     string `json:"peer_ip,omitempty"`
	Error      string `json:"error,omitempty"`
}

func probe(host string, timeout time.Duration) result {
	r := result{Host: host}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			// Reject non-public peers after DNS resolution but before the socket
			// connects, so private infrastructure is never handshaked at all.
			Control: func(_, address string, _ syscall.RawConn) error {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return err
				}
				if ip := net.ParseIP(host); ip == nil || !isPublicIP(ip) {
					return fmt.Errorf("non-public address: %s", host)
				}
				return nil
			},
		},
		Config: &tls.Config{
			MinVersion:       tls.VersionTLS13,
			MaxVersion:       tls.VersionTLS13,
			CurvePreferences: offered,
			ServerName:       hostname(host),
			// Certificate identity is verified against ServerName. A verdict is
			// only meaningful if the PQC exchange happened with the named
			// endpoint, not with a MITM, captive portal, or misrouted vhost, so
			// a certificate failure must collapse to unknown, not a false result.
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", withPort(host))
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer conn.Close()

	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		r.PeerIP = tcp.IP.String()
	}

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
		if err := enc.Encode(r); err != nil {
			// A lost line would silently drop a host from the dataset; fail loud
			// so the caller (which reconciles host counts) treats the run as
			// broken rather than publishing incomplete results.
			fmt.Fprintln(os.Stderr, "probe: encode:", err)
			os.Exit(1)
		}
	}
}
