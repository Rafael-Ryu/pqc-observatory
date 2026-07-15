// Command probe performs a real TLS 1.3 handshake against each host, offering
// the hybrid post-quantum key exchange X25519MLKEM768, and reports the group
// the server actually negotiated in its ServerHello. It emits one JSON object
// per sample (JSONL) on stdout, -samples independent samples per host. The
// negotiated group is the only PQC signal we trust: nothing is inferred from
// cipher lists, ALPN, or banners.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/netip"
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

// runSelfTest proves that clientCurves, offered over an in-memory pipe against
// a server that accepts ONLY X25519MLKEM768, actually lands on ML-KEM. It
// catches GODEBUG=tlsmlkem=0 (and any other runtime poisoning that strips the
// group from Go's effective ClientHello despite the source still listing it)
// before a single real host is contacted.
func runSelfTest(clientCurves []tls.CurveID) error {
	// The certificate exists only to let the loopback handshake complete;
	// nobody verifies its identity (InsecureSkipVerify below), so a fresh
	// throwaway key each run is correct and there is nothing to pin.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("selftest: generate key: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pqc-observatory selftest"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("selftest: create certificate: %w", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	serverConn := tls.Server(server, &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	})
	clientConn := tls.Client(client, &tls.Config{
		InsecureSkipVerify: true, // scoped: this checks our own runtime's offered groups, not a named peer's identity
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   clientCurves,
	})

	// net.Pipe has no timeout of its own; a wedged handshake would hang
	// startup forever instead of failing loud, so bound it explicitly.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverErr := make(chan error, 1)
	go func() { serverErr <- serverConn.HandshakeContext(ctx) }()

	if err := clientConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("selftest: client handshake: %w", err)
	}
	if err := <-serverErr; err != nil {
		return fmt.Errorf("selftest: server handshake: %w", err)
	}

	if got := clientConn.ConnectionState().CurveID; got != tls.X25519MLKEM768 {
		return fmt.Errorf("selftest: negotiated group %v, want X25519MLKEM768 (ML-KEM missing from effective ClientHello)", got)
	}
	return nil
}

// selfTest exercises the exact group set the real probe sends, so it reflects
// whatever the current runtime/GODEBUG actually offers, not just the source.
func selfTest() error {
	return runSelfTest(offered)
}

// specialPurposePrefixes are IANA special-purpose address blocks that are
// none of loopback/unspecified/link-local/multicast/RFC1918 (already checked
// separately below) but are still not globally routable: documentation
// ranges, benchmarking nets, NAT64, Teredo, CGNAT, and similar reserved
// space. A poisoned or split-horizon DNS answer pointing a public hostname at
// one of these must be rejected the same as private space.
var specialPurposePrefixes = []netip.Prefix{
	// IPv4
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), // TEST-NET-1
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),
	// IPv6
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"), // Teredo
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
}

// isPublicIP reports whether ip is a globally routable unicast address. This
// is an allowlist, not a partial denylist: an address must be valid, clear
// every existing categorical check below, AND fall outside every reserved
// prefix above before it counts as public. Only a genuinely global-unicast,
// non-special address returns true.
func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || !addr.IsValid() {
		return false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if !addr.IsGlobalUnicast() {
		return false
	}
	for _, p := range specialPurposePrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

type result struct {
	Host        string `json:"host"`
	SampleIndex int    `json:"sample_index"`
	Group       string `json:"group"`       // negotiated group name, "" on error
	GroupID     uint16 `json:"group_id"`    // negotiated group id, 0 on error
	TLSVersion  uint16 `json:"tls_version"` // 0 on error
	PeerIP      string `json:"peer_ip,omitempty"`
	Error       string `json:"error,omitempty"`
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
	samples := flag.Int("samples", 1, "independent samples per host")
	spacing := flag.Duration("spacing", 750*time.Millisecond, "delay between samples of the same host")
	selftestOnly := flag.Bool("selftest", false, "run the ML-KEM startup self-test and exit (0 pass / 1 fail), without probing hosts")
	flag.Parse()

	// Runs before any flag-dependent host work, and before the -selftest early
	// exit below, so both entrypoints (CI's explicit -selftest and a normal
	// scan) always confirm ML-KEM is actually offerable under this runtime
	// before touching a single real host.
	if err := selfTest(); err != nil {
		fmt.Fprintln(os.Stderr, "probe: startup self-test failed, refusing to run (check for GODEBUG=tlsmlkem=0 or similar runtime poisoning):", err)
		os.Exit(1)
	}
	if *selftestOnly {
		os.Exit(0)
	}

	hosts := flag.Args()
	if len(hosts) == 0 {
		os.Exit(0)
	}
	if *samples < 1 {
		*samples = 1
	}

	const workers = 16
	const timeout = 10 * time.Second

	jobs := make(chan string)
	results := make(chan result)

	// Job = host, not sample: a host's N samples run sequentially with spacing
	// in between (each is a fresh DNS resolution and connection, so spacing
	// avoids hammering one endpoint back-to-back), while the 16-worker pool
	// still fans out across hosts for throughput.
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				for i := 0; i < *samples; i++ {
					r := probe(h, timeout)
					r.SampleIndex = i
					results <- r
					if i < *samples-1 {
						time.Sleep(*spacing)
					}
				}
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
