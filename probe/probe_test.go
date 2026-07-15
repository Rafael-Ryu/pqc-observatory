package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsPublicIP(t *testing.T) {
	public := []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"}
	private := []string{
		"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1",
		"100.64.0.1", "100.127.255.255", // CGNAT
		"::1", "fc00::1", "fe80::1", "ff02::1", "::", "0.0.0.0",
		"::ffff:10.0.0.1", // IPv4-mapped private
	}
	for _, s := range public {
		if !isPublicIP(net.ParseIP(s)) {
			t.Errorf("%s should be public", s)
		}
	}
	for _, s := range private {
		if isPublicIP(net.ParseIP(s)) {
			t.Errorf("%s should be rejected", s)
		}
	}
	if isPublicIP(nil) {
		t.Error("nil should be rejected")
	}
}

func TestGroupName(t *testing.T) {
	cases := map[tls.CurveID]string{4588: "X25519MLKEM768", 29: "X25519", 0: ""}
	for id, want := range cases {
		if got := groupName(id); got != want {
			t.Errorf("groupName(%d) = %q, want %q", id, got, want)
		}
	}
}

func TestWithPortAndHostname(t *testing.T) {
	if got := withPort("example.com"); got != "example.com:443" {
		t.Errorf("withPort default = %q", got)
	}
	if got := withPort("example.com:8443"); got != "example.com:8443" {
		t.Errorf("withPort explicit = %q", got)
	}
	if got := hostname("example.com:443"); got != "example.com" {
		t.Errorf("hostname = %q", got)
	}
}

// A self-signed server on loopback must never yield a supported result: the
// certificate does not verify and the address is not public. This guards the
// two precision invariants at once.
func TestProbeLoopbackNeverSupported(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	r := probe(srv.Listener.Addr().String(), 5*time.Second)
	if r.Error == "" {
		t.Fatalf("expected an error for loopback self-signed server, got group %q", r.Group)
	}
	if r.Group == "X25519MLKEM768" {
		t.Fatalf("loopback server must never be reported as supporting PQC")
	}
}
