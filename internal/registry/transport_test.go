/*
Copyright 2026 The Tagwarden Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package registry

import (
	"bufio"
	"crypto/tls"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

const (
	proxyUser = "proxyuser"
	proxyPass = "s3cret-proxy-pass"
)

func caPEM(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func get(t *testing.T, rt http.RoundTripper, u string) error {
	t.Helper()
	resp, err := (&http.Client{Transport: rt}).Get(u)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	return nil
}

func TestCustomCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	rt, err := NewTransport(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, rt, srv.URL); err == nil || !strings.Contains(err.Error(), "x509") {
		t.Fatalf("want x509 error without CA, got %v", err)
	}

	rt, err = NewTransport(Options{CAPEM: caPEM(srv)})
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, rt, srv.URL); err != nil {
		t.Fatalf("with CA: %v", err)
	}
}

func TestInvalidCA(t *testing.T) {
	if _, err := NewTransport(Options{CAPEM: []byte("not a pem")}); err == nil {
		t.Fatal("want error for CA bundle without certificates")
	}
}

func TestMinTLSVersion(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS11} //nolint:gosec // the server must be too old
	srv.StartTLS()
	defer srv.Close()

	rt, err := NewTransport(Options{CAPEM: caPEM(srv)})
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, rt, srv.URL); err == nil {
		t.Fatal("want handshake failure against a TLS 1.1 server")
	}
	if v := rt.(*http.Transport).TLSClientConfig.MinVersion; v != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, want TLS 1.2", v)
	}
}

func TestClientCert(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	// The server's own key pair doubles as a client certificate.
	cert := srv.TLS.Certificates[0]
	rt, err := NewTransport(Options{CAPEM: caPEM(srv), ClientCert: &cert})
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, rt, srv.URL); err != nil {
		t.Fatalf("mTLS: %v", err)
	}
}

func TestProxySelection(t *testing.T) {
	proxy, _ := url.Parse("http://proxy.example.internal:3128")
	rt, err := NewTransport(Options{
		ProxyURL:      proxy,
		NoProxy:       []string{"registry.example.internal", ".corp.example.internal", "10.0.0.0/8", "cache.example.internal:5000"},
		ProxyUser:     proxyUser,
		ProxyPassword: proxyPass,
	})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.User != nil {
		t.Fatal("Options.ProxyURL was modified")
	}
	cases := []struct {
		target  string
		proxied bool
	}{
		{"https://ghcr.io/v2/", true},
		{"https://registry.example.internal/v2/", false},
		{"https://a.corp.example.internal/v2/", false},
		{"https://corp.example.internal.example.com/v2/", true},
		{"https://10.1.2.3/v2/", false},
		{"https://11.1.2.3/v2/", true},
		{"https://cache.example.internal:5000/v2/", false},
		{"https://cache.example.internal/v2/", true},
	}
	pf := rt.(*http.Transport).Proxy
	for _, tc := range cases {
		req, _ := http.NewRequest(http.MethodGet, tc.target, nil)
		got, err := pf(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.target, err)
		}
		if (got != nil) != tc.proxied {
			t.Fatalf("%s: proxy = %v, want proxied=%v", tc.target, RedactURL(got), tc.proxied)
		}
		if got != nil && (got.Host != "proxy.example.internal:3128" || got.User.Username() != proxyUser) {
			t.Fatalf("%s: unexpected proxy %s", tc.target, RedactURL(got))
		}
	}
}

// connectProxy is a minimal CONNECT proxy. It dials upstream for every
// requested host, so tests can use a non-loopback name: Go never proxies
// localhost or 127.0.0.1, whatever the proxy settings say.
type connectProxy struct {
	upstream string
	status   int
	mu       sync.Mutex
	auth     []string
}

func (p *connectProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.auth = append(p.auth, r.Header.Get("Proxy-Authorization"))
	p.mu.Unlock()
	if r.Method != http.MethodConnect || p.status != http.StatusOK {
		w.WriteHeader(p.status)
		return
	}
	up, err := net.Dial("tcp", p.upstream)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	conn, buf, err := w.(http.Hijacker).Hijack()
	if err != nil {
		_ = up.Close()
		return
	}
	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	go func() { _, _ = io.Copy(up, bufio.NewReader(buf)); _ = up.Close() }()
	_, _ = io.Copy(conn, up)
	_ = conn.Close()
}

func TestProxyConnect(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	for _, status := range []int{http.StatusOK, http.StatusProxyAuthRequired} {
		p := &connectProxy{upstream: srv.Listener.Addr().String(), status: status}
		ps := httptest.NewServer(p)
		proxy, _ := url.Parse(ps.URL)
		rt, err := NewTransport(Options{CAPEM: caPEM(srv), ProxyURL: proxy, ProxyUser: proxyUser, ProxyPassword: proxyPass})
		if err != nil {
			t.Fatal(err)
		}
		// example.com is in the httptest certificate and is not loopback,
		// so the request goes through the proxy.
		err = get(t, rt, "https://example.com/v2/")
		ps.Close()

		if len(p.auth) != 1 {
			t.Fatalf("status %d: %d CONNECT requests", status, len(p.auth))
		}
		r := &http.Request{Header: http.Header{"Authorization": {p.auth[0]}}}
		if u, pw, ok := r.BasicAuth(); !ok || u != proxyUser || pw != proxyPass {
			t.Fatalf("status %d: Proxy-Authorization does not carry the proxy credentials", status)
		}
		if status == http.StatusOK && err != nil {
			t.Fatalf("via proxy: %v", err)
		}
		if status != http.StatusOK {
			if err == nil {
				t.Fatal("want error from a rejecting proxy")
			}
			if strings.Contains(err.Error(), proxyPass) || strings.Contains(err.Error(), proxyUser) {
				t.Fatalf("credentials in error: %v", err)
			}
		}
	}
}

func TestRedactURL(t *testing.T) {
	cases := map[string]string{ //nolint:gosec // fake credentials
		"http://user:pass@proxy.example.internal:3128/x?y=1": "http://proxy.example.internal:3128/x?y=1",
		"https://user@registry.example.com/v2/":              "https://registry.example.com/v2/",
		"https://registry.example.com":                       "https://registry.example.com",
	}
	for in, want := range cases {
		u, _ := url.Parse(in)
		if got := RedactURL(u); got != want {
			t.Fatalf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
	if got := RedactURL(nil); got != "" {
		t.Fatalf("RedactURL(nil) = %q", got)
	}
}
