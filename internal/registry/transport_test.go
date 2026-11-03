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
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
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
	if v := rt.(retryTransport).next.(*http.Transport).TLSClientConfig.MinVersion; v != tls.VersionTLS12 {
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
	pf := rt.(retryTransport).next.(*http.Transport).Proxy
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
	noRetry(t)
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

var errRefused = errors.New("refused")

func TestCheckHost(t *testing.T) {
	// The redirect target must be refused before any dial.
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer redirect.Close()

	type call struct {
		host    string
		proxied bool
	}
	var calls []call
	rt, err := NewTransport(Options{
		CheckHost: func(_ context.Context, host string, proxied bool) error {
			calls = append(calls, call{host, proxied})
			if host == "169.254.169.254" {
				return errRefused
			}
			return nil
		},
		CheckDial: func(a netip.Addr) error {
			if a.IsLinkLocalUnicast() {
				t.Fatal("dialed the refused redirect target")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&http.Client{Transport: rt}).Get(redirect.URL); !errors.Is(err, errRefused) {
		t.Fatalf("err = %v, want refused", err)
	}
	want := []call{{"127.0.0.1", false}, {"169.254.169.254", false}}
	if !slices.Equal(calls, want) {
		t.Fatalf("calls %v, want %v", calls, want)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	ps := httptest.NewServer(&connectProxy{upstream: srv.Listener.Addr().String(), status: http.StatusOK})
	defer ps.Close()
	proxy, _ := url.Parse(ps.URL)
	calls = nil
	rt, err = NewTransport(Options{
		CAPEM: caPEM(srv), ProxyURL: proxy,
		CheckHost: func(_ context.Context, host string, proxied bool) error {
			calls = append(calls, call{host, proxied})
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, rt, "https://example.com/v2/"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(calls, []call{{"example.com", true}}) {
		t.Fatalf("calls %v", calls)
	}
}

func TestCheckDial(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	var checked []netip.Addr
	refuse := func(a netip.Addr) error {
		checked = append(checked, a)
		return errRefused
	}

	// localhost resolves to loopback; the connect is refused.
	rt, err := NewTransport(Options{CAPEM: caPEM(srv), CheckDial: refuse})
	if err != nil {
		t.Fatal(err)
	}
	u := "https://localhost:" + strings.Split(srv.Listener.Addr().String(), ":")[1] + "/v2/"
	if _, err := (&http.Client{Transport: rt}).Get(u); !errors.Is(err, errRefused) {
		t.Fatalf("err = %v, want refused", err)
	}
	if len(checked) == 0 || !checked[0].IsLoopback() {
		t.Fatalf("checked %v", checked)
	}

	// The proxy itself is not checked.
	ps := httptest.NewServer(&connectProxy{upstream: srv.Listener.Addr().String(), status: http.StatusOK})
	defer ps.Close()
	proxy, _ := url.Parse(ps.URL)
	checked = nil
	rt, err = NewTransport(Options{CAPEM: caPEM(srv), ProxyURL: proxy, CheckDial: refuse})
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, rt, "https://example.com/v2/"); err != nil {
		t.Fatalf("via proxy: %v", err)
	}
	if len(checked) != 0 {
		t.Fatalf("proxy dial checked: %v", checked)
	}
}

func TestNoEnvProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.example.internal:3128")
	t.Setenv("HTTP_PROXY", "http://proxy.example.internal:3128")
	var calls []bool
	rt, err := NewTransport(Options{
		NoEnvProxy: true,
		CheckHost: func(_ context.Context, _ string, proxied bool) error {
			calls = append(calls, proxied)
			return errRefused
		},
		CheckDial: func(netip.Addr) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if rt.(retryTransport).next.(*checkedTransport).Proxy != nil {
		t.Fatal("proxy func set without ProxyURL")
	}
	if _, err := (&http.Client{Transport: rt}).Get("https://ghcr.io/v2/"); !errors.Is(err, errRefused) {
		t.Fatalf("err = %v", err)
	}
	if !slices.Equal(calls, []bool{false}) {
		t.Fatalf("calls %v, want one direct request", calls)
	}
	if addrs := proxyAddrs(Options{NoEnvProxy: true}); len(addrs) != 0 {
		t.Fatalf("proxy addrs from env: %v", addrs)
	}
}

func TestCheckDialHTTP2(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	var checked []netip.Addr
	allow := func(a netip.Addr) error { checked = append(checked, a); return nil }
	rt, err := NewTransport(Options{CAPEM: caPEM(srv), CheckDial: allow})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: rt}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ProtoMajor != 2 {
		t.Fatalf("proto %s, want HTTP/2", resp.Proto)
	}
	if len(checked) != 1 || !checked[0].IsLoopback() {
		t.Fatalf("checked %v", checked)
	}

	rt, err = NewTransport(Options{CAPEM: caPEM(srv), CheckDial: func(netip.Addr) error { return errRefused }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&http.Client{Transport: rt}).Get(srv.URL); !errors.Is(err, errRefused) {
		t.Fatalf("err = %v, want refused", err)
	}
}

// freeAddr returns a loopback address that nothing listens on.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// stubWait replaces the backoff wait for the test. f gets the attempt
// number (1 for the first retry) and the scheduled delay.
func stubWait(t *testing.T, f func(ctx context.Context, n int, d time.Duration) error) {
	t.Helper()
	orig := wait
	n := 0
	wait = func(ctx context.Context, d time.Duration) error {
		n++
		return f(ctx, n, d)
	}
	t.Cleanup(func() { wait = orig })
}

func noRetry(t *testing.T) {
	t.Helper()
	stubWait(t, func(context.Context, int, time.Duration) error {
		t.Fatal("unexpected retry")
		return nil
	})
}

// serveOn starts an HTTP server on addr, which was refused until now.
func serveOn(t *testing.T, addr string, h http.Handler) {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	_ = srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
}

func TestRetryDialRefused(t *testing.T) {
	addr := freeAddr(t)
	var delays []time.Duration
	var got string
	stubWait(t, func(_ context.Context, n int, d time.Duration) error {
		delays = append(delays, d)
		if n == 3 {
			serveOn(t, addr, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				got = string(b)
			}))
		}
		return nil
	})
	rt, err := NewTransport(Options{})
	if err != nil {
		t.Fatal(err)
	}
	// NewRequest sets GetBody for a bytes reader, so the body is re-sent.
	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/v2/", strings.NewReader("blob"))
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if !slices.Equal(delays, backoff[:3]) {
		t.Fatalf("delays %v, want %v", delays, backoff[:3])
	}
	if got != "blob" {
		t.Fatalf("body %q", got)
	}
}

func TestRetryGivesUp(t *testing.T) {
	addr := freeAddr(t)
	var delays []time.Duration
	stubWait(t, func(_ context.Context, _ int, d time.Duration) error {
		delays = append(delays, d)
		return nil
	})
	rt, err := NewTransport(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, rt, "http://"+addr+"/v2/"); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("err = %v", err)
	}
	if !slices.Equal(delays, backoff) {
		t.Fatalf("delays %v, want %v", delays, backoff)
	}
}

func TestNoRetryBodyWithoutGetBody(t *testing.T) {
	noRetry(t)
	rt, err := NewTransport(Options{})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "http://"+freeAddr(t)+"/v2/", io.NopCloser(strings.NewReader("blob")))
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("want error")
	}
}

func TestNoRetryPolicyRefusal(t *testing.T) {
	noRetry(t)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	calls := 0
	rt, err := NewTransport(Options{CheckDial: func(netip.Addr) error { calls++; return errRefused }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&http.Client{Transport: rt}).Get(srv.URL)
	var pe *PolicyError
	if !errors.As(err, &pe) || !errors.Is(err, errRefused) {
		t.Fatalf("err = %v, want PolicyError wrapping refused", err)
	}
	if calls != 1 {
		t.Fatalf("CheckDial ran %d times", calls)
	}

	rt, err = NewTransport(Options{CheckHost: func(context.Context, string, bool) error { return errRefused }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = (&http.Client{Transport: rt}).Get(srv.URL); !errors.As(err, &pe) || !errors.Is(err, errRefused) {
		t.Fatalf("err = %v, want PolicyError wrapping refused", err)
	}
}

func TestRetryStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	orig := wait
	retries := 0
	stubWait(t, func(ctx context.Context, _ int, d time.Duration) error {
		retries++
		cancel()
		return orig(ctx, d)
	})
	rt, err := NewTransport(Options{})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+freeAddr(t)+"/v2/", nil)
	if _, err := rt.RoundTrip(req); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want canceled", err)
	}
	if retries != 1 {
		t.Fatalf("%d retries", retries)
	}
}

func TestNoRetryServerError(t *testing.T) {
	noRetry(t)
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	rt, err := NewTransport(Options{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: rt}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError || hits != 1 {
		t.Fatalf("status %d, %d hits", resp.StatusCode, hits)
	}
}

func TestNoRetryTLSError(t *testing.T) {
	noRetry(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	rt, err := NewTransport(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, rt, srv.URL); err == nil || !strings.Contains(err.Error(), "x509") {
		t.Fatalf("err = %v, want x509", err)
	}
}

func TestRetryProxyRefused(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	addr := freeAddr(t)
	p := &connectProxy{upstream: srv.Listener.Addr().String(), status: http.StatusOK}
	stubWait(t, func(_ context.Context, n int, _ time.Duration) error {
		if n == 1 {
			serveOn(t, addr, p)
		}
		return nil
	})
	proxy, _ := url.Parse("http://" + addr)
	rt, err := NewTransport(Options{CAPEM: caPEM(srv), ProxyURL: proxy})
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, rt, "https://example.com/v2/"); err != nil {
		t.Fatalf("via proxy: %v", err)
	}
	if len(p.auth) != 1 {
		t.Fatalf("%d CONNECT requests", len(p.auth))
	}
}
