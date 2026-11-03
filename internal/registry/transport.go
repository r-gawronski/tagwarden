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

// Package registry builds the HTTP transport used to reach OCI registries
// through an egress proxy, with a custom CA bundle and optional mTLS.
package registry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/http/httpproxy"
)

// Options configures NewTransport.
type Options struct {
	// CAPEM is added to the system roots, for example a TLS-inspecting proxy CA.
	CAPEM []byte
	// ProxyURL is used for every request except NoProxy hosts. When nil, the
	// HTTPS_PROXY, HTTP_PROXY and NO_PROXY environment variables apply,
	// unless NoEnvProxy is set.
	ProxyURL *url.URL
	// NoEnvProxy ignores the proxy environment variables: without ProxyURL
	// every request goes direct.
	NoEnvProxy bool
	// NoProxy uses NO_PROXY syntax: a host, a ".suffix" domain or a CIDR,
	// each with an optional port.
	NoProxy []string
	// ProxyUser and ProxyPassword are sent as Proxy-Authorization.
	ProxyUser, ProxyPassword string
	// ClientCert is presented for mTLS.
	ClientCert *tls.Certificate
	// CheckHost runs before every request, including each redirect hop,
	// with the URL host name and whether the request goes through the
	// proxy. An error fails the request before it is sent.
	CheckHost func(ctx context.Context, host string, proxied bool) error
	// CheckDial runs on the resolved address of every direct connection
	// before it connects. Connections to the proxy are not checked.
	CheckDial func(netip.Addr) error
	// Window bounds connection retries. Transports of one run share it.
	// When nil, NewTransport starts its own.
	Window *Window
}

// NewTransport returns a transport based on http.DefaultTransport. It trusts
// the system roots plus o.CAPEM and requires TLS 1.2 or later. Go never
// proxies requests to localhost or loopback addresses.
func NewTransport(o Options) (http.RoundTripper, error) {
	pool, err := x509.SystemCertPool()
	// No system roots (for example a scratch image) is fine: CAPEM may cover it.
	if err != nil {
		pool = x509.NewCertPool()
	}
	if len(o.CAPEM) > 0 && !pool.AppendCertsFromPEM(o.CAPEM) {
		return nil, errors.New("registry: CA bundle contains no PEM certificate")
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if o.ClientCert != nil {
		t.TLSClientConfig.Certificates = []tls.Certificate{*o.ClientCert}
	}
	if t.Proxy, err = proxyFunc(o); err != nil {
		return nil, err
	}
	if o.CheckDial != nil {
		t.DialContext = checkedDial(t.DialContext, o)
	}
	if o.Window == nil {
		o.Window = NewWindow()
	}
	if o.CheckHost != nil {
		return retryTransport{&checkedTransport{t, o.CheckHost}, o.Window}, nil
	}
	return retryTransport{t, o.Window}, nil
}

// PolicyError wraps an error from CheckHost or CheckDial. It is never retried.
type PolicyError struct{ Err error }

func (e *PolicyError) Error() string { return e.Err.Error() }
func (e *PolicyError) Unwrap() error { return e.Err }

// StartupWindow is how long after the start of a run failed dials and
// DNS lookups are retried. Some CNIs reject a new pod's packets until its
// NetworkPolicy is programmed, usually for about a second.
const StartupWindow = 35 * time.Second

// Window is the start of a run, during which connections and lookups may
// fail only because the pod's NetworkPolicy is not yet programmed. It
// ends after StartupWindow or at the first successful request.
type Window struct {
	mu    sync.Mutex
	until time.Time
	now   func() time.Time
}

// NewWindow starts a window of StartupWindow.
func NewWindow() *Window {
	return &Window{until: time.Now().Add(StartupWindow), now: time.Now}
}

// Open reports whether a failure may still be retried.
func (w *Window) Open() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.now().Before(w.until)
}

func (w *Window) end() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.until = time.Time{}
}

// Retry runs f until it succeeds, retry(err) is false, Backoff is used up
// or the window closes. On cancel it returns the last error joined with
// the context error.
func Retry(ctx context.Context, w *Window, retry func(error) bool, f func() error) error {
	for i := 0; ; i++ {
		err := f()
		if err == nil || i == len(Backoff) || !retry(err) || !w.Open() {
			return err
		}
		if werr := Wait(ctx, Backoff[i]); werr != nil {
			return errors.Join(err, werr)
		}
	}
}

// TemporaryDNS reports whether err holds a DNS error that may pass when
// tried again: a timeout or a temporary failure, which includes a query
// the network refused. A missing name is final.
func TemporaryDNS(err error) bool {
	var d *net.DNSError
	return errors.As(err, &d) && !d.IsNotFound && (d.IsTemporary || d.IsTimeout)
}

// Backoff is the wait before each retry of a failed dial or DNS lookup,
// about 30 s in total. Backoff and Wait are hooks for tests only; changing
// them is not safe while requests run, so such tests must not be parallel.
var Backoff = []time.Duration{
	500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second,
}

// Wait sleeps for d or until ctx is done.
var Wait = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// retryTransport retries requests whose connection could not be set up,
// for example while a NetworkPolicy for a new pod is not yet programmed
// and the CNI rejects its packets. Status codes are left to the caller.
type retryTransport struct {
	next   http.RoundTripper
	window *Window
}

func (rt retryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	var resp *http.Response
	rewindable := r.Body == nil || r.GetBody != nil
	first := true
	err := Retry(r.Context(), rt.window, func(err error) bool { return rewindable && dialFailed(err) }, func() error {
		if !first && r.GetBody != nil {
			body, err := r.GetBody()
			if err != nil {
				return err
			}
			c := *r
			c.Body = body
			r = &c
		}
		first = false
		var err error
		resp, err = rt.next.RoundTrip(r)
		return err
	})
	if err != nil {
		return nil, err
	}
	rt.window.end()
	return resp, nil
}

// dialFailed reports whether err comes from dialing the registry or the
// proxy. http.Transport reports those as a *net.OpError with Op "dial",
// wrapped in one with Op "proxyconnect" for the proxy. A dial error means
// nothing was written on the connection, so a retry cannot repeat a request.
// Errors after the TCP connect (TLS, a CONNECT refused with 407, a reset
// while reading the response) have other Ops or none and are not retried.
// Neither are policy refusals from CheckDial, which also surface as dial
// errors, nor DNS errors other than TemporaryDNS ones.
func dialFailed(err error) bool {
	if errors.As(err, new(*PolicyError)) {
		return false
	}
	if errors.As(err, new(*net.DNSError)) {
		return TemporaryDNS(err)
	}
	for {
		var op *net.OpError
		if !errors.As(err, &op) {
			return false
		}
		if op.Op == "dial" {
			return true
		}
		if op.Op != "proxyconnect" {
			return false
		}
		err = op.Err
	}
}

type checkedTransport struct {
	*http.Transport
	check func(ctx context.Context, host string, proxied bool) error
}

func (c *checkedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	var p *url.URL
	var err error
	if c.Proxy != nil {
		p, err = c.Proxy(r)
	}
	if err == nil {
		if err = c.check(r.Context(), r.URL.Hostname(), p != nil); err != nil {
			err = &PolicyError{err}
		}
	}
	if err != nil {
		if r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, err
	}
	return c.Transport.RoundTrip(r)
}

// checkedDial runs o.CheckDial on the address a direct connection is about
// to use, after DNS resolution, so a name cannot be rebound in between.
func checkedDial(plain func(context.Context, string, string) (net.Conn, error), o Options) func(context.Context, string, string) (net.Conn, error) {
	exempt := proxyAddrs(o)
	d := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return err
			}
			if err := o.CheckDial(ap.Addr()); err != nil {
				return &PolicyError{err}
			}
			return nil
		},
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if exempt[addr] {
			return plain(ctx, network, addr)
		}
		return d.DialContext(ctx, network, addr)
	}
}

// proxyAddrs returns the host:port of every proxy the transport may use,
// as the transport dials it.
func proxyAddrs(o Options) map[string]bool {
	urls := []string{}
	switch {
	case o.ProxyURL != nil:
		urls = append(urls, o.ProxyURL.String())
	case o.NoEnvProxy:
	default:
		env := httpproxy.FromEnvironment()
		urls = append(urls, env.HTTPProxy, env.HTTPSProxy)
	}
	out := map[string]bool{}
	for _, s := range urls {
		if s == "" {
			continue
		}
		if !strings.Contains(s, "://") {
			s = "http://" + s
		}
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			continue
		}
		port := u.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
		}
		out[net.JoinHostPort(u.Hostname(), port)] = true
	}
	return out
}

func proxyFunc(o Options) (func(*http.Request) (*url.URL, error), error) {
	if o.ProxyURL == nil {
		if o.NoEnvProxy {
			return nil, nil
		}
		return http.ProxyFromEnvironment, nil
	}
	if (o.ProxyURL.Scheme != "http" && o.ProxyURL.Scheme != "https") || o.ProxyURL.Host == "" {
		return nil, fmt.Errorf("registry: proxy URL %q must be http(s)://host[:port]", RedactURL(o.ProxyURL))
	}
	p := *o.ProxyURL
	if o.ProxyUser != "" || o.ProxyPassword != "" {
		p.User = url.UserPassword(o.ProxyUser, o.ProxyPassword)
	}
	proxy := p.String()
	f := (&httpproxy.Config{HTTPProxy: proxy, HTTPSProxy: proxy, NoProxy: strings.Join(o.NoProxy, ",")}).ProxyFunc()
	return func(r *http.Request) (*url.URL, error) { return f(r.URL) }, nil
}

// RedactURL returns u without userinfo, for errors and logs.
func RedactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	c.User = nil
	return c.String()
}
