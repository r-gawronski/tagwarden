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
	if o.CheckHost != nil {
		return &checkedTransport{t, o.CheckHost}, nil
	}
	return t, nil
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
		err = c.check(r.Context(), r.URL.Hostname(), p != nil)
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
			return o.CheckDial(ap.Addr())
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
